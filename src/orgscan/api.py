from __future__ import annotations

from collections.abc import Sequence
from datetime import date, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from orgscan.db import create_session_factory, init_db
from orgscan.reporting import build_summary, finding_rows, finding_trends, relationship_graph, render_dashboard_html
from orgscan.repositories import Storage


def _serialize_finding(finding, *, include_detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "triage_state": finding.triage_state,
        "triage_owner": finding.triage_owner,
        "triage_notes": finding.triage_notes,
        "source_tool": finding.source_tool,
        "source_name": finding.source_name,
        "organization_id": finding.organization_id,
        "domain_id": finding.domain_id,
        "repository_id": finding.repository_id,
        "account_id": finding.account_id,
        "scan_job_id": finding.scan_job_id,
        "risk_score": finding.risk_score,
        "detected_at": finding.detected_at.isoformat(),
        "fingerprint": finding.fingerprint,
    }
    if include_detail:
        payload.update(
            {
                "source_class": finding.source_class,
                "normalized_hash": finding.normalized_hash,
                "remediation_hint": finding.remediation_hint,
                "first_seen_at": finding.first_seen_at.isoformat(),
                "last_seen_at": finding.last_seen_at.isoformat(),
                "raw_payload": finding.raw_payload,
                "metadata": finding.metadata_json,
            }
        )
    return payload


def _serialize_evidence(evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "finding_id": evidence.finding_id,
        "source": evidence.source,
        "source_url": evidence.source_url,
        "repository_path": evidence.repository_path,
        "commit_sha": evidence.commit_sha,
        "line_start": evidence.line_start,
        "line_end": evidence.line_end,
        "snippet": evidence.snippet,
        "extracted_indicator": evidence.extracted_indicator,
        "confidence": evidence.confidence,
        "observed_at": evidence.observed_at.isoformat(),
        "related_entity_type": evidence.related_entity_type,
        "related_entity_id": evidence.related_entity_id,
        "source_class": evidence.source_class,
        "query_used": evidence.query_used,
    }


def _serialize_relationship(relationship) -> dict[str, Any]:
    return {
        "id": relationship.id,
        "from_entity_type": relationship.from_entity_type,
        "from_entity_id": relationship.from_entity_id,
        "to_entity_type": relationship.to_entity_type,
        "to_entity_id": relationship.to_entity_id,
        "relation_type": relationship.relation_type,
        "confidence": relationship.confidence,
        "source": relationship.source,
        "evidence_summary": relationship.evidence_summary,
    }


def _serialize_risk_score(risk_score) -> dict[str, Any]:
    return {
        "id": risk_score.id,
        "finding_id": risk_score.finding_id,
        "entity_type": risk_score.entity_type,
        "entity_id": risk_score.entity_id,
        "score": risk_score.score,
        "severity": risk_score.severity,
        "confidence": risk_score.confidence,
        "rationale": risk_score.rationale,
        "calculated_at": risk_score.calculated_at.isoformat(),
    }


class FindingUpdateRequest(BaseModel):
    status: str | None = None
    triage_state: str | None = None
    triage_owner: str | None = None
    triage_notes: str | None = None
    remediation_due_date: date | None = None


class FindingDecisionRequest(BaseModel):
    reason: str = Field(min_length=1)
    owner: str | None = None
    note: str | None = None
    due_date: date | None = None


class FindingReopenRequest(BaseModel):
    note: str | None = None


class OrgscanApiService:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        init_db(self.database_url)
        self.session_factory = create_session_factory(self.database_url)

    def _summary_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            return build_summary(Storage(session))

    def _findings_payload(
        self,
        *,
        limit: int = 50,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        source_tool: str | None = None,
        triage_state: str | None = None,
        organization_id: int | None = None,
        domain_id: int | None = None,
        repository_id: int | None = None,
        account_id: int | None = None,
        scan_job_id: int | None = None,
        risk_score_min: float | None = None,
        risk_score_max: float | None = None,
        detected_after: datetime | None = None,
        detected_before: datetime | None = None,
        high_signal_only: bool = False,
        min_confidence: str = "likely",
    ) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            findings = storage.list_findings(
                limit=max(limit * 4, limit) if high_signal_only else limit,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
                source_tool=source_tool,
                triage_state=triage_state,
                organization_id=organization_id,
                domain_id=domain_id,
                repository_id=repository_id,
                account_id=account_id,
                scan_job_id=scan_job_id,
                risk_score_min=risk_score_min,
                risk_score_max=risk_score_max,
                detected_after=detected_after,
                detected_before=detected_before,
            )
            if high_signal_only:
                findings = self._high_signal_findings(findings, min_confidence=min_confidence, limit=limit)
            return {
                "findings": [_serialize_finding(finding) for finding in findings]
            }

    @staticmethod
    def _parse_datetime_param(value: str | None) -> datetime | None:
        if value in (None, ""):
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _high_signal_findings(
        self,
        findings: Sequence[Any],
        *,
        min_confidence: str = "likely",
        limit: int = 10,
    ) -> list[Any]:
        allowed = set(Storage._allowed_confidences(min_confidence))
        return [
            finding
            for finding in findings
            if finding.confidence in allowed and finding.status not in {"suppressed"}
        ][:limit]

    def _update_finding_triage(
        self,
        finding_id: int,
        payload: FindingUpdateRequest,
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            finding = storage.get_finding(finding_id)
            if finding is None:
                return None
            updated = storage.update_finding_triage(
                finding_id,
                status=payload.status,
                triage_state=payload.triage_state,
                triage_owner=payload.triage_owner,
                triage_notes=payload.triage_notes,
                remediation_due_date=payload.remediation_due_date,
            )
            session.commit()
            return {"finding": _serialize_finding(updated, include_detail=True)}

    def _apply_finding_decision(
        self,
        finding_id: int,
        payload: FindingDecisionRequest,
        *,
        status: str,
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            finding = storage.get_finding(finding_id)
            if finding is None:
                return None
            updated = storage.suppress_finding(
                finding_id,
                reason=payload.reason,
                owner=payload.owner,
                deadline=payload.due_date,
                notes=payload.note,
                status=status,
            )
            session.commit()
            return {"finding": _serialize_finding(updated, include_detail=True)}

    def _reopen_finding(
        self,
        finding_id: int,
        payload: FindingReopenRequest,
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            finding = storage.get_finding(finding_id)
            if finding is None:
                return None
            updated = storage.update_finding_triage(
                finding_id,
                status="open",
                triage_state="reopened",
                triage_notes=payload.note,
            )
            session.commit()
            return {"finding": _serialize_finding(updated, include_detail=True)}

    def _entity_risk_profile(
        self,
        storage: Storage,
        *,
        entity_type: str,
        entity_id: int,
        min_confidence: str = "likely",
    ) -> dict[str, Any]:
        profiles = storage.list_entity_risk_profiles(
            entity_type=entity_type,
            entity_id=entity_id,
            min_confidence=min_confidence,
            limit=1,
        )
        if profiles:
            return profiles[0]
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "entity_name": f"{entity_type}:{entity_id}",
            "finding_count": 0,
            "active_finding_count": 0,
            "suppressed_count": 0,
            "verified_count": 0,
            "likely_count": 0,
            "heuristic_count": 0,
            "max_risk_score": 0.0,
            "average_risk_score": 0.0,
        }

    def _organizations_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            organizations = list(storage.list_organizations())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="organization",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return {
                "organizations": [
                    {
                        "id": organization.id,
                        "name": organization.name,
                        "display_name": organization.display_name,
                        "github_handle": organization.github_handle,
                        "description": organization.description,
                        "risk_summary": profiles.get(organization.id),
                    }
                    for organization in organizations
                ]
            }

    def _organization_payload(
        self,
        organization_id: int,
        *,
        finding_limit: int = 10,
        relationship_limit: int = 25,
        min_confidence: str = "likely",
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            organization = storage.get_organization(organization_id)
            if organization is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), organization_id=organization_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return {
                "organization": {
                    "id": organization.id,
                    "name": organization.name,
                    "display_name": organization.display_name,
                    "github_handle": organization.github_handle,
                    "description": organization.description,
                    "metadata": organization.metadata_json,
                },
                "risk_summary": self._entity_risk_profile(
                    storage, entity_type="organization", entity_id=organization_id, min_confidence=min_confidence
                ),
                "domains": [{"id": domain.id, "name": domain.name} for domain in organization.domains],
                "repositories": [{"id": repository.id, "full_name": repository.full_name} for repository in organization.repositories],
                "accounts": [{"id": account.id, "username": account.username} for account in organization.accounts],
                "relationships": [
                    _serialize_relationship(relationship)
                    for relationship in storage.list_relationships_for_entity("organization", str(organization_id), limit=relationship_limit)
                ],
                "top_findings": [_serialize_finding(finding) for finding in findings],
            }

    def _repositories_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            repositories = list(storage.list_repositories())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="repository",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return {
                "repositories": [
                    {
                        "id": repository.id,
                        "full_name": repository.full_name,
                        "provider": repository.provider,
                        "url": repository.url,
                        "default_branch": repository.default_branch,
                        "organization_id": repository.organization_id,
                        "owner_account_id": repository.owner_account_id,
                        "risk_summary": profiles.get(repository.id),
                    }
                    for repository in repositories
                ]
            }

    def _repository_payload(
        self,
        repository_id: int,
        *,
        finding_limit: int = 10,
        relationship_limit: int = 25,
        min_confidence: str = "likely",
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            repository = storage.get_repository(repository_id)
            if repository is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), repository_id=repository_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return {
                "repository": {
                    "id": repository.id,
                    "full_name": repository.full_name,
                    "provider": repository.provider,
                    "url": repository.url,
                    "default_branch": repository.default_branch,
                    "organization_id": repository.organization_id,
                    "owner_account_id": repository.owner_account_id,
                    "metadata": repository.metadata_json,
                },
                "risk_summary": self._entity_risk_profile(
                    storage, entity_type="repository", entity_id=repository_id, min_confidence=min_confidence
                ),
                "relationships": [
                    _serialize_relationship(relationship)
                    for relationship in storage.list_relationships_for_entity("repository", str(repository_id), limit=relationship_limit)
                ],
                "top_findings": [_serialize_finding(finding) for finding in findings],
            }

    def _domains_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            domains = list(storage.list_domains())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="domain",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return {
                "domains": [
                    {
                        "id": domain.id,
                        "name": domain.name,
                        "organization_id": domain.organization_id,
                        "ownership_confidence": domain.ownership_confidence,
                        "verification_status": domain.verification_status,
                        "risk_summary": profiles.get(domain.id),
                    }
                    for domain in domains
                ]
            }

    def _domain_payload(
        self,
        domain_id: int,
        *,
        finding_limit: int = 10,
        relationship_limit: int = 25,
        min_confidence: str = "likely",
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            domain = storage.get_domain(domain_id)
            if domain is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), domain_id=domain_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return {
                "domain": {
                    "id": domain.id,
                    "name": domain.name,
                    "organization_id": domain.organization_id,
                    "ownership_confidence": domain.ownership_confidence,
                    "verification_status": domain.verification_status,
                    "discovered_emails": domain.discovered_emails,
                    "discovered_subdomains": domain.discovered_subdomains,
                    "discovery_sources": domain.discovery_sources,
                    "risk_score": domain.risk_score,
                },
                "risk_summary": self._entity_risk_profile(
                    storage, entity_type="domain", entity_id=domain_id, min_confidence=min_confidence
                ),
                "exposures": [
                    {
                        "id": exposure.id,
                        "source": exposure.source,
                        "source_name": exposure.source_name,
                        "result_summary": exposure.result_summary,
                        "last_seen": exposure.last_seen.isoformat(),
                    }
                    for exposure in storage.list_domain_exposures(domain_id=domain_id)
                ],
                "identity_correlations": [
                    {
                        "id": correlation.id,
                        "email": correlation.email,
                        "username": correlation.username,
                        "relation_type": correlation.relation_type,
                        "confidence": correlation.confidence,
                    }
                    for correlation in storage.list_identity_correlations(domain_id=domain_id)
                ],
                "relationships": [
                    _serialize_relationship(relationship)
                    for relationship in storage.list_relationships_for_entity("domain", str(domain_id), limit=relationship_limit)
                ],
                "top_findings": [_serialize_finding(finding) for finding in findings],
            }

    def _accounts_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            accounts = list(storage.list_accounts())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="account",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return {
                "accounts": [
                    {
                        "id": account.id,
                        "username": account.username,
                        "provider": account.provider,
                        "account_type": account.account_type,
                        "display_name": account.display_name,
                        "email": account.email,
                        "organization_id": account.organization_id,
                        "risk_summary": profiles.get(account.id),
                    }
                    for account in accounts
                ]
            }

    def _account_payload(
        self,
        account_id: int,
        *,
        finding_limit: int = 10,
        relationship_limit: int = 25,
        min_confidence: str = "likely",
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            account = storage.get_account(account_id)
            if account is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), account_id=account_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return {
                "account": {
                    "id": account.id,
                    "username": account.username,
                    "provider": account.provider,
                    "account_type": account.account_type,
                    "display_name": account.display_name,
                    "email": account.email,
                    "organization_id": account.organization_id,
                    "metadata": account.metadata_json,
                },
                "risk_summary": self._entity_risk_profile(
                    storage, entity_type="account", entity_id=account_id, min_confidence=min_confidence
                ),
                "repositories": [{"id": repository.id, "full_name": repository.full_name} for repository in account.repositories],
                "relationships": [
                    _serialize_relationship(relationship)
                    for relationship in storage.list_relationships_for_entity("account", str(account_id), limit=relationship_limit)
                ],
                "top_findings": [_serialize_finding(finding) for finding in findings],
            }

    def _finding_payload(self, finding_id: int) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            finding = storage.get_finding(finding_id)
            if finding is None:
                return None
            return {
                "finding": _serialize_finding(finding, include_detail=True),
                "evidence": [_serialize_evidence(evidence) for evidence in storage.list_finding_evidence(finding_id)],
                "risk_scores": [_serialize_risk_score(score) for score in storage.list_risk_scores(finding_id=finding_id)],
            }

    def _risk_summary_payload(
        self,
        *,
        entity_type: str | None = None,
        min_confidence: str = "likely",
        limit: int = 50,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            return {
                "min_confidence": min_confidence,
                "risk_profiles": storage.list_entity_risk_profiles(
                    entity_type=entity_type,
                    min_confidence=min_confidence,
                    limit=limit,
                ),
            }

    def _scheduled_scans_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            return {
                "scheduled_scans": [
                    {
                        "id": scan.id,
                        "target_type": scan.target_type,
                        "target_value": scan.target_value,
                        "scanner_name": scan.scanner_name,
                        "cadence": scan.cadence,
                        "enabled": scan.enabled,
                        "next_run_at": scan.next_run_at.isoformat(),
                    }
                    for scan in storage.list_scheduled_scans()
                ]
            }

    def _relationship_graph_payload(self, *, limit: int = 200) -> dict[str, object]:
        with self.session_factory() as session:
            return relationship_graph(Storage(session), limit=limit)

    def _finding_trends_payload(self, *, days: int = 30) -> dict[str, object]:
        with self.session_factory() as session:
            return {"days": days, "trends": finding_trends(Storage(session), days=days)}

    def _dashboard_html(
        self,
        *,
        limit: int = 100,
        days: int = 30,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> str:
        with self.session_factory() as session:
            storage = Storage(session)
            summary = build_summary(storage)
            filtered_rows = [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "triage_state": finding.triage_state,
                    "triage_owner": finding.triage_owner,
                    "triage_notes": finding.triage_notes,
                    "remediation_due_date": finding.remediation_due_date.isoformat() if finding.remediation_due_date else None,
                    "source_tool": finding.source_tool,
                    "source_name": finding.source_name,
                    "repository_id": finding.repository_id,
                    "scan_job_id": finding.scan_job_id,
                    "detected_at": finding.detected_at.isoformat(),
                    "fingerprint": finding.fingerprint,
                }
                for finding in storage.list_findings(
                    limit=limit,
                    status=status,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                )
            ]
            return render_dashboard_html(
                summary,
                filtered_rows,
                trends=finding_trends(storage, days=days),
                graph=relationship_graph(storage, limit=200),
                filters={
                    "limit": limit,
                    "days": days,
                    "status": status or "",
                    "severity": severity or "",
                    "category": category or "",
                    "confidence": confidence or "",
                },
                live=True,
            )

    def handle(self, path: str) -> tuple[int, dict[str, object]]:
        parsed = urlparse(path)
        params = parse_qs(parsed.query)
        route = parsed.path
        if route == "/health":
            return 200, {"status": "ok"}
        if route == "/summary":
            return 200, self._summary_payload()
        if route == "/findings":
            return 200, self._findings_payload(
                limit=int(params.get("limit", ["50"])[0]),
                status=params.get("status", [None])[0],
                severity=params.get("severity", [None])[0],
                category=params.get("category", [None])[0],
                confidence=params.get("confidence", [None])[0],
                source_tool=params.get("source_tool", [None])[0],
                triage_state=params.get("triage_state", [None])[0],
                organization_id=int(params["organization_id"][0]) if params.get("organization_id") else None,
                domain_id=int(params["domain_id"][0]) if params.get("domain_id") else None,
                repository_id=int(params["repository_id"][0]) if params.get("repository_id") else None,
                account_id=int(params["account_id"][0]) if params.get("account_id") else None,
                scan_job_id=int(params["scan_job_id"][0]) if params.get("scan_job_id") else None,
                risk_score_min=float(params["risk_score_min"][0]) if params.get("risk_score_min") else None,
                risk_score_max=float(params["risk_score_max"][0]) if params.get("risk_score_max") else None,
                detected_after=self._parse_datetime_param(params.get("detected_after", [None])[0]),
                detected_before=self._parse_datetime_param(params.get("detected_before", [None])[0]),
                high_signal_only=params.get("high_signal_only", ["false"])[0].lower() == "true",
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
        if route == "/organizations":
            return 200, self._organizations_payload(
                limit=int(params.get("limit", ["100"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
        if route.startswith("/organizations/"):
            payload = self._organization_payload(
                int(route.rsplit("/", 1)[1]),
                finding_limit=int(params.get("finding_limit", ["10"])[0]),
                relationship_limit=int(params.get("relationship_limit", ["25"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
            return (200, payload) if payload is not None else (404, {"error": "Organization not found"})
        if route == "/repositories":
            return 200, self._repositories_payload(
                limit=int(params.get("limit", ["100"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
        if route.startswith("/repositories/"):
            payload = self._repository_payload(
                int(route.rsplit("/", 1)[1]),
                finding_limit=int(params.get("finding_limit", ["10"])[0]),
                relationship_limit=int(params.get("relationship_limit", ["25"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
            return (200, payload) if payload is not None else (404, {"error": "Repository not found"})
        if route == "/domains":
            return 200, self._domains_payload(
                limit=int(params.get("limit", ["100"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
        if route.startswith("/domains/"):
            payload = self._domain_payload(
                int(route.rsplit("/", 1)[1]),
                finding_limit=int(params.get("finding_limit", ["10"])[0]),
                relationship_limit=int(params.get("relationship_limit", ["25"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
            return (200, payload) if payload is not None else (404, {"error": "Domain not found"})
        if route == "/accounts":
            return 200, self._accounts_payload(
                limit=int(params.get("limit", ["100"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
        if route.startswith("/accounts/"):
            payload = self._account_payload(
                int(route.rsplit("/", 1)[1]),
                finding_limit=int(params.get("finding_limit", ["10"])[0]),
                relationship_limit=int(params.get("relationship_limit", ["25"])[0]),
                min_confidence=params.get("min_confidence", ["likely"])[0],
            )
            return (200, payload) if payload is not None else (404, {"error": "Account not found"})
        if route == "/risk-summary":
            return 200, self._risk_summary_payload(
                entity_type=params.get("entity_type", [None])[0],
                min_confidence=params.get("min_confidence", ["likely"])[0],
                limit=int(params.get("limit", ["50"])[0]),
            )
        if route.startswith("/findings/") and route.endswith("/evidence"):
            finding_id = int(route.removeprefix("/findings/").removesuffix("/evidence").rstrip("/"))
            payload = self._finding_payload(finding_id)
            return (200, {"finding_id": finding_id, "evidence": payload["evidence"]}) if payload is not None else (404, {"error": "Finding not found"})
        if route.startswith("/findings/"):
            payload = self._finding_payload(int(route.rsplit("/", 1)[1]))
            return (200, payload) if payload is not None else (404, {"error": "Finding not found"})
        if route == "/scheduled-scans":
            return 200, self._scheduled_scans_payload()
        if route == "/relationships/graph":
            return 200, self._relationship_graph_payload(limit=int(params.get("limit", ["200"])[0]))
        if route == "/trends/findings":
            return 200, self._finding_trends_payload(days=int(params.get("days", ["30"])[0]))
        return 404, {"error": f"Unknown route: {route}"}


def create_app(database_url: str) -> FastAPI:
    service = OrgscanApiService(database_url)
    app = FastAPI(title="orgscan", version="0.1.0")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/summary")
    def summary() -> dict[str, object]:
        return service._summary_payload()

    @app.get("/findings")
    def findings(
        limit: int = Query(50, ge=1, le=500),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        source_tool: str | None = None,
        triage_state: str | None = None,
        organization_id: int | None = None,
        domain_id: int | None = None,
        repository_id: int | None = None,
        account_id: int | None = None,
        scan_job_id: int | None = None,
        risk_score_min: float | None = None,
        risk_score_max: float | None = None,
        detected_after: datetime | None = None,
        detected_before: datetime | None = None,
        high_signal_only: bool = False,
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._findings_payload(
            limit=limit,
            status=status,
            severity=severity,
            category=category,
            confidence=confidence,
            source_tool=source_tool,
            triage_state=triage_state,
            organization_id=organization_id,
            domain_id=domain_id,
            repository_id=repository_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
            detected_after=detected_after,
            detected_before=detected_before,
            high_signal_only=high_signal_only,
            min_confidence=min_confidence,
        )

    @app.get("/findings/{finding_id}")
    def finding_detail(finding_id: int) -> dict[str, object]:
        payload = service._finding_payload(finding_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return payload

    @app.patch("/findings/{finding_id}")
    def update_finding(finding_id: int, payload: FindingUpdateRequest) -> dict[str, object]:
        result = service._update_finding_triage(finding_id, payload)
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @app.post("/findings/{finding_id}/suppress")
    def suppress_finding(finding_id: int, payload: FindingDecisionRequest) -> dict[str, object]:
        result = service._apply_finding_decision(finding_id, payload, status="suppressed")
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @app.post("/findings/{finding_id}/accept-risk")
    def accept_risk_finding(finding_id: int, payload: FindingDecisionRequest) -> dict[str, object]:
        result = service._apply_finding_decision(finding_id, payload, status="accepted_risk")
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @app.post("/findings/{finding_id}/reopen")
    def reopen_finding(finding_id: int, payload: FindingReopenRequest) -> dict[str, object]:
        result = service._reopen_finding(finding_id, payload)
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @app.get("/findings/{finding_id}/evidence")
    def finding_evidence(finding_id: int) -> dict[str, object]:
        payload = service._finding_payload(finding_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {"finding_id": finding_id, "evidence": payload["evidence"]}

    @app.get("/organizations")
    def organizations(
        limit: int = Query(100, ge=1, le=500),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._organizations_payload(limit=limit, min_confidence=min_confidence)

    @app.get("/organizations/{organization_id}")
    def organization_detail(
        organization_id: int,
        finding_limit: int = Query(10, ge=1, le=100),
        relationship_limit: int = Query(25, ge=1, le=200),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        payload = service._organization_payload(
            organization_id,
            finding_limit=finding_limit,
            relationship_limit=relationship_limit,
            min_confidence=min_confidence,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        return payload

    @app.get("/repositories")
    def repositories(
        limit: int = Query(100, ge=1, le=500),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._repositories_payload(limit=limit, min_confidence=min_confidence)

    @app.get("/repositories/{repository_id}")
    def repository_detail(
        repository_id: int,
        finding_limit: int = Query(10, ge=1, le=100),
        relationship_limit: int = Query(25, ge=1, le=200),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        payload = service._repository_payload(
            repository_id,
            finding_limit=finding_limit,
            relationship_limit=relationship_limit,
            min_confidence=min_confidence,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Repository not found")
        return payload

    @app.get("/domains")
    def domains(
        limit: int = Query(100, ge=1, le=500),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._domains_payload(limit=limit, min_confidence=min_confidence)

    @app.get("/domains/{domain_id}")
    def domain_detail(
        domain_id: int,
        finding_limit: int = Query(10, ge=1, le=100),
        relationship_limit: int = Query(25, ge=1, le=200),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        payload = service._domain_payload(
            domain_id,
            finding_limit=finding_limit,
            relationship_limit=relationship_limit,
            min_confidence=min_confidence,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Domain not found")
        return payload

    @app.get("/accounts")
    def accounts(
        limit: int = Query(100, ge=1, le=500),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._accounts_payload(limit=limit, min_confidence=min_confidence)

    @app.get("/accounts/{account_id}")
    def account_detail(
        account_id: int,
        finding_limit: int = Query(10, ge=1, le=100),
        relationship_limit: int = Query(25, ge=1, le=200),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        payload = service._account_payload(
            account_id,
            finding_limit=finding_limit,
            relationship_limit=relationship_limit,
            min_confidence=min_confidence,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Account not found")
        return payload

    @app.get("/risk-summary")
    def risk_summary(
        entity_type: str | None = Query(None, pattern="^(organization|domain|repository|account)$|^$"),
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
        limit: int = Query(50, ge=1, le=500),
    ) -> dict[str, object]:
        return service._risk_summary_payload(entity_type=entity_type or None, min_confidence=min_confidence, limit=limit)

    @app.get("/scheduled-scans")
    def scheduled_scans() -> dict[str, object]:
        return service._scheduled_scans_payload()

    @app.get("/relationships/graph")
    def relationships(limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
        return service._relationship_graph_payload(limit=limit)

    @app.get("/trends/findings")
    def trends(days: int = Query(30, ge=1, le=365)) -> dict[str, object]:
        return service._finding_trends_payload(days=days)

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(
        limit: int = Query(100, ge=1, le=500),
        days: int = Query(30, ge=1, le=365),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> HTMLResponse:
        return HTMLResponse(
            service._dashboard_html(
                limit=limit,
                days=days,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
            )
        )

    return app


def serve_api(database_url: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    uvicorn.run(create_app(database_url), host=host, port=port, log_level="info")
