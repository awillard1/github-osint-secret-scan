from __future__ import annotations

from orgscan.redaction import safe_output, redact
from orgscan.api.limits import RequestBodyLimit, read_upload
from orgscan.archive_limits import tar_stream, check_zip_directory
from hashlib import sha256

import tarfile
import tempfile
import zipfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from orgscan.bootstrap import optional_tool_inventory
from orgscan.config import Settings, get_settings
from orgscan.db import prepare_database, create_session_factory
from orgscan.models import ScanJob, ToolRun
from orgscan.runner import execute_scan
from orgscan.reporting import (
    build_summary,
    finding_rows,
    finding_trends,
    relationship_graph,
    render_dashboard_html,
    render_finding_detail_html,
    render_graph_html,
    render_scan_job_detail_html,
)
from orgscan.repositories import Storage
from orgscan.services.finding_service import (
    FindingDecision,
    FindingNotFound,
    FindingQuery,
    FindingService,
    TriageUpdate,
    high_signal_findings,
)
from orgscan.api.schemas import (
    DashboardFindingWorkflowRequest,
    FindingDecisionRequest,
    FindingReopenRequest,
    FindingUpdateRequest,
)
from orgscan.api.routes.findings import create_finding_router
from orgscan.api.routes.dashboard import create_operator_router
from orgscan.api.routes.reports import create_report_router
from orgscan.services.dashboard_service import DashboardService
from orgscan.scanners import get_registry
from orgscan.services.scanner_service import artifact_scanner_options, scanner_inventory
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.target_service import resolve_asset_context
from orgscan.services.scan_service import execute_plan, result_payload
from orgscan.scanners.external import ScannerExecutionError

MAX_ARTIFACT_UPLOAD_BYTES = 10_000_000
MAX_ARTIFACT_EXTRACTED_BYTES = 25_000_000
MAX_ARTIFACT_EXTRACTED_FILES = 2_000


from orgscan.lifecycle import lifecycle_fields, history_row


@safe_output
def _serialize_finding(finding, *, include_detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        **lifecycle_fields(finding),
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
    from orgscan.presentation import safe_finding_fields
    return safe_finding_fields(finding, payload)


@safe_output
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
        "metadata": evidence.metadata_json,
        "observation_fingerprint": evidence.observation_fingerprint,
    }


@safe_output
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
        "metadata": relationship.metadata_json,
    }


@safe_output
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


@safe_output
def _serialize_scan_job(scan_job: ScanJob) -> dict[str, Any]:
    return {
        "id": scan_job.id,
        "target_type": scan_job.target_type,
        "target_id": scan_job.target_id,
        "scanner_name": scan_job.scanner_name,
        "status": scan_job.status,
        "parameters_json": scan_job.parameters_json,
        "scope_json": scan_job.scope_json,
        "error_message": scan_job.error_message,
        "started_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
        "completed_at": scan_job.completed_at.isoformat() if scan_job.completed_at else None,
    }


@safe_output
def _serialize_tool_run(tool_run: ToolRun) -> dict[str, Any]:
    return {
        "id": tool_run.id,
        "scan_job_id": tool_run.scan_job_id,
        "tool_name": tool_run.tool_name,
        "target": tool_run.target,
        "command_line": tool_run.command_line,
        "status": tool_run.status,
        "stdout_log": tool_run.stdout_log,
        "stderr_log": tool_run.stderr_log,
        "started_at": tool_run.started_at.isoformat() if tool_run.started_at else None,
        "completed_at": tool_run.completed_at.isoformat() if tool_run.completed_at else None,
    }


from orgscan.services.artifact_service import _safe_artifact_name, _archive_type, _safe_extract_destination


def _extract_zip_artifact(artifact_path: Path, destination_root: Path) -> int:
    from orgscan.services.artifact_service import _extract_zip_artifact as extract
    return extract(artifact_path,destination_root,max_files=MAX_ARTIFACT_EXTRACTED_FILES,max_bytes=MAX_ARTIFACT_EXTRACTED_BYTES)


def _extract_tar_artifact(artifact_path: Path, destination_root: Path) -> int:
    from orgscan.services.artifact_service import _extract_tar_artifact as extract
    return extract(artifact_path,destination_root,max_files=MAX_ARTIFACT_EXTRACTED_FILES,max_bytes=MAX_ARTIFACT_EXTRACTED_BYTES)


class OrgscanApiService:
    def __init__(self, database_url: str, settings: Settings | None = None) -> None:
        self.database_url = database_url
        self.settings = (settings or get_settings()).model_copy(update={"database_url": database_url})
        prepare_database(self.settings)
        from orgscan.storage.authorization import authorized_session_factory
        self.session_factory = authorized_session_factory(create_session_factory(self.database_url))
        self.finding_service = FindingService(self.session_factory)

    def _access_context_note(self) -> str:
        from orgscan.security_context import current_auth
        auth = current_auth.get()
        if auth is not None and auth.authenticated:
            return f"Signed in as {auth.name} ({auth.role}); tenant scope: {', '.join(auth.tenants)}."
        return "Local development mode: authentication is not configured."

    @safe_output
    def _tooling_payload(self) -> dict[str, object]:
        inventory = scanner_inventory(self.settings)
        tools = optional_tool_inventory(self.settings, inventory=inventory)
        return {
            "scanners": artifact_scanner_options(self.settings, inventory=inventory),
            "scanner_readiness": inventory,
            "scanner_registry_warnings": list(get_registry().warnings),
            "optional_tools": tools,
            "installed_optional_tools": [item["name"] for item in tools if item["installed"]],
            "missing_optional_tools": [item["name"] for item in tools if not item["installed"]],
        }

    @safe_output
    def _summary_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            return build_summary(Storage(session))

    @safe_output
    def _findings_payload(
        self,
        *,
        limit: int = 50,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        source_tool: str | None = None,
        lifecycle_state: str | None = None,
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
        findings = self.finding_service.list_findings(FindingQuery(
            limit=limit, status=status, severity=severity, category=category,
            confidence=confidence, source_tool=source_tool, triage_state=triage_state, lifecycle_state=lifecycle_state,
            organization_id=organization_id, domain_id=domain_id, repository_id=repository_id,
            account_id=account_id, scan_job_id=scan_job_id, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max, detected_after=detected_after, detected_before=detected_before,
            high_signal_only=high_signal_only, min_confidence=min_confidence,
        ))
        return {"findings": [_serialize_finding(finding) for finding in findings]}

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
        return high_signal_findings(findings, min_confidence=min_confidence, limit=limit)

    def _update_finding_triage(
        self,
        finding_id: int,
        payload: FindingUpdateRequest,
    ) -> dict[str, object] | None:
        try:
            updated = self.finding_service.update_triage(finding_id, TriageUpdate(**payload.model_dump()))
        except FindingNotFound:
            return None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"finding": _serialize_finding(updated, include_detail=True)}

    def _apply_finding_decision(
        self,
        finding_id: int,
        payload: FindingDecisionRequest,
        *,
        status: str,
    ) -> dict[str, object] | None:
        try:
            updated = self.finding_service.apply_decision(finding_id, FindingDecision(**payload.model_dump()), status=status)
        except FindingNotFound:
            return None
        return {"finding": _serialize_finding(updated, include_detail=True)}

    def _reopen_finding(
        self,
        finding_id: int,
        payload: FindingReopenRequest,
    ) -> dict[str, object] | None:
        try:
            updated = self.finding_service.reopen(finding_id, note=payload.note)
        except FindingNotFound:
            return None
        return {"finding": _serialize_finding(updated, include_detail=True)}

    def _resolve_asset_context(self, storage, *, organization, repository, provider):
        return resolve_asset_context(storage, organization=organization, repository=repository, provider=provider)

    @safe_output
    def _scan_uploaded_artifact(
        self,
        *,
        filename: str | None,
        content: bytes,
        scanner_name: str | None = None,
        profile: str | None = None,
        organization: str | None,
        repository: str | None,
        provider: str,
    ) -> dict[str, object]:
        artifact_name = _safe_artifact_name(filename)
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded artifact is empty.")
        if len(content) > MAX_ARTIFACT_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Uploaded artifact exceeds the allowed size limit.")

        try:
            with tempfile.TemporaryDirectory(prefix="orgscan-artifact-") as temp_dir:
                workspace = Path(temp_dir)
                artifact_path = workspace / artifact_name
                artifact_path.write_bytes(content)
                archive_type = _archive_type(artifact_path)
                scan_target = artifact_path
                extracted = False

                if archive_type is not None:
                    extracted_root = workspace / "extracted"
                    extracted_root.mkdir()
                    try:
                        extracted_files = (
                            _extract_zip_artifact(artifact_path, extracted_root)
                            if archive_type == "zip"
                            else _extract_tar_artifact(artifact_path, extracted_root)
                        )
                    except (tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
                        raise HTTPException(status_code=400, detail=f"Invalid uploaded archive: {exc}") from exc
                    if extracted_files == 0:
                        raise HTTPException(status_code=400, detail="Uploaded archive does not contain any regular files.")
                    scan_target = extracted_root
                    extracted = True

                with self.session_factory() as session:
                    storage = Storage(session)
                    organization_id, repository_id = self._resolve_asset_context(
                        storage,
                        organization=organization,
                        repository=repository,
                        provider=provider,
                    )
                    plan = resolve_scan_plan(target=str(scan_target), target_type="artifact", profile=profile,
                                             scanners=[scanner_name] if scanner_name else None, settings=self.settings,
                                             organization_id=organization_id, repository_id=repository_id)
                    results = execute_plan(
                        storage, plan, settings=self.settings,
                        target_label=artifact_name,
                        canonical_root=Path("/orgscan-artifacts") / sha256(artifact_name.encode()).hexdigest(),
                        command_line=f"api artifact scan {artifact_name} --scanners {','.join(plan.scanners)}",
                        parameters_json={
                            "artifact_name": artifact_name,
                            "artifact_kind": archive_type or "file",
                            "extracted": extracted,
                            "scanner": plan.scanners[0],
                        },
                    )
        except ScannerExecutionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return {**result_payload(results), "artifact_name": artifact_name, "extracted": extracted}

    @safe_output
    def _finding_html_payload(self, finding_id: int) -> dict[str, object] | None:
        return self._finding_payload(finding_id)

    @safe_output
    def _scan_job_payload(self, scan_job_id: int) -> dict[str, object] | None:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='jobs')
            scan_job = storage.get_scan_job(scan_job_id)
            if scan_job is None:
                return None
            return storage.safe_projection({
                "scan_job": _serialize_scan_job(scan_job),
                "tool_runs": [_serialize_tool_run(run) for run in storage.list_tool_runs(limit=25, scan_job_id=scan_job_id)],
                "findings": [_serialize_finding(finding) for finding in storage.list_findings(limit=100, scan_job_id=scan_job_id)],
            }, family='jobs', source_context=context)

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

    @safe_output
    def _organizations_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='assets')
            organizations = list(storage.list_organizations())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="organization",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
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
            context = storage.projection_context(family='assets')
            organization = storage.get_organization(organization_id)
            if organization is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), organization_id=organization_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
    def _repositories_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='assets')
            repositories = list(storage.list_repositories())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="repository",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
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
            context = storage.projection_context(family='assets')
            repository = storage.get_repository(repository_id)
            if repository is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), repository_id=repository_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
    def _domains_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='assets')
            domains = list(storage.list_domains())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="domain",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
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
            context = storage.projection_context(family='assets')
            domain = storage.get_domain(domain_id)
            if domain is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), domain_id=domain_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
    def _accounts_payload(self, *, limit: int = 100, min_confidence: str = "likely") -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='assets')
            accounts = list(storage.list_accounts())[:limit]
            profiles = {
                item["entity_id"]: item
                for item in storage.list_entity_risk_profiles(
                    entity_type="account",
                    min_confidence=min_confidence,
                    limit=max(limit, 1),
                )
            }
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
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
            context = storage.projection_context(family='assets')
            account = storage.get_account(account_id)
            if account is None:
                return None
            findings = self._high_signal_findings(
                storage.list_findings(limit=max(finding_limit * 4, finding_limit), account_id=account_id),
                min_confidence=min_confidence,
                limit=finding_limit,
            )
            return storage.safe_projection({
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
            }, family='assets', source_context=context)

    @safe_output
    def _finding_payload(self, finding_id: int) -> dict[str, object] | None:
        detail = self.finding_service.get_detail(finding_id)
        if detail is None:
            return None
        from orgscan.presentation import safe_finding_fields
        return safe_finding_fields(detail.finding, {
            "finding": _serialize_finding(detail.finding, include_detail=True),
            "evidence": [_serialize_evidence(evidence) for evidence in detail.evidence],
            "history": [history_row(event) for event in detail.history],
            "risk_scores": [_serialize_risk_score(score) for score in detail.risk_scores],
        })

    @safe_output
    def _risk_summary_payload(
        self,
        *,
        entity_type: str | None = None,
        min_confidence: str = "likely",
        limit: int = 50,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='assets')
            return storage.safe_projection({
                "min_confidence": min_confidence,
                "risk_profiles": storage.list_entity_risk_profiles(
                    entity_type=entity_type,
                    min_confidence=min_confidence,
                    limit=limit,
                ),
            }, family='assets', source_context=context)

    @safe_output
    def _scheduled_scans_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            context = storage.projection_context(family='schedules')
            return storage.safe_projection({
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
            }, family='schedules', source_context=context)

    @safe_output
    def _relationship_graph_payload(self, *, limit: int = 200) -> dict[str, object]:
        with self.session_factory() as session:
            return relationship_graph(Storage(session), limit=limit)

    @safe_output
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
        high_signal_only: bool = False,
        min_confidence: str = "likely",
        artifact_scan_result: dict[str, object] | None = None,
        artifact_scan_error: str | None = None,
        finding_action_result: dict[str, object] | None = None,
        finding_action_error: str | None = None,
    ) -> str:
        with self.session_factory() as session:
            storage = Storage(session)
            from orgscan.storage.credential_context import build_report_context
            from orgscan.reports.projection import MAX_CONTEXT_ROWS
            context = build_report_context(storage, max_rows=MAX_CONTEXT_ROWS)
            summary = build_summary(storage, source_context=context)
            findings = storage.list_findings(
                limit=limit,
                high_signal_only=high_signal_only,
                min_confidence=min_confidence,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
            )
            filtered_rows = [_serialize_finding(finding) for finding in findings]
            tooling = self._tooling_payload()
            return render_dashboard_html(
                summary,
                filtered_rows,
                operations=DashboardService(self.session_factory).overview(days=days),
                trends=finding_trends(storage, days=days, source_context=context),
                graph=summary['relationship_graph'],
                filters={
                    "limit": limit,
                    "days": days,
                    "status": status or "",
                    "severity": severity or "",
                    "category": category or "",
                    "confidence": confidence or "",
                    "high_signal_only": high_signal_only,
                    "min_confidence": min_confidence,
                },
                live=True,
                artifact_scan_result=artifact_scan_result,
                artifact_scan_error=artifact_scan_error,
                finding_action_result=finding_action_result,
                finding_action_error=finding_action_error,
                scanner_options=artifact_scanner_options(
                    self.settings, inventory=tooling["scanner_readiness"], selected=str((artifact_scan_result or {}).get("scanner") or "custom-patterns")
                ),
                access_context_note=self._access_context_note(),
                tooling=tooling,
            )

    def _dashboard_finding_workflow(
        self,
        finding_id: int,
        payload: DashboardFindingWorkflowRequest,
    ) -> dict[str, object] | None:
        action = payload.action.strip().lower()
        if action == "triage":
            return self._update_finding_triage(
                finding_id,
                FindingUpdateRequest(
                    status="triaged",
                    triage_state=payload.triage_state or "reviewing",
                    triage_owner=payload.owner,
                    triage_notes=payload.note,
                ),
            )
        if action == "suppress":
            return self._apply_finding_decision(
                finding_id,
                FindingDecisionRequest(
                    reason=payload.note or "Updated from dashboard",
                    owner=payload.owner,
                    note=payload.note,
                ),
                status="suppressed",
            )
        if action == "accept-risk":
            return self._apply_finding_decision(
                finding_id,
                FindingDecisionRequest(
                    reason=payload.note or "Updated from dashboard",
                    owner=payload.owner,
                    note=payload.note,
                ),
                status="accepted_risk",
            )
        if action == "reopen":
            return self._reopen_finding(finding_id, FindingReopenRequest(note=payload.note))
        raise HTTPException(status_code=400, detail=f"Unsupported dashboard finding action: {payload.action}")

    def handle(self, path: str) -> tuple[int, dict[str, object]]:
        parsed = urlparse(path)
        params = parse_qs(parsed.query)
        route = parsed.path
        if route == "/health":
            return 200, {"status": "ok"}
        if route == "/summary":
            return 200, self._summary_payload()
        if route == "/scanners":
            return 200, self._tooling_payload()
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


def create_app(database_url: str, settings: Settings | None = None) -> FastAPI:
    from orgscan.api.authentication import AuthenticationMiddleware
    from orgscan.api.routes.auth import create_auth_router
    from orgscan.services.auth_service import AuthService
    service = OrgscanApiService(database_url, settings=settings)
    app = FastAPI(title="orgscan", version="0.1.0")
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory=Path(__file__).resolve().parents[1] / "web" / "static"), name="static")
    auth_service = AuthService(service.settings)
    app.state.auth_service = auth_service
    app.add_middleware(AuthenticationMiddleware, auth_service=auth_service)
    app.add_middleware(RequestBodyLimit)
    app.include_router(create_auth_router(auth_service))

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/assessments")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/summary")
    def summary() -> dict[str, object]:
        return service._summary_payload()

    @app.get("/scanners")
    def scanners() -> dict[str, object]:
        return service._tooling_payload()

    from orgscan.api.routes.secrets import create_secret_router
    app.include_router(create_secret_router(service.settings))
    app.include_router(create_finding_router(service))
    app.include_router(create_operator_router(service.session_factory))
    app.include_router(create_report_router(service.session_factory))
    from orgscan.api.routes.assessments import create_assessment_router
    app.include_router(create_assessment_router(service.settings))

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

    @app.post("/artifact-scans")
    async def artifact_scans(
        artifact: UploadFile = File(...),
        scanner: str | None = Form(None),
        profile: str | None = Form(None),
        organization: str | None = Form(None),
        repository: str | None = Form(None),
        provider: str = Form("github"),
    ) -> dict[str, object]:
        return service._scan_uploaded_artifact(
            filename=artifact.filename,
            content=await read_upload(artifact),
            scanner_name=scanner,
            profile=profile,
            organization=organization,
            repository=repository,
            provider=provider,
        )

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
        high_signal_only: bool = False,
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> HTMLResponse:
        return HTMLResponse(
            service._dashboard_html(
                limit=limit,
                days=days,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
                high_signal_only=high_signal_only,
                min_confidence=min_confidence,
            )
        )

    @app.get("/dashboard/findings/{finding_id}", response_class=HTMLResponse)
    def dashboard_finding_detail(finding_id: int) -> HTMLResponse:
        payload = service._finding_html_payload(finding_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        from orgscan.web.secret_reveal import render_secret_controls
        controls = render_secret_controls(service.settings, finding_id)
        return HTMLResponse(render_finding_detail_html(payload, secret_controls=controls))

    @app.get("/scan-jobs/{scan_job_id}")
    def scan_job_detail(scan_job_id: int) -> dict[str, object]:
        payload = service._scan_job_payload(scan_job_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Scan job not found")
        return payload

    @app.get("/dashboard/scan-jobs/{scan_job_id}", response_class=HTMLResponse)
    def dashboard_scan_job_detail(scan_job_id: int) -> HTMLResponse:
        payload = service._scan_job_payload(scan_job_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Scan job not found")
        import json
        from orgscan.web.render import render
        return HTMLResponse(render('pages/scan_job_detail.html',title=f'Scan job {scan_job_id}',
            active_section='queues',payload=payload,
            parameters_text=json.dumps(payload['scan_job'].get('parameters_json') or {},indent=2,sort_keys=True),
            scope_text=json.dumps(payload['scan_job'].get('scope_json') or {},indent=2,sort_keys=True)))

    @app.get("/dashboard/graph", response_class=HTMLResponse)
    def dashboard_graph(limit: int = Query(200, ge=1, le=1000)) -> HTMLResponse:
        from orgscan.web.relationships import page as relationship_page
        return HTMLResponse(relationship_page(service._relationship_graph_payload(limit=limit)))

    @app.post("/dashboard/artifact-scans", response_class=HTMLResponse)
    async def dashboard_artifact_scans(
        artifact: UploadFile = File(...),
        scanner: str | None = Form(None),
        profile: str | None = Form(None),
        organization: str | None = Form(None),
        repository: str | None = Form(None),
        provider: str = Form("github"),
    ) -> HTMLResponse:
        try:
            result = service._scan_uploaded_artifact(
                filename=artifact.filename,
                content=await read_upload(artifact),
                scanner_name=scanner,
                profile=profile,
                organization=organization,
                repository=repository,
                provider=provider,
            )
            return HTMLResponse(
                service._dashboard_html(
                    artifact_scan_result=result,
                    high_signal_only=False,
                    min_confidence="likely",
                )
            )
        except HTTPException as exc:
            return HTMLResponse(
                service._dashboard_html(artifact_scan_error=str(exc.detail), high_signal_only=False, min_confidence="likely"),
                status_code=exc.status_code,
            )

    return app


def serve_api(database_url: str, host: str = "127.0.0.1", port: int = 8000, *, unsafe_allow_unauthenticated_network: bool = False) -> None:
    from orgscan.services.server_safety import validate_bind
    app = create_app(database_url)
    validate_bind(host, authenticated=app.state.auth_service.enabled(),
                  unsafe_override=unsafe_allow_unauthenticated_network)
    uvicorn.run(app, host=host, port=port, log_level="info")
