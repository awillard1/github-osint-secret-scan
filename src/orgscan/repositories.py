from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from orgscan.models import (
    Account,
    Domain,
    Evidence,
    Finding,
    Organization,
    Relationship,
    Repository,
    RiskScore,
    ScanJob,
)
from orgscan.schemas import CanonicalFinding


class Storage:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_organization(self, name: str, **kwargs: Any) -> Organization:
        organization = Organization(name=name, **kwargs)
        self.session.add(organization)
        self.session.flush()
        return organization

    def get_organization_by_name(self, name: str) -> Organization | None:
        return self.session.scalar(select(Organization).where(Organization.name == name))

    def get_or_create_organization(self, name: str, **kwargs: Any) -> tuple[Organization, bool]:
        existing = self.get_organization_by_name(name)
        if existing:
            return existing, False
        return self.create_organization(name, **kwargs), True

    def create_domain(self, name: str, **kwargs: Any) -> Domain:
        domain = Domain(name=name, **kwargs)
        self.session.add(domain)
        self.session.flush()
        return domain

    def get_domain_by_name(self, name: str) -> Domain | None:
        return self.session.scalar(select(Domain).where(Domain.name == name))

    def get_or_create_domain(self, name: str, **kwargs: Any) -> tuple[Domain, bool]:
        existing = self.get_domain_by_name(name)
        if existing:
            return existing, False
        return self.create_domain(name, **kwargs), True

    def create_repository(self, full_name: str, **kwargs: Any) -> Repository:
        repository = Repository(full_name=full_name, **kwargs)
        self.session.add(repository)
        self.session.flush()
        return repository

    def get_repository_by_full_name(self, full_name: str) -> Repository | None:
        return self.session.scalar(select(Repository).where(Repository.full_name == full_name))

    def get_or_create_repository(self, full_name: str, **kwargs: Any) -> tuple[Repository, bool]:
        existing = self.get_repository_by_full_name(full_name)
        if existing:
            return existing, False
        return self.create_repository(full_name, **kwargs), True

    def create_account(self, username: str, **kwargs: Any) -> Account:
        account = Account(username=username, **kwargs)
        self.session.add(account)
        self.session.flush()
        return account

    def get_account_by_username(self, username: str) -> Account | None:
        return self.session.scalar(select(Account).where(Account.username == username))

    def get_or_create_account(self, username: str, **kwargs: Any) -> tuple[Account, bool]:
        existing = self.get_account_by_username(username)
        if existing:
            return existing, False
        return self.create_account(username, **kwargs), True

    def create_scan_job(self, target_type: str, target_id: str, scanner_name: str, **kwargs: Any) -> ScanJob:
        scan_job = ScanJob(target_type=target_type, target_id=target_id, scanner_name=scanner_name, **kwargs)
        self.session.add(scan_job)
        self.session.flush()
        return scan_job

    def mark_scan_job_running(self, scan_job: ScanJob) -> ScanJob:
        scan_job.status = "running"
        scan_job.started_at = datetime.now(UTC)
        self.session.flush()
        return scan_job

    def mark_scan_job_completed(self, scan_job: ScanJob) -> ScanJob:
        scan_job.status = "completed"
        scan_job.completed_at = datetime.now(UTC)
        self.session.flush()
        return scan_job

    def mark_scan_job_failed(self, scan_job: ScanJob, error_message: str) -> ScanJob:
        scan_job.status = "failed"
        scan_job.error_message = error_message
        scan_job.completed_at = datetime.now(UTC)
        self.session.flush()
        return scan_job

    def create_finding(self, finding: CanonicalFinding) -> Finding:
        existing = self.session.scalar(
            select(Finding).where(Finding.normalized_hash == finding.normalized_hash)
        )
        if existing:
            existing.last_seen_at = finding.last_seen_at
            existing.raw_payload = finding.raw_payload
            existing.metadata_json = finding.metadata
            self.session.flush()
            return existing

        record = Finding(**finding.to_storage_dict())
        self.session.add(record)
        self.session.flush()
        return record

    def create_evidence(self, finding_id: int, source: str, **kwargs: Any) -> Evidence:
        evidence = Evidence(finding_id=finding_id, source=source, **kwargs)
        self.session.add(evidence)
        self.session.flush()
        return evidence

    def create_relationship(
        self,
        from_entity_type: str,
        from_entity_id: str,
        to_entity_type: str,
        to_entity_id: str,
        relation_type: str,
        **kwargs: Any,
    ) -> Relationship:
        relationship = Relationship(
            from_entity_type=from_entity_type,
            from_entity_id=from_entity_id,
            to_entity_type=to_entity_type,
            to_entity_id=to_entity_id,
            relation_type=relation_type,
            **kwargs,
        )
        self.session.add(relationship)
        self.session.flush()
        return relationship

    def get_or_create_relationship(
        self,
        from_entity_type: str,
        from_entity_id: str,
        to_entity_type: str,
        to_entity_id: str,
        relation_type: str,
        **kwargs: Any,
    ) -> tuple[Relationship, bool]:
        existing = self.session.scalar(
            select(Relationship).where(
                Relationship.from_entity_type == from_entity_type,
                Relationship.from_entity_id == from_entity_id,
                Relationship.to_entity_type == to_entity_type,
                Relationship.to_entity_id == to_entity_id,
                Relationship.relation_type == relation_type,
            )
        )
        if existing:
            return existing, False
        return (
            self.create_relationship(
                from_entity_type=from_entity_type,
                from_entity_id=from_entity_id,
                to_entity_type=to_entity_type,
                to_entity_id=to_entity_id,
                relation_type=relation_type,
                **kwargs,
            ),
            True,
        )

    def create_risk_score(self, entity_type: str, entity_id: str, score: float, **kwargs: Any) -> RiskScore:
        risk_score = RiskScore(entity_type=entity_type, entity_id=entity_id, score=score, **kwargs)
        self.session.add(risk_score)
        self.session.flush()
        return risk_score

    def list_findings(self, limit: int = 50, status: str | None = None) -> Sequence[Finding]:
        query = select(Finding).order_by(Finding.detected_at.desc(), Finding.id.desc()).limit(limit)
        if status:
            query = query.where(Finding.status == status)
        return list(self.session.scalars(query))

    def list_organizations(self) -> Sequence[Organization]:
        return list(self.session.scalars(select(Organization).order_by(Organization.name.asc())))

    def list_repositories(self) -> Sequence[Repository]:
        return list(self.session.scalars(select(Repository).order_by(Repository.full_name.asc())))

    def list_scan_jobs(self, limit: int = 25) -> Sequence[ScanJob]:
        query = select(ScanJob).order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(limit)
        return list(self.session.scalars(query))

    def finding_counts_by_severity(self) -> Mapping[str, int]:
        rows = self.session.execute(
            select(Finding.severity, func.count()).group_by(Finding.severity).order_by(Finding.severity.asc())
        )
        return {severity: count for severity, count in rows}

    def finding_counts_by_category(self) -> Mapping[str, int]:
        rows = self.session.execute(
            select(Finding.category, func.count()).group_by(Finding.category).order_by(Finding.category.asc())
        )
        return {category: count for category, count in rows}

    def counts(self) -> Mapping[str, int]:
        tables = {
            "organizations": Organization,
            "domains": Domain,
            "repositories": Repository,
            "accounts": Account,
            "scan_jobs": ScanJob,
            "findings": Finding,
            "evidence": Evidence,
            "relationships": Relationship,
            "risk_scores": RiskScore,
        }
        return {
            name: self.session.scalar(select(func.count()).select_from(model)) or 0
            for name, model in tables.items()
        }
