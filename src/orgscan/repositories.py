from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from orgscan.models import (
    QueueTask,
    Account,
    Domain,
    DomainExposure,
    Evidence,
    Finding,
    IdentityCorrelation,
    Organization,
    Relationship,
    Repository,
    RiskScore,
    ScheduledReport,
    ScheduledScan,
    ScanJob,
    Suppression,
    ToolRun,
    User,
    UserSession,
    UserTenantMembership,
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
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
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
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing, False
        return self.create_domain(name, **kwargs), True

    def create_repository(self, full_name: str, **kwargs: Any) -> Repository:
        repository = Repository(full_name=full_name, **kwargs)
        self.session.add(repository)
        self.session.flush()
        return repository

    def get_repository_by_full_name(self, full_name: str) -> Repository | None:
        return self.session.scalar(select(Repository).where(Repository.full_name == full_name))

    def create_user(self, username: str, **kwargs: Any) -> User:
        user = User(username=username, **kwargs)
        self.session.add(user)
        self.session.flush()
        return user

    def get_user_by_username(self, username: str) -> User | None:
        return self.session.scalar(select(User).where(User.username == username))

    def get_or_create_user(self, username: str, **kwargs: Any) -> tuple[User, bool]:
        existing = self.get_user_by_username(username)
        if existing:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing, False
        return self.create_user(username, **kwargs), True

    def grant_tenant_membership(self, user_id: int, tenant_key: str, role: str, **kwargs: Any) -> UserTenantMembership:
        existing = self.session.scalar(
            select(UserTenantMembership).where(
                UserTenantMembership.user_id == user_id,
                UserTenantMembership.tenant_key == tenant_key,
            )
        )
        if existing is not None:
            existing.role = role
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing
        membership = UserTenantMembership(user_id=user_id, tenant_key=tenant_key, role=role, **kwargs)
        self.session.add(membership)
        self.session.flush()
        return membership

    def list_user_tenant_memberships(self, user_id: int | None = None) -> Sequence[UserTenantMembership]:
        query = select(UserTenantMembership).order_by(UserTenantMembership.tenant_key.asc(), UserTenantMembership.id.asc())
        if user_id is not None:
            query = query.where(UserTenantMembership.user_id == user_id)
        return list(self.session.scalars(query))

    def create_user_session(self, user_id: int, token_hash: str, **kwargs: Any) -> UserSession:
        session_row = UserSession(user_id=user_id, token_hash=token_hash, **kwargs)
        self.session.add(session_row)
        self.session.flush()
        return session_row

    def get_user_session_by_hash(self, token_hash: str) -> UserSession | None:
        return self.session.scalar(select(UserSession).where(UserSession.token_hash == token_hash))

    def list_user_sessions(self, user_id: int | None = None) -> Sequence[UserSession]:
        query = select(UserSession).order_by(UserSession.created_at.desc(), UserSession.id.desc())
        if user_id is not None:
            query = query.where(UserSession.user_id == user_id)
        return list(self.session.scalars(query))

    def revoke_user_session(self, session_id: int) -> UserSession:
        session_row = self.session.get(UserSession, session_id)
        if session_row is None:
            raise ValueError(f"User session {session_id} does not exist")
        session_row.revoked_at = datetime.now(UTC)
        self.session.flush()
        return session_row

    def touch_user_session(self, session_row: UserSession) -> UserSession:
        session_row.last_used_at = datetime.now(UTC)
        self.session.flush()
        return session_row

    def get_or_create_repository(self, full_name: str, **kwargs: Any) -> tuple[Repository, bool]:
        existing = self.get_repository_by_full_name(full_name)
        if existing:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
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
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing, False
        return self.create_account(username, **kwargs), True

    def create_scan_job(self, target_type: str, target_id: str, scanner_name: str, **kwargs: Any) -> ScanJob:
        scan_job = ScanJob(target_type=target_type, target_id=target_id, scanner_name=scanner_name, **kwargs)
        self.session.add(scan_job)
        self.session.flush()
        return scan_job

    def create_tool_run(self, tool_name: str, target: str, **kwargs: Any) -> ToolRun:
        tool_run = ToolRun(tool_name=tool_name, target=target, **kwargs)
        self.session.add(tool_run)
        self.session.flush()
        return tool_run

    def mark_tool_run_running(self, tool_run: ToolRun) -> ToolRun:
        tool_run.status = "running"
        tool_run.started_at = datetime.now(UTC)
        self.session.flush()
        return tool_run

    def mark_tool_run_completed(self, tool_run: ToolRun, *, stdout_log: str | None = None, stderr_log: str | None = None) -> ToolRun:
        tool_run.status = "completed"
        tool_run.completed_at = datetime.now(UTC)
        if stdout_log is not None:
            tool_run.stdout_log = stdout_log
        if stderr_log is not None:
            tool_run.stderr_log = stderr_log
        self.session.flush()
        return tool_run

    def mark_tool_run_failed(self, tool_run: ToolRun, *, stderr_log: str | None = None) -> ToolRun:
        tool_run.status = "failed"
        tool_run.completed_at = datetime.now(UTC)
        if stderr_log is not None:
            tool_run.stderr_log = stderr_log
        self.session.flush()
        return tool_run

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
            previous_status = existing.status
            should_update_status = finding.status != "open" or previous_status == "resolved"
            existing.last_seen_at = finding.last_seen_at
            existing.raw_payload = finding.raw_payload
            existing.metadata_json = finding.metadata
            existing.scan_job_id = finding.scan_job_id
            if should_update_status:
                existing.status = finding.status
            if previous_status == "resolved" and finding.status != "resolved":
                existing.triage_state = "reopened"
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

    def create_domain_exposure(
        self,
        domain_id: int,
        source: str,
        *,
        source_name: str,
        result_summary: str,
        normalized_hash: str,
        **kwargs: Any,
    ) -> DomainExposure:
        existing = self.session.scalar(select(DomainExposure).where(DomainExposure.normalized_hash == normalized_hash))
        if existing:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            existing.result_summary = result_summary
            existing.last_seen = datetime.now(UTC)
            self.session.flush()
            return existing
        exposure = DomainExposure(
            domain_id=domain_id,
            source=source,
            source_name=source_name,
            result_summary=result_summary,
            normalized_hash=normalized_hash,
            **kwargs,
        )
        self.session.add(exposure)
        self.session.flush()
        return exposure

    def create_identity_correlation(
        self,
        domain_id: int,
        source: str,
        relation_type: str,
        **kwargs: Any,
    ) -> IdentityCorrelation:
        existing = self.session.scalar(
            select(IdentityCorrelation).where(
                IdentityCorrelation.domain_id == domain_id,
                IdentityCorrelation.source == source,
                IdentityCorrelation.relation_type == relation_type,
                IdentityCorrelation.email == kwargs.get("email"),
                IdentityCorrelation.username == kwargs.get("username"),
            )
        )
        if existing:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing
        correlation = IdentityCorrelation(domain_id=domain_id, source=source, relation_type=relation_type, **kwargs)
        self.session.add(correlation)
        self.session.flush()
        return correlation

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

    def create_suppression(self, finding_id: int, status: str, reason: str, **kwargs: Any) -> Suppression:
        suppression = Suppression(finding_id=finding_id, status=status, reason=reason, **kwargs)
        self.session.add(suppression)
        self.session.flush()
        return suppression

    def create_scheduled_scan(
        self,
        target_type: str,
        target_value: str,
        scanner_name: str,
        next_run_at: datetime,
        **kwargs: Any,
    ) -> ScheduledScan:
        scheduled_scan = ScheduledScan(
            target_type=target_type,
            target_value=target_value,
            scanner_name=scanner_name,
            next_run_at=next_run_at,
            **kwargs,
        )
        self.session.add(scheduled_scan)
        self.session.flush()
        return scheduled_scan

    def create_scheduled_report(
        self,
        target_type: str,
        next_run_at: datetime,
        **kwargs: Any,
    ) -> ScheduledReport:
        scheduled_report = ScheduledReport(
            target_type=target_type,
            next_run_at=next_run_at,
            **kwargs,
        )
        self.session.add(scheduled_report)
        self.session.flush()
        return scheduled_report

    def create_queue_task(
        self,
        scheduled_scan_id: int,
        *,
        backend: str,
        queue_name: str,
        status: str,
        max_attempts: int,
        available_at: datetime,
        metadata_json: dict[str, Any] | None = None,
    ) -> QueueTask:
        task = QueueTask(
            scheduled_scan_id=scheduled_scan_id,
            backend=backend,
            queue_name=queue_name,
            status=status,
            max_attempts=max_attempts,
            available_at=available_at,
            metadata_json=metadata_json or {},
        )
        self.session.add(task)
        self.session.flush()
        return task

    def get_queue_task(self, queue_task_id: int) -> QueueTask | None:
        return self.session.get(QueueTask, queue_task_id)

    def list_queue_tasks(
        self,
        backend: str | None = None,
        status: str | None = None,
        queue_name: str | None = None,
        limit: int | None = 100,
    ) -> Sequence[QueueTask]:
        query = select(QueueTask).order_by(QueueTask.created_at.desc(), QueueTask.id.desc())
        if backend is not None:
            query = query.where(QueueTask.backend == backend)
        if status is not None:
            query = query.where(QueueTask.status == status)
        if queue_name is not None:
            query = query.where(QueueTask.queue_name == queue_name)
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def find_active_queue_task(self, scheduled_scan_id: int, *, backend: str) -> QueueTask | None:
        return self.session.scalar(
            select(QueueTask)
            .where(
                QueueTask.scheduled_scan_id == scheduled_scan_id,
                QueueTask.backend == backend,
                QueueTask.status.in_(("queued", "running")),
            )
            .order_by(QueueTask.id.desc())
            .limit(1)
        )

    def claim_queue_task(
        self,
        *,
        backend: str,
        queue_name: str,
        worker_id: str,
        lease_until: datetime,
        now: datetime | None = None,
    ) -> QueueTask | None:
        current = now or datetime.now(UTC)
        candidates = list(
            self.session.scalars(
                select(QueueTask)
                .where(
                    QueueTask.backend == backend,
                    QueueTask.queue_name == queue_name,
                    QueueTask.status == "queued",
                    QueueTask.available_at <= current,
                )
                .order_by(QueueTask.available_at.asc(), QueueTask.id.asc())
            )
        )
        for task in candidates:
            if task.lease_expires_at is not None and task.lease_expires_at > current:
                continue
            task.status = "running"
            task.lease_owner = worker_id
            task.lease_expires_at = lease_until
            task.started_at = current
            task.attempt_count += 1
            self.session.flush()
            return task
        return None

    def mark_queue_task_completed(self, task: QueueTask, *, scan_job_id: int | None = None, tool_run_id: int | None = None) -> QueueTask:
        task.status = "completed"
        task.completed_at = datetime.now(UTC)
        task.lease_owner = None
        task.lease_expires_at = None
        task.result_scan_job_id = scan_job_id
        task.result_tool_run_id = tool_run_id
        task.last_error = None
        self.session.flush()
        return task

    def mark_queue_task_retry(self, task: QueueTask, *, available_at: datetime, error_message: str) -> QueueTask:
        task.status = "queued"
        task.available_at = available_at
        task.lease_owner = None
        task.lease_expires_at = None
        task.last_error = error_message
        self.session.flush()
        return task

    def mark_queue_task_failed(self, task: QueueTask, *, error_message: str) -> QueueTask:
        task.status = "failed"
        task.completed_at = datetime.now(UTC)
        task.lease_owner = None
        task.lease_expires_at = None
        task.last_error = error_message
        self.session.flush()
        return task

    def list_findings(
        self,
        limit: int | None = 50,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
    ) -> Sequence[Finding]:
        query = select(Finding).order_by(Finding.detected_at.desc(), Finding.id.desc())
        if status:
            query = query.where(Finding.status == status)
        if category:
            query = query.where(Finding.category == category)
        if severity:
            query = query.where(Finding.severity == severity)
        if confidence:
            query = query.where(Finding.confidence == confidence)
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def get_finding(self, finding_id: int) -> Finding | None:
        return self.session.get(Finding, finding_id)

    def update_finding_triage(
        self,
        finding_id: int,
        *,
        status: str | None = None,
        triage_state: str | None = None,
        triage_owner: str | None = None,
        triage_notes: str | None = None,
        remediation_due_date: Any | None = None,
    ) -> Finding:
        finding = self.session.get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} does not exist")
        if status is not None:
            finding.status = status
        if triage_state is not None:
            finding.triage_state = triage_state
        if triage_owner is not None:
            finding.triage_owner = triage_owner
        if triage_notes is not None:
            finding.triage_notes = triage_notes
        if remediation_due_date is not None:
            finding.remediation_due_date = remediation_due_date
        self.session.flush()
        return finding

    def suppress_finding(
        self,
        finding_id: int,
        *,
        reason: str,
        owner: str | None = None,
        deadline: Any | None = None,
        notes: str | None = None,
        status: str = "suppressed",
    ) -> Finding:
        finding = self.update_finding_triage(
            finding_id,
            status=status,
            triage_state=status,
            triage_owner=owner,
            triage_notes=notes,
            remediation_due_date=deadline,
        )
        self.create_suppression(
            finding_id,
            status=status,
            reason=reason,
            owner=owner,
            deadline=deadline,
            notes=notes,
        )
        return finding

    def list_organizations(self) -> Sequence[Organization]:
        return list(self.session.scalars(select(Organization).order_by(Organization.name.asc())))

    def list_domains(self) -> Sequence[Domain]:
        return list(self.session.scalars(select(Domain).order_by(Domain.name.asc())))

    def list_repositories(self) -> Sequence[Repository]:
        return list(self.session.scalars(select(Repository).order_by(Repository.full_name.asc())))

    def list_accounts(self) -> Sequence[Account]:
        return list(self.session.scalars(select(Account).order_by(Account.username.asc())))

    def list_domain_exposures(
        self,
        domain_id: int | None = None,
        *,
        source_name: str | None = None,
        source_class: str | None = None,
        confidence: str | None = None,
        limit: int | None = None,
    ) -> Sequence[DomainExposure]:
        query = select(DomainExposure).order_by(DomainExposure.last_seen.desc(), DomainExposure.id.desc())
        if domain_id is not None:
            query = query.where(DomainExposure.domain_id == domain_id)
        if source_name:
            query = query.where(DomainExposure.source_name == source_name)
        if source_class:
            query = query.where(DomainExposure.source_class == source_class)
        if confidence:
            query = query.where(DomainExposure.confidence == confidence)
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def list_identity_correlations(self, domain_id: int | None = None) -> Sequence[IdentityCorrelation]:
        query = select(IdentityCorrelation).order_by(IdentityCorrelation.id.desc())
        if domain_id is not None:
            query = query.where(IdentityCorrelation.domain_id == domain_id)
        return list(self.session.scalars(query))

    def list_scan_jobs(self, limit: int | None = 25) -> Sequence[ScanJob]:
        query = select(ScanJob).order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def list_tool_runs(self, limit: int | None = 25) -> Sequence[ToolRun]:
        query = select(ToolRun).order_by(ToolRun.created_at.desc(), ToolRun.id.desc())
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def list_scheduled_scans(self, enabled_only: bool = False) -> Sequence[ScheduledScan]:
        query = select(ScheduledScan).order_by(ScheduledScan.next_run_at.asc(), ScheduledScan.id.asc())
        if enabled_only:
            query = query.where(ScheduledScan.enabled.is_(True))
        return list(self.session.scalars(query))

    def list_scheduled_reports(self, enabled_only: bool = False) -> Sequence[ScheduledReport]:
        query = select(ScheduledReport).order_by(ScheduledReport.next_run_at.asc(), ScheduledReport.id.asc())
        if enabled_only:
            query = query.where(ScheduledReport.enabled.is_(True))
        return list(self.session.scalars(query))

    def list_relationships(self, limit: int | None = 250) -> Sequence[Relationship]:
        query = select(Relationship).order_by(Relationship.created_at.desc(), Relationship.id.desc())
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def list_due_scheduled_scans(self, now: datetime | None = None) -> Sequence[ScheduledScan]:
        current = now or datetime.now(UTC)
        query = (
            select(ScheduledScan)
            .where(ScheduledScan.enabled.is_(True), ScheduledScan.next_run_at <= current)
            .order_by(ScheduledScan.next_run_at.asc(), ScheduledScan.id.asc())
        )
        return list(self.session.scalars(query))

    def list_due_scheduled_reports(self, now: datetime | None = None) -> Sequence[ScheduledReport]:
        current = now or datetime.now(UTC)
        query = (
            select(ScheduledReport)
            .where(ScheduledReport.enabled.is_(True), ScheduledReport.next_run_at <= current)
            .order_by(ScheduledReport.next_run_at.asc(), ScheduledReport.id.asc())
        )
        return list(self.session.scalars(query))

    def mark_scheduled_scan_run(
        self,
        scheduled_scan: ScheduledScan,
        next_run_at: datetime,
        *,
        enabled: bool | None = None,
    ) -> ScheduledScan:
        scheduled_scan.last_run_at = datetime.now(UTC)
        scheduled_scan.next_run_at = next_run_at
        if enabled is not None:
            scheduled_scan.enabled = enabled
        self.session.flush()
        return scheduled_scan

    def get_scheduled_scan(self, scheduled_scan_id: int) -> ScheduledScan | None:
        return self.session.get(ScheduledScan, scheduled_scan_id)

    def mark_scheduled_report_run(
        self,
        scheduled_report: ScheduledReport,
        next_run_at: datetime,
        *,
        enabled: bool | None = None,
    ) -> ScheduledReport:
        scheduled_report.last_run_at = datetime.now(UTC)
        scheduled_report.next_run_at = next_run_at
        if enabled is not None:
            scheduled_report.enabled = enabled
        self.session.flush()
        return scheduled_report

    def get_scheduled_report(self, scheduled_report_id: int) -> ScheduledReport | None:
        return self.session.get(ScheduledReport, scheduled_report_id)

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

    def finding_counts_by_source_tool(self) -> Mapping[str, int]:
        rows = self.session.execute(
            select(Finding.source_tool, func.count()).group_by(Finding.source_tool).order_by(Finding.source_tool.asc())
        )
        return {source_tool: count for source_tool, count in rows}

    def finding_counts_by_status(self) -> Mapping[str, int]:
        rows = self.session.execute(
            select(Finding.status, func.count()).group_by(Finding.status).order_by(Finding.status.asc())
        )
        return {status: count for status, count in rows}

    def list_top_risky_findings(self, limit: int = 10) -> Sequence[Finding]:
        query = (
            select(Finding)
            .order_by(Finding.risk_score.desc().nullslast(), Finding.detected_at.desc(), Finding.id.desc())
            .limit(limit)
        )
        return list(self.session.scalars(query))

    def finding_counts_by_repository(self, limit: int = 10) -> list[tuple[str, int]]:
        rows = self.session.execute(
            select(func.coalesce(Repository.full_name, "unassigned"), func.count())
            .select_from(Finding)
            .join(Repository, Repository.id == Finding.repository_id, isouter=True)
            .group_by(func.coalesce(Repository.full_name, "unassigned"))
            .order_by(func.count().desc(), func.coalesce(Repository.full_name, "unassigned").asc())
            .limit(limit)
        )
        return [(repository_name, count) for repository_name, count in rows]

    def finding_trends_by_day(self, days: int = 30) -> list[tuple[str, str, int]]:
        cutoff = datetime.now(UTC) - timedelta(days=max(days, 1) - 1)
        rows = self.session.execute(
            select(func.date(Finding.detected_at), Finding.severity, func.count())
            .where(Finding.detected_at >= cutoff)
            .group_by(func.date(Finding.detected_at), Finding.severity)
            .order_by(func.date(Finding.detected_at).asc(), Finding.severity.asc())
        )
        return [(str(day), severity, count) for day, severity, count in rows if day is not None]

    def counts(self) -> Mapping[str, int]:
        tables = {
            "organizations": Organization,
            "domains": Domain,
            "repositories": Repository,
            "accounts": Account,
            "scan_jobs": ScanJob,
            "findings": Finding,
            "evidence": Evidence,
            "domain_exposures": DomainExposure,
            "identity_correlations": IdentityCorrelation,
            "relationships": Relationship,
            "risk_scores": RiskScore,
            "scheduled_scans": ScheduledScan,
            "scheduled_reports": ScheduledReport,
            "queue_tasks": QueueTask,
            "suppressions": Suppression,
            "tool_runs": ToolRun,
            "users": User,
            "user_tenant_memberships": UserTenantMembership,
            "user_sessions": UserSession,
        }
        return {
            name: self.session.scalar(select(func.count()).select_from(model)) or 0
            for name, model in tables.items()
        }
