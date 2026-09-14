from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session, selectinload

from orgscan.models import (
    QueueTask,
    RateLimitState,
    Account,
    Domain,
    DomainExposure,
    Evidence,
    Finding,
    FindingHistory,
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
from orgscan.lifecycle import from_legacy, validate_transition, snapshot, LEGACY_STATUS
from orgscan.security_context import current_auth


class Storage:
    CONFIDENCE_ORDER = (
        "unverified",
        "heuristic",
        "likely",
        "verified",
    )

    def __init__(self, session: Session) -> None:
        self.session = session

    def record_repository_sync(self, repository: Repository, *, refs: dict[str, str], default_branch: str) -> None:
        from copy import deepcopy
        metadata = deepcopy(repository.metadata_json or {})
        state = metadata.setdefault("repository_state", {"version": 1, "checkpoints": {}})
        state.update(job_type="REPO_SYNC", previous_refs=state.get("current_refs", {}), current_refs=refs,
                     observed_at=datetime.now(UTC).isoformat(), default_branch=default_branch)
        repository.default_branch = default_branch
        repository.metadata_json = metadata
        self.session.flush()

    def get_repository_checkpoint(self, repository: Repository, *, ref: str, scanner: str, configuration_key: str):
        from orgscan.repository_state import RepositoryCheckpoint, checkpoint_key
        value = (repository.metadata_json or {}).get("repository_state", {}).get("checkpoints", {}).get(checkpoint_key(ref, scanner, configuration_key))
        return RepositoryCheckpoint(**value) if value else None

    def record_repository_checkpoint(self, repository: Repository, checkpoint) -> None:
        from copy import deepcopy
        from dataclasses import asdict
        from orgscan.repository_state import checkpoint_key
        metadata = deepcopy(repository.metadata_json or {})
        state = metadata.setdefault("repository_state", {"version": 1})
        state.setdefault("checkpoints", {})[checkpoint_key(checkpoint.ref, checkpoint.scanner, checkpoint.configuration_key)] = asdict(checkpoint)
        repository.metadata_json = metadata
        self.session.flush()

    def create_organization(self, name: str, **kwargs: Any) -> Organization:
        organization = Organization(name=name, **kwargs)
        self.session.add(organization)
        self.session.flush()
        return organization

    def get_organization_by_name(self, name: str) -> Organization | None:
        return self.session.scalar(select(Organization).where(Organization.name == name))

    def _claim_unassigned_owner(self, existing, field, value):
        if value is None or getattr(existing, field) is not None:
            return
        model = type(existing)
        claimed = self.session.execute(update(model).where(model.id == existing.id,
            getattr(model, field).is_(None)).values({field:value}),
            execution_options={"synchronize_session":False})
        if claimed.rowcount != 1:
            raise ValueError('Discovery ownership conflict; existing tenant association is immutable')
        self.session.refresh(existing)

    def get_or_create_organization(self, name: str, **kwargs: Any) -> tuple[Organization, bool]:
        existing = self.get_organization_by_name(name)
        if existing:
            if kwargs.get("tenant_key") is not None and getattr(existing, "tenant_key") not in (None, kwargs["tenant_key"]):
                raise ValueError("Discovery ownership conflict; existing tenant association is immutable")
            self._claim_unassigned_owner(existing, "tenant_key", kwargs.get("tenant_key"))
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
            if kwargs.get("organization_id") is not None and getattr(existing, "organization_id") not in (None, kwargs["organization_id"]):
                raise ValueError("Discovery ownership conflict; existing tenant association is immutable")
            self._claim_unassigned_owner(existing, "organization_id", kwargs.get("organization_id"))
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

    def get_organization(self, organization_id: int) -> Organization | None:
        return self.session.get(Organization, organization_id)

    def get_domain(self, domain_id: int) -> Domain | None:
        return self.session.get(Domain, domain_id)

    def get_repository(self, repository_id: int) -> Repository | None:
        return self.session.get(Repository, repository_id)

    def get_account(self, account_id: int) -> Account | None:
        return self.session.get(Account, account_id)

    def create_user(self, username: str, **kwargs: Any) -> User:
        user = User(username=username, **kwargs)
        self.session.add(user)
        self.session.flush()
        return user

    def list_users(self) -> Sequence[User]:
        return list(self.session.scalars(select(User).order_by(User.username)))

    def has_auth_users(self) -> bool:
        return self.session.scalar(select(User.id).limit(1)) is not None

    def get_user_session(self, session_id: int) -> UserSession | None:
        return self.session.get(UserSession, session_id)

    def set_user_active(self, username: str, active: bool) -> User:
        user = self.get_user_by_username(username)
        if user is None:
            raise ValueError("User does not exist")
        user.is_active = active
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
        if role not in {"reader", "analyst", "admin"} or not tenant_key.strip() or len(tenant_key) > 255:
            raise ValueError("Invalid tenant or role")
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
            if kwargs.get("organization_id") is not None and getattr(existing, "organization_id") not in (None, kwargs["organization_id"]):
                raise ValueError("Discovery ownership conflict; existing tenant association is immutable")
            self._claim_unassigned_owner(existing, "organization_id", kwargs.get("organization_id"))
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
            if kwargs.get("organization_id") is not None and getattr(existing, "organization_id") not in (None, kwargs["organization_id"]):
                raise ValueError("Discovery ownership conflict; existing tenant association is immutable")
            self._claim_unassigned_owner(existing, "organization_id", kwargs.get("organization_id"))
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing, False
        return self.create_account(username, **kwargs), True

    def create_scan_job(self, target_type: str, target_id: str, scanner_name: str, **kwargs: Any) -> ScanJob:
        from orgscan.services.job_policy import logical_job_type
        parameters = dict(kwargs.pop("parameters_json", {}) or {})
        parameters.setdefault("job_type", logical_job_type(target_type, scanner_name))
        scan_job = ScanJob(target_type=target_type, target_id=target_id, scanner_name=scanner_name,
                           parameters_json=parameters, **kwargs)
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

    def create_finding(self, finding: CanonicalFinding, *, protected_candidates=()) -> Finding:
        from orgscan.services.secret_evidence import SecretCandidateContext
        settings = self.session.info.get('secret_settings')
        source = finding.model_dump()
        with SecretCandidateContext.from_source(source, settings=settings, candidates=protected_candidates) as context:
            safe = finding.model_copy(update=context.sanitize(source, preserve_root_keys=True))
            record = self._create_finding(safe)
            context.persist(self.session, record, settings=settings)
            return record

    def _create_finding(self, finding: CanonicalFinding) -> Finding:
        existing = self.session.scalar(
            select(Finding).where(Finding.normalized_hash == finding.normalized_hash)
        )
        if existing:
            previous_job_id = existing.scan_job_id
            incoming_job = self.get_scan_job(finding.scan_job_id) if finding.scan_job_id else None
            observed = incoming_job.started_at or incoming_job.created_at if incoming_job else None
            if (existing.lifecycle_state == "REMEDIATED" and existing.remediated_at and observed
                    and self._regression_evidence_is_new(existing, finding, incoming_job)
                    and finding.scan_job_id != previous_job_id
                    and self._normalize_datetime_filter(observed) > self._normalize_datetime_filter(existing.remediated_at)):
                self._transition(existing, "REGRESSED", automatic=True, scan_job_id=finding.scan_job_id,
                                 reason="Fingerprint observed in a scan started after remediation")
            if self._normalize_datetime_filter(finding.last_seen_at) > self._normalize_datetime_filter(existing.last_seen_at):
                existing.last_seen_at = finding.last_seen_at
            existing.raw_payload = finding.raw_payload
            existing.metadata_json = finding.metadata
            existing.scan_job_id = finding.scan_job_id
            self.session.flush()
            return existing

        record = Finding(**finding.to_storage_dict())
        record.lifecycle_state = from_legacy(record.status, initial=True)
        if record.lifecycle_state == "REMEDIATED":
            record.remediated_at = datetime.now(UTC)
        self.session.add(record)
        self.session.flush()
        self._record_history(record, None, reason="Initial observation", scan_job_id=record.scan_job_id)
        self.session.flush()
        return record

    def _regression_evidence_is_new(self, existing, finding, incoming_job=None):
        # Import time is not observation time; saved reports cannot prove that
        # remediation failed, even when their original timestamp is absent.
        if incoming_job and (incoming_job.parameters_json or {}).get('ingested'):
            return False
        metadata = finding.metadata
        commit = (metadata.get('commit_sha') or metadata.get('commit')
                  or finding.raw_payload.get('commit_sha') or finding.raw_payload.get('commit'))
        if not commit:
            if finding.source_tool == 'git-history-patterns':
                return False
            return True  # Current tree observation, subject to job chronology.
        if metadata.get('change_type') != 'added':
            return False
        timestamp = metadata.get('commit_timestamp')
        try:
            committed = datetime.fromtimestamp(float(timestamp), UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            return False
        if self._normalize_datetime_filter(committed) <= self._normalize_datetime_filter(existing.remediated_at):
            return False
        return self.session.scalar(select(Evidence.id).where(
            Evidence.finding_id == existing.id, Evidence.commit_sha == commit).limit(1)) is None

    def upsert_correlated_finding(self, finding: CanonicalFinding, *, protected_candidates=()) -> Finding:
        record = self.create_finding(finding, protected_candidates=protected_candidates)
        # Keep stronger observations visible regardless of scanner ordering.
        for field, order in (
            ("severity", ("info", "low", "medium", "high", "critical")),
            ("confidence", ("unverified", "heuristic", "likely", "verified")),
        ):
            incoming, current = str(getattr(finding, field)), getattr(record, field)
            if incoming in order and (current not in order or order.index(incoming) > order.index(current)):
                setattr(record, field, incoming)
        record.risk_score = max(record.risk_score or 0, finding.risk_score or 0)
        self.session.flush()
        return record

    def create_evidence(self, finding_id: int, source: str, *, protected_candidates=(), **kwargs: Any) -> Evidence:
        from orgscan.services.secret_evidence import SecretCandidateContext
        settings = self.session.info.get('secret_settings')
        with SecretCandidateContext.from_source({'source': source, **kwargs}, settings=settings, candidates=protected_candidates) as context:
            evidence = Evidence(finding_id=finding_id, **context.sanitize({'source': source, **kwargs}, preserve_root_keys=True))
            self.session.add(evidence)
            self.session.flush()
            context.persist(self.session, self.session.get(Finding, finding_id), settings=settings, evidence_id=evidence.id)
            return evidence

    def upsert_scanner_evidence(
        self, finding_id: int, source: str, *, observation_fingerprint: str,
        metadata_json: dict[str, Any], protected_candidates=(), **kwargs: Any,
    ) -> Evidence:
        from orgscan.services.secret_evidence import SecretCandidateContext
        settings = self.session.info.get('secret_settings')
        incoming = {'source': source, 'metadata_json': metadata_json, **kwargs}
        with SecretCandidateContext.from_source(incoming, settings=settings, candidates=protected_candidates) as context:
            safe = context.sanitize(incoming, preserve_root_keys=True)
            source, metadata_json = safe.pop('source'), safe.pop('metadata_json')
            existing = self.session.scalar(
                select(Evidence).where(Evidence.observation_fingerprint == observation_fingerprint)
            )
            if existing:
                previous = existing.metadata_json or {}
                for key, value in safe.items():
                    setattr(existing, key, value)
                existing.observed_at = datetime.now(UTC)
                new_job = previous.get("last_scan_job_id") != metadata_json.get("last_scan_job_id")
                existing.metadata_json = {
                    **metadata_json,
                    "first_scan_job_id": previous.get("first_scan_job_id"),
                    "observations": previous.get("observations", 1) + int(new_job),
                }
                self.session.flush()
                context.persist(self.session, self.session.get(Finding, finding_id), settings=settings, evidence_id=existing.id)
                return existing
            return self.create_evidence(
                finding_id, source, observation_fingerprint=observation_fingerprint,
                protected_candidates=context._candidates,
                metadata_json={
                    **metadata_json,
                    "first_scan_job_id": metadata_json.get("last_scan_job_id"), "observations": 1,
                }, **safe,
            )

    def record_domain_discovery_source(self, domain: Domain, source: str) -> None:
        domain.discovery_sources = sorted(set(domain.discovery_sources or []) | {source})
        self.session.flush()

    def record_search_page(self, job: ScanJob, metadata: dict[str, Any]) -> None:
        scope = dict(job.scope_json or {})
        scope["pages"] = [*scope.get("pages", []), metadata]
        job.scope_json = scope
        self.session.flush()

    def create_domain_exposure(
        self,
        domain_id: int,
        source: str,
        *,
        source_name: str,
        result_summary: str,
        normalized_hash: str,
        protected_candidates=(),
        **kwargs: Any,
    ) -> DomainExposure:
        from orgscan.services.secret_evidence import SecretCandidateContext
        settings = self.session.info.get('secret_settings')
        incoming = {'result_summary': result_summary, 'source': source, 'source_name': source_name, **kwargs}
        with SecretCandidateContext.from_source(incoming, settings=settings, candidates=protected_candidates) as context:
            safe = context.sanitize(incoming, preserve_root_keys=True)
            result_summary, source, source_name = safe.pop('result_summary'), safe.pop('source'), safe.pop('source_name')
            kwargs = safe
            if context._candidates:
                self.create_finding(CanonicalFinding(
                    source_tool=source, source_name=source_name, category='secret', domain_id=domain_id,
                    title='Protected credential in provider evidence', description=result_summary,
                    fingerprint=normalized_hash, normalized_hash=normalized_hash), protected_candidates=context._candidates)
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

    def merge_discovery_metadata(self, record: Repository | Account, **values: Any) -> None:
        metadata = dict(record.metadata_json or {})
        metadata.update(values)
        record.metadata_json = metadata
        self.session.flush()

    def upsert_relationship_provenance(
        self, from_type: str, from_id: str, to_type: str, to_id: str, relation_type: str,
        *, confidence: str, source: str, provenance: dict[str, Any],
    ) -> tuple[Relationship, bool]:
        record, created = self.get_or_create_relationship(
            from_type, from_id, to_type, to_id, relation_type, confidence=confidence, source=source,
        )
        metadata = dict(record.metadata_json or {})
        observations = list(metadata.get("provenance", []))
        if provenance not in observations:
            observations.append(provenance)
        now = datetime.now(UTC).isoformat()
        metadata.update({"provenance": observations[-50:], "last_observed_at": now})
        metadata.setdefault("first_observed_at", now)
        record.metadata_json = metadata
        record.evidence_summary = provenance.get("reason")
        levels = ("unverified", "heuristic", "likely", "verified")
        if levels.index(confidence) > levels.index(record.confidence):
            record.confidence = confidence
        self.session.flush()
        return record, created

    def correct_legacy_fork_direction(self, parent_id: int, fork_id: int) -> None:
        # Correct only old, unannotated github-api edges after a fresh API observation.
        legacy = self.session.scalar(select(Relationship).where(
            Relationship.from_entity_type == "repository",
            Relationship.from_entity_id == str(parent_id),
            Relationship.to_entity_type == "repository",
            Relationship.to_entity_id == str(fork_id),
            Relationship.relation_type == "fork_of", Relationship.source == "github-api",
        ))
        if legacy is not None and not legacy.metadata_json:
            self.session.delete(legacy)
            self.session.flush()

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

    def reserve_queue_execution(self, scheduled, *, backend, queue_name, max_attempts):
        """Claim one schedule and create its durable execution in the same transaction."""
        import uuid
        key = uuid.uuid4().hex
        claimed = self.session.execute(update(ScheduledScan).where(
            ScheduledScan.id == scheduled.id, ScheduledScan.queue_execution_key.is_(None),
            ScheduledScan.enabled.is_(True), ScheduledScan.next_run_at == scheduled.next_run_at,
        ).values(queue_execution_key=key), execution_options={"synchronize_session": False})
        if claimed.rowcount != 1:
            return None
        self.session.refresh(scheduled)
        task = self.create_queue_task(scheduled.id, backend=backend, queue_name=queue_name,
                                     status='queued', max_attempts=max_attempts, available_at=datetime.now(UTC))
        task.execution_key = key
        self.session.flush()
        return task

    def release_queue_execution(self, task):
        if task.execution_key:
            self.session.execute(update(ScheduledScan).where(
                ScheduledScan.id == task.scheduled_scan_id,
                ScheduledScan.queue_execution_key == task.execution_key,
            ).values(queue_execution_key=None), execution_options={"synchronize_session": False})

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
            # Compare-and-set claim prevents two workers claiming the same queued row.
            claimed = self.session.execute(update(QueueTask).where(
                QueueTask.id == task.id, QueueTask.status == "queued", QueueTask.available_at <= current,
                or_(QueueTask.lease_expires_at.is_(None), QueueTask.lease_expires_at <= current),
            ).values(status="running", lease_owner=worker_id, lease_expires_at=lease_until,
                     started_at=current, attempt_count=QueueTask.attempt_count + 1),
                execution_options={"synchronize_session": False})
            if claimed.rowcount == 1:
                self.session.refresh(task)
                return task
        return None

    def mark_queue_task_completed(self, task: QueueTask, *, scan_job_id: int | None = None, tool_run_id: int | None = None) -> QueueTask:
        self.release_queue_execution(task)
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

    def get_rate_limit_state(self, scope: str) -> RateLimitState | None:
        return self.session.scalar(select(RateLimitState).where(RateLimitState.scope == scope))

    def get_or_create_rate_limit_state(self, scope: str, **kwargs: Any) -> tuple[RateLimitState, bool]:
        existing = self.get_rate_limit_state(scope)
        if existing is not None:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing, False
        state = RateLimitState(scope=scope, **kwargs)
        self.session.add(state)
        self.session.flush()
        return state, True

    def list_rate_limit_states(self, backend: str | None = None, limit: int | None = 100) -> Sequence[RateLimitState]:
        query = select(RateLimitState).order_by(RateLimitState.scope.asc())
        if backend is not None:
            query = query.where(RateLimitState.backend == backend)
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))

    def list_findings(
        self,
        limit: int | None = 50,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
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
        tenant_keys: list[str] | None = None,
        include_evidence: bool = False,
        high_signal_only: bool = False,
        min_confidence: str = "likely",
        include_safety_context: bool = True,
    ) -> Sequence[Finding]:
        query = select(Finding).order_by(Finding.detected_at.desc(), Finding.id.desc())
        if tenant_keys is not None:
            query = query.where(self.finding_tenant_scope(tenant_keys))
        if high_signal_only:
            query = query.where(Finding.confidence.in_(self._allowed_confidences(min_confidence)), Finding.status != "suppressed")
        if include_evidence:
            query = query.options(selectinload(Finding.evidence_items), selectinload(Finding.repository), selectinload(Finding.scan_job))
        if status:
            query = query.where(Finding.status == status)
        if lifecycle_state:
            query = query.where(Finding.lifecycle_state == lifecycle_state)
        if category:
            query = query.where(Finding.category == category)
        if severity:
            query = query.where(Finding.severity == severity)
        if confidence:
            query = query.where(Finding.confidence == confidence)
        if source_tool:
            query = query.where(Finding.source_tool == source_tool)
        if triage_state:
            query = query.where(Finding.triage_state == triage_state)
        if organization_id is not None:
            query = query.where(Finding.organization_id == organization_id)
        if domain_id is not None:
            query = query.where(Finding.domain_id == domain_id)
        if repository_id is not None:
            query = query.where(Finding.repository_id == repository_id)
        if account_id is not None:
            query = query.where(Finding.account_id == account_id)
        if scan_job_id is not None:
            query = query.where(Finding.scan_job_id == scan_job_id)
        if risk_score_min is not None:
            query = query.where(Finding.risk_score >= risk_score_min)
        if risk_score_max is not None:
            query = query.where(Finding.risk_score <= risk_score_max)
        if detected_after is not None:
            query = query.where(Finding.detected_at >= self._normalize_datetime_filter(detected_after))
        if detected_before is not None:
            query = query.where(Finding.detected_at <= self._normalize_datetime_filter(detected_before))
        if limit is not None:
            query = query.limit(limit)
        findings = list(self.session.scalars(query))
        return self.bind_finding_contexts(findings, tenant_keys=tenant_keys) if include_safety_context else findings

    @staticmethod
    def _normalize_datetime_filter(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    @staticmethod
    def finding_tenant_scope(tenant_keys):
        from sqlalchemy import true
        if tenant_keys is None:
            return true()
        from orgscan.storage.visibility import visibility_ids
        return Finding.id.in_(visibility_ids(tenant_keys)[Finding])

    def visible_rows(self, model, tenant_keys=None):
        from orgscan.storage.visibility import visibility_ids
        query = select(model).order_by(model.id.desc())
        if tenant_keys is not None:
            query = query.where(model.id.in_(visibility_ids(tenant_keys)[model]))
        return list(self.session.scalars(query))

    def domain_sources(self, domain):
        """Tenant-scoped, fresh read session; cached foreign objects cannot bypass scope."""
        from orgscan.storage.sources import domain_sources
        return domain_sources(self, domain)

    def report_summary(self, *, tenant_keys=None, source_context=None):
        from orgscan.storage.report_queries import report_summary
        return report_summary(self, tenant_keys=tenant_keys, source_context=source_context)

    def get_finding(self, finding_id: int) -> Finding | None:
        finding = self.session.get(Finding, finding_id)
        if finding is not None:
            self.bind_finding_contexts([finding])
        return finding

    def bind_finding_contexts(self, findings, *, tenant_keys=None):
        from orgscan.storage.credential_context import bind_finding_contexts
        return bind_finding_contexts(self, findings, tenant_keys=tenant_keys)

    def get_scan_jobs_by_ids(self, identities):
        return {job.id: job for job in self.session.scalars(select(ScanJob).where(ScanJob.id.in_(identities)))}

    def get_scan_job(self, scan_job_id: int) -> ScanJob | None:
        return self.session.get(ScanJob, scan_job_id)

    def get_tool_run(self, tool_run_id: int) -> ToolRun | None:
        return self.session.get(ToolRun, tool_run_id)

    def list_finding_evidence(self, finding_id: int) -> Sequence[Evidence]:
        query = select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.observed_at.desc(), Evidence.id.desc())
        return list(self.session.scalars(query))

    def list_risk_scores(
        self,
        *,
        finding_id: int | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 50,
    ) -> Sequence[RiskScore]:
        query = select(RiskScore)
        if finding_id is not None:
            query = query.where(RiskScore.finding_id == finding_id)
        if entity_type is not None:
            query = query.where(RiskScore.entity_type == entity_type)
        if entity_id is not None:
            query = query.where(RiskScore.entity_id == entity_id)
        query = query.order_by(RiskScore.calculated_at.desc(), RiskScore.id.desc()).limit(limit)
        return list(self.session.scalars(query))

    def update_finding_triage(
        self,
        finding_id: int,
        *,
        status: str | None = None,
        lifecycle_state: str | None = None,
        triage_state: str | None = None,
        triage_owner: str | None = None,
        triage_notes: str | None = None,
        remediation_due_date: Any | None = None,
        reason: str | None = None,
    ) -> Finding:
        finding = self.session.get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} does not exist")
        before = snapshot(finding)
        target = lifecycle_state or (from_legacy(status) if status is not None else finding.lifecycle_state)
        if lifecycle_state and status is not None and LEGACY_STATUS.get(lifecycle_state) != status:
            raise ValueError("Status conflicts with lifecycle_state")
        self._transition(finding, target, record_history=False)
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
        if before != snapshot(finding):
            self._record_history(finding, before, reason=reason)
        self.session.flush()
        return finding

    def _record_history(self, finding, before, *, reason=None, scan_job_id=None):
        auth = current_auth.get()
        self.session.add(FindingHistory(
            finding_id=finding.id, from_state=before["lifecycle_state"] if before else None,
            to_state=finding.lifecycle_state, actor="scanner" if scan_job_id else (auth.name if auth else "local"),
            reason=reason, scan_job_id=scan_job_id,
            metadata_json={"before": before, "after": snapshot(finding)},
        ))

    def _transition(self, finding, target, *, automatic=False, scan_job_id=None, reason=None, record_history=True):
        before = snapshot(finding)
        target = validate_transition(finding.lifecycle_state, target, automatic=automatic)
        if target == finding.lifecycle_state:
            return
        finding.lifecycle_state = target
        finding.status = LEGACY_STATUS[target]
        if target == "REMEDIATED":
            finding.remediated_at = datetime.now(UTC)
        if target == "REGRESSED":
            finding.regressed_at = datetime.now(UTC)
            finding.regression_count += 1
            finding.triage_state = "reopened"
        if record_history:
            self._record_history(finding, before, reason=reason, scan_job_id=scan_job_id)

    def list_finding_history(self, finding_id):
        return list(self.session.scalars(select(FindingHistory).where(
            FindingHistory.finding_id == finding_id).order_by(FindingHistory.occurred_at, FindingHistory.id)))

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
            reason=reason,
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

    def list_tool_runs(self, limit: int = 25, scan_job_id: int | None = None) -> Sequence[ToolRun]:
        query = select(ToolRun).order_by(ToolRun.created_at.desc(), ToolRun.id.desc())
        if scan_job_id is not None:
            query = query.where(ToolRun.scan_job_id == scan_job_id)
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

    def list_relationships_for_entity(self, entity_type: str, entity_id: str, limit: int = 100) -> Sequence[Relationship]:
        query = (
            select(Relationship)
            .where(
                or_(
                    (Relationship.from_entity_type == entity_type) & (Relationship.from_entity_id == entity_id),
                    (Relationship.to_entity_type == entity_type) & (Relationship.to_entity_id == entity_id),
                )
            )
            .order_by(Relationship.created_at.desc(), Relationship.id.desc())
            .limit(limit)
        )
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
        return self.bind_finding_contexts(list(self.session.scalars(query)))

    def list_entity_risk_profiles(
        self,
        *,
        entity_type: str | None = None,
        entity_id: int | None = None,
        min_confidence: str = "likely",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        entity_mappings = {
            "organization": (Finding.organization_id, Organization, Organization.name),
            "domain": (Finding.domain_id, Domain, Domain.name),
            "repository": (Finding.repository_id, Repository, Repository.full_name),
            "account": (Finding.account_id, Account, Account.username),
        }
        if entity_type is not None and entity_type not in entity_mappings:
            raise ValueError(f"Unsupported entity type: {entity_type}")

        selected_types = [entity_type] if entity_type is not None else list(entity_mappings)
        profiles: list[dict[str, Any]] = []
        allowed_confidences = self._allowed_confidences(min_confidence)

        for current_type in selected_types:
            entity_column, model, label_column = entity_mappings[current_type]
            query = (
                select(
                    entity_column.label("entity_id"),
                    label_column.label("entity_name"),
                    func.count(Finding.id).label("finding_count"),
                    func.sum(case((Finding.status.not_in(("resolved", "suppressed")), 1), else_=0)).label("active_finding_count"),
                    func.sum(case((Finding.status == "suppressed", 1), else_=0)).label("suppressed_count"),
                    func.sum(case((Finding.confidence == "verified", 1), else_=0)).label("verified_count"),
                    func.sum(case((Finding.confidence == "likely", 1), else_=0)).label("likely_count"),
                    func.sum(case((Finding.confidence == "heuristic", 1), else_=0)).label("heuristic_count"),
                    func.max(Finding.risk_score).label("max_risk_score"),
                    func.avg(Finding.risk_score).label("average_risk_score"),
                )
                .select_from(Finding)
                .join(model, model.id == entity_column, isouter=True)
                .where(entity_column.is_not(None), Finding.confidence.in_(allowed_confidences))
                .group_by(entity_column, label_column)
                .order_by(func.max(Finding.risk_score).desc().nullslast(), func.count(Finding.id).desc(), label_column.asc())
            )
            if entity_id is not None:
                query = query.where(entity_column == entity_id)
            rows = self.session.execute(query.limit(limit))
            for row in rows:
                profiles.append(
                    {
                        "entity_type": current_type,
                        "entity_id": row.entity_id,
                        "entity_name": row.entity_name or f"{current_type}:{row.entity_id}",
                        "finding_count": int(row.finding_count or 0),
                        "active_finding_count": int(row.active_finding_count or 0),
                        "suppressed_count": int(row.suppressed_count or 0),
                        "verified_count": int(row.verified_count or 0),
                        "likely_count": int(row.likely_count or 0),
                        "heuristic_count": int(row.heuristic_count or 0),
                        "max_risk_score": float(row.max_risk_score or 0),
                        "average_risk_score": float(row.average_risk_score or 0),
                    }
                )

        profiles.sort(
            key=lambda item: (
                item["max_risk_score"],
                item["finding_count"],
                item["entity_type"],
                str(item["entity_name"]),
            ),
            reverse=True,
        )
        return profiles[:limit]

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
            "rate_limit_states": RateLimitState,
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

    @classmethod
    def _allowed_confidences(cls, min_confidence: str) -> tuple[str, ...]:
        try:
            start_index = cls.CONFIDENCE_ORDER.index(min_confidence)
        except ValueError as exc:
            raise ValueError(f"Unsupported confidence level: {min_confidence}") from exc
        return cls.CONFIDENCE_ORDER[start_index:]
