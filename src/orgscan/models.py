from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, Index, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ControlPlaneRecord:
    """Ordinary control-plane text must cross persistence and projection safety."""
    pass


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(StrEnum):
    VERIFIED = "verified"
    LIKELY = "likely"
    HEURISTIC = "heuristic"
    UNVERIFIED = "unverified"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


class ScanJobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class QueueTaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    LIKELY = "likely"
    UNVERIFIED = "unverified"


class SourceClass(StrEnum):
    FREE = "free"
    PAID = "paid"
    INTERNAL = "internal"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    tenant_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_handle: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    domains: Mapped[list[Domain]] = relationship(back_populates="organization")
    repositories: Mapped[list[Repository]] = relationship(back_populates="organization")
    accounts: Mapped[list[Account]] = relationship(back_populates="organization")


class DomainIdentity(Base):
    """Global DNS identity only. Never an authorization or observation boundary."""
    __tablename__ = "domain_identities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    normalized_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)


class Domain(TimestampMixin, Base):
    """Tenant-domain association; historical IDs remain stable for every reference."""
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("tenant_key", "identity_id", name="uq_domain_tenant_identity"),
        Index("uq_domain_legacy_identity", "identity_id", unique=True,
              sqlite_where=text("tenant_key IS NULL"), postgresql_where=text("tenant_key IS NULL")),
    )

    identity_id: Mapped[int] = mapped_column(ForeignKey("domain_identities.id"), nullable=False)
    tenant_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    ownership_confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    verification_status: Mapped[str] = mapped_column(String(32), default=VerificationStatus.UNVERIFIED.value)
    discovered_emails: Mapped[list[str]] = mapped_column(JSON, default=list)
    discovered_subdomains: Mapped[list[str]] = mapped_column(JSON, default=list)
    discovery_sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    organization: Mapped[Organization | None] = relationship(back_populates="domains")
    exposures: Mapped[list[DomainExposure]] = relationship(back_populates="domain")
    identity_correlations: Mapped[list[IdentityCorrelation]] = relationship(back_populates="domain")


class Repository(TimestampMixin, Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    owner_account_id: Mapped[int | None] = mapped_column(ForeignKey("accounts.id"), nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), default="github")
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    mirror_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_mirrored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    organization: Mapped[Organization | None] = relationship(back_populates="repositories")
    owner_account: Mapped[Account | None] = relationship(back_populates="repositories")
    findings: Mapped[list[Finding]] = relationship(back_populates="repository")


class Account(TimestampMixin, Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), default="github")
    account_type: Mapped[str] = mapped_column(String(64), default="user")
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    organization: Mapped[Organization | None] = relationship(back_populates="accounts")
    repositories: Mapped[list[Repository]] = relationship(back_populates="owner_account")


class ScanJob(TimestampMixin, Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[str] = mapped_column(String(1024), index=True)
    target_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scanner_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default=ScanJobStatus.PENDING.value)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list[Finding]] = relationship(back_populates="scan_job")
    tool_runs: Mapped[list[ToolRun]] = relationship(back_populates="scan_job")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id"), nullable=True)
    repository_id: Mapped[int | None] = mapped_column(ForeignKey("repositories.id"), nullable=True)
    account_id: Mapped[int | None] = mapped_column(ForeignKey("accounts.id"), nullable=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(255))
    source_name: Mapped[str] = mapped_column(String(255))
    source_class: Mapped[str] = mapped_column(String(32), default=SourceClass.INTERNAL.value)
    category: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), default=SeverityLevel.INFO.value)
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.OPEN.value)
    lifecycle_state: Mapped[str] = mapped_column(String(32), default="NEW", index=True)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    regressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    regression_count: Mapped[int] = mapped_column(Integer, default=0)
    triage_state: Mapped[str] = mapped_column(String(32), default="new")
    triage_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    normalized_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    remediation_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    repository: Mapped[Repository | None] = relationship(back_populates="findings")
    scan_job: Mapped[ScanJob | None] = relationship(back_populates="findings")
    evidence_items: Mapped[list[Evidence]] = relationship(back_populates="finding")
    risk_scores: Mapped[list[RiskScore]] = relationship(back_populates="finding")
    suppressions: Mapped[list[Suppression]] = relationship(back_populates="finding")


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    source: Mapped[str] = mapped_column(String(255))
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    repository_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ref_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    extracted_indicator: Mapped[str | None] = mapped_column(String(512), nullable=True)
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    related_entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    related_entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_class: Mapped[str] = mapped_column(String(32), default=SourceClass.INTERNAL.value)
    query_used: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observation_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="evidence_items")


class Relationship(TimestampMixin, Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "from_entity_type",
            "from_entity_id",
            "to_entity_type",
            "to_entity_id",
            "relation_type",
            name="uq_relationship_edge",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    from_entity_type: Mapped[str] = mapped_column(String(64), index=True)
    from_entity_id: Mapped[str] = mapped_column(String(64), index=True)
    to_entity_type: Mapped[str] = mapped_column(String(64), index=True)
    to_entity_id: Mapped[str] = mapped_column(String(64), index=True)
    relation_type: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RiskScore(TimestampMixin, Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    score: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(32), default=SeverityLevel.INFO.value)
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    finding: Mapped[Finding | None] = relationship(back_populates="risk_scores")


class ToolRun(TimestampMixin, Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(255), index=True)
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target: Mapped[str] = mapped_column(String(1024))
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=ScanJobStatus.PENDING.value)
    stdout_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan_job: Mapped[ScanJob | None] = relationship(back_populates="tool_runs")


class ScheduledScan(TimestampMixin, Base):
    __tablename__ = "scheduled_scans"

    queue_execution_key: Mapped[str | None] = mapped_column(String(64), nullable=True)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_value: Mapped[str] = mapped_column(String(1024), index=True)
    scanner_name: Mapped[str] = mapped_column(String(255))
    cadence: Mapped[str] = mapped_column(String(32), default="daily")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ScheduledReport(TimestampMixin, Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True, default="global")
    target_value: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    output_format: Mapped[str] = mapped_column(String(32), default="json")
    cadence: Mapped[str] = mapped_column(String(32), default="daily")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    output_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    tenant_memberships: Mapped[list[UserTenantMembership]] = relationship(back_populates="user")
    sessions: Mapped[list[UserSession]] = relationship(back_populates="user")


class UserTenantMembership(TimestampMixin, Base):
    __tablename__ = "user_tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_key", name="uq_user_tenant_membership"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[str] = mapped_column(String(32), default="reader")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    user: Mapped[User] = relationship(back_populates="tenant_memberships")


class UserSession(TimestampMixin, Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    session_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), default="reader")
    tenant_scopes_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    user: Mapped[User] = relationship(back_populates="sessions")


class QueueTask(TimestampMixin, Base):
    __tablename__ = "queue_tasks"

    execution_key: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scheduled_scan_id: Mapped[int] = mapped_column(ForeignKey("scheduled_scans.id"), index=True)
    backend: Mapped[str] = mapped_column(String(32), default="db", index=True)
    queue_name: Mapped[str] = mapped_column(String(255), default="orgscan:db")
    status: Mapped[str] = mapped_column(String(32), default=QueueTaskStatus.QUEUED.value, index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_scan_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_tool_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scheduled_scan: Mapped[ScheduledScan] = relationship()


class RateLimitState(TimestampMixin, Base):
    __tablename__ = "rate_limit_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    backend: Mapped[str] = mapped_column(String(32), default="db", index=True)
    requests_per_minute: Mapped[int] = mapped_column(Integer, default=0)
    min_interval_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    window_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    last_request_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_allowed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class DomainExposure(TimestampMixin, Base):
    __tablename__ = "domain_exposures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), index=True)
    source: Mapped[str] = mapped_column(String(255))
    source_class: Mapped[str] = mapped_column(String(32), default=SourceClass.FREE.value)
    source_name: Mapped[str] = mapped_column(String(255))
    query_used: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result_summary: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    severity: Mapped[str] = mapped_column(String(32), default=SeverityLevel.INFO.value)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    evidence_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    normalized_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    domain: Mapped[Domain] = relationship(back_populates="exposures")


class IdentityCorrelation(TimestampMixin, Base):
    __tablename__ = "identity_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    person_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[str] = mapped_column(String(32), default=ConfidenceLevel.UNVERIFIED.value)
    relation_type: Mapped[str] = mapped_column(String(64))
    evidence_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    domain: Mapped[Domain] = relationship(back_populates="identity_correlations")


class Suppression(TimestampMixin, Base):
    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="suppressions")


from orgscan.storage.safety import install as _install_evidence_safety
_install_evidence_safety()


class SecretEvidence(Base):
    """Ciphertext only. No property, repr or serializer decrypts this model."""
    __tablename__ = 'secret_evidence'
    __table_args__ = (UniqueConstraint('finding_id', 'fingerprint', 'key_id', name='uq_secret_finding_fingerprint_key'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey('findings.id'), index=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey('evidence.id'), nullable=True)
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    secret_type: Mapped[str] = mapped_column(String(128))
    redacted_display: Mapped[str] = mapped_column(String(64), default='••••••••••••')
    fingerprint: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(64))
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    source: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class SecretRevealAudit(Base):
    __tablename__ = 'secret_reveal_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    principal: Mapped[str] = mapped_column(String(255))
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey('findings.id'))
    secret_evidence_id: Mapped[int] = mapped_column(ForeignKey('secret_evidence.id'))
    source: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class Assessment(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'assessments'
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(32), default='draft')
    created_by: Mapped[str] = mapped_column(String(255))
    organization_id: Mapped[int] = mapped_column(ForeignKey('organizations.id'))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovery_profile: Mapped[dict] = mapped_column(JSON, default=dict)
    scan_profile: Mapped[dict] = mapped_column(JSON, default=dict)


class GitHubConnection(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'github_connections'
    __table_args__ = (UniqueConstraint('tenant_key', 'web_base_url', name='uq_connection_tenant_web'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    connection_type: Mapped[str] = mapped_column(String(32))
    web_base_url: Mapped[str] = mapped_column(String(512))
    api_base_url: Mapped[str] = mapped_column(String(512))
    credential_env: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_private: Mapped[bool] = mapped_column(Boolean, default=False)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_status: Mapped[str] = mapped_column(String(32), default='not-tested')
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class AssessmentTarget(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'assessment_targets'
    __table_args__ = (UniqueConstraint('assessment_id','identity',name='uq_assessment_target_identity'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'), index=True)
    connection_id: Mapped[int | None] = mapped_column(ForeignKey('github_connections.id'))
    identity: Mapped[str] = mapped_column(String(64))
    raw_input: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(String(2048))
    target_type: Mapped[str] = mapped_column(String(32))
    validation_status: Mapped[str] = mapped_column(String(32), default='valid')
    notes: Mapped[str] = mapped_column(Text, default='')
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class AssessmentEntity(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'assessment_entities'
    __table_args__ = (UniqueConstraint('assessment_id','entity_type','entity_id',name='uq_assessment_entity'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'), index=True)
    connection_id: Mapped[int | None] = mapped_column(ForeignKey('github_connections.id'))
    entity_type: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[int] = mapped_column(Integer, index=True)
    included: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[str] = mapped_column(String(32), default='unverified')
    source: Mapped[str] = mapped_column(String(128))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class AssessmentRun(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'assessment_runs'
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey('assessment_targets.id'))
    scheduled_scan_id: Mapped[int] = mapped_column(ForeignKey('scheduled_scans.id'), unique=True)
    kind: Mapped[str] = mapped_column(String(32))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class ReconProfile(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'recon_profiles'
    __table_args__ = (UniqueConstraint('tenant_key','name',name='uq_recon_profile_tenant_name'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_key: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)


class LocalAIConfiguration(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'local_ai_configurations'
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_key: Mapped[str] = mapped_column(String(255), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    base_url: Mapped[str] = mapped_column(String(512))
    model: Mapped[str] = mapped_column(String(255))


class AIAdvice(ControlPlaneRecord, TimestampMixin, Base):
    __tablename__ = 'ai_advice'
    __table_args__ = (UniqueConstraint('assessment_id','fingerprint',name='uq_ai_advice_input'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'), index=True)
    purpose: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(32), default='ollama')
    model: Mapped[str] = mapped_column(String(255))
    policy_version: Mapped[str] = mapped_column(String(32))
    fingerprint: Mapped[str] = mapped_column(String(64))
    output_json: Mapped[dict] = mapped_column(JSON, default=dict)


class ReconAsset(ControlPlaneRecord, TimestampMixin, Base):
    """Tenant-owned canonical IP/service/endpoint/certificate with safe observations."""
    __tablename__ = 'recon_assets'
    __table_args__ = (UniqueConstraint('organization_id','kind','identity',name='uq_recon_asset_identity'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey('organizations.id'),index=True)
    kind: Mapped[str] = mapped_column(String(32),index=True)
    identity: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(2048))
    metadata_json: Mapped[dict] = mapped_column(JSON,default=dict)
