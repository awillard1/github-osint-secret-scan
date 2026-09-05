from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
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
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_handle: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    domains: Mapped[list[Domain]] = relationship(back_populates="organization")
    repositories: Mapped[list[Repository]] = relationship(back_populates="organization")
    accounts: Mapped[list[Account]] = relationship(back_populates="organization")


class Domain(TimestampMixin, Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
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
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    scanner_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default=ScanJobStatus.PENDING.value)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
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


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    source: Mapped[str] = mapped_column(String(255))
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    repository_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
    status: Mapped[str] = mapped_column(String(32), default=ScanJobStatus.PENDING.value)
    stdout_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan_job: Mapped[ScanJob | None] = relationship(back_populates="tool_runs")


class ScheduledScan(TimestampMixin, Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_value: Mapped[str] = mapped_column(String(1024), index=True)
    scanner_name: Mapped[str] = mapped_column(String(255))
    cadence: Mapped[str] = mapped_column(String(32), default="daily")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
