"""Finding reads and operator decisions, independent of HTTP and CLI transports.

The caller supplies the existing session factory after database initialization.
Each mutation owns one transaction, including its suppression record. Access is
provided by the session factory. HTTP sessions derive the request AuthContext
and enforce tenant reads/writes in storage; local CLI sessions remain trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import date, datetime

from sqlalchemy.orm import Session

from orgscan.models import Evidence, Finding, FindingHistory, RiskScore
from orgscan.repositories import Storage


class FindingNotFound(ValueError):
    def __init__(self, finding_id: int) -> None:
        super().__init__(f"Finding {finding_id} does not exist")


@dataclass(frozen=True)
class FindingQuery:
    limit: int = 50
    status: str | None = None
    category: str | None = None
    severity: str | None = None
    confidence: str | None = None
    source_tool: str | None = None
    lifecycle_state: str | None = None
    triage_state: str | None = None
    organization_id: int | None = None
    domain_id: int | None = None
    repository_id: int | None = None
    account_id: int | None = None
    scan_job_id: int | None = None
    risk_score_min: float | None = None
    risk_score_max: float | None = None
    detected_after: datetime | None = None
    detected_before: datetime | None = None
    high_signal_only: bool = False
    min_confidence: str = "likely"


@dataclass(frozen=True)
class TriageUpdate:
    # None preserves the stored value, as in Storage.update_finding_triage.
    status: str | None = None
    lifecycle_state: str | None = None
    triage_state: str | None = None
    triage_owner: str | None = None
    triage_notes: str | None = None
    remediation_due_date: date | None = None


@dataclass(frozen=True)
class FindingDecision:
    reason: str
    owner: str | None = None
    note: str | None = None
    due_date: date | None = None


@dataclass(frozen=True)
class FindingDetail:
    finding: Finding
    evidence: Sequence[Evidence]
    risk_scores: Sequence[RiskScore]
    history: Sequence[FindingHistory]


def high_signal_findings(
    findings: Sequence[Finding], *, min_confidence: str = "likely", limit: int = 10
) -> list[Finding]:
    allowed = set(Storage._allowed_confidences(min_confidence))
    return [
        finding
        for finding in findings
        if finding.confidence in allowed and finding.status not in {"suppressed"}
    ][:limit]


class FindingService:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    def list_findings(self, query: FindingQuery) -> list[Finding]:
        filters = asdict(query)
        filters.pop("high_signal_only")
        filters.pop("min_confidence")
        # Preserve the API's existing bounded candidate window and ordering.
        if query.high_signal_only:
            filters["limit"] = max(query.limit * 4, query.limit)
        with self.session_factory() as session:
            storage = Storage(session)
            findings = list(storage.list_findings(**filters, include_safety_context=False))
            if query.high_signal_only:
                findings = high_signal_findings(findings, min_confidence=query.min_confidence, limit=query.limit)
            storage.bind_finding_contexts(findings)
        return findings

    def get_detail(self, finding_id: int) -> FindingDetail | None:
        with self.session_factory() as session:
            storage = Storage(session)
            finding = storage.get_finding(finding_id)
            if finding is None:
                return None
            return FindingDetail(
                finding=finding,
                evidence=storage.list_finding_evidence(finding_id),
                history=storage.list_finding_history(finding_id),
                risk_scores=storage.list_risk_scores(finding_id=finding_id),
            )

    @staticmethod
    def _require_finding(storage: Storage, finding_id: int) -> None:
        if storage.get_finding(finding_id) is None:
            raise FindingNotFound(finding_id)

    def update_triage(self, finding_id: int, update: TriageUpdate) -> Finding:
        with self.session_factory() as session:
            storage = Storage(session)
            self._require_finding(storage, finding_id)
            finding = storage.update_finding_triage(finding_id, **asdict(update))
            session.commit()
            storage.bind_finding_contexts([finding])
            return finding

    def apply_decision(self, finding_id: int, decision: FindingDecision, *, status: str) -> Finding:
        with self.session_factory() as session:
            storage = Storage(session)
            self._require_finding(storage, finding_id)
            finding = storage.suppress_finding(
                finding_id,
                reason=decision.reason,
                owner=decision.owner,
                deadline=decision.due_date,
                notes=decision.note,
                status=status,
            )
            session.commit()
            storage.bind_finding_contexts([finding])
            return finding

    def reopen(self, finding_id: int, *, note: str | None = None) -> Finding:
        # Reopening retains owner/deadline and earlier suppression records.
        return self.update_triage(
            finding_id, TriageUpdate(status="open", triage_state="reopened", triage_notes=note)
        )
