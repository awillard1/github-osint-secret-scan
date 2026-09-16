from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from orgscan.db import create_session_factory, init_db
from orgscan.models import Suppression
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.services.finding_service import (
    FindingDecision,
    FindingNotFound,
    FindingQuery,
    FindingService,
    TriageUpdate,
)


@pytest.fixture
def session_factory(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'findings.db'}"
    init_db(database_url)
    return create_session_factory(database_url)


def seed_finding(session_factory, **fields):
    with session_factory() as session:
        finding = Storage(session).create_finding(CanonicalFinding(
            source_tool="custom-patterns",
            category="secret",
            title=fields.pop("title", "Review this finding"),
            description="Synthetic finding for operator workflow tests",
            **fields,
        ))
        session.commit()
        return finding.id


def test_triage_partial_update_preserves_omitted_fields(session_factory):
    finding_id = seed_finding(session_factory)
    service = FindingService(session_factory)
    service.update_triage(finding_id, TriageUpdate(
        status="triaged",
        triage_state="reviewing",
        triage_owner="alice",
        triage_notes="validated",
        remediation_due_date=date(2026, 9, 30),
    ))
    service.update_triage(finding_id, TriageUpdate(status="resolved", triage_notes=""))

    stored = service.get_detail(finding_id).finding
    assert stored.status == "resolved"
    assert stored.triage_state == "reviewing"
    assert stored.triage_owner == "alice"
    assert stored.triage_notes == ""
    assert stored.remediation_due_date == date(2026, 9, 30)


@pytest.mark.parametrize("status", ["suppressed", "accepted_risk"])
def test_decision_and_reopen_preserve_review_history(session_factory, status):
    finding_id = seed_finding(session_factory)
    service = FindingService(session_factory)
    decision = FindingDecision(
        reason="Documented exception", owner="alice", note="Review quarterly", due_date=date(2026, 12, 1)
    )
    decided = service.apply_decision(finding_id, decision, status=status)
    assert decided.status == status
    assert decided.triage_state == status

    reopened = service.reopen(finding_id, note="Needs another review")
    assert reopened.status == "open"
    assert reopened.triage_state == "reopened"
    assert reopened.triage_notes == "Needs another review"
    assert reopened.triage_owner == "alice"
    assert reopened.remediation_due_date == decision.due_date
    with session_factory() as session:
        records = list(session.scalars(select(Suppression).where(Suppression.finding_id == finding_id)))
        assert len(records) == 1
        assert records[0].status == status
        assert records[0].reason == decision.reason
        assert records[0].owner == decision.owner
        assert records[0].notes == decision.note
        assert records[0].deadline == decision.due_date


def test_reopen_without_note_retains_previous_notes(session_factory):
    finding_id = seed_finding(session_factory)
    service = FindingService(session_factory)
    service.update_triage(finding_id, TriageUpdate(triage_notes="Existing review"))
    assert service.reopen(finding_id).triage_notes == "Existing review"


def test_decision_rolls_back_finding_and_suppression_on_failure(session_factory, monkeypatch):
    finding_id = seed_finding(session_factory)
    original = Storage.create_suppression

    def fail_after_insert(storage, *args, **kwargs):
        original(storage, *args, **kwargs)
        raise RuntimeError("Synthetic persistence failure")

    monkeypatch.setattr(Storage, "create_suppression", fail_after_insert)
    service = FindingService(session_factory)
    with pytest.raises(RuntimeError, match="Synthetic persistence failure"):
        service.apply_decision(finding_id, FindingDecision(reason="Exception"), status="suppressed")

    assert service.get_detail(finding_id).finding.status == "open"
    with session_factory() as session:
        assert list(session.scalars(select(Suppression))) == []


@pytest.mark.parametrize("operation", ["triage", "decision", "reopen"])
def test_missing_finding_does_not_create_workflow_records(session_factory, operation):
    service = FindingService(session_factory)
    assert service.get_detail(404) is None
    with pytest.raises(FindingNotFound, match="Finding 404 does not exist"):
        if operation == "triage":
            service.update_triage(404, TriageUpdate(status="triaged"))
        elif operation == "decision":
            service.apply_decision(404, FindingDecision(reason="Exception"), status="accepted_risk")
        else:
            service.reopen(404)
    assert service.list_findings(FindingQuery()) == []
    with session_factory() as session:
        assert list(session.scalars(select(Suppression))) == []


def test_high_signal_keeps_accepted_risk_and_filters_before_result_limit(session_factory):
    now = datetime.now(UTC)
    seed_finding(session_factory, title="Suppressed", confidence="verified", status="suppressed", detected_at=now)
    seed_finding(session_factory, title="Heuristic", confidence="heuristic", detected_at=now - timedelta(minutes=1))
    accepted_id = seed_finding(
        session_factory, title="Accepted", confidence="likely", status="accepted_risk", detected_at=now - timedelta(minutes=2)
    )
    seed_finding(session_factory, title="Verified", confidence="verified", detected_at=now - timedelta(minutes=3))

    service = FindingService(session_factory)
    findings = service.list_findings(FindingQuery(limit=1, high_signal_only=True))
    assert [finding.id for finding in findings] == [accepted_id]
    assert len(service.list_findings(FindingQuery())) == 4
    assert [finding.title for finding in service.list_findings(
        FindingQuery(high_signal_only=True, min_confidence="verified")
    )] == ["Verified"]


def test_list_filters_and_detail_evidence_use_same_stored_finding(session_factory):
    now = datetime.now(UTC)
    matching_id = seed_finding(
        session_factory, title="Matching", confidence="likely", severity="high", risk_score=90,
        detected_at=now - timedelta(hours=1),
    )
    other_id = seed_finding(session_factory, title="Other", risk_score=10, detected_at=now - timedelta(days=3))
    with session_factory() as session:
        storage = Storage(session)
        evidence = storage.create_evidence(matching_id, "fixture", snippet="<redacted>")
        risk = storage.create_risk_score("finding", str(matching_id), 90, finding_id=matching_id)
        storage.create_evidence(other_id, "other")
        session.commit()
        evidence_id, risk_id = evidence.id, risk.id

    service = FindingService(session_factory)
    service.update_triage(matching_id, TriageUpdate(triage_state="reviewing"))
    matches = service.list_findings(FindingQuery(
        source_tool="custom-patterns", triage_state="reviewing", severity="high", confidence="likely",
        risk_score_min=80, risk_score_max=95, detected_after=now - timedelta(days=1), detected_before=now,
    ))
    assert [finding.id for finding in matches] == [matching_id]
    detail = service.get_detail(matching_id)
    assert detail.finding.id == matching_id
    assert [item.id for item in detail.evidence] == [evidence_id]
    assert [item.id for item in detail.risk_scores] == [risk_id]
