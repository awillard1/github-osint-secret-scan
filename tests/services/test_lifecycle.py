from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import inspect

from orgscan.db import init_db, create_session_factory, create_engine_from_url, _alembic_config
from orgscan.lifecycle import LifecycleState, validate_transition
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.services.finding_service import FindingService, FindingQuery, TriageUpdate
from orgscan.reporting import build_summary, finding_rows


@pytest.fixture
def factory(tmp_path):
    url = f"sqlite:///{tmp_path / 'lifecycle.db'}"
    init_db(url)
    return create_session_factory(url)


def observation(job_id=None):
    return CanonicalFinding(source_tool="fixture", category="secret", title="Redacted exposure",
                            description="Safe fixture", scan_job_id=job_id)


def test_transitions_audit_and_compatibility(factory):
    with factory() as session:
        row = Storage(session).create_finding(observation())
        session.commit()
        identity = row.id
    service = FindingService(factory)
    service.update_triage(identity, TriageUpdate(triage_owner="Alice", triage_notes="Keep me"))
    for state in ("REVIEWING", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "SUPPRESSED", "REMEDIATED"):
        service.update_triage(identity, TriageUpdate(lifecycle_state=state))
    detail = service.get_detail(identity)
    assert detail.finding.status == "resolved"
    assert detail.finding.remediated_at
    assert detail.finding.triage_notes == "Keep me"
    assert len(detail.history) == 8
    assert detail.history[-1].metadata_json["before"]["lifecycle_state"] == "SUPPRESSED"
    service.update_triage(identity, TriageUpdate(lifecycle_state="REMEDIATED"))
    assert len(service.get_detail(identity).history) == 8
    for invalid in ("NEW", "REGRESSED", "unknown"):
        with pytest.raises(ValueError):
            service.update_triage(identity, TriageUpdate(lifecycle_state=invalid))
    with pytest.raises(ValueError, match="conflicts"):
        service.update_triage(identity, TriageUpdate(lifecycle_state="CONFIRMED", status="resolved"))
    assert service.list_findings(FindingQuery(lifecycle_state="REMEDIATED"))[0].id == identity
    with factory() as session:
        assert build_summary(Storage(session))["lifecycle_breakdown"] == {"REMEDIATED": 1}
        assert finding_rows(Storage(session))[0]["remediated_at"]
    reopened = service.reopen(identity)
    assert (reopened.status, reopened.triage_state, reopened.lifecycle_state) == ("open", "reopened", "REVIEWING")
    assert reopened.triage_owner == "Alice"


def test_regression_requires_later_scan_and_is_idempotent(factory):
    with factory() as session:
        storage = Storage(session)
        old = storage.create_scan_job(target_type="path", target_id="fixture", scanner_name="fixture")
        old.started_at = datetime.now(UTC) - timedelta(days=1)
        row = storage.create_finding(observation(old.id))
        identity, old_id = row.id, old.id
        session.commit()
    service = FindingService(factory)
    service.update_triage(identity, TriageUpdate(status="resolved", triage_notes="Rotated", triage_owner="Alice"))
    with factory() as session:
        storage = Storage(session)
        assert storage.create_finding(observation(old_id)).lifecycle_state == "REMEDIATED"
        assert storage.create_finding(observation()).lifecycle_state == "REMEDIATED"
        later = storage.create_scan_job(target_type="path", target_id="fixture", scanner_name="fixture")
        later.started_at = datetime.now(UTC) + timedelta(seconds=1)
        row = storage.create_finding(observation(later.id))
        assert row.lifecycle_state == "REGRESSED"
        assert row.status == "open" and row.triage_state == "reopened"
        assert row.triage_owner == "Alice" and row.triage_notes == "Rotated"
        assert row.regression_count == 1
        storage.create_finding(observation(later.id))
        session.commit()
    detail = service.get_detail(identity)
    assert len(detail.history) == 3
    assert detail.history[-1].actor == "scanner"
    assert detail.history[-1].scan_job_id == later.id
    assert detail.finding.regressed_at >= detail.finding.remediated_at


def test_state_policy_rejects_manual_regression():
    for state in LifecycleState:
        assert validate_transition(state, state) == state
    with pytest.raises(ValueError):
        validate_transition("CONFIRMED", "REGRESSED", automatic=True)


def test_populated_lifecycle_upgrade(tmp_path):
    url = f"sqlite:///{tmp_path / 'legacy.db'}"
    command.upgrade(_alembic_config(url), "20260915_0015")
    factory = create_session_factory(url)
    with factory() as session:
        row = Storage(session).create_finding(observation())
        Storage(session).update_finding_triage(row.id, status="resolved", triage_notes="Rotated", triage_owner="Alice")
        session.commit()
    command.downgrade(_alembic_config(url), "20260911_0006")
    assert "lifecycle_state" not in {c['name'] for c in inspect(create_engine_from_url(url)).get_columns("findings")}
    init_db(url)
    detail = FindingService(factory).get_detail(row.id)
    assert detail.finding.lifecycle_state == "REMEDIATED"
    assert detail.finding.triage_notes == "Rotated"
    assert detail.finding.triage_owner == "Alice"
    assert detail.finding.remediated_at
    assert detail.history[0].metadata_json["timestamp_inferred"]
