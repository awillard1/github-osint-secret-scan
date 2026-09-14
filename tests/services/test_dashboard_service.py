from datetime import UTC, datetime, timedelta

from sqlalchemy import event

from orgscan.db import init_db, create_session_factory
from orgscan.lifecycle import is_actionable_high_risk
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.services.dashboard_service import DashboardService
from orgscan.security_context import AuthContext, current_auth
from orgscan.storage.authorization import authorized_session_factory


def test_operator_queues_counts_sorting_and_window(tmp_path):
    url = f"sqlite:///{tmp_path / 'dashboard.db'}"
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        for index in range(12):
            storage.create_finding(CanonicalFinding(source_tool="fixture", category="secret", title=f"Item {index}", description="safe", risk_score=70+index))
        old = storage.create_finding(CanonicalFinding(source_tool="fixture", category="secret", title="Old managed", description="safe", status="resolved", risk_score=100))
        old.first_seen_at = datetime.now(UTC) - timedelta(days=30)
        storage.create_scan_job('path','example','fixture',status='running')
        storage.create_scan_job('path','example','fixture',status='failed')
        storage.create_repository('new/repository')
        session.commit()
    result = DashboardService(factory).overview(limit=2)
    queues = result['queues']
    assert queues['new']['count'] == 12
    assert queues['high-risk']['count'] == 12
    assert [r['risk_score'] for r in queues['high-risk']['items']] == [81,80]
    assert queues['triage']['count'] == 12
    assert queues['regressions']['count'] == 0
    assert queues['active-scans']['count'] == queues['failed-scans']['count'] == 1
    assert queues['new-assets']['count'] == 1
    assert DashboardService(factory).overview(limit=2,offset=2)['queues']['high-risk']['items'][0]['risk_score'] == 79


def test_queue_pagination_is_bounded_and_stable(tmp_path):
    url = f"sqlite:///{tmp_path / 'pages.db'}"
    init_db(url)
    factory = create_session_factory(url)
    observed = datetime.now(UTC) - timedelta(hours=1)
    with factory() as session:
        storage = Storage(session)
        for index in range(30):
            finding = storage.create_finding(CanonicalFinding(
                source_tool="fixture", category="secret", title=f"Finding {index}",
                description="safe", risk_score=90))
            finding.detected_at = observed
            for status in ("running", "failed"):
                storage.create_scan_job("path", str(index), "fixture", status=status, created_at=observed)
            for create, name in ((storage.create_organization, f"Org {index}"),
                                 (storage.create_repository, f"org/repo-{index}"),
                                 (storage.create_domain, f"domain-{index}.example"),
                                 (storage.create_account, f"account-{index}")):
                create(name, created_at=observed)
        session.commit()

    loaded = []

    def measured_factory():
        session = factory()
        event.listen(session, "loaded_as_persistent", lambda session, record: loaded.append(record))
        return session

    service = DashboardService(measured_factory)
    first = service.overview(limit=3)["queues"]
    # Four finding queues and two job queues can each load at most one page.
    # Asset rows are projected directly, with no ORM entity materialization.
    assert len(loaded) <= 6 * 3
    assert first["new-assets"]["count"] == 120
    assert first["new"]["count"] == first["active-scans"]["count"] == 30
    second = service.overview(limit=3, offset=3)["queues"]
    for name in first:
        assert first[name]["count"] == second[name]["count"]
        assert not ({row["href"] for row in first[name]["items"]}
                    & {row["href"] for row in second[name]["items"]})
    assert service.overview(limit=3)["queues"] == first
    assert all(not queue["items"] for queue in service.overview(offset=1000)["queues"].values())


def test_sql_high_risk_queue_matches_lifecycle_policy(tmp_path):
    url = f"sqlite:///{tmp_path / 'policy.db'}"
    init_db(url)
    factory = create_session_factory(url)
    expected = set()
    with factory() as session:
        storage = Storage(session)
        for state in ("NEW", "REVIEWING", "CONFIRMED", "REGRESSED", "REMEDIATED",
                      "SUPPRESSED", "ACCEPTED_RISK", "FALSE_POSITIVE"):
            for risk in (None, 0, 69.9, 70, 100):
                finding = storage.create_finding(CanonicalFinding(
                    source_tool="fixture", category="secret", title=f"{state} {risk}", description="safe"))
                finding.lifecycle_state = state
                finding.risk_score = risk
                if is_actionable_high_risk(finding):
                    expected.add(finding.id)
        session.commit()
    queue = DashboardService(factory).overview(limit=500)["queues"]["high-risk"]
    assert queue["count"] == len(expected)
    assert {row["id"] for row in queue["items"]} == expected


def test_all_queue_counts_and_union_pages_enforce_tenants(tmp_path):
    url = f"sqlite:///{tmp_path / 'tenants.db'}"
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        for tenant in ("a", "b"):
            org = storage.create_organization(tenant, tenant_key=tenant)
            storage.create_repository(f"{tenant}/repo", organization_id=org.id)
            storage.create_domain(f"{tenant}.example", organization_id=org.id)
            storage.create_account(f"{tenant}-account", organization_id=org.id)
            finding = storage.create_finding(CanonicalFinding(
                source_tool="fixture", category="secret", title=tenant, description="safe",
                organization_id=org.id, risk_score=90))
            finding.lifecycle_state = "REGRESSED"
            for status in ("running", "failed"):
                storage.create_scan_job("organization", str(org.id), tenant, status=status)
        session.commit()
    service = DashboardService(authorized_session_factory(factory))
    for tenant in ("a", "b", "missing", "a"):
        token = current_auth.set(AuthContext("reader", "reader", (tenant,), True))
        try:
            queues = service.overview(limit=1)["queues"]
            exists = tenant != "missing"
            for name, queue in queues.items():
                assert queue["count"] == (4 if name == "new-assets" else 1) * exists
                assert all(row["label"].startswith(tenant) for row in queue["items"])
            assets = [service.overview(limit=1, offset=offset)["queues"]["new-assets"]
                      for offset in range(5)]
            assert all(page["count"] == 4 * exists for page in assets)
            assert len({row["href"] for page in assets for row in page["items"]}) == 4 * exists
        finally:
            current_auth.reset(token)
