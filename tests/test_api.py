from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from orgscan.api import OrgscanApiService, create_app
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_api_service_returns_summary_and_findings(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'api.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org, _ = storage.get_or_create_organization("example-org")
        repo, _ = storage.get_or_create_repository("example-org/app", organization_id=org.id)
        account, _ = storage.get_or_create_account("alice", organization_id=org.id)
        matching = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="API finding",
                description="Stored for API output",
                severity="high",
                repository_id=repo.id,
                detected_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
        matching = storage.create_finding(
            CanonicalFinding(
                source_tool="semgrep",
                source_name="semgrep",
                category="governance",
                title="Policy finding",
                description="Stored for filtered output",
                severity="low",
                status="triaged",
                repository_id=repo.id,
                detected_at=datetime.now(UTC),
            )
        )
        storage.get_or_create_relationship("organization", str(org.id), "repository", str(repo.id), "owns", confidence="verified")
        storage.get_or_create_relationship("account", str(account.id), "repository", str(repo.id), "contributes_to", confidence="likely")
        session.commit()

    service = OrgscanApiService(database_url)
    health_status, health_payload = service.handle("/health")
    summary_status, summary_payload = service.handle("/summary")
    findings_status, findings_payload = service.handle("/findings?limit=10&severity=high")
    graph_status, graph_payload = service.handle("/relationships/graph?limit=10")
    trends_status, trends_payload = service.handle("/trends/findings?days=7")

    assert health_status == 200
    assert health_payload["status"] == "ok"
    assert summary_status == 200
    assert summary_payload["counts"]["findings"] == 2
    assert summary_payload["source_tool_breakdown"]["custom-patterns"] == 1
    assert summary_payload["relationship_graph"]["edges"]
    assert findings_status == 200
    assert findings_payload["findings"][0]["title"] == "API finding"
    assert len(findings_payload["findings"]) == 1
    assert graph_status == 200
    assert len(graph_payload["edges"]) == 2
    assert trends_status == 200
    assert trends_payload["days"] == 7
    assert trends_payload["trends"]


def test_api_findings_supports_extended_filters(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'api-filters.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    now = datetime.now(UTC)
    with session_factory() as session:
        storage = Storage(session)
        org, _ = storage.get_or_create_organization("example-org")
        domain, _ = storage.get_or_create_domain("example.com", organization_id=org.id)
        repo, _ = storage.get_or_create_repository("example-org/app", organization_id=org.id)
        scan_job = storage.create_scan_job("repository", repo.full_name, "gitleaks", status="completed")
        organization_id = org.id
        domain_id = domain.id
        repository_id = repo.id
        scan_job_id = scan_job.id
        matching = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Matching API finding",
                description="Stored for extended filter output",
                severity="high",
                status="triaged",
                organization_id=organization_id,
                domain_id=domain_id,
                repository_id=repository_id,
                scan_job_id=scan_job_id,
                risk_score=87,
                detected_at=now - timedelta(hours=1),
            )
        )
        storage.update_finding_triage(matching.id, triage_state="reviewing")
        storage.create_finding(
            CanonicalFinding(
                source_tool="semgrep",
                source_name="semgrep",
                category="governance",
                title="Other API finding",
                description="Should be filtered out",
                severity="low",
                risk_score=10,
                detected_at=now - timedelta(days=2),
            )
        )
        session.commit()

    client = TestClient(create_app(database_url))
    response = client.get(
        "/findings",
        params={
            "source_tool": "gitleaks",
            "triage_state": "reviewing",
            "organization_id": organization_id,
            "domain_id": domain_id,
            "repository_id": repository_id,
            "scan_job_id": scan_job_id,
            "risk_score_min": 80,
            "risk_score_max": 90,
            "detected_after": (now - timedelta(days=1)).isoformat(),
            "detected_before": now.isoformat(),
        },
    )

    assert response.status_code == 200
    findings = response.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["title"] == "Matching API finding"
    assert findings[0]["risk_score"] == 87
    assert findings[0]["organization_id"] == organization_id


def test_fastapi_dashboard_and_json_routes(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'fastapi.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repo, _ = storage.get_or_create_repository("example-org/app")
        storage.create_finding(
            CanonicalFinding(
                source_tool="trufflehog",
                source_name="trufflehog",
                category="secret",
                title="Live dashboard finding",
                description="Exposed via live dashboard",
                severity="critical",
                repository_id=repo.id,
            )
        )
        session.commit()

    client = TestClient(create_app(database_url))

    root = client.get("/", follow_redirects=False)
    dashboard = client.get("/dashboard?severity=critical&limit=5&days=14")
    findings = client.get("/findings?severity=critical")
    summary = client.get("/summary")

    assert root.status_code in {307, 308}
    assert root.headers["location"] == "/dashboard"
    assert dashboard.status_code == 200
    assert "Live filters" in dashboard.text
    assert "Live dashboard finding" in dashboard.text
    assert findings.status_code == 200
    assert findings.json()["findings"][0]["title"] == "Live dashboard finding"
    assert summary.status_code == 200
    assert summary.json()["counts"]["findings"] == 1
