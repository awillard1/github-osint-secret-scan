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
        domain, _ = storage.get_or_create_domain("example.org", organization_id=org.id)
        repo, _ = storage.get_or_create_repository("example-org/app", organization_id=org.id)
        account, _ = storage.get_or_create_account("alice", organization_id=org.id)
        storage.create_finding(
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
        storage.create_finding(
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
        storage.create_domain_exposure(
            domain.id,
            source="hibp",
            source_name="hibp",
            source_class="paid",
            result_summary="HIBP breach linked to example.org: Example",
            normalized_hash="hibp-example",
            confidence="likely",
            severity="medium",
        )
        session.commit()

    service = OrgscanApiService(database_url)
    health_status, health_payload = service.handle("/health")
    summary_status, summary_payload = service.handle("/summary")
    findings_status, findings_payload = service.handle("/findings?limit=10&severity=high")
    exposures_status, exposures_payload = service.handle("/domain-exposures?source_name=hibp&source_class=paid")
    graph_status, graph_payload = service.handle("/relationships/graph?limit=10")
    trends_status, trends_payload = service.handle("/trends/findings?days=7")
    comparison_status, comparison_payload = service.handle("/comparisons/organizations")
    remediation_status, remediation_payload = service.handle("/remediation/suggestions")

    assert health_status == 200
    assert health_payload["status"] == "ok"
    assert summary_status == 200
    assert summary_payload["counts"]["findings"] == 2
    assert summary_payload["source_tool_breakdown"]["custom-patterns"] == 1
    assert summary_payload["relationship_graph"]["edges"]
    assert findings_status == 200
    assert findings_payload["findings"][0]["title"] == "API finding"
    assert len(findings_payload["findings"]) == 1
    assert exposures_status == 200
    assert exposures_payload["provider_summary"]["hibp"] == 1
    assert graph_status == 200
    assert len(graph_payload["edges"]) == 2
    assert graph_payload["summary"]["node_count"] == 3
    assert trends_status == 200
    assert trends_payload["days"] == 7
    assert trends_payload["trends"]
    assert comparison_status == 200
    assert comparison_payload["organizations"]
    assert remediation_status == 200
    assert remediation_payload["suggestions"]


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
    exposures = client.get("/domain-exposures?limit=10")
    comparisons = client.get("/comparisons/organizations")
    remediation = client.get("/remediation/suggestions")

    assert root.status_code in {307, 308}
    assert root.headers["location"] == "/dashboard"
    assert dashboard.status_code == 200
    assert "Live filters" in dashboard.text
    assert "Client-side trend chart" in dashboard.text
    assert "Relationship graph explorer" in dashboard.text
    assert "Automatic remediation suggestions" in dashboard.text
    assert "Live dashboard finding" in dashboard.text
    assert findings.status_code == 200
    assert findings.json()["findings"][0]["title"] == "Live dashboard finding"
    assert summary.status_code == 200
    assert summary.json()["counts"]["findings"] == 1
    assert exposures.status_code == 200
    assert "provider_summary" in exposures.json()
    assert comparisons.status_code == 200
    assert "organizations" in comparisons.json()
    assert remediation.status_code == 200
    assert "suggestions" in remediation.json()
