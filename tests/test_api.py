import io
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from orgscan.api import OrgscanApiService, create_app
from orgscan.db import create_session_factory, init_db
from orgscan.models import ConfidenceLevel, ScanJob, SeverityLevel
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.scanners.base import ScanMatch


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


def test_api_entity_and_risk_endpoints_return_high_signal_views(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'entity-api.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org = storage.create_organization("example-org", display_name="Example Org")
        account = storage.create_account("alice", organization_id=org.id, email="alice@example.com")
        repo = storage.create_repository("example-org/app", organization_id=org.id, owner_account_id=account.id)
        domain = storage.create_domain("example.com", organization_id=org.id)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Verified repo finding",
                description="High signal finding",
                confidence="verified",
                organization_id=org.id,
                repository_id=repo.id,
                domain_id=domain.id,
                account_id=account.id,
                risk_score=96,
            )
        )
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Heuristic repo finding",
                description="Lower signal finding",
                confidence="heuristic",
                organization_id=org.id,
                repository_id=repo.id,
                risk_score=41,
            )
        )
        storage.create_evidence(
            finding.id,
            "gitleaks",
            repository_path="config.py",
            line_start=7,
            line_end=7,
            snippet="<redacted:gitleaks>",
            extracted_indicator="prod...cdef",
        )
        storage.create_risk_score("finding", str(finding.id), 96, finding_id=finding.id, severity="critical", confidence="verified")
        storage.create_domain_exposure(
            domain.id,
            source="crtsh",
            source_name="crtsh",
            result_summary="cert for example.com",
            normalized_hash="domain-exposure-1",
        )
        storage.create_identity_correlation(
            domain.id,
            source="github-metadata",
            relation_type="email-domain-match",
            email="alice@example.com",
            username="alice",
            confidence="verified",
        )
        storage.create_relationship("organization", str(org.id), "repository", str(repo.id), "owns", confidence="verified")
        storage.create_relationship("account", str(account.id), "repository", str(repo.id), "maintains", confidence="verified")
        storage.create_relationship("organization", str(org.id), "domain", str(domain.id), "owns", confidence="verified")
        session.commit()

    client = TestClient(create_app(database_url))

    organizations = client.get("/organizations").json()["organizations"]
    repositories = client.get("/repositories").json()["repositories"]
    domains = client.get("/domains").json()["domains"]
    accounts = client.get("/accounts").json()["accounts"]
    org_detail = client.get(f"/organizations/{org.id}").json()
    repo_detail = client.get(f"/repositories/{repo.id}").json()
    domain_detail = client.get(f"/domains/{domain.id}").json()
    account_detail = client.get(f"/accounts/{account.id}").json()
    finding_detail = client.get(f"/findings/{finding.id}").json()
    finding_evidence = client.get(f"/findings/{finding.id}/evidence").json()
    risk_summary = client.get("/risk-summary?entity_type=repository&min_confidence=likely").json()

    assert organizations[0]["risk_summary"]["finding_count"] == 1
    assert repositories[0]["risk_summary"]["max_risk_score"] == 96.0
    assert domains[0]["name"] == "example.com"
    assert accounts[0]["username"] == "alice"
    assert org_detail["organization"]["name"] == "example-org"
    assert len(org_detail["top_findings"]) == 1
    assert org_detail["top_findings"][0]["title"] == "Verified repo finding"
    assert repo_detail["repository"]["full_name"] == "example-org/app"
    assert repo_detail["risk_summary"]["verified_count"] == 1
    assert domain_detail["exposures"][0]["source"] == "crtsh"
    assert domain_detail["identity_correlations"][0]["username"] == "alice"
    assert account_detail["repositories"][0]["full_name"] == "example-org/app"
    assert finding_detail["finding"]["title"] == "Verified repo finding"
    assert finding_detail["evidence"][0]["repository_path"] == "config.py"
    assert finding_evidence["evidence"][0]["line_start"] == 7
    assert risk_summary["risk_profiles"][0]["entity_name"] == "example-org/app"
    assert risk_summary["risk_profiles"][0]["finding_count"] == 1


def test_api_finding_management_endpoints_and_high_signal_filter(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'finding-management.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repo, _ = storage.get_or_create_repository("example-org/app")
        heuristic = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Heuristic finding",
                description="Lower signal",
                confidence="heuristic",
                repository_id=repo.id,
                risk_score=35,
            )
        )
        likely = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Likely finding",
                description="Higher signal",
                confidence="likely",
                repository_id=repo.id,
                risk_score=88,
            )
        )
        session.commit()

    client = TestClient(create_app(database_url))

    high_signal = client.get("/findings?high_signal_only=true&min_confidence=likely")
    assert high_signal.status_code == 200
    payload = high_signal.json()["findings"]
    assert len(payload) == 1
    assert payload[0]["title"] == "Likely finding"

    triage = client.patch(
        f"/findings/{likely.id}",
        json={
            "status": "triaged",
            "triage_state": "reviewing",
            "triage_owner": "alice",
            "triage_notes": "validated",
        },
    )
    assert triage.status_code == 200
    assert triage.json()["finding"]["triage_owner"] == "alice"

    suppress = client.post(
        f"/findings/{heuristic.id}/suppress",
        json={"reason": "false positive", "owner": "alice", "note": "demo value"},
    )
    assert suppress.status_code == 200
    assert suppress.json()["finding"]["status"] == "suppressed"

    accepted = client.post(
        f"/findings/{likely.id}/accept-risk",
        json={"reason": "known exposure", "owner": "bob", "note": "tracked externally"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["finding"]["status"] == "accepted_risk"

    reopened = client.post(
        f"/findings/{likely.id}/reopen",
        json={"note": "needs another review"},
    )
    assert reopened.status_code == 200
    assert reopened.json()["finding"]["status"] == "open"
    assert reopened.json()["finding"]["triage_state"] == "reopened"

    high_signal_after = client.get("/findings?high_signal_only=true&min_confidence=likely").json()["findings"]
    assert len(high_signal_after) == 1
    assert high_signal_after[0]["title"] == "Likely finding"


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
    dashboard = client.get("/dashboard?severity=critical&limit=5&days=14&high_signal_only=true&min_confidence=likely")
    findings = client.get("/findings?severity=critical")
    summary = client.get("/summary")

    assert root.status_code in {307, 308}
    assert root.headers["location"] == "/dashboard"
    assert dashboard.status_code == 200
    assert "Live filters" in dashboard.text
    assert "Artifact upload analysis" in dashboard.text
    assert "High signal only" in dashboard.text
    assert "Live dashboard finding" in dashboard.text
    assert findings.status_code == 200
    assert findings.json()["findings"][0]["title"] == "Live dashboard finding"
    assert summary.status_code == 200
    assert summary.json()["counts"]["findings"] == 1


def test_dashboard_artifact_upload_returns_html_result(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'dashboard-artifact.db'}"
    client = TestClient(create_app(database_url))

    response = client.post(
        "/dashboard/artifact-scans",
        data={"organization": "example-org", "repository": "example-org/app"},
        files={"artifact": ("credentials.env", b'token = "prod-super-secret-1234567890"\n', "text/plain")},
    )

    assert response.status_code == 200
    assert "Artifact scan completed." in response.text
    assert "credentials.env" in response.text
    assert "Recent scan activity" in response.text


def test_dashboard_finding_and_scan_job_detail_pages(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'dashboard-detail.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repo, _ = storage.get_or_create_repository("example-org/app")
        scan_job = storage.create_scan_job("artifact", "bundle.zip", "custom-patterns", status="completed")
        tool_run = storage.create_tool_run(
            "custom-patterns",
            "bundle.zip",
            scan_job_id=scan_job.id,
            status="completed",
            stdout_log="findings=1",
            stderr_log="",
        )
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Detailed finding",
                description="Detail view coverage",
                repository_id=repo.id,
                scan_job_id=scan_job.id,
                risk_score=73,
            )
        )
        storage.create_evidence(
            finding.id,
            "custom-patterns",
            repository_path="nested/secrets.txt",
            line_start=4,
            line_end=4,
            snippet="<redacted:custom-patterns>",
            extracted_indicator="prod...7890",
        )
        storage.create_risk_score("finding", str(finding.id), 73, finding_id=finding.id, severity="high", confidence="likely")
        session.commit()

    client = TestClient(create_app(database_url))
    finding_response = client.get(f"/dashboard/findings/{finding.id}")
    scan_job_response = client.get(f"/dashboard/scan-jobs/{scan_job.id}")

    assert finding_response.status_code == 200
    assert "Detailed finding" in finding_response.text
    assert "Evidence" in finding_response.text
    assert scan_job_response.status_code == 200
    assert "Scan job" in scan_job_response.text
    assert "findings=1" in scan_job_response.text
    assert "Detailed finding" in scan_job_response.text


def test_dashboard_graph_view_renders_relationships(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'graph-view.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org = storage.create_organization("example-org")
        repo = storage.create_repository("example-org/app", organization_id=org.id)
        storage.create_relationship("organization", str(org.id), "repository", str(repo.id), "owns", confidence="verified")
        session.commit()

    client = TestClient(create_app(database_url))
    response = client.get("/dashboard/graph")

    assert response.status_code == 200
    assert "Relationship graph" in response.text
    assert "organization" in response.text
    assert "owns" in response.text


def test_dashboard_artifact_upload_returns_html_error(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'dashboard-artifact-error.db'}"
    client = TestClient(create_app(database_url))

    response = client.post(
        "/dashboard/artifact-scans",
        files={"artifact": ("bundle.zip", b"not-a-valid-zip", "application/zip")},
    )

    assert response.status_code == 400
    assert "Artifact scan failed." in response.text
    assert "Invalid uploaded archive" in response.text


def test_dashboard_finding_workflow_updates_state(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'dashboard-finding-workflow.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repo, _ = storage.get_or_create_repository("example-org/app")
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Dashboard workflow finding",
                description="Needs analyst action",
                repository_id=repo.id,
            )
        )
        session.commit()

    client = TestClient(create_app(database_url))
    response = client.post(
        f"/dashboard/findings/{finding.id}/workflow",
        data={"action": "suppress", "owner": "alice", "note": "confirmed false positive", "high_signal_only": "false"},
    )

    assert response.status_code == 200
    assert "Finding workflow updated." in response.text
    assert "suppressed" in response.text

    with session_factory() as session:
        stored = Storage(session).get_finding(finding.id)
        assert stored is not None
        assert stored.status == "suppressed"
        assert stored.triage_owner == "alice"


def test_api_artifact_upload_supports_external_scanner_selection(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'artifact-external.db'}"

    class FakeExternalScanner:
        name = "gitleaks"
        source_class = "free"

        def scan_path(self, target: Path) -> list[ScanMatch]:
            return [
                ScanMatch(
                    path=target / "results.txt" if target.is_dir() else target,
                    line_start=1,
                    line_end=1,
                    category="secret",
                    title="Gitleaks: fake-rule",
                    description="Fake external result",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.LIKELY,
                    indicator="prod...7890",
                    snippet="<redacted:gitleaks>",
                )
            ]

    monkeypatch.setattr("orgscan.runner.get_scanner", lambda name, settings=None: FakeExternalScanner())
    client = TestClient(create_app(database_url))

    response = client.post(
        "/artifact-scans",
        data={"scanner": "gitleaks"},
        files={"artifact": ("credentials.env", b'token = "prod-super-secret-1234567890"\n', "text/plain")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scanner"] == "gitleaks"
    assert payload["findings"] == 1


def test_api_artifact_upload_scans_text_file(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'artifact.db'}"
    client = TestClient(create_app(database_url))

    response = client.post(
        "/artifact-scans",
        data={"organization": "example-org", "repository": "example-org/app"},
        files={"artifact": ("credentials.env", b'password = "prod-super-secret-1234567890"\n', "text/plain")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scanner"] == "custom-patterns"
    assert payload["extracted"] is False
    assert payload["findings"] == 1

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        stored = Storage(session).list_findings(limit=10)
        assert len(stored) == 1
        assert stored[0].repository_id is not None
        assert stored[0].organization_id is not None
        scan_job = session.get(ScanJob, payload["scan_job_id"])
        assert scan_job is not None
        assert scan_job.target_type == "artifact"
        assert scan_job.target_id == "credentials.env"
        assert scan_job.parameters_json["artifact_kind"] == "file"


def test_api_artifact_upload_scans_zip_archive(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'artifact-zip.db'}"
    client = TestClient(create_app(database_url))
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("nested/secrets.txt", 'token = "prod-real-token-1234567890"\n')
        zipped.writestr("nested/example.txt", 'password = "example-not-real-password"\n')

    response = client.post(
        "/artifact-scans",
        files={"artifact": ("bundle.zip", archive.getvalue(), "application/zip")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["extracted"] is True
    assert payload["findings"] == 1


def test_api_artifact_upload_rejects_invalid_archive(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'artifact-invalid.db'}"
    client = TestClient(create_app(database_url))

    response = client.post(
        "/artifact-scans",
        files={"artifact": ("bundle.zip", b"not-a-valid-zip", "application/zip")},
    )

    assert response.status_code == 400
    assert "Invalid uploaded archive" in response.json()["detail"]
