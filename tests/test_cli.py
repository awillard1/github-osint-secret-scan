from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.discovery import GitHubAccountRecord, GitHubRepositoryRecord
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding

runner = CliRunner()


def test_cli_init_db_and_status(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    init_result = runner.invoke(app, ["init-db"])
    assert init_result.exit_code == 0
    assert "Initialized database" in init_result.stdout

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert f"database_url: {database_url}" in status_result.stdout
    assert "organizations: 0" in status_result.stdout

    setup_result = runner.invoke(app, ["setup", "--verify-only"])
    assert setup_result.exit_code == 0
    assert "next_steps:" in setup_result.stdout

    get_settings.cache_clear()


def test_cli_add_target_and_findings(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase2.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    add_org_result = runner.invoke(app, ["add-target", "organization", "example-org"])
    assert add_org_result.exit_code == 0
    assert "Created organization" in add_org_result.stdout

    add_domain_result = runner.invoke(
        app,
        ["add-target", "domain", "example.com", "--organization", "example-org"],
    )
    assert add_domain_result.exit_code == 0
    assert "Created domain" in add_domain_result.stdout

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org = storage.get_organization_by_name("example-org")
        domain = storage.get_domain_by_name("example.com")
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-regex",
                source_name="custom-regex",
                source_class="internal",
                category="domain-exposure",
                title="Public domain reference",
                description="The domain was referenced in a public artifact.",
                organization_id=org.id if org else None,
                domain_id=domain.id if domain else None,
            )
        )
        session.commit()

    findings_result = runner.invoke(app, ["findings"])
    assert findings_result.exit_code == 0
    assert "Public domain reference" in findings_result.stdout

    filtered_result = runner.invoke(app, ["findings", "--category", "domain-exposure", "--json"])
    assert filtered_result.exit_code == 0
    assert "Public domain reference" in filtered_result.stdout

    get_settings.cache_clear()


def test_cli_verify_deps_json(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'verify.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "orgscan.cli.bootstrap",
        lambda settings, **kwargs: {
            "required": {"git": True, "curl": True, "openssl": True},
            "optional": {},
            "platform": "test",
            "package_manager": "apt",
            "recommended_install": "sudo apt install -y git curl openssl",
            "optional_install_notes": {},
            "venv_path": ".venv",
            "venv_exists": False,
            "install_returncode": None,
            "mode": "verify-only",
            "database_url": settings.database_url,
            "data_dir": str(settings.data_dir),
            "next_steps": ["Install deps"],
        },
    )
    get_settings.cache_clear()

    result = runner.invoke(app, ["verify-deps", "--json"])
    assert result.exit_code == 0
    assert '"ok": true' in result.stdout

    get_settings.cache_clear()


def test_cli_scan_persists_findings(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scan.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "config.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "path",
            str(sample),
            "--organization",
            "example-org",
            "--repository",
            "example-org/app",
        ],
    )
    assert result.exit_code == 0
    assert "Completed scan job" in result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert "Possible hardcoded secret assignment" in findings_result.stdout

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert "scan_jobs: 1" in status_result.stdout
    assert "findings: 1" in status_result.stdout
    assert "evidence: 1" in status_result.stdout

    get_settings.cache_clear()


def test_cli_discover_report_export_and_dashboard(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'discover.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository",
        lambda self, full_name: GitHubRepositoryRecord(
            full_name=full_name,
            html_url=f"https://github.com/{full_name}",
            default_branch="main",
            private=False,
            owner_login="example-org",
            owner_type="Organization",
            description="Example repository",
        ),
    )
    get_settings.cache_clear()

    discover_result = runner.invoke(app, ["discover", "repository", "example-org/example-repo", "--json"])
    assert discover_result.exit_code == 0
    assert "example-org/example-repo" in discover_result.stdout

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repository = storage.get_repository_by_full_name("example-org/example-repo")
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Discovered secret",
                description="Example finding for export",
                repository_id=repository.id if repository else None,
            )
        )
        session.commit()

    report_result = runner.invoke(app, ["report"])
    assert report_result.exit_code == 0
    assert "orgscan summary" in report_result.stdout
    assert "repositories: 1" in report_result.stdout

    json_export = tmp_path / "findings.json"
    export_result = runner.invoke(app, ["export", str(json_export), "--format", "json"])
    assert export_result.exit_code == 0
    assert json_export.exists()
    assert "Discovered secret" in json_export.read_text(encoding="utf-8")

    dashboard_path = tmp_path / "dashboard.html"
    dashboard_result = runner.invoke(app, ["dashboard", str(dashboard_path)])
    assert dashboard_result.exit_code == 0
    assert dashboard_path.exists()
    assert "orgscan dashboard" in dashboard_path.read_text(encoding="utf-8")

    domain_result = runner.invoke(app, ["discover", "domain", "example.org", "--json"])
    assert domain_result.exit_code == 0
    assert "domain_exposures" in domain_result.stdout

    get_settings.cache_clear()


def test_cli_expand_schedule_and_jobs(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'ops.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository_contributors",
        lambda self, full_name, limit=20: [
            GitHubAccountRecord(login="alice", account_type="User", html_url="https://github.com/alice")
        ],
    )
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository_forks",
        lambda self, full_name, limit=20: [
            GitHubRepositoryRecord(
                full_name="alice/example-repo-fork",
                html_url="https://github.com/alice/example-repo-fork",
                default_branch="main",
                private=False,
                owner_login="alice",
                owner_type="User",
                description="Fork",
            )
        ],
    )
    get_settings.cache_clear()

    expand_result = runner.invoke(app, ["expand", "repository", "example/example-repo", "--json"])
    assert expand_result.exit_code == 0
    assert "alice/example-repo-fork" in expand_result.stdout

    schedule_result = runner.invoke(
        app,
        ["schedule-scan", str(sample), "--repository", "example/example-repo", "--cadence", "manual"],
    )
    assert schedule_result.exit_code == 0
    assert "Scheduled scan" in schedule_result.stdout

    run_result = runner.invoke(app, ["run-scheduled", "--json"])
    assert run_result.exit_code == 0
    assert '"findings": 1' in run_result.stdout

    jobs_result = runner.invoke(app, ["jobs", "--json"])
    assert jobs_result.exit_code == 0
    assert "tool_runs" in jobs_result.stdout
    assert "scheduled_scans" in jobs_result.stdout

    get_settings.cache_clear()


def test_cli_scan_reports_missing_external_scanner(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'missing-scanner.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "config.py"
    sample.write_text('token = "example-not-real-123456789"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", "path", str(sample), "--scanner", "gitleaks"])
    assert result.exit_code == 1
    assert "Scan failed: gitleaks is not installed" in result.stderr

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert "scan_jobs: 1" in status_result.stdout
    assert "findings: 0" in status_result.stdout

    get_settings.cache_clear()


def test_cli_triage_updates_finding(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'triage.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    init_db(database_url)

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Needs triage",
                description="Pending review",
            )
        )
        session.commit()

    result = runner.invoke(
        app,
        [
            "triage",
            str(finding.id),
            "--status",
            "triaged",
            "--triage-state",
            "reviewing",
            "--owner",
            "alice",
            "--note",
            "validated",
            "--due-date",
            "2026-09-30",
        ],
    )
    assert result.exit_code == 0
    assert "Updated finding" in result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert '"triage_owner": "alice"' in findings_result.stdout
    assert '"remediation_due_date": "2026-09-30"' in findings_result.stdout

    get_settings.cache_clear()


def test_cli_suppress_and_accept_risk(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'suppress.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    init_db(database_url)

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Needs decision",
                description="Pending suppression",
            )
        )
        session.commit()

    suppress_result = runner.invoke(app, ["suppress", str(finding.id), "--reason", "false positive"])
    assert suppress_result.exit_code == 0
    assert "Suppressed finding" in suppress_result.stdout

    accept_result = runner.invoke(
        app,
        ["accept-risk", str(finding.id), "--reason", "documented compensating controls", "--owner", "alice"],
    )
    assert accept_result.exit_code == 0
    assert "Accepted risk" in accept_result.stdout

    reopen_result = runner.invoke(app, ["unsuppress", str(finding.id), "--note", "needs follow-up"])
    assert reopen_result.exit_code == 0
    assert "Reopened finding" in reopen_result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert '"status": "open"' in findings_result.stdout
    assert '"triage_state": "reopened"' in findings_result.stdout

    get_settings.cache_clear()
