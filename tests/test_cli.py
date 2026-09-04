from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.discovery import GitHubRepositoryRecord
from orgscan.db import create_session_factory
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

    get_settings.cache_clear()


def test_cli_verify_deps_json(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'verify.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "orgscan.cli.bootstrap",
        lambda settings: {
            "required": {"git": True, "curl": True, "openssl": True},
            "optional": {},
            "platform": "test",
            "package_manager": "apt",
            "recommended_install": "sudo apt install -y git curl openssl",
            "optional_install_notes": {},
            "venv_path": ".venv",
            "install_returncode": None,
            "database_url": settings.database_url,
            "data_dir": str(settings.data_dir),
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
