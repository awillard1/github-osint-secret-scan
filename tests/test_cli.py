from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
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
