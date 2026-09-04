from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings

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
