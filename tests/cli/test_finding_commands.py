import pytest
from typer.testing import CliRunner

from orgscan.cli import app, main, triage
from orgscan.cli.commands.findings import triage as extracted_triage
from orgscan.config import get_settings


@pytest.fixture
def cli(monkeypatch, tmp_path):
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", f"sqlite:///{tmp_path / 'commands.db'}")
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    yield CliRunner()
    get_settings.cache_clear()


@pytest.mark.parametrize("args", [
    ["triage", "999", "--status", "triaged"],
    ["suppress", "999", "--reason", "Review"],
    ["accept-risk", "999", "--reason", "Review"],
    ["unsuppress", "999"],
])
def test_missing_finding_commands_preserve_usage_error(cli, args):
    result = cli.invoke(app, args)
    assert result.exit_code == 2
    assert "Finding 999 does not exist" in result.stderr


def test_finding_command_validation_and_compatibility_exports(cli):
    assert triage is extracted_triage
    assert callable(main)
    result = cli.invoke(app, ["triage", "999", "--status", "triaged", "--due-date", "not-a-date"])
    assert result.exit_code == 2
    assert "Due dates must use YYYY-MM-DD format." in result.stderr
    result = cli.invoke(app, ["findings", "--detected-after", "not-a-date"])
    assert result.exit_code == 2
    assert "--detected-after must use ISO 8601 datetime format." in result.stderr
