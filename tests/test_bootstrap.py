from pathlib import Path
from types import SimpleNamespace

import pytest

from orgscan.bootstrap import bootstrap, optional_tool_inventory
from orgscan.config import Settings


@pytest.mark.parametrize("venv_exists", [False, True])
def test_bootstrap_verify_only_reports_mode(monkeypatch, tmp_path: Path, venv_exists: bool) -> None:
    # Bootstrap derives its checkout root from __file__, not the working directory.
    monkeypatch.setattr("orgscan.bootstrap.__file__", str(tmp_path / "src" / "orgscan" / "bootstrap.py"))
    if venv_exists:
        (tmp_path / ".venv").mkdir()

    def unexpected_install(*args, **kwargs):
        pytest.fail("verify-only must not create a venv or install dependencies")

    monkeypatch.setattr("orgscan.bootstrap.venv.EnvBuilder.create", unexpected_install)
    monkeypatch.setattr("orgscan.bootstrap.subprocess", SimpleNamespace(run=unexpected_install))
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'app.db'}")

    result = bootstrap(settings, create_venv=True, install_dev=True, verify_only=True)

    assert result["mode"] == "verify-only"
    assert result["venv_path"] == str(tmp_path / ".venv")
    assert result["venv_exists"] is venv_exists
    assert (tmp_path / ".venv").exists() is venv_exists
    assert result["install_returncode"] is None
    assert result["next_steps"]


def test_optional_tool_inventory_reports_configured_commands(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        database_url=f"sqlite:///{tmp_path / 'app.db'}",
        gitleaks_binary="/opt/tools/gitleaks",
    )

    inventory = optional_tool_inventory(settings)

    gitleaks = next(item for item in inventory if item["name"] == "gitleaks")
    assert gitleaks["configured_command"] == "/opt/tools/gitleaks"
    assert gitleaks["env_var"] == "ORGSCAN_GITLEAKS_BINARY"
    assert gitleaks["category"] == "scanner"

    result = bootstrap(settings, verify_only=True)
    assert "yara" in result["optional"]
    assert "rg" in result["optional"]
