from pathlib import Path

from orgscan.bootstrap import bootstrap, optional_tool_inventory
from orgscan.config import Settings


def test_bootstrap_verify_only_reports_mode(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'app.db'}")

    result = bootstrap(settings, create_venv=True, install_dev=True, verify_only=True)

    assert result["mode"] == "verify-only"
    assert result["venv_exists"] is False
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
