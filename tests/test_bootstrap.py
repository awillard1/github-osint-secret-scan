from pathlib import Path

from orgscan.bootstrap import bootstrap
from orgscan.config import Settings


def test_bootstrap_verify_only_reports_mode(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'app.db'}")

    result = bootstrap(settings, create_venv=True, install_dev=True, verify_only=True)

    assert result["mode"] == "verify-only"
    assert result["venv_exists"] is False
    assert result["install_returncode"] is None
    assert result["next_steps"]
