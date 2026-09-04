from pathlib import Path

from orgscan.config import Settings


def test_settings_load_from_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ORGSCAN_DATABASE_URL=sqlite:///./tmp-orgscan.db\n"
        "ORGSCAN_LOG_LEVEL=DEBUG\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_file)

    assert settings.database_url == "sqlite:///./tmp-orgscan.db"
    assert settings.log_level == "DEBUG"
