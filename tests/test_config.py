from pathlib import Path

from orgscan.config import Settings, render_env_template


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


def test_settings_redacts_secret_by_default() -> None:
    settings = Settings(github_token="example-secret-token")

    payload = settings.as_dict()

    assert payload["github_token"] == "<redacted>"


def test_render_env_template_lists_tool_binaries() -> None:
    template = render_env_template()

    assert "ORGSCAN_DETECT_SECRETS_BINARY=detect-secrets" in template
    assert "ORGSCAN_SEMGREP_BINARY=semgrep" in template
    assert "ORGSCAN_SUBFINDER_BINARY=subfinder" in template
    assert "ORGSCAN_HTTPX_BINARY=httpx" in template
    assert "ORGSCAN_WHOIS_BINARY=whois" in template
    assert "ORGSCAN_CRTSH_BASE_URL=https://crt.sh" in template
