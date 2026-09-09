from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ORGSCAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "orgscan"
    app_env: str = "development"
    log_level: str = "INFO"
    data_dir: Path = Field(default_factory=lambda: Path("./data"))
    database_url: str = "sqlite:///./data/orgscan.db"
    github_api_base_url: str = "https://api.github.com"
    crtsh_base_url: str = "https://crt.sh"
    github_token: str | None = None
    http_timeout_seconds: int = 15
    redis_url: str = "redis://127.0.0.1:6379/0"
    scan_queue_name: str = "orgscan:scans"
    gitleaks_binary: str = "gitleaks"
    detect_secrets_binary: str = "detect-secrets"
    semgrep_binary: str = "semgrep"
    trufflehog_binary: str = "trufflehog"
    yara_binary: str = "yara"
    yara_rules_path: str | None = None
    rg_binary: str = "rg"
    heuristic_terms: str = ""
    internal_hostname_suffixes: str = "corp,internal,local,lan"
    git_history_max_commits: int = 250
    subfinder_binary: str = "subfinder"
    httpx_binary: str = "httpx"
    whois_binary: str = "whois"

    def ensure_data_dir(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir

    def as_dict(self, *, include_secrets: bool = False) -> dict[str, object]:
        payload = self.model_dump()
        payload["data_dir"] = str(self.data_dir)
        if not include_secrets and payload.get("github_token"):
            payload["github_token"] = "<redacted>"
        return payload

    def heuristic_term_list(self) -> list[str]:
        return [value.strip() for value in self.heuristic_terms.split(",") if value.strip()]

    def internal_hostname_suffix_list(self) -> list[str]:
        return [value.strip().lstrip(".") for value in self.internal_hostname_suffixes.split(",") if value.strip()]


def render_env_template(overrides: Mapping[str, object] | None = None) -> str:
    values: dict[str, object] = {
        "ORGSCAN_APP_ENV": "development",
        "ORGSCAN_LOG_LEVEL": "INFO",
        "ORGSCAN_DATA_DIR": "./data",
        "ORGSCAN_DATABASE_URL": "sqlite:///./data/orgscan.db",
        "ORGSCAN_GITHUB_API_BASE_URL": "https://api.github.com",
        "ORGSCAN_CRTSH_BASE_URL": "https://crt.sh",
        "ORGSCAN_GITHUB_TOKEN": "",
        "ORGSCAN_HTTP_TIMEOUT_SECONDS": 15,
        "ORGSCAN_REDIS_URL": "redis://127.0.0.1:6379/0",
        "ORGSCAN_SCAN_QUEUE_NAME": "orgscan:scans",
        "ORGSCAN_GITLEAKS_BINARY": "gitleaks",
        "ORGSCAN_DETECT_SECRETS_BINARY": "detect-secrets",
        "ORGSCAN_SEMGREP_BINARY": "semgrep",
        "ORGSCAN_TRUFFLEHOG_BINARY": "trufflehog",
        "ORGSCAN_YARA_BINARY": "yara",
        "ORGSCAN_YARA_RULES_PATH": "",
        "ORGSCAN_RG_BINARY": "rg",
        "ORGSCAN_HEURISTIC_TERMS": "",
        "ORGSCAN_INTERNAL_HOSTNAME_SUFFIXES": "corp,internal,local,lan",
        "ORGSCAN_GIT_HISTORY_MAX_COMMITS": 250,
        "ORGSCAN_SUBFINDER_BINARY": "subfinder",
        "ORGSCAN_HTTPX_BINARY": "httpx",
        "ORGSCAN_WHOIS_BINARY": "whois",
    }
    if overrides:
        values.update(overrides)

    lines = [
        "# orgscan configuration",
        "# Copy this file to .env and adjust values for your environment.",
        "",
    ]
    for key, value in values.items():
        lines.append(f"{key}={value}")
    lines.append("")
    return "\n".join(lines)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_data_dir()
    return settings
