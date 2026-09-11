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
    outbound_requests_per_minute: int = 0
    outbound_min_interval_seconds: float = 0.0
    rate_limit_backend: str = "db"
    rate_limit_scope_overrides_json: str = ""
    rate_limit_poll_interval_seconds: float = 1.0
    redis_url: str = "redis://127.0.0.1:6379/0"
    scan_queue_backend: str = "rq"
    scan_queue_name: str = "orgscan:scans"
    scan_queue_retry_max: int = 2
    scan_queue_retry_intervals: str = "30,120"
    scan_queue_lease_seconds: int = 300
    scan_queue_poll_interval_seconds: float = 5.0
    scan_queue_worker_id: str | None = None
    api_tokens_json: str = ""
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"
    hibp_api_key: str | None = None
    dehashed_base_url: str = "https://api.dehashed.com/search"
    dehashed_email: str | None = None
    dehashed_api_key: str | None = None
    intelligencex_base_url: str = "https://2.intelx.io"
    intelligencex_api_key: str | None = None
    gitleaks_binary: str = "gitleaks"
    scanner_timeout_seconds: float = Field(default=300, gt=0, allow_inf_nan=False)
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

    def mirror_base_dir(self) -> Path:
        return self.ensure_data_dir() / "mirrors"

    def as_dict(self, *, include_secrets: bool = False) -> dict[str, object]:
        payload = self.model_dump()
        payload["data_dir"] = str(self.data_dir)
        if not include_secrets:
            for secret_field in (
                "github_token",
                "hibp_api_key",
                "dehashed_api_key",
                "intelligencex_api_key",
                "dehashed_email",
                "api_tokens_json",
            ):
                if payload.get(secret_field):
                    payload[secret_field] = "<redacted>"
        return payload

    def heuristic_term_list(self) -> list[str]:
        return [value.strip() for value in self.heuristic_terms.split(",") if value.strip()]

    def internal_hostname_suffix_list(self) -> list[str]:
        return [value.strip().lstrip(".") for value in self.internal_hostname_suffixes.split(",") if value.strip()]

    def scan_queue_retry_interval_list(self) -> list[int]:
        return [int(value.strip()) for value in self.scan_queue_retry_intervals.split(",") if value.strip()]


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
        "ORGSCAN_OUTBOUND_REQUESTS_PER_MINUTE": 0,
        "ORGSCAN_OUTBOUND_MIN_INTERVAL_SECONDS": 0,
        "ORGSCAN_RATE_LIMIT_BACKEND": "db",
        "ORGSCAN_RATE_LIMIT_SCOPE_OVERRIDES_JSON": "",
        "ORGSCAN_RATE_LIMIT_POLL_INTERVAL_SECONDS": 1,
        "ORGSCAN_REDIS_URL": "redis://127.0.0.1:6379/0",
        "ORGSCAN_SCAN_QUEUE_BACKEND": "rq",
        "ORGSCAN_SCAN_QUEUE_NAME": "orgscan:scans",
        "ORGSCAN_SCAN_QUEUE_RETRY_MAX": 2,
        "ORGSCAN_SCAN_QUEUE_RETRY_INTERVALS": "30,120",
        "ORGSCAN_SCAN_QUEUE_LEASE_SECONDS": 300,
        "ORGSCAN_SCAN_QUEUE_POLL_INTERVAL_SECONDS": 5,
        "ORGSCAN_SCAN_QUEUE_WORKER_ID": "",
        'ORGSCAN_API_TOKENS_JSON': '[{"name":"viewer","token":"change-me","role":"reader","tenants":["*"]}]',
        "ORGSCAN_HIBP_BASE_URL": "https://haveibeenpwned.com/api/v3",
        "ORGSCAN_HIBP_API_KEY": "",
        "ORGSCAN_DEHASHED_BASE_URL": "https://api.dehashed.com/search",
        "ORGSCAN_DEHASHED_EMAIL": "",
        "ORGSCAN_DEHASHED_API_KEY": "",
        "ORGSCAN_INTELLIGENCEX_BASE_URL": "https://2.intelx.io",
        "ORGSCAN_INTELLIGENCEX_API_KEY": "",
        "ORGSCAN_GITLEAKS_BINARY": "gitleaks",
        "ORGSCAN_SCANNER_TIMEOUT_SECONDS": 300,
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
