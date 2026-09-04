from __future__ import annotations

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
    github_token: str | None = None
    http_timeout_seconds: int = 15

    def ensure_data_dir(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_data_dir()
    return settings
