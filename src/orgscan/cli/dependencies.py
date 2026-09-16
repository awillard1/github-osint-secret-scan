from orgscan.config import Settings, get_settings
from orgscan.logging_config import setup_logging


def _settings() -> Settings:
    settings = get_settings()
    setup_logging(settings.log_level)
    return settings
