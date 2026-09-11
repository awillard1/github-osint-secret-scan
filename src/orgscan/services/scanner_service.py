"""Registry-backed scanner information for CLI, API and dashboard adapters."""

from __future__ import annotations

from typing import Any

from orgscan.config import Settings
from orgscan.scanners import get_registry


def scanner_inventory(settings: Settings) -> list[dict[str, Any]]:
    return get_registry().inventory(settings=settings)


def artifact_scanner_options(settings: Settings, *, selected: str = "custom-patterns") -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "available": row["readiness"]["ready"],
            "selected": row["name"] == selected,
            "status": row["readiness"]["status"],
        }
        for row in scanner_inventory(settings)
        if "artifact" in row["metadata"]["supported_targets"]
    ]
