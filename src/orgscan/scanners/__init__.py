"""Scanner implementations for orgscan."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from importlib.metadata import entry_points
from inspect import Signature, signature
from pathlib import Path
from typing import TYPE_CHECKING, Any

from orgscan.scanners.base import ScanMatch
from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.external import DetectSecretsScanner, GitleaksScanner, ScannerExecutionError, SemgrepScanner, TruffleHogScanner
from orgscan.scanners.repo_governance import RepositoryGovernanceScanner

if TYPE_CHECKING:
    from orgscan.config import Settings

SCANNER_ENTRY_POINT_GROUP = "orgscan.scanners"

ScannerClass = type[Any]

BUILTIN_SCANNERS: dict[str, ScannerClass] = {
    CustomPatternScanner.name: CustomPatternScanner,
    RepositoryGovernanceScanner.name: RepositoryGovernanceScanner,
    DetectSecretsScanner.name: DetectSecretsScanner,
    GitleaksScanner.name: GitleaksScanner,
    SemgrepScanner.name: SemgrepScanner,
    TruffleHogScanner.name: TruffleHogScanner,
}


@lru_cache(maxsize=1)
def _plugin_scanner_classes() -> dict[str, ScannerClass]:
    discovered: dict[str, ScannerClass] = {}
    for candidate in entry_points(group=SCANNER_ENTRY_POINT_GROUP):
        try:
            scanner_class = candidate.load()
        except Exception:
            continue
        name = getattr(scanner_class, "name", candidate.name)
        if isinstance(name, str) and name:
            discovered[name] = scanner_class
    return discovered


def _scanner_registry() -> dict[str, ScannerClass]:
    registry = dict(_plugin_scanner_classes())
    registry.update(BUILTIN_SCANNERS)
    return registry


def available_scanner_names() -> list[str]:
    return sorted(_scanner_registry())


def get_scanner_class(name: str) -> ScannerClass:
    try:
        return _scanner_registry()[name]
    except KeyError as exc:
        raise ValueError(f"Unsupported scanner: {name}") from exc


def _scanner_supports_settings(scanner_class: ScannerClass) -> bool:
    try:
        params = signature(scanner_class).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(parameter.name == "settings" or parameter.kind == Signature.VAR_KEYWORD for parameter in params)


def get_scanner(name: str, *, settings: Settings | None = None) -> Any:
    scanner_class = get_scanner_class(name)
    if settings is not None and _scanner_supports_settings(scanner_class):
        return scanner_class(settings=settings)
    return scanner_class()


def load_report(scanner_name: str, report_path: Path) -> tuple[str, list[ScanMatch]]:
    scanner_class = get_scanner_class(scanner_name)
    report_loader = getattr(scanner_class, "load_report", None)
    if not isinstance(report_loader, Callable):
        raise ValueError(f"Scanner does not support report ingestion: {scanner_name}")
    source_class = str(getattr(scanner_class, "source_class", "internal"))
    return source_class, report_loader(report_path)


__all__ = [
    "CustomPatternScanner",
    "RepositoryGovernanceScanner",
    "DetectSecretsScanner",
    "GitleaksScanner",
    "SemgrepScanner",
    "TruffleHogScanner",
    "ScannerExecutionError",
    "available_scanner_names",
    "get_scanner",
    "get_scanner_class",
    "load_report",
]
