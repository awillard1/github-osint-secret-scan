"""Scanner implementations for orgscan."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

from orgscan.scanners.base import ScanMatch
from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.external import DetectSecretsScanner, GitleaksScanner, ScannerExecutionError, SemgrepScanner, TruffleHogScanner
from orgscan.scanners.git_history import GitHistoryPatternScanner
from orgscan.scanners.ripgrep_heuristics import RipgrepHeuristicScanner
from orgscan.scanners.repo_governance import RepositoryGovernanceScanner
from orgscan.scanners.yara_scanner import YaraScanner
from orgscan.scanners.registry import DuplicateScannerError, ScannerRegistry, scanner_id_for, supports_settings

if TYPE_CHECKING:
    from orgscan.config import Settings

SCANNER_ENTRY_POINT_GROUP = "orgscan.scanners"

ScannerClass = type[Any]
_plugin_load_warnings: list[str] = []

BUILTIN_SCANNERS: dict[str, ScannerClass] = {
    CustomPatternScanner.name: CustomPatternScanner,
    GitHistoryPatternScanner.name: GitHistoryPatternScanner,
    RepositoryGovernanceScanner.name: RepositoryGovernanceScanner,
    DetectSecretsScanner.name: DetectSecretsScanner,
    GitleaksScanner.name: GitleaksScanner,
    RipgrepHeuristicScanner.name: RipgrepHeuristicScanner,
    SemgrepScanner.name: SemgrepScanner,
    TruffleHogScanner.name: TruffleHogScanner,
    YaraScanner.name: YaraScanner,
}


@lru_cache(maxsize=1)
def _plugin_scanner_classes() -> dict[str, ScannerClass]:
    discovered: dict[str, ScannerClass] = {}
    _plugin_load_warnings.clear()
    for candidate in sorted(entry_points(group=SCANNER_ENTRY_POINT_GROUP), key=lambda item: (item.name, item.value)):
        try:
            scanner_class = candidate.load()
        except Exception:
            _plugin_load_warnings.append(f"Could not load scanner entry point: {candidate.name}")
            continue
        name = scanner_id_for(scanner_class, candidate.name)
        if name in discovered:
            raise DuplicateScannerError(f"Duplicate scanner ID: {name}")
        discovered[name] = scanner_class
    return discovered


def _scanner_registry() -> dict[str, ScannerClass]:
    registry = get_registry()
    return {name: registry.get_class(name) for name in registry.names()}


def get_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    for name, scanner_class in BUILTIN_SCANNERS.items():
        registry.register(scanner_class, scanner_id=name)
    for name, scanner_class in _plugin_scanner_classes().items():
        registry.register(scanner_class, scanner_id=name)
    registry.warnings = tuple(_plugin_load_warnings)
    return registry


def available_scanner_names() -> list[str]:
    return get_registry().names()


def get_scanner_class(name: str) -> ScannerClass:
    return get_registry().get_class(name)


def _scanner_supports_settings(scanner_class: ScannerClass) -> bool:
    return supports_settings(scanner_class)


def get_scanner(name: str, *, settings: Settings | None = None) -> Any:
    """Compatibility factory; new callers use get_registry().get()."""
    return get_registry().create_legacy(name, settings=settings)


def load_report(scanner_name: str, report_path: Path) -> tuple[str, list[ScanMatch]]:
    return get_registry().load_report(scanner_name, report_path)


__all__ = [
    "CustomPatternScanner",
    "GitHistoryPatternScanner",
    "RepositoryGovernanceScanner",
    "DetectSecretsScanner",
    "GitleaksScanner",
    "RipgrepHeuristicScanner",
    "SemgrepScanner",
    "TruffleHogScanner",
    "YaraScanner",
    "ScannerExecutionError",
    "available_scanner_names",
    "get_scanner",
    "get_scanner_class",
    "load_report",
    "get_registry",
    "ScannerRegistry",
    "DuplicateScannerError",
]
