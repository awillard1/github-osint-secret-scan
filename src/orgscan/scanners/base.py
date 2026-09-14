from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite
from pathlib import Path
from typing import Any, Protocol

from orgscan.models import ConfidenceLevel, SeverityLevel


@dataclass(frozen=True)
class ScanMatch:
    path: Path
    line_start: int
    line_end: int
    category: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    indicator: str
    snippet: str
    remediation_hint: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class ScannerExecutionError(RuntimeError):
    """A scanner failure whose message is safe for operator diagnostics."""


class ScannerReadinessError(ScannerExecutionError):
    """Pre-execution configuration diagnostic, sanitized by the registry."""


def not_installed_error(name: str) -> ScannerExecutionError:
    return ScannerExecutionError(
        f"{name} is not installed; run orgscan verify-deps and review docs/open-source-tooling-gaps.md for installation guidance."
    )


@dataclass(frozen=True)
class ScannerMetadata:
    scanner_id: str
    display_name: str
    kind: str = "builtin"
    supported_targets: frozenset[str] = frozenset({"path", "mirror", "artifact"})
    supports_history: bool = False
    supports_incremental: bool = False
    version: str | None = None
    description: str = ""
    binary: str | None = None
    binary_setting: str | None = None
    binary_env_var: str | None = None
    configuration_requirements: tuple[str, ...] = ()
    # Optional file settings must reference readable files when configured.
    file_settings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScannerReadiness:
    ready: bool
    status: str
    binary_path: str | None = None
    version: str | None = None
    missing_requirements: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    kind: str = "path"
    ref: str | None = "workspace"


@dataclass(frozen=True)
class ScanContext:
    target: ScanTarget
    scan_job_id: int | None = None
    organization_id: int | None = None
    repository_id: int | None = None
    timeout_seconds: float = 300
    environment: dict[str, str] | None = field(default=None, repr=False)
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("Scanner timeout must be finite and positive")


@dataclass(frozen=True)
class ScanResult:
    scanner_id: str
    started_at: datetime
    completed_at: datetime
    findings: list[ScanMatch] = field(default_factory=list)
    # Logical scan status: zero means the scanner accepted its tool's exit code.
    exit_status: int = 0
    warnings: tuple[str, ...] = ()


class ScannerPlugin(Protocol):
    metadata: ScannerMetadata
    source_class: str

    def readiness(self) -> ScannerReadiness: ...

    def supports(self, target: ScanTarget) -> bool: ...

    def scan(self, context: ScanContext) -> ScanResult: ...
