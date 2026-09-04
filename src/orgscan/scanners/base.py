from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
