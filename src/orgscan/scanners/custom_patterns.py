from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orgscan import __version__
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch, ScannerMetadata

GENERIC_SECRET_ASSIGNMENT_NAME = "generic-secret-assignment"
ASSIGNED_SECRET_VALUE = re.compile(r"[:=]\s*['\"]([^'\"]{8,})['\"]")
PLACEHOLDER_SECRET_MARKERS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "not-real",
    "changeme",
    "replace-me",
    "replace_me",
    "replace-this",
    "replace_this",
    "fake",
    "mock",
)


@dataclass(frozen=True)
class PatternDefinition:
    name: str
    regex: str
    category: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    remediation_hint: str | None = None


DEFAULT_PATTERNS: tuple[PatternDefinition, ...] = (
    PatternDefinition(
        name="github-token",
        regex=r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
        category="secret",
        title="Possible GitHub token exposure",
        description="A string matching a GitHub token pattern was found in a scanned file.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.LIKELY,
        remediation_hint="Rotate the token, remove it from source control, and move it to managed secret storage.",
    ),
    PatternDefinition(
        name="aws-access-key",
        regex=r"\bAKIA[0-9A-Z]{16}\b",
        category="secret",
        title="Possible AWS access key exposure",
        description="A string matching an AWS access key ID pattern was found in a scanned file.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.LIKELY,
        remediation_hint="Revoke or rotate the AWS credential and remove the exposed value from the repository.",
    ),
    PatternDefinition(
        name="private-key",
        regex=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        category="secret",
        title="Private key material detected",
        description="A private key header was found in a scanned file.",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.VERIFIED,
        remediation_hint="Treat the key as compromised, rotate it immediately, and purge it from source control history.",
    ),
    PatternDefinition(
        name="generic-secret-assignment",
        regex=r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        category="secret",
        title="Possible hardcoded secret assignment",
        description="A variable assignment that looks like a hardcoded secret was found in a scanned file.",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HEURISTIC,
        remediation_hint="Move the value into environment-based secret management and remove it from committed files.",
    ),
)


class CustomPatternScanner:
    name = "custom-patterns"
    source_class = "internal"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="Custom patterns",
        kind="builtin",
        version=__version__,
    )

    def __init__(self, patterns: tuple[PatternDefinition, ...] = DEFAULT_PATTERNS, max_file_bytes: int = 1_000_000) -> None:
        self._patterns = tuple((pattern, re.compile(pattern.regex)) for pattern in patterns)
        self.max_file_bytes = max_file_bytes

    def scan_path(self, target: Path) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        for file_path in self._iter_files(target):
            matches.extend(self._scan_file(file_path))
        return matches

    def _iter_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        return sorted(path for path in target.rglob("*") if path.is_file())

    def _scan_file(self, file_path: Path) -> list[ScanMatch]:
        if file_path.stat().st_size > self.max_file_bytes:
            return []
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return []
        if "\x00" in content:
            return []

        results: list[ScanMatch] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            for pattern, compiled in self._patterns:
                for matched in compiled.finditer(line):
                    value = matched.group(0)
                    if should_skip_pattern_match(pattern.name, value):
                        continue
                    results.append(
                        ScanMatch(
                            path=file_path,
                            line_start=line_number,
                            line_end=line_number,
                            category=pattern.category,
                            title=pattern.title,
                            description=pattern.description,
                            severity=pattern.severity,
                            confidence=pattern.confidence,
                            indicator=self._redact(value),
                            snippet=self._redact_in_line(line, value, pattern.name),
                            remediation_hint=pattern.remediation_hint,
                            raw_payload={
                                "pattern": pattern.name,
                                "match": self._redact(value),
                            },
                            metadata={
                                "path": str(file_path),
                                "pattern": pattern.name,
                            },
                        )
                    )
        return results

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return "<redacted>"
        return f"{value[:4]}...{value[-4:]}"

    @classmethod
    def _redact_in_line(cls, line: str, value: str, pattern_name: str) -> str:
        return line.replace(value, f"<redacted:{pattern_name}>")


def should_skip_pattern_match(pattern_name: str, matched_value: str) -> bool:
    if pattern_name != GENERIC_SECRET_ASSIGNMENT_NAME:
        return False
    extracted = _extract_assigned_secret(matched_value)
    if extracted is None:
        return False
    normalized = extracted.strip().lower()
    condensed = re.sub(r"[\s._-]+", "", normalized)
    if condensed in {"example", "sample", "dummy", "placeholder", "changeme", "replaceme", "fake", "mock"}:
        return True
    return any(marker in normalized for marker in PLACEHOLDER_SECRET_MARKERS)


def _extract_assigned_secret(matched_value: str) -> str | None:
    matched = ASSIGNED_SECRET_VALUE.search(matched_value)
    if matched is None:
        return None
    return matched.group(1)
