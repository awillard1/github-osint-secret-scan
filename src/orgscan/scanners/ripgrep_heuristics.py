from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from orgscan.config import Settings
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch
from orgscan.scanners.external import ScannerExecutionError, _not_installed_error


@dataclass(frozen=True)
class HeuristicDefinition:
    name: str
    pattern: str
    category: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    remediation_hint: str
    fixed_strings: bool = False


class RipgrepHeuristicScanner:
    name = "ripgrep-heuristics"
    source_class = "internal"

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.settings = settings
        self.binary = settings.rg_binary if settings is not None else "rg"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        results: list[ScanMatch] = []
        for definition in self._heuristics():
            command = [
                self.binary,
                "--json",
                "-n",
                "-I",
                "-S",
                "-e",
                definition.pattern,
                str(target),
            ]
            if definition.fixed_strings:
                command.insert(1, "-F")
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            if completed.returncode not in (0, 1):
                raise ScannerExecutionError(completed.stderr.strip() or "ripgrep execution failed")
            results.extend(self.parse_output(completed.stdout, definition))
        return results

    def _heuristics(self) -> list[HeuristicDefinition]:
        suffix_pattern = "|".join(re.escape(value) for value in self._internal_suffixes()) or "internal"
        heuristics = [
            HeuristicDefinition(
                name="internal-hostname",
                pattern=rf"\b(?:[A-Za-z0-9-]+\.)+(?:{suffix_pattern})\b",
                category="infrastructure-exposure",
                title="Internal hostname reference detected",
                description="ripgrep matched a hostname that appears to reference an internal or non-public environment.",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HEURISTIC,
                remediation_hint="Review the referenced hostname and remove unnecessary internal environment disclosure from public artifacts.",
            ),
            HeuristicDefinition(
                name="internal-url",
                pattern=rf"https?://[^\s\"'<>]+(?:\.(?:{suffix_pattern}))(?::\d+)?[^\s\"'<>]*",
                category="infrastructure-exposure",
                title="Internal service URL detected",
                description="ripgrep matched a URL that appears to point at an internal environment or service.",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HEURISTIC,
                remediation_hint="Remove or sanitize internal service references that should not be exposed in public code or documentation.",
            ),
        ]
        heuristics.extend(
            HeuristicDefinition(
                name=f"org-term:{term}",
                pattern=term,
                category="org-exposure",
                title="Organization-specific string detected",
                description="ripgrep matched a configured organization-specific indicator string.",
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.HEURISTIC,
                remediation_hint="Review whether the matched term exposes internal naming, vendors, projects, or other sensitive organization context.",
                fixed_strings=True,
            )
            for term in self._heuristic_terms()
        )
        return heuristics

    def _heuristic_terms(self) -> list[str]:
        if self.settings is None:
            return []
        return self.settings.heuristic_term_list()

    def _internal_suffixes(self) -> list[str]:
        if self.settings is None:
            return ["corp", "internal", "local", "lan"]
        return self.settings.internal_hostname_suffix_list() or ["corp", "internal", "local", "lan"]

    @staticmethod
    def parse_output(output: str, definition: HeuristicDefinition) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        for raw_line in output.splitlines():
            if not raw_line.strip():
                continue
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ScannerExecutionError("ripgrep produced invalid JSON output") from exc
            if event.get("type") != "match":
                continue
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            path_info = data.get("path") if isinstance(data.get("path"), dict) else {}
            line_info = data.get("lines") if isinstance(data.get("lines"), dict) else {}
            submatches = data.get("submatches") if isinstance(data.get("submatches"), list) else []
            line = str(line_info.get("text") or "").rstrip("\n")
            path = Path(str(path_info.get("text") or ""))
            line_number = int(data.get("line_number") or 1)
            if not submatches:
                submatches = [{"match": {"text": line}}]
            for submatch in submatches:
                match_info = submatch.get("match") if isinstance(submatch, dict) else {}
                match_text = str(match_info.get("text") or "").strip()
                results.append(
                    ScanMatch(
                        path=path,
                        line_start=line_number,
                        line_end=line_number,
                        category=definition.category,
                        title=definition.title,
                        description=definition.description,
                        severity=definition.severity,
                        confidence=definition.confidence,
                        indicator=match_text or definition.name,
                        snippet=line,
                        remediation_hint=definition.remediation_hint,
                        raw_payload={"heuristic": definition.name, "match": match_text},
                        metadata={"path": str(path), "heuristic": definition.name},
                    )
                )
        return results
