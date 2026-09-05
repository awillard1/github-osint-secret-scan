from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch

SEMGREP_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "error": SeverityLevel.CRITICAL,
    "warning": SeverityLevel.MEDIUM,
    "info": SeverityLevel.LOW,
}


class ScannerExecutionError(RuntimeError):
    pass


def _not_installed_error(name: str) -> ScannerExecutionError:
    return ScannerExecutionError(f"{name} is not installed; run orgscan verify-deps or install the official binary.")


def _redact(value: str) -> str:
    if not value:
        return "<redacted>"
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _redact_in_line(line: str, value: str, label: str) -> str:
    return line.replace(value, f"<redacted:{label}>") if value else line


class GitleaksScanner:
    name = "gitleaks"
    source_class = "free"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        if not shutil.which(self.name):
            raise _not_installed_error(self.name)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            report_path = Path(handle.name)

        try:
            completed = subprocess.run(
                [
                    self.name,
                    "detect",
                    "--no-git",
                    "--source",
                    str(target),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode not in (0, 1):
                raise ScannerExecutionError(completed.stderr.strip() or "gitleaks execution failed")
            content = report_path.read_text(encoding="utf-8").strip() or "[]"
            return self.parse_output(json.loads(content))
        finally:
            report_path.unlink(missing_ok=True)

    @staticmethod
    def parse_output(payload: list[dict[str, Any]]) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        for item in payload:
            match_value = str(item.get("Secret") or item.get("Match") or "")
            line = str(item.get("Match") or match_value or "")
            results.append(
                ScanMatch(
                    path=Path(str(item.get("File") or "")),
                    line_start=int(item.get("StartLine") or 1),
                    line_end=int(item.get("EndLine") or item.get("StartLine") or 1),
                    category="secret",
                    title=f"Gitleaks: {item.get('RuleID') or 'secret detected'}",
                    description=str(item.get("Description") or "Gitleaks identified a potential secret."),
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.LIKELY,
                    indicator=_redact(match_value),
                    snippet=_redact_in_line(line, match_value, "gitleaks"),
                    remediation_hint="Rotate the exposed secret and remove it from source control.",
                    raw_payload={
                        "rule_id": item.get("RuleID"),
                        "commit": item.get("Commit"),
                        "match": _redact(match_value),
                    },
                    metadata={
                        "path": str(item.get("File") or ""),
                        "rule_id": item.get("RuleID"),
                    },
                )
            )
        return results

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8").strip() or "[]")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("gitleaks report contained invalid JSON") from exc
        if not isinstance(payload, list):
            raise ScannerExecutionError("gitleaks report must contain a JSON array")
        return cls.parse_output(payload)


class SemgrepScanner:
    name = "semgrep"
    source_class = "free"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        if not shutil.which(self.name):
            raise _not_installed_error(self.name)

        completed = subprocess.run(
            [self.name, "scan", "--config", "auto", "--json", "--metrics=off", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(completed.stderr.strip() or "semgrep execution failed")
        try:
            payload = json.loads((completed.stdout or "").strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("semgrep produced invalid JSON output") from exc
        return self.parse_output(payload)

    @staticmethod
    def parse_output(payload: dict[str, Any]) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        items = payload.get("results")
        if not isinstance(items, list):
            return results

        for item in items:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            start = item.get("start") if isinstance(item.get("start"), dict) else {}
            end = item.get("end") if isinstance(item.get("end"), dict) else {}
            severity = str(extra.get("severity") or "INFO").lower()
            lines = str(extra.get("lines") or "")
            check_id = str(item.get("check_id") or "semgrep-rule")
            path = str(item.get("path") or "")
            results.append(
                ScanMatch(
                    path=Path(path),
                    line_start=int(start.get("line") or 1),
                    line_end=int(end.get("line") or start.get("line") or 1),
                    category="code-policy",
                    title=f"Semgrep: {check_id}",
                    description=str(extra.get("message") or "Semgrep detected a policy or code issue."),
                    severity=SEMGREP_SEVERITY_MAP.get(severity, SeverityLevel.LOW),
                    confidence=ConfidenceLevel.LIKELY,
                    indicator=check_id,
                    snippet=lines,
                    remediation_hint="Review the matched rule, validate impact, and remediate the flagged code or configuration.",
                    raw_payload={
                        "check_id": check_id,
                        "severity": severity,
                        "path": path,
                    },
                    metadata={
                        "path": path,
                        "check_id": check_id,
                        "severity": severity,
                    },
                )
            )
        return results

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8").strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("semgrep report contained invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ScannerExecutionError("semgrep report must contain a JSON object")
        return cls.parse_output(payload)


class TruffleHogScanner:
    name = "trufflehog"
    source_class = "free"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        if not shutil.which(self.name):
            raise _not_installed_error(self.name)

        completed = subprocess.run(
            [self.name, "filesystem", "--json", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(completed.stderr.strip() or "trufflehog execution failed")
        lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        return self.parse_output(lines)

    @staticmethod
    def parse_output(payload: list[dict[str, Any]]) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        for item in payload:
            source_metadata = item.get("SourceMetadata") if isinstance(item.get("SourceMetadata"), dict) else {}
            data = source_metadata.get("Data") if isinstance(source_metadata.get("Data"), dict) else {}
            filesystem = data.get("Filesystem") if isinstance(data.get("Filesystem"), dict) else {}
            match_value = str(item.get("Raw") or item.get("RawV2") or "")
            detector_name = str(item.get("DetectorName") or "secret")
            line = str(item.get("Raw") or match_value or "")
            results.append(
                ScanMatch(
                    path=Path(str(filesystem.get("file") or "")),
                    line_start=int(filesystem.get("line") or 1),
                    line_end=int(filesystem.get("line") or 1),
                    category="secret",
                    title=f"TruffleHog: {detector_name}",
                    description="TruffleHog identified a potential secret.",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.VERIFIED if item.get("Verified") else ConfidenceLevel.LIKELY,
                    indicator=_redact(match_value),
                    snippet=_redact_in_line(line, match_value, "trufflehog"),
                    remediation_hint="Rotate the exposed secret and remove it from source control.",
                    raw_payload={
                        "detector": detector_name,
                        "verified": bool(item.get("Verified")),
                        "match": _redact(match_value),
                    },
                    metadata={
                        "path": str(filesystem.get("file") or ""),
                        "detector": detector_name,
                    },
                )
            )
        return results

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        results: list[dict[str, Any]] = []
        for line in report_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ScannerExecutionError("trufflehog report contained invalid JSON lines") from exc
            if isinstance(item, dict):
                results.append(item)
        return cls.parse_output(results)
