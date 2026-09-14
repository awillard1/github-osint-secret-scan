from __future__ import annotations

from orgscan.redaction import sanitize_matches

import json
from hashlib import sha256
import shutil
from orgscan import processes as subprocess
import tempfile
from pathlib import Path
from typing import Any

from orgscan.config import Settings
from orgscan.scanners.execution import run_scanner_process
from orgscan.scanners.files import read_report, validate_scan_target
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch, ScannerMetadata, ScannerReadiness, ScannerExecutionError, not_installed_error as _not_installed_error

SEMGREP_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "error": SeverityLevel.CRITICAL,
    "warning": SeverityLevel.MEDIUM,
    "info": SeverityLevel.LOW,
}


def _redact(value: str) -> str:
    if not value:
        return "<redacted>"
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _redact_in_line(line: str, value: str, label: str) -> str:
    return f"<redacted:{label}>"


class GitleaksScanner:
    name = "gitleaks"
    source_class = "free"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="Gitleaks",
        kind="external",
        description="Generic secret scanner for files and uploaded artifacts.",
        binary="gitleaks",
        binary_setting="gitleaks_binary",
        binary_env_var="ORGSCAN_GITLEAKS_BINARY",
    )

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.binary = settings.gitleaks_binary if settings is not None else self.name

    def scan_path(self, target: Path) -> list[ScanMatch]:
        target = validate_scan_target(target, external=True)
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            report_path = Path(handle.name)

        try:
            completed = run_scanner_process(
                [
                    self.binary,
                    "detect",
                    "--no-git",
                    "--source",
                    str(target),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                ],
                output_files=(report_path,),
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode not in (0, 1):
                raise ScannerExecutionError(f"gitleaks execution failed (exit status {completed.returncode})")
            content = read_report(report_path).strip() or "[]"
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
                        **({"secret_digest":sha256(match_value.encode()).hexdigest()} if item.get("Secret") and match_value and "PRIVATE KEY-----" not in match_value else {}),
                    },
                )
            )
        return sanitize_matches(results, payload)

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        try:
            payload = json.loads(read_report(report_path).strip() or "[]")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("gitleaks report contained invalid JSON") from exc
        if not isinstance(payload, list):
            raise ScannerExecutionError("gitleaks report must contain a JSON array")
        return cls.parse_output(payload)


class DetectSecretsScanner:
    name = "detect-secrets"
    source_class = "free"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="detect-secrets",
        kind="external",
        description="Baseline-oriented secret scanner with plugin coverage.",
        binary="detect-secrets",
        binary_setting="detect_secrets_binary",
        binary_env_var="ORGSCAN_DETECT_SECRETS_BINARY",
    )

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.binary = settings.detect_secrets_binary if settings is not None else self.name

    def scan_path(self, target: Path) -> list[ScanMatch]:
        target = validate_scan_target(target, external=True)
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        completed = run_scanner_process(
            [self.binary, "scan", "--all-files", "--force-use-all-plugins", "--json", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise ScannerExecutionError(f"detect-secrets execution failed (exit status {completed.returncode})")
        try:
            payload = json.loads((completed.stdout or "").strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("detect-secrets produced invalid JSON output") from exc
        return self.parse_output(payload)

    @staticmethod
    def parse_output(payload: dict[str, Any]) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        raw_results = payload.get("results")
        if not isinstance(raw_results, dict):
            return sanitize_matches(results, payload)

        for path, findings in raw_results.items():
            if not isinstance(findings, list):
                continue
            for item in findings:
                if not isinstance(item, dict):
                    continue
                secret_type = str(item.get("type") or "secret")
                line_number = int(item.get("line_number") or 1)
                verified = bool(item.get("is_verified"))
                hashed_secret = str(item.get("hashed_secret") or "")
                results.append(
                    ScanMatch(
                        path=Path(path),
                        line_start=line_number,
                        line_end=line_number,
                        category="secret",
                        title=f"detect-secrets: {secret_type}",
                        description="detect-secrets identified a potential secret that should be reviewed and rotated if valid.",
                        severity=SeverityLevel.CRITICAL if verified else SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.VERIFIED if verified else ConfidenceLevel.LIKELY,
                        indicator=_redact(hashed_secret),
                        snippet=f"<redacted:detect-secrets:{secret_type}>",
                        remediation_hint="Validate the secret, rotate it if exposed, and remove it from committed artifacts.",
                        raw_payload={
                            "type": secret_type,
                            "verified": verified,
                            "hashed_secret": _redact(hashed_secret),
                        },
                        metadata={
                            "path": path,
                            "type": secret_type,
                            **({"observation_digest":sha256(hashed_secret.encode()).hexdigest()} if hashed_secret else {}),
                        },
                    )
                )
        return sanitize_matches(results, payload)

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        try:
            payload = json.loads(read_report(report_path).strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("detect-secrets report contained invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ScannerExecutionError("detect-secrets report must contain a JSON object")
        return cls.parse_output(payload)


class SemgrepScanner:
    name = "semgrep"
    source_class = "free"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="Semgrep",
        kind="external",
        description="Code and configuration rule scanner for policy findings.",
        binary="semgrep",
        binary_setting="semgrep_binary",
        binary_env_var="ORGSCAN_SEMGREP_BINARY",
        file_settings=("semgrep_rules_path",),
        configuration_requirements=("ORGSCAN_SEMGREP_RULES_PATH: readable local rules file",),
    )

    def __init__(self, *, settings: Settings | None = None) -> None:
        settings = settings or Settings()
        self.binary = settings.semgrep_binary
        self.rules = settings.semgrep_rules_path
        self.metrics = settings.semgrep_metrics

    def readiness(self):
        binary = shutil.which(self.binary)
        if not binary:
            return ScannerReadiness(False, 'missing_binary')
        if not self.rules or not Path(self.rules).is_file():
            return ScannerReadiness(False, 'missing_configuration', binary_path=binary,
                                    missing_requirements=('semgrep requires ORGSCAN_SEMGREP_RULES_PATH pointing to local rules',))
        return ScannerReadiness(True, 'ready', binary_path=binary,
                                warnings=('Local rules configured; runtime rule compatibility is not certified',))

    def scan_path(self, target: Path) -> list[ScanMatch]:
        target = validate_scan_target(target, external=True)
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        if not self.readiness().ready:
            raise ScannerExecutionError('semgrep requires a readable local ORGSCAN_SEMGREP_RULES_PATH')
        completed = run_scanner_process(
            [self.binary, "scan", "--config", str(Path(self.rules).resolve()), "--json", "--metrics=on" if self.metrics else "--metrics=off", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(f"semgrep execution failed (exit status {completed.returncode})")
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
            return sanitize_matches(results, payload)

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
                    description="Semgrep detected a policy or code issue; review the rule and location.",
                    severity=SEMGREP_SEVERITY_MAP.get(severity, SeverityLevel.LOW),
                    confidence=ConfidenceLevel.LIKELY,
                    indicator=check_id,
                    snippet="<redacted:semgrep>",
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
        return sanitize_matches(results, payload)

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        try:
            payload = json.loads(read_report(report_path).strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("semgrep report contained invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ScannerExecutionError("semgrep report must contain a JSON object")
        return cls.parse_output(payload)


class TruffleHogScanner:
    name = "trufflehog"
    source_class = "free"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="TruffleHog",
        kind="external",
        description="Secret scanner with verified-detector support.",
        binary="trufflehog",
        binary_setting="trufflehog_binary",
        binary_env_var="ORGSCAN_TRUFFLEHOG_BINARY",
    )

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.binary = settings.trufflehog_binary if settings is not None else self.name

    def scan_path(self, target: Path) -> list[ScanMatch]:
        target = validate_scan_target(target, external=True)
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        completed = run_scanner_process(
            [self.binary, "filesystem", "--json", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(f"trufflehog execution failed (exit status {completed.returncode})")
        try:
            lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("trufflehog produced invalid JSON output") from exc
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
                        **({"secret_digest":sha256(match_value.encode()).hexdigest()} if match_value and "PRIVATE KEY-----" not in match_value else {}),
                    },
                )
            )
        return sanitize_matches(results, payload)

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        results: list[dict[str, Any]] = []
        for line in read_report(report_path).splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ScannerExecutionError("trufflehog report contained invalid JSON lines") from exc
            if isinstance(item, dict):
                results.append(item)
        return cls.parse_output(results)
