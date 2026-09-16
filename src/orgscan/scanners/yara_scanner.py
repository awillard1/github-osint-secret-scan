from __future__ import annotations

import shutil
import json
import re
from hashlib import sha256
import tempfile
from dataclasses import dataclass
from pathlib import Path

from orgscan.config import Settings
from orgscan.scanners.execution import run_scanner_process
from orgscan.scanners.files import read_text, validate_scan_target
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch, ScannerMetadata, ScannerReadiness
from orgscan.scanners.external import ScannerExecutionError, _not_installed_error

DEFAULT_YARA_RULE_SOURCE = """
rule github_token_exposure
{
  strings:
    $token = /gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}/ ascii
  condition:
    any of them
}

rule aws_access_key_exposure
{
  strings:
    $token = /AKIA[0-9A-Z]{16}/ ascii
  condition:
    any of them
}

rule private_key_material
{
  strings:
    $header = /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ ascii
  condition:
    any of them
}
""".strip()


@dataclass(frozen=True)
class YaraRuleDefinition:
    category: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    remediation_hint: str


RULE_DEFINITIONS = {
    "github_token_exposure": YaraRuleDefinition(
        category="secret",
        title="YARA: Possible GitHub token exposure",
        description="A YARA rule matched a value that looks like a GitHub token.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.LIKELY,
        remediation_hint="Rotate the token, remove it from source control, and move it to managed secret storage.",
    ),
    "aws_access_key_exposure": YaraRuleDefinition(
        category="secret",
        title="YARA: Possible AWS access key exposure",
        description="A YARA rule matched a value that looks like an AWS access key.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.LIKELY,
        remediation_hint="Revoke or rotate the AWS credential and remove the exposed value from the repository.",
    ),
    "private_key_material": YaraRuleDefinition(
        category="secret",
        title="YARA: Private key material detected",
        description="A YARA rule matched private key material.",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.VERIFIED,
        remediation_hint="Treat the key as compromised, rotate it immediately, and purge it from source control history.",
    ),
}


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _redact_in_line(line: str, value: str, label: str) -> str:
    return line.replace(value, f"<redacted:{label}>") if value else line


class YaraScanner:
    name = "yara"
    source_class = "internal"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="YARA",
        kind="external",
        binary="yara",
        binary_setting="yara_binary",
        binary_env_var="ORGSCAN_YARA_BINARY",
        configuration_requirements=("ORGSCAN_YARA_RULES_PATH (optional; defaults to bundled rules)",),
        file_settings=("yara_rules_path",),
    )

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.settings = settings
        self.binary = settings.yara_binary if settings is not None else self.name

    def readiness(self) -> ScannerReadiness:
        binary = shutil.which(self.binary)
        if not binary:
            return ScannerReadiness(False, "missing_binary", missing_requirements=("YARA executable not found",))
        paths = [self.settings.yara_rules_path] if self.settings and self.settings.yara_rules_path else []
        if any(not Path(path).is_file() for path in paths):
            return ScannerReadiness(False, "missing_configuration", binary_path=binary,
                                    missing_requirements=("Configured yara_rules_path must reference a readable file",))
        try:
            result = run_scanner_process([self.binary, '--version'], timeout=5)
            version = result.stdout.strip()
            if result.returncode or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?", version):
                raise ScannerExecutionError("YARA version unavailable")
        except ScannerExecutionError:
            return ScannerReadiness(True, "ready", binary_path=binary, warnings=("YARA version probe failed; runtime rules remain unvalidated",))
        return ScannerReadiness(True, "ready", binary_path=binary, version=version,
                                warnings=("Rule syntax is validated by YARA during execution",))

    def _resolve_rules_path(self) -> tuple[Path, bool]:
        if self.settings is not None and self.settings.yara_rules_path:
            return Path(self.settings.yara_rules_path), False
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yar", delete=False)
        try:
            handle.write(DEFAULT_YARA_RULE_SOURCE)
            handle.flush()
            return Path(handle.name), True
        finally:
            handle.close()

    def scan_path(self, target: Path) -> list[ScanMatch]:
        target = validate_scan_target(target, external=True)
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        rules_path, delete_after = self._resolve_rules_path()
        try:
            completed = run_scanner_process(
                [self.binary, "-r", "-N", "-m", "-s", str(rules_path.resolve()), str(target.resolve())],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise ScannerExecutionError(f"yara execution failed (exit status {completed.returncode})")
            return self.parse_output(completed.stdout, target_root=target.resolve())
        finally:
            if delete_after:
                rules_path.unlink(missing_ok=True)

    @classmethod
    def parse_output(cls, output: str, *, target_root: Path | None = None) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        active_rule: str | None = None
        active_path: Path | None = None
        captured_strings: list[str] = []
        rule_metadata: dict = {}

        def flush() -> None:
            nonlocal active_rule, active_path, captured_strings
            if active_rule is None or active_path is None:
                return
            if target_root is not None:
                root = target_root if target_root.is_dir() else target_root.parent
                try:
                    active_path.resolve().relative_to(root)
                except ValueError:
                    raise ScannerExecutionError("YARA returned a path outside the scan target") from None
            fallback = RULE_DEFINITIONS.get(active_rule) or YaraRuleDefinition(
                "exposure", f"YARA: {active_rule}", "A local YARA rule matched this artifact.",
                SeverityLevel.MEDIUM, ConfidenceLevel.HEURISTIC, "Review the rule match and remove unintended exposure.")
            try:
                definition = YaraRuleDefinition(
                    str(rule_metadata.get('category', fallback.category)), str(rule_metadata.get('title', fallback.title)),
                    str(rule_metadata.get('description', fallback.description)),
                    SeverityLevel(rule_metadata.get('severity', fallback.severity)),
                    ConfidenceLevel(rule_metadata.get('confidence', fallback.confidence)),
                    str(rule_metadata.get('remediation', fallback.remediation_hint)))
            except ValueError:
                raise ScannerExecutionError(f"Invalid severity/confidence metadata for YARA rule {active_rule}") from None
            values = captured_strings or [""]
            for value in values:
                complete_secret = rule_metadata.get("secret_value") is True or bool(
                    active_rule in {"github_token_exposure", "aws_access_key_exposure"}
                    and re.fullmatch(r"gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AKIA[0-9A-Z]{16}", value)
                )
                value_metadata = {}
                if value and definition.category != "secret":
                    value_metadata["observation_digest"] = sha256(value.encode()).hexdigest()
                if value and complete_secret and "PRIVATE KEY-----" not in value:
                    value_metadata["secret_digest"] = sha256(value.encode()).hexdigest()
                line_number, snippet = cls._locate_match(active_path, value)
                results.append(
                    ScanMatch(
                        path=active_path,
                        line_start=line_number,
                        line_end=line_number,
                        category=definition.category,
                        title=definition.title,
                        description=definition.description,
                        severity=definition.severity,
                        confidence=definition.confidence,
                        indicator="<redacted>" if value else active_rule,
                        snippet=f"<redacted:yara:{active_rule}>",
                        remediation_hint=definition.remediation_hint,
                        raw_payload={"rule": active_rule},
                        metadata={"path": str(active_path), "rule": active_rule,
                                  **value_metadata},
                    )
                )
            active_rule = None
            active_path = None
            captured_strings = []

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if raw_line.startswith("0x"):
                _, _, tail = raw_line.partition(": ")
                if tail:
                    captured_strings.append(tail)
                continue
            flush()
            parts = raw_line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            active_rule = parts[0]
            tail = parts[1].strip()
            rule_metadata = {}
            if tail.startswith('['):
                header = re.match(r'\[((?:"(?:\\.|[^"\\])*"|[^"\]])*)\]\s+(.+)$', tail)
                if not header:
                    raise ScannerExecutionError("Malformed YARA metadata output")
                for item in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"\\])*"|-?\d+|true|false)', header[1]):
                    rule_metadata[item[1]] = json.loads(item[2])
                tail = header[2]
            active_path = Path(tail)
        flush()
        return results

    @staticmethod
    def _locate_match(path: Path, value: str) -> tuple[int, str]:
        if not value:
            return 1, ""
        try:
            content = read_text(path, path.parent)
        except (OSError, UnicodeDecodeError):
            return 1, f"<redacted:yara:{path.name}>"
        for line_number, line in enumerate(content.splitlines(), start=1):
            if value in line:
                return line_number, "<redacted:yara>"
        return 1, f"<redacted:yara:{path.name}>"
