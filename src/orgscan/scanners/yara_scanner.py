from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from orgscan.config import Settings
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch
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

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.settings = settings
        self.binary = settings.yara_binary if settings is not None else self.name

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
        if not shutil.which(self.binary):
            raise _not_installed_error(self.binary)

        rules_path, delete_after = self._resolve_rules_path()
        try:
            completed = subprocess.run(
                [self.binary, "-r", "-s", str(rules_path), str(target)],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise ScannerExecutionError(completed.stderr.strip() or "yara execution failed")
            return self.parse_output(completed.stdout)
        finally:
            if delete_after:
                rules_path.unlink(missing_ok=True)

    @classmethod
    def parse_output(cls, output: str) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        active_rule: str | None = None
        active_path: Path | None = None
        captured_strings: list[str] = []

        def flush() -> None:
            nonlocal active_rule, active_path, captured_strings
            if active_rule is None or active_path is None:
                return
            definition = RULE_DEFINITIONS.get(active_rule)
            if definition is None:
                active_rule = None
                active_path = None
                captured_strings = []
                return
            values = captured_strings or [""]
            for value in values:
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
                        indicator=_redact(value) if value else active_rule,
                        snippet=snippet or f"<yara:{active_rule}>",
                        remediation_hint=definition.remediation_hint,
                        raw_payload={"rule": active_rule, "match": _redact(value) if value else ""},
                        metadata={"path": str(active_path), "rule": active_rule},
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
            active_path = Path(parts[1].strip())
        flush()
        return results

    @staticmethod
    def _locate_match(path: Path, value: str) -> tuple[int, str]:
        if not value:
            return 1, ""
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return 1, f"<redacted:yara:{path.name}>"
        for line_number, line in enumerate(content.splitlines(), start=1):
            if value in line:
                return line_number, _redact_in_line(line, value, "yara")
        return 1, f"<redacted:yara:{path.name}>"
