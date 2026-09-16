"""Validated operator-authored JSON heuristics with bounded regex matching."""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from hashlib import sha256
from pathlib import Path

import regex
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from orgscan import __version__
from orgscan.scanners.files import read_text
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch, ScannerMetadata, ScannerReadiness, ScannerExecutionError
from orgscan.scanners.custom_patterns import CustomPatternScanner, should_skip_pattern_match


class HeuristicRule(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    id: str = Field(pattern=r'^[a-z0-9][a-z0-9_.-]{0,79}$')
    category: str = Field(min_length=1, max_length=80)
    severity: SeverityLevel
    confidence: ConfidenceLevel
    regex: str = Field(min_length=1, max_length=4096)
    include: tuple[str, ...] = ('*',)
    exclude: tuple[str, ...] = ()
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)


DEFAULT_RULES = Path(__file__).with_name('rules') / 'starter.json'


def load_rules(path: Path):
    try:
        if path.stat().st_size > 1_000_000:
            raise ScannerExecutionError('Heuristic rule file exceeds 1 MB')
        records = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ScannerExecutionError(f'Cannot load heuristic rules from {path.name}: expected readable UTF-8 JSON') from None
    if not isinstance(records, list) or not 1 <= len(records) <= 100:
        raise ScannerExecutionError(f'{path.name}: expected 1–100 rule objects')
    result = []
    seen = set()
    for index, record in enumerate(records, 1):
        try:
            rule = HeuristicRule.model_validate(record)
        except ValidationError as exc:
            fields = ', '.join('.'.join(str(v) for v in e['loc']) for e in exc.errors(include_input=False))
            raise ScannerExecutionError(f'{path.name}, rule {index}: invalid fields {fields}') from None
        if rule.id in seen:
            raise ScannerExecutionError(f'{path.name}: duplicate rule ID {rule.id}')
        seen.add(rule.id)
        try:
            compiled = regex.compile(rule.regex)
            if compiled.search('', timeout=0.02) is not None:
                raise ScannerExecutionError(f'{path.name}, rule {rule.id}: empty matches are not allowed')
        except (regex.error, TimeoutError):
            raise ScannerExecutionError(f'{path.name}, rule {rule.id}: invalid or excessive regex') from None
        result.append((rule, compiled))
    return tuple(result)


class HeuristicRuleScanner(CustomPatternScanner):
    name = 'heuristic-rules'
    metadata = ScannerMetadata(name, 'Rule-driven heuristics', version=__version__,
                               configuration_requirements=('ORGSCAN_HEURISTIC_RULES_PATH (optional; bundled starter JSON)',),
                               file_settings=('heuristic_rules_path',))

    def __init__(self, *, settings=None):
        super().__init__(patterns=())
        self.rule_path = Path(settings.heuristic_rules_path) if settings and settings.heuristic_rules_path else DEFAULT_RULES
        self.match_timeout = settings.heuristic_match_timeout_seconds if settings else 0.05

    def readiness(self):
        try:
            load_rules(self.rule_path)
        except ScannerExecutionError as exc:
            return ScannerReadiness(False, 'missing_configuration', missing_requirements=(str(exc),))
        return ScannerReadiness(True, 'ready', version=__version__)

    def scan_path(self, target: Path):
        rules = load_rules(self.rule_path)
        root = target.resolve() if target.is_dir() else target.resolve().parent
        findings = []
        for path in self._iter_files(target):
            if path.is_symlink() or not path.resolve().is_relative_to(root) or '.git' in path.parts:
                continue
            if path.stat().st_size > self.max_file_bytes:
                continue
            try:
                content = read_text(path, root, self.max_file_bytes)
            except (OSError, UnicodeError):
                continue
            if '\x00' in content:
                continue
            relative = path.resolve().relative_to(root).as_posix()
            for rule, compiled in rules:
                if not any(fnmatchcase(relative, p) for p in rule.include) or any(fnmatchcase(relative, p) for p in rule.exclude):
                    continue
                for number, line in enumerate(content.splitlines(), 1):
                    try:
                        for matched in compiled.finditer(line, timeout=self.match_timeout):
                            value = matched.groupdict().get('value') or matched.group()
                            if not value or should_skip_pattern_match('generic-secret-assignment', matched.group()):
                                continue
                            metadata = {'path':str(path), 'rule':rule.id}
                            if rule.category != 'secret':
                                metadata['observation_digest'] = sha256(value.encode()).hexdigest()
                            if rule.category == 'secret' and matched.groupdict().get('value') and 'PRIVATE KEY-----' not in value:
                                metadata['secret_digest'] = sha256(value.encode()).hexdigest()
                            findings.append(ScanMatch(path, number, number, rule.category, rule.title, rule.description,
                                                      rule.severity, rule.confidence, '<redacted>', f'<redacted:{rule.id}>',
                                                      rule.remediation, {'rule':rule.id}, metadata))
                    except TimeoutError:
                        raise ScannerExecutionError(f'Rule {rule.id} exceeded the per-line matching timeout') from None
        return findings
