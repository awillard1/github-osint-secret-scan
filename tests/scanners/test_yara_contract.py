import subprocess
from dataclasses import asdict

import pytest

from orgscan.config import Settings
from orgscan.scanners import get_registry
from orgscan.scanners.base import ScanContext, ScanTarget, ScannerExecutionError
from orgscan.scanners.yara_scanner import YaraScanner


def test_custom_rule_metadata_and_multiple_secrets_are_redacted(tmp_path):
    target = tmp_path / 'file with spaces.env'
    target.write_text('first-private-value second-private-value')
    output = f'company_rule [title="Config exposure",category="secret",secret_value=true,severity="high",confidence="likely",description="Review config",remediation="Rotate credentials"] {target}\n0x0:$a: first-private-value\n0x14:$b: second-private-value\n'
    matches = YaraScanner.parse_output(output, target_root=target)
    assert len(matches) == 2
    assert matches[0].title == 'Config exposure'
    assert matches[0].severity == 'high'
    assert matches[0].remediation_hint == 'Rotate credentials'
    assert matches[0].metadata['secret_digest'] != matches[1].metadata['secret_digest']
    assert 'first-private-value' not in repr([asdict(m) for m in matches])
    assert 'second-private-value' not in repr([asdict(m) for m in matches])


def test_unknown_rule_has_conservative_defaults(tmp_path):
    match = YaraScanner.parse_output(f'company_rule {tmp_path / "file"}\n')[0]
    assert match.confidence == 'heuristic'
    assert match.severity == 'medium'


def test_invalid_metadata_or_escaping_path_fails_safely(tmp_path):
    for output in [f'rule [severity="private-invalid-value"] {tmp_path}/file', 'rule /outside/file']:
        with pytest.raises(ScannerExecutionError) as error:
            YaraScanner.parse_output(output, target_root=tmp_path)
        assert 'private-invalid-value' not in str(error.value)


def test_readiness_version_and_execution_without_real_binary(monkeypatch, tmp_path):
    monkeypatch.setattr('shutil.which', lambda name: '/fake/yara')
    rules = tmp_path / 'rules.yar'
    rules.write_text('rule custom { condition: true }')
    calls = []
    def run(command, **kwargs):
        calls.append((command,kwargs))
        if command[-1] == '--version':
            assert kwargs['timeout'] == 5
            return subprocess.CompletedProcess(command, 0, stdout='4.5.0\n')
        assert '-m' in command and '-N' in command
        assert kwargs['timeout'] == 9
        return subprocess.CompletedProcess(command, 0, stdout=f'custom [title="Custom match"] {tmp_path}/sample')
    monkeypatch.setattr('orgscan.scanners.execution.subprocess.run', run)
    scanner = get_registry().get('yara',settings=Settings(yara_rules_path=str(rules)))
    assert scanner.readiness().version == '4.5.0'
    assert scanner.scan(ScanContext(ScanTarget(tmp_path),timeout_seconds=9)).findings[0].title == 'Custom match'
    assert scanner.metadata.version == '4.5.0'
    assert rules.exists()


def test_version_diagnostics_do_not_leak(monkeypatch):
    monkeypatch.setattr('shutil.which', lambda name:'/fake/yara')
    monkeypatch.setattr('orgscan.scanners.execution.subprocess.run', lambda *a,**k: subprocess.CompletedProcess([],1,stdout='private-output',stderr='private-error'))
    readiness = YaraScanner().readiness()
    assert readiness.ready and readiness.version is None
    assert 'private-' not in repr(readiness)


def test_yara_structural_strings_do_not_cross_correlate_as_credentials(tmp_path):
    output = f'company_rule [category="secret"] {tmp_path}/file\n0x0:$a: password=\n'
    match = YaraScanner.parse_output(output)[0]
    assert "secret_digest" not in match.metadata
    assert "observation_digest" not in match.metadata
