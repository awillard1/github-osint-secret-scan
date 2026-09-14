import json
from dataclasses import asdict

import pytest

from orgscan.config import Settings
from orgscan.scanners import get_registry
from orgscan.scanners.base import ScannerExecutionError
from orgscan.scanners.heuristic_rules import HeuristicRuleScanner, load_rules, DEFAULT_RULES


def rule(**kwargs):
    return dict(id='test-rule', category='secret', severity='high', confidence='likely',
                regex=r'password=(?P<value>[a-z0-9]+)', title='Credential', description='Credential found',
                remediation='Rotate credential', **kwargs)


def test_data_rule_selection_redaction_and_stable_digests(tmp_path):
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps([rule(include=['*.env'], exclude=['test*'])]))
    target = tmp_path / 'input'
    target.mkdir()
    (target / 'real.env').write_text('password=firstsecret password=secondsecret')
    (target / 'test.env').write_text('password=excludedsecret')
    (target / 'file.txt').write_text('password=ignoredsecret')
    scanner = get_registry().get('heuristic-rules',settings=Settings(heuristic_rules_path=str(rules)))
    assert scanner.readiness().ready
    matches = scanner.scanner.scan_path(target)
    assert len(matches) == 2
    assert matches[0].metadata['secret_digest'] != matches[1].metadata['secret_digest']
    assert 'firstsecret' not in repr([asdict(m) for m in matches])
    (target / 'real.env').write_text('\npassword=firstsecret password=secondsecret')
    assert matches[0].metadata == scanner.scanner.scan_path(target)[0].metadata


@pytest.mark.parametrize('payload', ['invalid', '{}', '[]', '[{}]'])
def test_bad_json_or_schema_does_not_echo_contents(tmp_path,payload):
    path = tmp_path / 'bad.json'
    path.write_text(payload)
    with pytest.raises(ScannerExecutionError,match='bad.json'):
        load_rules(path)


def test_duplicate_and_invalid_regex_diagnostics(tmp_path):
    path = tmp_path / 'rules.json'
    for data, message in [([rule(),rule()],'duplicate rule ID'),([dict(rule(),regex='(')],'invalid or excessive regex'),([dict(rule(),regex='.*')],'empty matches')]:
        path.write_text(json.dumps(data))
        with pytest.raises(ScannerExecutionError,match=message):
            load_rules(path)


def test_timeout_is_bounded_and_does_not_echo_target(tmp_path):
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps([dict(rule(),regex=r'(a+)+$')]))
    target = tmp_path / 'target.txt'
    target.write_text('a'*10000+'!')
    scanner = HeuristicRuleScanner(settings=Settings(heuristic_rules_path=str(path),heuristic_match_timeout_seconds=0.00001))
    with pytest.raises(ScannerExecutionError,match='test-rule.*timeout'):
        scanner.scan_path(target)


def test_starter_rules_cover_intended_signals_and_skip_obvious_noise(tmp_path):
    assert len(load_rules(DEFAULT_RULES)) == 5
    sample = tmp_path / 'deployment.yaml'
    sample.write_text('api.service.internal\npostgres://user:private1234@db/service\n-----BEGIN PRIVATE KEY-----\narn:aws:s3::123456789012:bucket/private\nprivileged: true\n')
    matches = HeuristicRuleScanner().scan_path(sample)
    assert len(matches) == 5
    sample.write_text('example.com\npassword: example\nprivileged: false\n')
    assert HeuristicRuleScanner().scan_path(sample) == []


def test_rules_do_not_follow_external_links_or_scan_binary_files(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    outside = tmp_path / 'outside'
    outside.write_text('api.secret.internal')
    (target / 'link').symlink_to(outside)
    (target / 'binary').write_bytes(b'\x00api.secret.internal')
    assert HeuristicRuleScanner().scan_path(target) == []
