from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.scheduler import execute_scheduled_scan
from orgscan.services.scan_plan import PROFILES, ScanPlan, resolve_scan_plan
from orgscan.services.scan_service import execute_plan


@pytest.mark.parametrize('profile,scanners,provider', [
    ('quick', ('custom-patterns',), None),
    ('standard', ('custom-patterns', 'repo-governance'), None),
    ('comprehensive', ('custom-patterns', 'repo-governance', 'gitleaks', 'detect-secrets', 'semgrep', 'trufflehog', 'yara', 'ripgrep-heuristics'), None),
    ('history', ('git-history-patterns',), None),
    ('secrets-only', ('custom-patterns', 'gitleaks', 'detect-secrets', 'trufflehog'), None),
    ('osint-only', (), 'github-search'), ('domain-only', (), 'local-metadata'),
    ('governance-only', ('repo-governance',), None),
])
def test_every_profile_is_explicit_and_round_trips(profile, scanners, provider):
    plan = resolve_scan_plan(target='example.com' if provider else '/repo', target_type='domain' if provider else 'path', profile=profile)
    assert plan.scanners == scanners
    assert plan.discovery_provider == provider
    assert ScanPlan.model_validate_json(plan.model_dump_json()) == plan
    assert plan == resolve_scan_plan(target=plan.target, target_type=plan.target_type, profile=profile)


def test_override_precedence_and_legacy_defaults():
    assert resolve_scan_plan(target='/repo').scanners == ('custom-patterns',)
    assert resolve_scan_plan(target='org/repo', target_type='mirror').scanners == ('git-history-patterns',)
    plan = resolve_scan_plan(target='org/repo', target_type='mirror', profile='standard', scanners=['repo-governance'],
                             refs=['release', 'release', 'stable'], timeout_seconds=12, history_policy='current-ref',
                             settings=Settings(scanner_timeout_seconds=8))
    assert plan.scanners == ('repo-governance',)
    assert plan.refs == ('release', 'stable')
    assert plan.branch_policy == 'selected'
    assert plan.timeout_seconds == 12
    assert plan.history_policy == 'current-ref'


@pytest.mark.parametrize('kwargs', [
    {'profile':'unknown'}, {'profile':'domain-only'}, {'scanners':[]}, {'scanners':['unknown']},
    {'refs':['main']}, {'mode':'incremental'}, {'profile':'history', 'scanners':['custom-patterns']},
    {'timeout_seconds':0}, {'target_type':'mirror','branch_policy':'selected'},
])
def test_incompatible_intent_is_rejected(kwargs):
    with pytest.raises(ValueError):
        resolve_scan_plan(target='/repo', **kwargs)


def test_synchronous_and_scheduled_plans_persist_identical_intent(tmp_path):
    url = f'sqlite:///{tmp_path / "plans.db"}'
    init_db(url)
    sample = tmp_path / 'sample.txt'
    sample.write_text('safe content')
    plan = resolve_scan_plan(target=str(sample), profile='standard', timeout_seconds=17)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        direct = execute_plan(storage, plan)
        scheduled = storage.create_scheduled_scan('path', str(sample), 'unused-legacy-name', datetime.now(UTC),
                                                  metadata_json={'scan_plan': plan.serialized()})
        queued = execute_scheduled_scan(storage, scheduled)
        assert [r.scanner for r in direct] == [r.scanner for r in queued] == list(plan.scanners)
        assert len(storage.list_scan_jobs()) == 4
        assert all(job.parameters_json['scan_plan'] == plan.serialized() for job in storage.list_scan_jobs())


def test_domain_plan_uses_existing_provider_and_records_intent(monkeypatch, tmp_path):
    url = f'sqlite:///{tmp_path / "domain.db"}'
    init_db(url)
    seen = []
    monkeypatch.setattr('orgscan.providers.get_domain_provider', lambda name, settings: SimpleNamespace(discover=lambda storage, target: seen.append((name,target))))
    plan = resolve_scan_plan(target='example.com', target_type='domain', profile='domain-only')
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = execute_plan(storage, plan)
        assert seen == [('local-metadata', 'example.com')]
        assert result[0].findings == 0
        assert storage.list_scan_jobs()[0].parameters_json['scan_plan'] == plan.serialized()
