from dataclasses import replace

import pytest

from orgscan.mirroring import scan_repository_mirror_refs, MirrorError
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan
from orgscan.scanners.base import ScannerExecutionError

# Reuse the small local Git fixture used by the cache engine tests.
from test_repository_cache import cache, git


def plan_for(settings, **kwargs):
    return resolve_scan_plan(target='example/repo', target_type='mirror', settings=settings,
                             scanners=kwargs.pop('scanners', ['custom-patterns']), mode=kwargs.pop('mode', 'incremental'), **kwargs)


def run(cache, plan, **kwargs):
    _, _, storage, settings, _, _ = cache
    return execute_plan(storage, plan, settings=settings, **kwargs)


def commit_push(cache, name='next.txt', text='safe'):
    source, remote, *_ = cache
    (source / name).write_text(text)
    git(source, 'add', '.')
    git(source, 'commit', '-m', name)
    git(source, 'push', str(remote), 'trunk')
    return git(source, 'rev-parse', 'HEAD')


def test_first_scan_unchanged_skip_and_explicit_full(cache, monkeypatch):
    _, _, storage, settings, manager, repo = cache
    plan = plan_for(settings)
    first = run(cache, plan)[0]
    assert first.status == 'completed'
    original = dict(repo.metadata_json['repository_state']['checkpoints'])
    first_scope = storage.get_scan_job(first.scan_job_id).scope_json
    assert first_scope['decision']['reason'] == 'first-scan-or-configuration-changed'
    with monkeypatch.context() as patch:
        patch.setattr('orgscan.mirroring.RepositoryMirrorManager.materialize', lambda *a: pytest.fail('Unchanged target must not materialize'))
        skipped = run(cache, plan)[0]
    assert skipped.status == 'skipped'
    assert skipped.skip_reason == 'unchanged'
    assert repo.metadata_json['repository_state']['checkpoints'] == original
    assert storage.get_scan_job(skipped.scan_job_id).scope_json['coverage'] == 'none'
    assert run(cache, plan_for(settings, mode='full'))[0].status == 'completed'


def test_changed_content_requires_full_tree_and_configuration_change_invalidates(cache):
    _, _, storage, settings, _, _ = cache
    plan = plan_for(settings)
    run(cache, plan)
    oid = commit_push(cache)
    result = run(cache, plan, resync=True)[0]
    scope = storage.get_scan_job(result.scan_job_id).scope_json
    assert scope['decision']['reason'] == 'changed-full-tree-required'
    assert scope['commit_oid'] == oid
    assert scope['coverage'] == 'tree'
    changed = plan_for(settings, scope={'rule_revision':'v2'})
    assert run(cache, changed)[0].status == 'completed'


def test_history_range_covers_all_new_commits_even_above_limit(cache):
    _, _, storage, settings, _, _ = cache
    # Keep the initial history window tiny; incremental ranges must not truncate.
    settings.git_history_max_commits = 1
    plan = plan_for(settings, scanners=['git-history-patterns'])
    first = run(cache, plan)[0]
    previous = storage.get_scan_job(first.scan_job_id).scope_json['commit_oid']
    secret_oid = commit_push(cache, 'secret.txt', 'api_key = "new-token-abcdef1234567890"\n')
    latest = commit_push(cache, 'safe.txt')
    result = run(cache, plan, resync=True)[0]
    scope = storage.get_scan_job(result.scan_job_id).scope_json
    assert scope['commit_range'] == f'{previous}..{latest}'
    assert scope['history_max_commits'] is None
    assert scope['coverage'] == 'commit-range'
    assert result.findings >= 1
    assert any(f.metadata_json.get('commit_sha') == secret_oid for f in storage.list_findings())
    assert run(cache, plan)[0].status == 'skipped'
    assert run(cache, plan_for(settings, scanners=['git-history-patterns'], mode='history'))[0].status == 'completed'


def test_new_branch_and_deleted_branch_are_recorded_without_stale_local_scans(cache):
    source, remote, storage, settings, _, repo = cache
    plan = plan_for(settings, branch_policy='all')
    run(cache, plan)
    git(source, 'checkout', '-b', 'new-branch')
    git(source, 'push', str(remote), 'new-branch')
    results = run(cache, plan, resync=True)
    assert {r.target:r.status for r in results} == {'example/repo@new-branch':'completed','example/repo@trunk':'skipped'}
    old = dict(repo.metadata_json['repository_state']['checkpoints'])
    git(source, 'push', str(remote), '--delete', 'new-branch')
    results = run(cache, plan, resync=True)
    deleted = next(r for r in results if r.skip_reason == 'ref-deleted')
    assert storage.get_scan_job(deleted.scan_job_id).scope_json['commit_oid'] is None
    assert repo.metadata_json['repository_state']['checkpoints'] == old
    selected = plan_for(settings, refs=['new-branch'])
    assert run(cache, selected, resync=True)[0].skip_reason == 'ref-deleted'
    with pytest.raises(MirrorError, match='not available'):
        run(cache, plan_for(settings, refs=['typo']))


def test_force_push_falls_back_and_failed_scan_does_not_advance(cache, monkeypatch):
    source, remote, storage, settings, _, repo = cache
    plan = plan_for(settings, scanners=['git-history-patterns'])
    run(cache, plan)
    old = dict(repo.metadata_json['repository_state']['checkpoints'])
    git(source, 'checkout', '--orphan', 'rewritten')
    git(source, 'add', '.')
    git(source, 'commit', '-m', 'unrelated root')
    git(source, 'push', '--force', str(remote), 'HEAD:trunk')
    with monkeypatch.context() as patch:
        def fail(*args, **kwargs):
            raise ScannerExecutionError('Synthetic scanner failure')
        patch.setattr('orgscan.scanners.git_history.GitHistoryPatternScanner.scan_path_with_context', fail)
        with pytest.raises(ScannerExecutionError):
            run(cache, plan, resync=True)
    assert repo.metadata_json['repository_state']['checkpoints'] == old
    assert storage.list_scan_jobs()[0].status == 'failed'
    result = run(cache, plan)[0]
    scope = storage.get_scan_job(result.scan_job_id).scope_json
    assert scope['decision']['reason'] == 'diverged-or-checkpoint-unavailable'
    assert scope['commit_range'] is None
    assert scope['coverage'] == 'history'
    assert repo.metadata_json['repository_state']['checkpoints'] != old


def test_default_selected_and_legacy_tracked_policies(cache):
    source, remote, storage, settings, manager, repo = cache
    git(source, 'checkout', '-b', 'release')
    git(source, 'push', str(remote), 'release')
    manager.sync(storage, refs=['release'])
    assert run(cache, plan_for(settings))[0].target.endswith('@release')
    assert run(cache, plan_for(settings, branch_policy='default-only'))[0].target.endswith('@trunk')
    assert run(cache, plan_for(settings, refs=['release']))[0].target.endswith('@release')


def test_annotated_tag_change_and_explicit_tag_selection(cache):
    source, remote, storage, settings, _, _ = cache
    git(source, 'tag', '-a', 'v1', '-m', 'first annotation')
    git(source, 'push', str(remote), 'v1')
    plan = plan_for(settings, refs=['refs/tags/v1'])
    run(cache, plan, resync=True)
    assert run(cache, plan)[0].status == 'skipped'
    git(source, 'tag', '-f', '-a', 'v1', '-m', 'new annotation')
    git(source, 'push', '--force', str(remote), 'v1')
    result = run(cache, plan, resync=True)[0]
    assert storage.get_scan_job(result.scan_job_id).scope_json['decision']['reason'] == 'ref-object-changed'


def test_concurrent_jobs_share_success_checkpoint(cache, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from orgscan.db import create_session_factory
    from orgscan.repositories import Storage
    _, _, _, settings, _, _ = cache
    calls = []
    def scan(self, path):
        calls.append(path)
        return []
    monkeypatch.setattr('orgscan.scanners.custom_patterns.CustomPatternScanner.scan_path', scan)
    plan = plan_for(settings)
    def job():
        with create_session_factory(settings.database_url)() as session:
            return execute_plan(Storage(session), plan, settings=settings)[0].status
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: job(), range(2)))
    assert sorted(statuses) == ['completed','skipped']
    assert len(calls) == 1


@pytest.mark.parametrize('backend', ['rq','db'])
def test_queued_incremental_plan_can_complete_with_all_scanners_skipped(cache, backend, monkeypatch):
    monkeypatch.setattr("orgscan.queueing.SafeWorker._start_scheduler", lambda *a, **k: None)
    from datetime import UTC, datetime
    import fakeredis
    from orgscan.queueing import enqueue_due_scheduled_scans, run_worker
    _, _, storage, settings, _, _ = cache
    settings.scan_queue_backend = backend
    settings.scan_queue_poll_interval_seconds = 0.01
    plan = plan_for(settings)
    run(cache, plan)
    scheduled = storage.create_scheduled_scan('mirror', plan.target, plan.scanners[0], datetime.now(UTC), cadence='manual',
                                               metadata_json={'scan_plan':plan.serialized(),'resync_before_run':False})
    storage.session.commit()
    connection = fakeredis.FakeRedis()
    assert enqueue_due_scheduled_scans(settings, connection=connection)
    assert run_worker(settings, burst=True, connection=connection, max_jobs=1)
    storage.session.expire_all()
    assert storage.list_scan_jobs()[0].status == 'skipped'
    assert scheduled.metadata_json['queue_status'] == 'completed'
    assert scheduled.enabled is False


def test_rule_file_change_invalidates_same_path_configuration(cache, tmp_path):
    from orgscan.repository_state import scanner_configuration_key
    _, _, _, settings, _, _ = cache
    rules = tmp_path / 'rules.yar'
    rules.write_text('rule first { condition: true }')
    settings.yara_rules_path = str(rules)
    plan = plan_for(settings, scanners=['yara'])
    before = scanner_configuration_key(settings, plan, 'yara')
    rules.write_text('rule second { condition: true }')
    assert scanner_configuration_key(settings, plan, 'yara') != before


def test_cli_mode_and_branch_policy_reach_plan_and_schedule(cache, monkeypatch):
    import json
    from typer.testing import CliRunner
    from orgscan.cli import app
    from orgscan.config import get_settings
    _, _, storage, settings, _, _ = cache
    monkeypatch.setenv('ORGSCAN_DATABASE_URL', settings.database_url)
    monkeypatch.setenv('ORGSCAN_DATA_DIR', str(settings.data_dir))
    get_settings.cache_clear()
    try:
        args = ['scan-mirror','example/repo','--scanner','custom-patterns','--mode','incremental','--branch-policy','default-only','--json']
        runner = CliRunner()
        first = runner.invoke(app,args)
        assert first.exit_code == 0, first.output
        second = runner.invoke(app,args)
        assert second.exit_code == 0, second.output
        assert json.loads(second.stdout)['results'][0]['skip_reason'] == 'unchanged'
        scheduled = runner.invoke(app,['schedule-mirror-scan','example/repo','--scanner','custom-patterns','--mode','incremental','--branch-policy','all','--no-resync'])
        assert scheduled.exit_code == 0, scheduled.output
        storage.session.expire_all()
        plan = storage.list_scheduled_scans()[0].metadata_json['scan_plan']
        assert plan['mode'] == 'incremental'
        assert plan['branch_policy'] == 'all'
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize('scope', [{'commit_range':'--all'},{'commit_oid':'--all'}])
def test_history_revisions_cannot_be_options(scope):
    from orgscan.scanners.git_history import GitHistoryPatternScanner
    with pytest.raises(ScannerExecutionError):
        GitHistoryPatternScanner._revision_args(target_ref=None, scope_json=scope)


def test_mirror_adapter_rejects_mismatched_plan_before_execution(cache):
    _, _, storage, settings, _, _ = cache
    plan = resolve_scan_plan(target='other/repo', target_type='mirror', scanners=['custom-patterns'])
    with pytest.raises(ValueError, match='does not match'):
        scan_repository_mirror_refs(storage, settings=settings, repository_full_name='example/repo',
                                    scanner_name='custom-patterns', plan=plan)
    assert storage.list_scan_jobs() == []


def test_unchanged_repository_rescanned_after_effective_json_rules_change(cache, tmp_path):
    import json
    from orgscan.scanners.heuristic_rules import DEFAULT_RULES
    _, _, _, settings, _, _ = cache
    rules = tmp_path / 'rules.json'
    definitions = json.loads(DEFAULT_RULES.read_text())
    rules.write_text(json.dumps(definitions))
    settings.heuristic_rules_path = str(rules)
    plan = plan_for(settings, scanners=['heuristic-rules'])
    assert run(cache, plan)[0].status == 'completed'
    assert run(cache, plan)[0].status == 'skipped'
    definitions[0]['regex'] = 'phase18_changed_rule_[0-9]+'
    rules.write_text(json.dumps(definitions))
    assert run(cache, plan)[0].status == 'completed'


def test_yara_transitive_include_change_and_unresolved_dependencies(cache, tmp_path):
    from orgscan.repository_state import scanner_configuration_key
    _, _, _, settings, _, _ = cache
    rules, child = tmp_path / 'rules.yar', tmp_path / 'child.yar'
    rules.write_text('include "child.yar"\n')
    child.write_text('rule first { condition: true }')
    settings.yara_rules_path = str(rules)
    plan = plan_for(settings, scanners=['yara'])
    first = scanner_configuration_key(settings, plan, 'yara')
    assert first
    child.write_text('rule second { condition: false }')
    assert scanner_configuration_key(settings, plan, 'yara') != first
    child.write_text('include "missing.yar"\n')
    assert scanner_configuration_key(settings, plan, 'yara') is None


def test_unknown_effective_configuration_never_skips_unchanged_repo(cache, monkeypatch):
    plan = plan_for(cache[3])
    run(cache, plan)
    monkeypatch.setattr('orgscan.repository_state.scanner_configuration_key', lambda *a: None)
    for _ in range(2):
        result = run(cache, plan)[0]
        assert result.status == 'completed'
        assert cache[2].get_scan_job(result.scan_job_id).scope_json['decision']['reason'] == 'configuration-not-fingerprintable'
