import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.mirroring import RepositoryMirrorManager, MirrorError, sync_repository_mirror, scan_repository_mirror_refs
from orgscan.repositories import Storage
from orgscan.repository_state import RepositoryCheckpoint


def git(root, *args):
    result = subprocess.run(['git', *args], cwd=root, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def cache(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    git(source, 'init', '-b', 'trunk')
    git(source, 'config', 'user.email', 'test@example.com')
    git(source, 'config', 'user.name', 'Test')
    (source / 'config.py').write_text('api_key = "prod-token-1234567890abcdef"\n')
    git(source, 'add', '.')
    git(source, 'commit', '-m', 'seed')
    remote = tmp_path / 'remote.git'
    git(tmp_path, 'clone', '--bare', str(source), str(remote))
    url = f'sqlite:///{tmp_path / "cache.db"}'
    init_db(url)
    settings = Settings(database_url=url, data_dir=tmp_path / 'data')
    with create_session_factory(url)() as session:
        storage = Storage(session)
        manager = RepositoryMirrorManager(settings, 'example/repo')
        repo, _ = manager.sync(storage, clone_url=str(remote))
        yield source, remote, storage, settings, manager, repo


def test_sync_reuses_cache_and_separates_observations_from_checkpoints(cache):
    source, remote, storage, settings, manager, repo = cache
    assert repo.default_branch == 'trunk'
    original = repo.metadata_json['repository_state']['current_refs']
    marker = manager.path / '.git' / 'cache-marker'
    marker.write_text('preserve')
    manager.sync(storage)
    assert marker.exists()
    assert repo.metadata_json['repository_state']['previous_refs'] == original
    assert repo.metadata_json['repository_state']['current_refs'] == original
    (source / 'next.txt').write_text('next')
    git(source, 'add', '.')
    git(source, 'commit', '-m', 'next')
    git(source, 'push', str(remote), 'trunk')
    manager.sync(storage)
    state = repo.metadata_json['repository_state']
    assert state['previous_refs'] == original
    assert state['current_refs'] != original
    assert state['checkpoints'] == {}


def test_success_checkpoint_failure_preservation_cleanup_and_stable_hashes(cache, monkeypatch):
    source, remote, storage, settings, manager, repo = cache
    def scan():
        return scan_repository_mirror_refs(storage, settings=settings, repository_full_name='example/repo', scanner_name='custom-patterns')
    scan()
    checkpoints = repo.metadata_json['repository_state']['checkpoints']
    assert checkpoints
    hashes = [finding.normalized_hash for finding in storage.list_findings()]
    scan()
    assert [finding.normalized_hash for finding in storage.list_findings()] == hashes
    assert all('.worktrees' not in str(f.metadata_json) for f in storage.list_findings())
    previous = dict(repo.metadata_json['repository_state']['checkpoints'])
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic scan failure')
    monkeypatch.setattr('orgscan.runner.execute_scan', fail)
    with pytest.raises(RuntimeError):
        scan()
    assert repo.metadata_json['repository_state']['checkpoints'] == previous
    assert list((manager.path.parent / '.worktrees').iterdir()) == []
    assert len(git(manager.path, 'worktree', 'list', '--porcelain').split('worktree ')) == 2


def test_materialization_removes_external_symlink_and_never_runs_hooks(cache, tmp_path):
    source, remote, storage, settings, manager, repo = cache
    outside = tmp_path / 'outside.txt'
    outside.write_text('must not be scanned')
    (source / 'escape').symlink_to(outside)
    git(source, 'add', '.')
    git(source, 'commit', '-m', 'link')
    git(source, 'push', str(remote), 'trunk')
    marker = tmp_path / 'hook-ran'
    hook = manager.path / '.git' / 'hooks' / 'post-checkout'
    hook.write_text(f'#!/bin/sh\ntouch {marker}\n')
    hook.chmod(0o755)
    manager.sync(storage)
    with manager.materialize('trunk') as (worktree, ref, oid):
        assert not (worktree / 'escape').exists()
        assert not (worktree / 'escape').is_symlink()
        assert (worktree / 'config.py').exists()
    assert not marker.exists()
    assert outside.read_text() == 'must not be scanned'


def test_lock_contention_is_bounded_and_released(cache):
    _, _, _, settings, manager, _ = cache
    other = RepositoryMirrorManager(settings.model_copy(update={'git_timeout_seconds':0.1}), 'example/repo')
    def attempt():
        with other.locked():
            return True
    with manager.locked(), ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(MirrorError, match='lock'):
            pool.submit(attempt).result(timeout=2)
    assert attempt() is True


def test_failed_fetch_keeps_observations(cache, monkeypatch):
    _, _, storage, _, manager, repo = cache
    before = dict(repo.metadata_json['repository_state'])
    def timeout(command, **kwargs):
        assert kwargs['timeout'] == 300
        assert kwargs['capture_output']
        raise subprocess.TimeoutExpired(command, 300, stderr='private-value')
    monkeypatch.setattr('orgscan.mirroring.subprocess.run', timeout)
    with pytest.raises(MirrorError, match='timed out') as error:
        manager.sync(storage)
    assert 'private-value' not in str(error.value)
    assert repo.metadata_json['repository_state'] == before


def test_existing_repository_json_preserved_when_adding_checkpoint(cache):
    _, _, storage, settings, manager, repo = cache
    repo.metadata_json = {'legacy_key':'retained'}
    storage.session.commit()
    manager.sync(storage)
    cp = RepositoryCheckpoint('refs/remotes/origin/trunk','custom-patterns','key','abc',1,datetime.now(UTC).isoformat())
    storage.record_repository_checkpoint(repo, cp)
    storage.session.commit()
    storage.session.expire_all()
    assert repo.metadata_json['legacy_key'] == 'retained'
    assert storage.get_repository_checkpoint(repo,ref=cp.ref,scanner=cp.scanner,configuration_key='key') == cp


def test_remote_default_branch_change_is_discovered(cache):
    source, remote, storage, settings, manager, repo = cache
    git(source, 'checkout', '-b', 'release')
    git(source, 'push', str(remote), 'release')
    git(remote, 'symbolic-ref', 'HEAD', 'refs/heads/release')
    manager.sync(storage)
    assert repo.default_branch == 'release'
    assert repo.metadata_json['repository_state']['default_branch'] == 'release'


@pytest.mark.parametrize('name', ['../outside', '/tmp/repo', 'owner/..', 'owner/repo/extra'])
def test_repository_paths_are_contained(tmp_path, name):
    with pytest.raises(MirrorError):
        RepositoryMirrorManager(Settings(data_dir=tmp_path), name)


def test_cache_names_do_not_collide_at_owner_separator(tmp_path):
    settings = Settings(data_dir=tmp_path)
    assert RepositoryMirrorManager(settings, 'owner_/repo').path != RepositoryMirrorManager(settings, 'owner/_repo').path
