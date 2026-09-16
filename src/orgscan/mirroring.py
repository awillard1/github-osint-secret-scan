from __future__ import annotations

from orgscan import processes as subprocess
import os
import tempfile
import time
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

from orgscan.config import Settings
from orgscan.repositories import Storage


_GIT_TIMEOUT = ContextVar("git_timeout", default=300)
_GIT_ENV = ContextVar("git_connection_environment", default={})
_GIT_OUTPUT_LIMIT = ContextVar("git_output_limit", default=8_000_000)
_GIT_DISK_CHECK = ContextVar("git_disk_check", default=lambda: None)


class MirrorError(RuntimeError):
    pass


def mirror_directory(settings: Settings) -> Path:
    path = settings.mirror_base_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def mirror_path_for_repository(settings: Settings, repository_full_name: str) -> Path:
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository_full_name) or any(part in {".", ".."} for part in repository_full_name.split("/")):
        raise MirrorError("Repository name must be owner/name")
    safe_name = repository_full_name.replace("/", "__")
    if '_' in repository_full_name:
        from hashlib import sha256
        safe_name += '-' + sha256(repository_full_name.encode()).hexdigest()[:16]
    path = mirror_directory(settings).resolve() / safe_name
    if path.is_symlink():
        raise MirrorError("Repository cache path must not be a symlink")
    return path


class RepositoryMirrorManager:
    """Serialize cache mutation and scans; use disposable detached worktrees."""

    def __init__(self, settings: Settings, repository_full_name: str):
        self.settings = settings
        self.repository_full_name = repository_full_name
        self.path = mirror_path_for_repository(settings, repository_full_name)
        self._depth = 0
        self._owner = None

    def _check_disk_budget(self):
        total = 0
        if self.path.exists():
            for root, directories, files in os.walk(self.path, followlinks=False):
                for name in files:
                    total += (Path(root) / name).lstat().st_size
                    if total > self.settings.repository_max_bytes:
                        raise MirrorError('Repository cache exceeds the configured disk budget; quarantine or remove it before retry')

    @contextmanager
    def locked(self):
        if self._depth and self._owner == threading.get_ident():
            self._depth += 1
            try:
                yield self
                self._check_disk_budget()
            finally:
                self._depth -= 1
            return
        try:
            import fcntl
        except ImportError:
            raise MirrorError("Repository locking requires a POSIX host") from None
        lock_path = self.path.parent / (self.path.name + '.lock')
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(lock_path, flags, 0o600), 'w') as handle:
            deadline = time.monotonic() + self.settings.git_timeout_seconds
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise MirrorError("Timed out waiting for repository lock") from None
                    time.sleep(0.05)
            self._depth = 1
            self._owner = threading.get_ident()
            token = _GIT_TIMEOUT.set(self.settings.git_timeout_seconds)
            output_token = _GIT_OUTPUT_LIMIT.set(self.settings.git_output_max_bytes)
            disk_token = _GIT_DISK_CHECK.set(self._check_disk_budget)
            try:
                self._check_disk_budget()
                yield self
                self._check_disk_budget()
            finally:
                _GIT_TIMEOUT.reset(token)
                _GIT_OUTPUT_LIMIT.reset(output_token)
                _GIT_DISK_CHECK.reset(disk_token)
                self._depth = 0
                self._owner = None
                fcntl.flock(handle, fcntl.LOCK_UN)

    def sync(self, storage: Storage, **kwargs):
        with self.locked():
            # Refresh persisted state after acquiring the filesystem lock.
            storage.session.expire_all()
            result = _sync_repository_mirror(storage, settings=self.settings,
                                             repository_full_name=self.repository_full_name, **kwargs)
            storage.session.commit()
            return result

    def inventory(self) -> dict[str, str]:
        with self.locked():
            output = _git_stdout(['git', '-C', str(self.path), 'for-each-ref', '--format=%(refname) %(objectname)',
                                  'refs/remotes/origin', 'refs/tags'], 'inventory mirror refs')
            return {ref: oid for ref, oid in (line.split() for line in output.splitlines()) if ref != 'refs/remotes/origin/HEAD'}

    def resolve_ref(self, ref: str) -> tuple[str, str]:
        if not ref or ref.startswith('-') or ref == 'HEAD':
            raise MirrorError('Select an available branch or tag')
        available = self.inventory()
        names = [ref] if ref.startswith('refs/') else [f'refs/remotes/origin/{ref}', f'refs/tags/{ref}']
        for name in names:
            if name in available:
                oid = _git_stdout(['git', '-C', str(self.path), 'rev-parse', '--verify', name + '^{commit}'], 'resolve ref commit')
                return name, oid
        raise MirrorError(f'Requested mirror ref is not available: {ref}')

    @contextmanager
    def materialize(self, ref: str):
        with self.locked():
            qualified_ref, oid = self.resolve_ref(ref)
            root = self.path.parent / '.worktrees'
            if root.is_symlink():
                raise MirrorError('Worktree root must not be a symlink')
            root.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='scan-', dir=root) as temporary:
                worktree = Path(temporary) / 'checkout'
                try:
                    _run_git(['git', '-C', str(self.path), 'worktree', 'add', '--detach', str(worktree), oid], 'materialize scan worktree')
                    # Scanners must not read links outside the isolated target.
                    for directory, dirs, files in os.walk(worktree, followlinks=False):
                        for name in dirs + files:
                            path = Path(directory) / name
                            if path.is_symlink():
                                try:
                                    path.resolve().relative_to(worktree)
                                except (ValueError, RuntimeError, OSError):
                                    path.unlink()
                    yield worktree, qualified_ref, oid
                finally:
                    if worktree.exists():
                        _run_git(['git', '-C', str(self.path), 'worktree', 'remove', '--force', str(worktree)], 'remove scan worktree')
                    _run_git(['git', '-C', str(self.path), 'worktree', 'prune'], 'prune scan worktrees')


def sync_repository_mirror(storage: Storage, *, settings: Settings, repository_full_name: str, **kwargs):
    return RepositoryMirrorManager(settings, repository_full_name).sync(storage, **kwargs)


def scan_repository_mirror_refs(storage: Storage, *, settings: Settings, repository_full_name: str, **kwargs):
    manager = RepositoryMirrorManager(settings, repository_full_name)
    with manager.locked():
        storage.session.expire_all()
        return _scan_repository_mirror_refs(storage, settings=settings, repository_full_name=repository_full_name,
                                            manager=manager, **kwargs)


def _sync_repository_mirror(
    storage: Storage,
    *,
    settings: Settings,
    repository_full_name: str,
    provider: str = "github",
    clone_url: str | None = None,
    refs: list[str] | None = None,
    checkout_refs: bool = True,
) -> tuple[object, bool]:
    existing = storage.get_repository_by_full_name(repository_full_name)
    repository, created = storage.get_or_create_repository(
        repository_full_name,
        provider=provider,
        url=clone_url or (existing.url if existing else None) or f"https://github.com/{repository_full_name}.git",
    )
    target_path = mirror_path_for_repository(settings, repository_full_name)
    repo_url = clone_url or repository.url or f"https://github.com/{repository_full_name}.git"
    if repo_url.startswith('-') or repo_url.startswith('ext::') or '\n' in repo_url:
        raise MirrorError("Unsupported repository clone URL")
    if not target_path.exists():
        _run_git(["git", "clone", "--no-local", "--filter=blob:none", "--", repo_url, str(target_path)], "clone mirror")
    else:
        if (target_path / ".git").is_symlink() or not (target_path / ".git").is_dir():
            raise MirrorError(f"Mirror path exists but is not a git repository: {target_path}")
        _run_git(["git", "-C", str(target_path), "remote", "set-url", "origin", repo_url], "update mirror origin")
    _run_git(
        [
            "git",
            "-C",
            str(target_path),
            "fetch",
            "--prune",
            "--prune-tags",
            "--tags",
            "--force",
            "--filter=blob:none",
            "origin",
        ],
        "sync mirror fetch",
    )
    head = _git_stdout(['git', '-C', str(target_path), 'ls-remote', '--symref', 'origin', 'HEAD'], 'discover remote default branch')
    default_branch = next((line.split()[1].removeprefix('refs/heads/') for line in head.splitlines() if line.startswith('ref: refs/heads/')), None)
    if not default_branch:
        raise MirrorError('Remote default branch is unavailable')
    resolved_refs = _normalize_refs(refs)
    for ref_name in (resolved_refs if checkout_refs else []) or [default_branch]:
        checkout_mirror_ref(target_path, ref_name)
    metadata = dict(repository.metadata_json or {})
    metadata["tracked_refs"] = resolved_refs
    metadata["available_refs"] = list_remote_refs(target_path)
    metadata["current_ref"] = resolved_refs[-1] if resolved_refs and checkout_refs else default_branch
    repository.metadata_json = metadata
    repository.mirror_path = str(target_path)
    repository.last_mirrored_at = datetime.now(UTC)
    output = _git_stdout(['git', '-C', str(target_path), 'for-each-ref', '--format=%(refname) %(objectname)', 'refs/remotes/origin', 'refs/tags'], 'inventory synced refs')
    inventory = {ref: oid for ref, oid in (line.split() for line in output.splitlines()) if ref != 'refs/remotes/origin/HEAD'}
    storage.record_repository_sync(repository, refs=inventory, default_branch=default_branch)
    storage.session.flush()
    return repository, created


def scan_repository_mirror(
    storage: Storage,
    *,
    settings: Settings,
    repository_full_name: str,
    scanner_name: str,
    ref_name: str | None = None,
):
    results = scan_repository_mirror_refs(
        storage,
        settings=settings,
        repository_full_name=repository_full_name,
        scanner_name=scanner_name,
        refs=[ref_name] if ref_name else None,
    )
    return results[0]


def _scan_repository_mirror_refs(
    storage: Storage,
    *,
    settings: Settings,
    repository_full_name: str,
    scanner_name: str,
    refs: list[str] | None = None,
    provider: str = "github",
    clone_url: str | None = None,
    resync: bool = False,
    plan=None,
    manager: RepositoryMirrorManager,
):
    from dataclasses import asdict
    from orgscan.runner import execute_scan, record_skipped_scan
    from orgscan.scanners import get_registry
    from orgscan.repository_state import RepositoryCheckpoint, scanner_configuration_key
    from orgscan.services.scan_plan import resolve_scan_plan, validate_plan_scanners
    from orgscan.services.incremental import decide_scan, select_refs

    plan = plan or resolve_scan_plan(target=repository_full_name, target_type="mirror", scanners=[scanner_name], refs=refs, settings=settings)
    validate_plan_scanners(plan, settings=settings)
    if plan.target_type != "mirror" or plan.target != repository_full_name:
        raise ValueError("Scan plan target does not match the repository")
    repository = storage.get_repository_by_full_name(repository_full_name)
    tracked = _default_scan_refs(repository) if repository is not None and plan.branch_policy == 'tracked' else []
    if resync:
        repository, _ = manager.sync(storage, provider=provider, clone_url=clone_url,
                                     refs=list(plan.refs) or tracked, checkout_refs=False)
    if repository is None or not repository.mirror_path:
        raise MirrorError(f"Repository mirror is not configured for {repository_full_name}")
    mirror_path = Path(repository.mirror_path)
    if mirror_path.resolve() != manager.path or mirror_path.is_symlink():
        raise MirrorError("Repository mirror path does not match managed cache")
    if not mirror_path.exists():
        raise MirrorError(f"Repository mirror path does not exist: {mirror_path}")
    available = manager.inventory()
    scan_refs = select_refs(plan, repository, available)
    state = (repository.metadata_json or {}).get('repository_state', {})
    previous = state.get('previous_refs', {})
    known = set(previous) | {cp['ref'] for cp in state.get('checkpoints', {}).values()}
    if plan.branch_policy == 'all':
        scan_refs += sorted(ref for ref in previous if ref.startswith('refs/remotes/origin/') and ref not in available)
    # Resolve the whole selection before running any scanner, so typos fail early.
    targets = []
    for ref_name in scan_refs:
        candidates = [ref_name] if ref_name.startswith('refs/') else [f'refs/remotes/origin/{ref_name}', f'refs/tags/{ref_name}']
        qualified = next((ref for ref in candidates if ref in available), None)
        if qualified is not None:
            _, oid = manager.resolve_ref(qualified)
        else:
            qualified = next((ref for ref in candidates if ref in known), None)
            if qualified is None:
                raise MirrorError(f'Requested mirror ref is not available: {ref_name}')
            oid = None
        targets.append((ref_name, qualified, oid))

    def is_ancestor(start, end):
        completed = _git_process(['git', '-C', str(mirror_path), 'merge-base', '--is-ancestor', start, end], 'compare checkpoint ancestry')
        if completed.returncode in (0, 1, 128):
            return completed.returncode == 0
        raise MirrorError('Could not compare checkpoint ancestry')

    results = []
    for ref_name, qualified_ref, oid in targets:
        for scanner_name in plan.scanners:
            metadata = get_registry().get(scanner_name, settings=settings).metadata
            key = scanner_configuration_key(settings, plan, scanner_name)
            checkpoint = storage.get_repository_checkpoint(repository, ref=qualified_ref, scanner=scanner_name, configuration_key=key) if key else None
            decision = decide_scan(mode=plan.mode, checkpoint=checkpoint, oid=oid,
                                   supports_history=metadata.supports_history, supports_incremental=metadata.supports_incremental,
                                   is_ancestor=is_ancestor)
            if key is None and oid is not None:
                from orgscan.services.incremental import RepositoryScanDecision
                decision = RepositoryScanDecision('history' if metadata.supports_history else 'full', 'configuration-not-fingerprintable', None, oid)
            if decision.reason == 'unchanged' and checkpoint.ref_oid != available.get(qualified_ref):
                from orgscan.services.incremental import RepositoryScanDecision
                decision = RepositoryScanDecision('history' if metadata.supports_history else 'full',
                                                  'ref-object-changed', checkpoint.oid, oid)
            scope = {**plan.scope, 'mode': 'mirror', 'history_mode': plan.history_policy,
                     'repository_full_name': repository.full_name, 'mirror_path': str(mirror_path),
                     'ref_name': ref_name, 'qualified_ref': qualified_ref, 'commit_oid': oid, 'ref_oid': available.get(qualified_ref),
                     'commit_range': decision.commit_range, 'decision': asdict(decision),
                     'branch_policy': plan.branch_policy, 'configuration_key': key,
                     'history_max_commits': None if decision.commit_range else settings.git_history_max_commits if metadata.supports_history else None,
                     'coverage': 'none' if decision.action == 'skip' else 'commit-range' if decision.commit_range else 'history' if metadata.supports_history else 'tree'}
            if decision.action == 'skip':
                results.append(record_skipped_scan(storage, plan=plan, scanner_name=scanner_name, ref_name=ref_name,
                                                    scope=scope, reason=decision.reason))
                continue
            with manager.materialize(qualified_ref) as (worktree, _, materialized_oid):
                if materialized_oid != oid:
                    raise MirrorError('Repository ref changed during preparation')
                result = execute_scan(storage, target_path=worktree, canonical_root=mirror_path, scanner_name=scanner_name,
                                      settings=settings, plan=plan, organization_id=repository.organization_id, repository_id=repository.id,
                                      target_type='mirror', target_id=repository.full_name, target_ref=ref_name, scope_json=scope,
                                      command_line=f'orgscan scan-mirror {repository.full_name} --scanner {scanner_name} --ref {ref_name}',
                                      tool_target=f'{repository.full_name}@{ref_name}')
            # Only advance after execution AND materialization cleanup succeed.
            if key is not None:
                storage.record_repository_checkpoint(repository, RepositoryCheckpoint(qualified_ref, scanner_name, key, oid,
                                                                                      result.scan_job_id, datetime.now(UTC).isoformat(), available[qualified_ref]))
            storage.session.commit()
            results.append(result)
    return results


def list_remote_refs(target_path: Path) -> list[str]:
    output = _git_stdout(
        ["git", "-C", str(target_path), "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin", "refs/tags"],
        "list mirror refs",
    )
    values = [line.strip() for line in output.splitlines() if line.strip() and line.strip() != "origin/HEAD"]
    refs = [value.removeprefix("origin/") for value in values]
    return sorted(set(refs))


def checkout_mirror_ref(target_path: Path, ref_name: str) -> str:
    if not ref_name.strip():
        raise MirrorError("Mirror ref name cannot be empty")
    local_heads = _git_stdout(["git", "-C", str(target_path), "branch", "--format=%(refname:short)"], "list mirror branches").splitlines()
    if ref_name in local_heads:
        _run_git(["git", "-C", str(target_path), "checkout", "--force", ref_name], "checkout mirror branch")
        _run_git(["git", "-C", str(target_path), "reset", "--hard", f"origin/{ref_name}"], "fast-forward mirror branch")
        return ref_name
    remote_heads = list_remote_refs(target_path)
    if ref_name in remote_heads:
        if _ref_exists(target_path, f"refs/tags/{ref_name}"):
            _run_git(["git", "-C", str(target_path), "checkout", "--force", "--detach", f"refs/tags/{ref_name}"], "checkout mirror tag")
            return ref_name
        _run_git(["git", "-C", str(target_path), "checkout", "--force", "-B", ref_name, f"origin/{ref_name}"], "checkout mirror branch")
        return ref_name
    raise MirrorError(f"Requested mirror ref is not available: {ref_name}")


def _normalize_refs(refs: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for ref_name in refs or []:
        value = ref_name.strip()
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def _default_scan_refs(repository: object) -> list[str]:
    metadata = getattr(repository, "metadata_json", {}) or {}
    tracked_refs = metadata.get("tracked_refs")
    if isinstance(tracked_refs, list):
        normalized = _normalize_refs([str(value) for value in tracked_refs])
        if normalized:
            return normalized
    current_ref = str(metadata.get("current_ref") or "").strip()
    return [current_ref] if current_ref else []


def _current_mirror_ref(target_path: Path) -> str:
    current = _git_stdout(["git", "-C", str(target_path), "rev-parse", "--abbrev-ref", "HEAD"], "resolve mirror branch")
    if current and current != "HEAD":
        return current
    return "HEAD"


def _git_process(command: list[str], action: str):
    command = [command[0], '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '-c', 'protocol.ext.allow=never', *command[1:]]
    environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, **_GIT_ENV.get()}
    try:
        _GIT_DISK_CHECK.get()()
        result = subprocess.run(command, check=False, capture_output=True, text=True,
                              timeout=_GIT_TIMEOUT.get(), max_output_bytes=_GIT_OUTPUT_LIMIT.get(), env=environment)
        _GIT_DISK_CHECK.get()()
        return result
    except subprocess.OutputLimitExceeded:
        raise MirrorError(f"Git output exceeded the allowed size limit: {action}") from None
    except subprocess.TimeoutExpired:
        raise MirrorError(f'Git operation timed out: {action}') from None
    except OSError:
        raise MirrorError(f'Git operation could not start: {action}') from None


def _run_git(command: list[str], action: str) -> None:
    _git_stdout(command, action)


def _git_stdout(command: list[str], action: str) -> str:
    completed = _git_process(command, action)
    if completed.returncode != 0:
        raise MirrorError(f'Failed to {action} (exit status {completed.returncode})')
    return completed.stdout.strip()


def _ref_exists(target_path: Path, ref_name: str) -> bool:
    return _git_process(['git', '-C', str(target_path), 'rev-parse', '--verify', '--quiet', ref_name], 'check ref').returncode == 0
