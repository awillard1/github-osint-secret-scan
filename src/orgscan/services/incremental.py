"""Conservative repository scope decisions, independent of transport adapters."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryScanDecision:
    action: str
    reason: str
    start_oid: str | None
    end_oid: str | None
    commit_range: str | None = None


def decide_scan(*, mode: str, checkpoint, oid: str | None, supports_history: bool,
                supports_incremental: bool, is_ancestor) -> RepositoryScanDecision:
    start = checkpoint.oid if checkpoint else None
    if oid is None:
        return RepositoryScanDecision('skip', 'ref-deleted', start, None)
    if mode != 'incremental':
        return RepositoryScanDecision('history' if supports_history else 'full', 'explicit-' + mode, start, oid)
    if checkpoint is None:
        return RepositoryScanDecision('history' if supports_history else 'full', 'first-scan-or-configuration-changed', None, oid)
    if start == oid:
        return RepositoryScanDecision('skip', 'unchanged', start, oid)
    if not is_ancestor(start, oid):
        return RepositoryScanDecision('history' if supports_history else 'full', 'diverged-or-checkpoint-unavailable', start, oid)
    if supports_history and supports_incremental:
        return RepositoryScanDecision('incremental', 'fast-forward', start, oid, f'{start}..{oid}')
    return RepositoryScanDecision('full', 'changed-full-tree-required', start, oid)


def select_refs(plan, repository, available: dict[str, str]) -> list[str]:
    """Selected refs keep user order; all branches have deterministic ordering."""
    if plan.branch_policy == 'selected':
        return list(plan.refs)
    if plan.branch_policy == 'all':
        return sorted(ref.removeprefix('refs/remotes/origin/') for ref in available if ref.startswith('refs/remotes/origin/'))
    if plan.branch_policy == 'tracked':
        tracked = (repository.metadata_json or {}).get('tracked_refs') or []
        if tracked:
            return list(dict.fromkeys(tracked))
    if repository.default_branch:
        return [repository.default_branch]
    raise ValueError('Repository default branch is unknown; synchronize the cache first')
