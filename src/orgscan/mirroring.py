from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from orgscan.config import Settings
from orgscan.repositories import Storage


class MirrorError(RuntimeError):
    pass


def mirror_directory(settings: Settings) -> Path:
    path = settings.mirror_base_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def mirror_path_for_repository(settings: Settings, repository_full_name: str) -> Path:
    safe_name = repository_full_name.strip().replace("/", "__").replace("\\", "__")
    return mirror_directory(settings) / safe_name


def sync_repository_mirror(
    storage: Storage,
    *,
    settings: Settings,
    repository_full_name: str,
    provider: str = "github",
    clone_url: str | None = None,
    refs: list[str] | None = None,
) -> tuple[object, bool]:
    repository, created = storage.get_or_create_repository(
        repository_full_name,
        provider=provider,
        url=clone_url or f"https://github.com/{repository_full_name}.git",
    )
    target_path = mirror_path_for_repository(settings, repository_full_name)
    repo_url = clone_url or repository.url or f"https://github.com/{repository_full_name}.git"
    if not target_path.exists():
        _run_git(["git", "clone", "--filter=blob:none", repo_url, str(target_path)], "clone mirror")
    else:
        if not (target_path / ".git").exists():
            raise MirrorError(f"Mirror path exists but is not a git repository: {target_path}")
        _run_git(["git", "-C", str(target_path), "remote", "set-url", "origin", repo_url], "update mirror origin")
    _run_git(
        [
            "git",
            "-C",
            str(target_path),
            "fetch",
            "--prune",
            "--tags",
            "--force",
            "--filter=blob:none",
            "origin",
        ],
        "sync mirror fetch",
    )
    resolved_refs = _normalize_refs(refs)
    if resolved_refs:
        for ref_name in resolved_refs:
            checkout_mirror_ref(target_path, ref_name)
    else:
        current_branch = _git_stdout(["git", "-C", str(target_path), "rev-parse", "--abbrev-ref", "HEAD"], "resolve mirror branch")
        if current_branch and current_branch != "HEAD":
            _run_git(["git", "-C", str(target_path), "reset", "--hard", f"origin/{current_branch}"], "fast-forward mirror branch")
    metadata = dict(repository.metadata_json or {})
    metadata["tracked_refs"] = resolved_refs
    metadata["available_refs"] = list_remote_refs(target_path)
    if resolved_refs:
        metadata["current_ref"] = resolved_refs[-1]
    repository.metadata_json = metadata
    repository.mirror_path = str(target_path)
    repository.last_mirrored_at = datetime.now(UTC)
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


def scan_repository_mirror_refs(
    storage: Storage,
    *,
    settings: Settings,
    repository_full_name: str,
    scanner_name: str,
    refs: list[str] | None = None,
    provider: str = "github",
    clone_url: str | None = None,
    resync: bool = False,
):
    from orgscan.runner import execute_scan

    resolved_refs = _normalize_refs(refs)
    repository = storage.get_repository_by_full_name(repository_full_name)
    if resync:
        repository, _ = sync_repository_mirror(
            storage,
            settings=settings,
            repository_full_name=repository_full_name,
            provider=provider,
            clone_url=clone_url,
            refs=resolved_refs,
        )
    if repository is None:
        repository = storage.get_repository_by_full_name(repository_full_name)
    if repository is None or not repository.mirror_path:
        raise MirrorError(f"Repository mirror is not configured for {repository_full_name}")
    mirror_path = Path(repository.mirror_path)
    if not mirror_path.exists():
        raise MirrorError(f"Repository mirror path does not exist: {mirror_path}")
    scan_refs = resolved_refs or _default_scan_refs(repository)
    if not scan_refs:
        scan_refs = [_current_mirror_ref(mirror_path)]
    results = []
    for ref_name in scan_refs:
        checkout_mirror_ref(mirror_path, ref_name)
        metadata = dict(repository.metadata_json or {})
        metadata["current_ref"] = ref_name
        repository.metadata_json = metadata
        storage.session.flush()
        results.append(
            execute_scan(
                storage,
                target_path=mirror_path,
                scanner_name=scanner_name,
                settings=settings,
                organization_id=repository.organization_id,
                repository_id=repository.id,
                target_type="mirror",
                target_id=repository.full_name,
                target_ref=ref_name,
                scope_json={
                    "mode": "mirror",
                    "repository_full_name": repository.full_name,
                    "mirror_path": str(mirror_path),
                    "ref_name": ref_name,
                },
                command_line=f"orgscan scan-mirror {repository.full_name} --scanner {scanner_name} --ref {ref_name}",
                tool_target=f"{repository.full_name}@{ref_name}",
            )
        )
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


def _run_git(command: list[str], action: str) -> None:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise MirrorError(completed.stderr.strip() or f"Failed to {action}")


def _git_stdout(command: list[str], action: str) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise MirrorError(completed.stderr.strip() or f"Failed to {action}")
    return completed.stdout.strip()


def _ref_exists(target_path: Path, ref_name: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(target_path), "rev-parse", "--verify", "--quiet", ref_name],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0
