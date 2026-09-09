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
    current_branch = _git_stdout(["git", "-C", str(target_path), "rev-parse", "--abbrev-ref", "HEAD"], "resolve mirror branch")
    if current_branch and current_branch != "HEAD":
        _run_git(["git", "-C", str(target_path), "reset", "--hard", f"origin/{current_branch}"], "fast-forward mirror branch")
    repository.mirror_path = str(target_path)
    repository.last_mirrored_at = datetime.now(UTC)
    storage.session.flush()
    return repository, created


def scan_repository_mirror(storage: Storage, *, settings: Settings, repository_full_name: str, scanner_name: str):
    from orgscan.runner import execute_scan

    repository = storage.get_repository_by_full_name(repository_full_name)
    if repository is None or not repository.mirror_path:
        raise MirrorError(f"Repository mirror is not configured for {repository_full_name}")
    mirror_path = Path(repository.mirror_path)
    if not mirror_path.exists():
        raise MirrorError(f"Repository mirror path does not exist: {mirror_path}")
    return execute_scan(
        storage,
        target_path=mirror_path,
        scanner_name=scanner_name,
        settings=settings,
        organization_id=repository.organization_id,
        repository_id=repository.id,
    )


def _run_git(command: list[str], action: str) -> None:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise MirrorError(completed.stderr.strip() or f"Failed to {action}")


def _git_stdout(command: list[str], action: str) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise MirrorError(completed.stderr.strip() or f"Failed to {action}")
    return completed.stdout.strip()
