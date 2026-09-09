import subprocess
from pathlib import Path

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.mirroring import scan_repository_mirror, sync_repository_mirror
from orgscan.repositories import Storage


def _git(*args: str, cwd: Path) -> None:
    completed = subprocess.run(["git", *args], cwd=cwd, check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def test_sync_and_scan_repository_mirror(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git("init", cwd=source)
    _git("config", "user.email", "test@example.com", cwd=source)
    _git("config", "user.name", "Test User", cwd=source)
    (source / "config.py").write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")
    _git("add", "config.py", cwd=source)
    _git("commit", "-m", "seed", cwd=source)

    remote = tmp_path / "remote.git"
    completed = subprocess.run(["git", "clone", "--bare", str(source), str(remote)], check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr

    database_url = f"sqlite:///{tmp_path / 'mirror.db'}"
    init_db(database_url)
    settings = Settings(database_url=database_url, data_dir=tmp_path / "data")
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        record, created = sync_repository_mirror(
            storage,
            settings=settings,
            repository_full_name="example-org/app",
            clone_url=str(remote),
        )
        session.commit()
        result = scan_repository_mirror(
            storage,
            settings=settings,
            repository_full_name="example-org/app",
            scanner_name="custom-patterns",
        )
        session.commit()
        findings = storage.list_findings()

    assert created is True
    assert record.mirror_path is not None
    assert (Path(record.mirror_path) / "config.py").exists()
    assert result.findings == 1
    assert len(findings) == 1
