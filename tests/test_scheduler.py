import subprocess
from datetime import UTC, datetime
from pathlib import Path

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.scheduler import next_run_from_cadence, run_due_scans


def test_next_run_from_cadence() -> None:
    reference = datetime(2026, 1, 1, tzinfo=UTC)
    assert next_run_from_cadence("hourly", reference).hour == 1
    assert next_run_from_cadence("weekly", reference).day == 8


def test_run_due_scans_executes_scheduled_scan(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scheduled.db'}"
    init_db(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "prod-token-1234567890abcdef"\n', encoding="utf-8")
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        storage.create_scheduled_scan(
            "path",
            str(sample),
            "custom-patterns",
            datetime(2026, 1, 1, tzinfo=UTC),
            cadence="manual",
        )
        session.commit()

    with session_factory() as session:
        storage = Storage(session)
        results = run_due_scans(storage)
        session.commit()

    assert len(results) == 1
    assert results[0].findings == 1


def _git(*args: str, cwd: Path) -> None:
    completed = subprocess.run(["git", *args], cwd=cwd, check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def test_run_due_scans_executes_scheduled_mirror_scan_for_requested_refs(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scheduled-mirror.db'}"
    init_db(database_url)
    source = tmp_path / "source"
    source.mkdir()
    _git("init", cwd=source)
    _git("config", "user.email", "test@example.com", cwd=source)
    _git("config", "user.name", "Test User", cwd=source)
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    _git("add", "app.py", cwd=source)
    _git("commit", "-m", "main", cwd=source)
    _git("checkout", "-b", "release/test", cwd=source)
    (source / "release.env").write_text('api_key = "prod-token-1234567890abcdef"\n', encoding="utf-8")
    _git("add", "release.env", cwd=source)
    _git("commit", "-m", "release", cwd=source)

    remote = tmp_path / "remote.git"
    completed = subprocess.run(["git", "clone", "--bare", str(source), str(remote)], check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        storage.create_scheduled_scan(
            "mirror",
            "example-org/app",
            "custom-patterns",
            datetime(2026, 1, 1, tzinfo=UTC),
            cadence="manual",
            metadata_json={
                "clone_url": str(remote),
                "provider": "github",
                "refs": ["release/test"],
                "resync_before_run": True,
            },
        )
        session.commit()

    settings = Settings(database_url=database_url, data_dir=tmp_path / "data")
    with session_factory() as session:
        storage = Storage(session)
        results = run_due_scans(storage, settings=settings)
        session.commit()

    assert len(results) == 1
    assert results[0].target == "example-org/app@release/test"
    assert results[0].findings == 1
