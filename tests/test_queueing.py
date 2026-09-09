from datetime import UTC, datetime
from pathlib import Path

import fakeredis

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.queueing import enqueue_due_scheduled_scans, queue_status, run_worker
from orgscan.repositories import Storage


def test_rq_queue_enqueues_and_processes_scheduled_scan(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'queue.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

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

    connection = fakeredis.FakeRedis()
    settings = Settings(
        database_url=database_url,
        data_dir=tmp_path / "data",
        redis_url="redis://localhost:6379/0",
        scan_queue_name="orgscan:test",
    )

    queued = enqueue_due_scheduled_scans(settings, limit=10, connection=connection)
    assert len(queued) == 1
    status = queue_status(settings, connection=connection)
    assert status["pending_jobs"] == 1
    assert status["retry_max"] == 2
    assert status["retry_intervals"] == [30, 120]

    worked = run_worker(settings, burst=True, connection=connection, max_jobs=1)
    assert worked is True

    with session_factory() as session:
        storage = Storage(session)
        findings = storage.list_findings()
        scheduled = storage.list_scheduled_scans()[0]

    assert len(findings) == 1
    assert scheduled.enabled is False
    assert (scheduled.metadata_json or {}).get("queue_status") == "completed"


def test_db_queue_enqueues_and_processes_scheduled_scan(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'db-queue.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

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

    settings = Settings(
        database_url=database_url,
        data_dir=tmp_path / "data",
        scan_queue_backend="db",
        scan_queue_name="orgscan:db-test",
        scan_queue_retry_max=1,
        scan_queue_poll_interval_seconds=0.01,
    )

    queued = enqueue_due_scheduled_scans(settings, limit=10)
    assert len(queued) == 1
    assert queued[0]["queue_task_id"] > 0
    status = queue_status(settings)
    assert status["backend"] == "db"
    assert status["pending_jobs"] == 1

    worked = run_worker(settings, burst=True, max_jobs=1)
    assert worked is True

    with session_factory() as session:
        storage = Storage(session)
        findings = storage.list_findings()
        scheduled = storage.list_scheduled_scans()[0]
        queue_tasks = storage.list_queue_tasks(backend="db")

    assert len(findings) == 1
    assert scheduled.enabled is False
    assert (scheduled.metadata_json or {}).get("queue_backend") == "db"
    assert (scheduled.metadata_json or {}).get("queue_status") == "completed"
    assert queue_tasks[0].status == "completed"
