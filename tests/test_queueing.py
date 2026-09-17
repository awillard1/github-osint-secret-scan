from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
import sys
import time

from orgscan import models as m
from orgscan.cancellation import CancellationRequested, cancellation_scope
from orgscan import processes

import fakeredis

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.queueing import enqueue_due_scheduled_scans, queue_status, run_worker, execute_scheduled_scan_job
from orgscan.repositories import Storage


def test_running_external_process_stops_on_durable_request(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'cancel.db'}"
    init_db(database_url)
    factory = create_session_factory(database_url)
    with factory() as session:
        schedule = Storage(session).create_scheduled_scan('path', '/sample', 'custom-patterns',
            datetime.now(UTC), cadence='manual')
        task = Storage(session).create_queue_task(schedule.id, backend='db', queue_name='test',
            status='running', max_attempts=1, available_at=datetime.now(UTC))
        session.commit()
        task_id = task.id
    started = Event()
    result = []

    def execute():
        try:
            with cancellation_scope(database_url, task_id):
                started.set()
                processes.run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=30)
        except CancellationRequested:
            result.append('cancelled')

    worker = Thread(target=execute)
    worker.start()
    assert started.wait(3)
    time.sleep(0.2)
    with factory() as session:
        task = session.get(m.QueueTask, task_id)
        task.metadata_json = {'cancel_requested_at': datetime.now(UTC).isoformat()}
        session.commit()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert result == ['cancelled']


def test_cancelled_rq_execution_replay_does_not_start_tool(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'cancel-rq.db'}"
    init_db(database_url)
    factory = create_session_factory(database_url)
    with factory() as session:
        storage = Storage(session)
        schedule = storage.create_scheduled_scan('path', '/sample', 'custom-patterns',
            datetime.now(UTC), cadence='manual')
        task = storage.create_queue_task(schedule.id, backend='rq', queue_name='test',
            status='cancelled', max_attempts=1, available_at=datetime.now(UTC))
        task.execution_key = 'cancelled-execution'
        session.commit()
        schedule_id = schedule.id
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan',
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('tool started')))
    result = execute_scheduled_scan_job(schedule_id, {'database_url': database_url,
        'data_dir': str(tmp_path / 'data')}, 'cancelled-execution')
    assert result['status'] == 'cancelled'


def test_running_rq_execution_stops_owned_process(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'running-rq.db'}"
    init_db(database_url)
    factory = create_session_factory(database_url)
    with factory() as session:
        storage = Storage(session)
        schedule = storage.create_scheduled_scan('path', '/sample', 'custom-patterns',
            datetime.now(UTC), cadence='manual')
        task = storage.create_queue_task(schedule.id, backend='rq', queue_name='test',
            status='queued', max_attempts=1, available_at=datetime.now(UTC))
        task.execution_key = 'running-execution'
        session.commit()
        schedule_id, task_id = schedule.id, task.id
    started = Event()

    def external_tool(*args, **kwargs):
        started.set()
        processes.run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=30)

    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan', external_tool)
    outcomes = []
    worker = Thread(target=lambda: outcomes.append(execute_scheduled_scan_job(schedule_id,
        {'database_url': database_url, 'data_dir': str(tmp_path / 'data')}, 'running-execution')))
    worker.start()
    assert started.wait(5)
    with factory() as session:
        task = session.get(m.QueueTask, task_id)
        task.metadata_json = {'cancel_requested_at': datetime.now(UTC).isoformat()}
        session.commit()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert outcomes[0]['status'] == 'cancelled'
    with factory() as session:
        assert session.get(m.QueueTask, task_id).status == 'cancelled'


def test_rq_queue_enqueues_and_processes_scheduled_scan(tmp_path: Path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'queue.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "prod-token-1234567890abcdef"\n', encoding="utf-8")

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

    monkeypatch.setattr("orgscan.queueing.SafeWorker._start_scheduler", lambda *a, **k: None)
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
    sample.write_text('api_key = "prod-token-1234567890abcdef"\n', encoding="utf-8")

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
