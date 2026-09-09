from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue, Retry, SimpleWorker
from rq.registry import FailedJobRegistry, StartedJobRegistry

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.scheduler import execute_scheduled_scan, next_run_from_cadence


class QueueBackendError(RuntimeError):
    pass


def _queue_backend(settings: Settings) -> str:
    backend = settings.scan_queue_backend.strip().lower()
    if backend not in {"rq", "db"}:
        raise QueueBackendError("Unsupported queue backend. Configure ORGSCAN_SCAN_QUEUE_BACKEND as 'rq' or 'db'.")
    return backend


def get_queue_connection(settings: Settings) -> Redis:
    try:
        connection = Redis.from_url(settings.redis_url)
        connection.ping()
    except RedisError as exc:
        raise QueueBackendError(
            f"Unable to connect to Redis at {settings.redis_url}. Configure ORGSCAN_REDIS_URL or start Redis."
        ) from exc
    return connection


def get_scan_queue(settings: Settings, *, connection: Redis | None = None, is_async: bool = True) -> Queue:
    return Queue(name=settings.scan_queue_name, connection=connection or get_queue_connection(settings), is_async=is_async)


def _queue_retry(settings: Settings) -> Retry | None:
    max_attempts = max(settings.scan_queue_retry_max, 0)
    if max_attempts <= 0:
        return None
    intervals = settings.scan_queue_retry_interval_list()
    return Retry(max=max_attempts, interval=intervals or [30])


def queue_status(settings: Settings, *, connection: Redis | None = None) -> dict[str, Any]:
    if _queue_backend(settings) == "db":
        return _db_queue_status(settings)
    queue = get_scan_queue(settings, connection=connection)
    failed = FailedJobRegistry(queue=queue)
    started = StartedJobRegistry(queue=queue)
    return {
        "backend": "rq",
        "redis_url": settings.redis_url,
        "queue_name": settings.scan_queue_name,
        "retry_max": settings.scan_queue_retry_max,
        "retry_intervals": settings.scan_queue_retry_interval_list(),
        "pending_jobs": queue.count,
        "started_jobs": len(started.get_job_ids()),
        "failed_jobs": len(failed.get_job_ids()),
    }


def enqueue_due_scheduled_scans(
    settings: Settings,
    *,
    limit: int = 10,
    connection: Redis | None = None,
    is_async: bool = True,
) -> list[dict[str, Any]]:
    if _queue_backend(settings) == "db":
        return _enqueue_due_scheduled_scans_db(settings, limit=limit)
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    queue = get_scan_queue(settings, connection=connection, is_async=is_async)
    queued: list[dict[str, Any]] = []

    with session_factory() as session:
        storage = Storage(session)
        due_scans = storage.list_due_scheduled_scans()[:limit]
        for scheduled in due_scans:
            metadata = dict(scheduled.metadata_json or {})
            if metadata.get("queue_status") in {"queued", "running"}:
                continue
            job = queue.enqueue(
                execute_scheduled_scan_job,
                scheduled.id,
                settings.as_dict(include_secrets=True),
                job_timeout=600,
                retry=_queue_retry(settings),
            )
            metadata.update(
                {
                    "queue_backend": "rq",
                    "queue_status": "queued",
                    "queue_name": settings.scan_queue_name,
                    "queue_job_id": job.id,
                    "retry_max": settings.scan_queue_retry_max,
                    "retry_intervals": settings.scan_queue_retry_interval_list(),
                    "queued_at": datetime.now(UTC).isoformat(),
                    "last_error": None,
                }
            )
            scheduled.metadata_json = metadata
            queued.append(
                {
                    "scheduled_scan_id": scheduled.id,
                    "scanner_name": scheduled.scanner_name,
                    "target_value": scheduled.target_value,
                    "queue_job_id": job.id,
                }
            )
        session.commit()

    return queued


def execute_scheduled_scan_job(scheduled_scan_id: int, settings_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = Settings(**(settings_payload or {}))
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        scheduled = storage.get_scheduled_scan(scheduled_scan_id)
        if scheduled is None:
            raise QueueBackendError(f"Scheduled scan {scheduled_scan_id} does not exist")

        metadata = dict(scheduled.metadata_json or {})
        metadata["queue_status"] = "running"
        metadata["started_at"] = datetime.now(UTC).isoformat()
        scheduled.metadata_json = metadata
        session.commit()

        try:
            results = execute_scheduled_scan(storage, scheduled, settings=settings)
            result = results[0] if results else None
            if result is None:
                raise QueueBackendError("Scheduled scan did not produce a result")
            storage.mark_scheduled_scan_run(
                scheduled,
                next_run_from_cadence(scheduled.cadence),
                enabled=False if scheduled.cadence == "manual" else None,
            )
            metadata = dict(scheduled.metadata_json or {})
            metadata.update(
                {
                    "queue_status": "completed",
                    "queue_backend": "rq",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "last_scan_job_id": result.scan_job_id,
                    "last_tool_run_id": result.tool_run_id,
                    "last_error": None,
                }
            )
            scheduled.metadata_json = metadata
            session.commit()
        except Exception as exc:
            metadata = dict(scheduled.metadata_json or {})
            metadata.update(
                {
                    "queue_status": "failed",
                    "queue_backend": "rq",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "last_error": str(exc),
                }
            )
            scheduled.metadata_json = metadata
            session.commit()
            raise

    return {
        "scheduled_scan_id": scheduled_scan_id,
        "scan_job_id": result.scan_job_id,
        "tool_run_id": result.tool_run_id,
        "scanner": result.scanner,
        "target": result.target,
        "findings": result.findings,
        "finding_ids": result.finding_ids,
    }


def run_worker(
    settings: Settings,
    *,
    burst: bool = False,
    connection: Redis | None = None,
    max_jobs: int | None = None,
) -> bool:
    if _queue_backend(settings) == "db":
        return _run_db_worker(settings, burst=burst, max_jobs=max_jobs)
    queue = get_scan_queue(settings, connection=connection)
    worker = SimpleWorker([queue], connection=queue.connection)
    return bool(worker.work(burst=burst, max_jobs=max_jobs))


def _db_queue_status(settings: Settings) -> dict[str, Any]:
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        tasks = storage.list_queue_tasks(backend="db", queue_name=settings.scan_queue_name, limit=None)
    return {
        "backend": "db",
        "redis_url": None,
        "queue_name": settings.scan_queue_name,
        "retry_max": settings.scan_queue_retry_max,
        "retry_intervals": settings.scan_queue_retry_interval_list(),
        "lease_seconds": settings.scan_queue_lease_seconds,
        "poll_interval_seconds": settings.scan_queue_poll_interval_seconds,
        "pending_jobs": sum(1 for task in tasks if task.status == "queued"),
        "started_jobs": sum(1 for task in tasks if task.status == "running"),
        "failed_jobs": sum(1 for task in tasks if task.status == "failed"),
        "completed_jobs": sum(1 for task in tasks if task.status == "completed"),
    }


def _enqueue_due_scheduled_scans_db(settings: Settings, *, limit: int = 10) -> list[dict[str, Any]]:
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    queued: list[dict[str, Any]] = []
    with session_factory() as session:
        storage = Storage(session)
        due_scans = storage.list_due_scheduled_scans()[:limit]
        for scheduled in due_scans:
            metadata = dict(scheduled.metadata_json or {})
            existing = storage.find_active_queue_task(scheduled.id, backend="db")
            if existing is not None:
                continue
            task = storage.create_queue_task(
                scheduled.id,
                backend="db",
                queue_name=settings.scan_queue_name,
                status="queued",
                max_attempts=max(settings.scan_queue_retry_max + 1, 1),
                available_at=datetime.now(UTC),
                metadata_json={
                    "scanner_name": scheduled.scanner_name,
                    "target_value": scheduled.target_value,
                    "target_type": scheduled.target_type,
                    "tenant_key": metadata.get("tenant_key"),
                    "refs": metadata.get("refs", []),
                },
            )
            metadata.update(
                {
                    "queue_backend": "db",
                    "queue_status": "queued",
                    "queue_name": settings.scan_queue_name,
                    "queue_task_id": task.id,
                    "retry_max": settings.scan_queue_retry_max,
                    "retry_intervals": settings.scan_queue_retry_interval_list(),
                    "queued_at": datetime.now(UTC).isoformat(),
                    "last_error": None,
                }
            )
            scheduled.metadata_json = metadata
            queued.append(
                {
                    "scheduled_scan_id": scheduled.id,
                    "scanner_name": scheduled.scanner_name,
                    "target_value": scheduled.target_value,
                    "queue_task_id": task.id,
                }
            )
        session.commit()
    return queued


def _run_db_worker(settings: Settings, *, burst: bool = False, max_jobs: int | None = None) -> bool:
    init_db(settings.database_url)
    processed = 0
    worker_id = settings.scan_queue_worker_id or f"db-worker-{uuid.uuid4().hex[:12]}"
    while True:
        result = _process_one_db_task(settings, worker_id=worker_id)
        if result is None:
            if burst:
                break
            time.sleep(max(float(settings.scan_queue_poll_interval_seconds), 0.1))
            continue
        processed += 1
        if max_jobs is not None and processed >= max_jobs:
            break
    return processed > 0


def _process_one_db_task(settings: Settings, *, worker_id: str) -> dict[str, Any] | None:
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        claimed = storage.claim_queue_task(
            backend="db",
            queue_name=settings.scan_queue_name,
            worker_id=worker_id,
            lease_until=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=max(settings.scan_queue_lease_seconds, 30)),
        )
        if claimed is None:
            session.commit()
            return None
        scheduled = storage.get_scheduled_scan(claimed.scheduled_scan_id)
        if scheduled is None:
            storage.mark_queue_task_failed(claimed, error_message=f"Scheduled scan {claimed.scheduled_scan_id} does not exist")
            session.commit()
            return None
        metadata = dict(scheduled.metadata_json or {})
        metadata["queue_backend"] = "db"
        metadata["queue_status"] = "running"
        metadata["queue_task_id"] = claimed.id
        metadata["started_at"] = datetime.now(UTC).isoformat()
        metadata["worker_id"] = worker_id
        scheduled.metadata_json = metadata
        session.commit()
    return _execute_db_queue_task(settings, claimed.id, worker_id=worker_id)


def _execute_db_queue_task(settings: Settings, queue_task_id: int, *, worker_id: str) -> dict[str, Any]:
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        task = storage.get_queue_task(queue_task_id)
        if task is None:
            raise QueueBackendError(f"Queue task {queue_task_id} does not exist")
        scheduled = storage.get_scheduled_scan(task.scheduled_scan_id)
        if scheduled is None:
            storage.mark_queue_task_failed(task, error_message=f"Scheduled scan {task.scheduled_scan_id} does not exist")
            session.commit()
            raise QueueBackendError(f"Scheduled scan {task.scheduled_scan_id} does not exist")
        metadata = dict(scheduled.metadata_json or {})
        try:
            results = execute_scheduled_scan(storage, scheduled, settings=settings)
            result = results[0] if results else None
            if result is None:
                raise QueueBackendError("Scheduled scan did not produce a result")
            storage.mark_scheduled_scan_run(
                scheduled,
                next_run_from_cadence(scheduled.cadence),
                enabled=False if scheduled.cadence == "manual" else None,
            )
            storage.mark_queue_task_completed(task, scan_job_id=result.scan_job_id, tool_run_id=result.tool_run_id)
            metadata.update(
                {
                    "queue_backend": "db",
                    "queue_status": "completed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "worker_id": worker_id,
                    "last_scan_job_id": result.scan_job_id,
                    "last_tool_run_id": result.tool_run_id,
                    "last_error": None,
                }
            )
            scheduled.metadata_json = metadata
            session.commit()
            return {
                "scheduled_scan_id": scheduled.id,
                "queue_task_id": task.id,
                "scan_job_id": result.scan_job_id,
                "tool_run_id": result.tool_run_id,
                "scanner": result.scanner,
                "target": result.target,
                "findings": result.findings,
                "finding_ids": result.finding_ids,
            }
        except Exception as exc:
            retry_intervals = settings.scan_queue_retry_interval_list()
            if task.attempt_count < task.max_attempts:
                delay = retry_intervals[min(task.attempt_count - 1, len(retry_intervals) - 1)] if retry_intervals else 30
                next_attempt = datetime.now(UTC) + timedelta(seconds=delay)
                storage.mark_queue_task_retry(task, available_at=next_attempt, error_message=str(exc))
                metadata.update(
                    {
                        "queue_backend": "db",
                        "queue_status": "queued",
                        "worker_id": worker_id,
                        "last_error": str(exc),
                        "next_retry_at": next_attempt.isoformat(),
                    }
                )
            else:
                storage.mark_queue_task_failed(task, error_message=str(exc))
                metadata.update(
                    {
                        "queue_backend": "db",
                        "queue_status": "failed",
                        "worker_id": worker_id,
                        "completed_at": datetime.now(UTC).isoformat(),
                        "last_error": str(exc),
                    }
                )
            scheduled.metadata_json = metadata
            session.commit()
            raise
