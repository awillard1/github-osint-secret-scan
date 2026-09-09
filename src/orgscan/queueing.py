from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue, SimpleWorker
from rq.job import Job
from rq.registry import FailedJobRegistry, StartedJobRegistry

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.runner import execute_scan
from orgscan.scheduler import next_run_from_cadence


class QueueBackendError(RuntimeError):
    pass


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


def queue_status(settings: Settings, *, connection: Redis | None = None) -> dict[str, Any]:
    queue = get_scan_queue(settings, connection=connection)
    failed = FailedJobRegistry(queue=queue)
    started = StartedJobRegistry(queue=queue)
    return {
        "backend": "rq",
        "redis_url": settings.redis_url,
        "queue_name": settings.scan_queue_name,
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
                settings.database_url,
                scheduled.id,
                job_timeout=600,
            )
            metadata.update(
                {
                    "queue_status": "queued",
                    "queue_name": settings.scan_queue_name,
                    "queue_job_id": job.id,
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


def execute_scheduled_scan_job(database_url: str, scheduled_scan_id: int) -> dict[str, Any]:
    init_db(database_url)
    session_factory = create_session_factory(database_url)

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
            settings = Settings(database_url=database_url)
            organization_id = metadata.get("organization_id")
            repository_id = metadata.get("repository_id")
            result = execute_scan(
                storage,
                target_path=Path(scheduled.target_value),
                scanner_name=scheduled.scanner_name,
                settings=settings,
                organization_id=int(organization_id) if organization_id is not None else None,
                repository_id=int(repository_id) if repository_id is not None else None,
            )
            storage.mark_scheduled_scan_run(
                scheduled,
                next_run_from_cadence(scheduled.cadence),
                enabled=False if scheduled.cadence == "manual" else None,
            )
            metadata = dict(scheduled.metadata_json or {})
            metadata.update(
                {
                    "queue_status": "completed",
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
    queue = get_scan_queue(settings, connection=connection)
    worker = SimpleWorker([queue], connection=queue.connection)
    return bool(worker.work(burst=burst, max_jobs=max_jobs))
