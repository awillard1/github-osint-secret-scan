from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update, or_
from orgscan.models import QueueTask

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue, Retry, SimpleWorker, get_current_job
from rq.registry import FailedJobRegistry, StartedJobRegistry

from orgscan.config import Settings
from orgscan.db import prepare_database, create_session_factory
from orgscan.repositories import Storage
from orgscan.scheduler import execute_scheduled_scan, next_run_from_cadence
from orgscan.services.job_policy import (classify_failure, retry_delay, retry_limit, Failure, JobExecutionError, logical_job_type)


class QueueBackendError(RuntimeError):
    pass


class SafeWorker(SimpleWorker):
    """Keep RQ exception records/log extras free of serialized credentials."""
    def handle_exception(self, job, *exc_info):
        if not isinstance(exc_info[1], JobExecutionError):
            failure = classify_failure(exc_info[1])
            job.meta["failure"] = {"code": failure.code, "retryable": failure.retryable}
            if not failure.retryable:
                job.retries_left = 0
            elif failure.retry_after:
                job.retry_intervals = [max(failure.retry_after, max(job.retry_intervals or [30]))] * max(job.retries_left or 1, 1)
            job.save()
        self.log.error("orgscan queue job %s failed (%s)", job.id, job.meta.get("failure", {}).get("code", "permanent"))

    def handle_job_failure(self, job, queue, started_job_registry=None, exc_string=""):
        code = job.meta.get("failure", {}).get("code", "permanent")
        return super().handle_job_failure(job, queue, started_job_registry, exc_string=f"orgscan job failure: {code}")


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
            "Unable to connect to Redis. Review ORGSCAN_REDIS_URL or start Redis."
        ) from exc
    return connection


def get_scan_queue(settings: Settings, *, connection: Redis | None = None, is_async: bool = True) -> Queue:
    return Queue(name=settings.scan_queue_name, connection=connection or get_queue_connection(settings), is_async=is_async)


def _queue_retry(settings: Settings) -> Retry | None:
    max_attempts = retry_limit(settings)
    if max_attempts <= 0:
        return None
    intervals = [retry_delay(settings, attempt+1, Failure("retry", True, "")) for attempt in range(max_attempts)]
    return Retry(max=max_attempts, interval=intervals)


def queue_status(settings: Settings, *, connection: Redis | None = None) -> dict[str, Any]:
    if _queue_backend(settings) == "db":
        return _db_queue_status(settings)
    queue = get_scan_queue(settings, connection=connection)
    failed = FailedJobRegistry(queue=queue)
    started = StartedJobRegistry(queue=queue)
    return {
        "backend": "rq",
        "redis_url": "configured",
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
    prepare_database(settings)
    session_factory = create_session_factory(settings.database_url)
    queue = get_scan_queue(settings, connection=connection, is_async=is_async)
    _reserve_due(settings, backend='rq', limit=limit)
    queued = []
    # Durable tasks are an outbox. A crash before publication leaves a retryable row.
    with session_factory() as session:
        tasks = list(session.scalars(select(QueueTask).where(QueueTask.backend == 'rq',
                     QueueTask.queue_name == settings.scan_queue_name, QueueTask.status == 'queued')))
        identifiers = [task.id for task in tasks if not (task.metadata_json or {}).get('published')][:limit]
    for task_id in identifiers:
        publisher = 'publish-' + uuid.uuid4().hex
        now = datetime.now(UTC)
        with session_factory() as session:
            changed = session.execute(update(QueueTask).where(QueueTask.id == task_id, QueueTask.status == 'queued',
                or_(QueueTask.lease_owner.is_(None), QueueTask.lease_expires_at <= now)
            ).values(lease_owner=publisher, lease_expires_at=now+timedelta(seconds=60)))
            session.commit()
            if changed.rowcount != 1:
                continue
            task = session.get(QueueTask,task_id)
            key, schedule_id = task.execution_key, task.scheduled_scan_id
            scheduled = Storage(session).get_scheduled_scan(schedule_id)
            payload = {'scheduled_scan_id':schedule_id, 'scanner_name':scheduled.scanner_name,
                       'target_value':scheduled.target_value, 'queue_job_id':key}
        try:
            if queue.fetch_job(key) is None:
                queue.enqueue(execute_scheduled_scan_job, schedule_id, settings.as_dict(include_secrets=True),
                              key, job_id=key, description=f'orgscan scheduled scan {schedule_id}',
                              job_timeout=600, retry=_queue_retry(settings))
            with session_factory() as session:
                # Never overwrite state committed by a fast worker.
                session.execute(update(QueueTask).where(QueueTask.id == task_id, QueueTask.status == 'queued',
                    QueueTask.lease_owner == publisher).values(lease_owner=None, lease_expires_at=None,
                                                               metadata_json={'published':True}))
                session.commit()
            queued.append(payload)
        except Exception:
            with session_factory() as session:
                session.execute(update(QueueTask).where(QueueTask.id == task_id, QueueTask.lease_owner == publisher,
                    QueueTask.status == 'queued').values(lease_owner=None, lease_expires_at=None))
                session.commit()
            raise QueueBackendError('Queue publication failed; durable execution remains available for retry') from None
    return queued


def _reserve_due(settings, *, backend, limit):
    queued = []
    with create_session_factory(settings.database_url)() as session:
        storage = Storage(session)
        for scheduled in storage.list_due_scheduled_scans()[:limit]:
            task = storage.reserve_queue_execution(scheduled, backend=backend, queue_name=settings.scan_queue_name,
                                                   max_attempts=retry_limit(settings)+1)
            if task is None:
                continue
            metadata = dict(scheduled.metadata_json or {})
            metadata.update(queue_status='queued',queue_backend=backend,queue_task_id=task.id,
                            queue_job_id=task.execution_key,queue_name=settings.scan_queue_name,
                            queued_at=datetime.now(UTC).isoformat(),last_error=None)
            scheduled.metadata_json = metadata
            queued.append({'scheduled_scan_id':scheduled.id,'scanner_name':scheduled.scanner_name,
                           'target_value':scheduled.target_value,'queue_task_id':task.id})
            session.commit()
    return queued


def execute_scheduled_scan_job(scheduled_scan_id: int, settings_payload: dict[str, Any] | None = None, execution_key: str | None = None) -> dict[str, Any]:
    settings = Settings(**(settings_payload or {}))
    prepare_database(settings)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        scheduled = storage.get_scheduled_scan(scheduled_scan_id)
        if scheduled is None:
            raise QueueBackendError(f"Scheduled scan {scheduled_scan_id} does not exist")

        metadata = dict(scheduled.metadata_json or {})
        rq_job = get_current_job()
        execution_id = execution_key or (rq_job.id if rq_job else None)
        task = session.scalar(select(QueueTask).where(QueueTask.execution_key == execution_id)) if execution_id else None
        if task is None or task.scheduled_scan_id != scheduled_scan_id:
            raise JobExecutionError('Missing durable queue execution; review legacy job before rescheduling')
        if task.status == 'completed':
            return (task.metadata_json or {})['result']
        claimed = session.execute(update(QueueTask).where(QueueTask.id == task.id, QueueTask.status == 'queued',
            QueueTask.available_at <= datetime.now(UTC)).values(status='running', lease_owner=execution_id,
            lease_expires_at=datetime.now(UTC)+timedelta(seconds=600),started_at=datetime.now(UTC),
            attempt_count=QueueTask.attempt_count+1), execution_options={'synchronize_session':False})
        if claimed.rowcount != 1:
            session.rollback()
            raise JobExecutionError('Queue execution is already claimed or requires operator review')
        session.refresh(task)
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
                    "failure_code": None,
                    "next_retry_at": None,
                }
            )
            task.metadata_json = {'result':_result_payload(scheduled.id, result)}
            storage.mark_queue_task_completed(task, scan_job_id=result.scan_job_id, tool_run_id=result.tool_run_id)
            metadata["completed_execution_id"] = execution_id
            metadata["completed_result"] = _result_payload(scheduled.id, result)
            scheduled.metadata_json = metadata
            session.commit()
        except Exception as exc:
            failure = classify_failure(exc)
            session.rollback()
            scheduled = storage.get_scheduled_scan(scheduled_scan_id)
            metadata = dict(scheduled.metadata_json or {})
            retrying = bool(rq_job and failure.retryable and rq_job.retries_left)
            delay = retry_delay(settings, max(1, retry_limit(settings) - (rq_job.retries_left or 0) + 1), failure) if rq_job else 0
            if rq_job:
                if retrying:
                    rq_job.retry_intervals = [delay] * max(rq_job.retries_left, 1)
                else:
                    rq_job.retries_left = 0
                rq_job.meta["failure"] = {"code": failure.code, "retryable": failure.retryable}
                rq_job.save()
            metadata.update(queue_status="queued" if retrying else "failed", queue_backend="rq",
                            last_error=failure.message, failure_code=failure.code,
                            next_retry_at=(datetime.now(UTC)+timedelta(seconds=delay)).isoformat() if retrying else None)
            if retrying:
                storage.mark_queue_task_retry(task, available_at=datetime.now(UTC)+timedelta(seconds=delay), error_message=failure.message)
                task.metadata_json = {**(task.metadata_json or {}), 'published':True}
            else:
                storage.mark_queue_task_failed(task, error_message=failure.message)
            if not retrying:
                scheduled.enabled = False
            scheduled.metadata_json = metadata
            session.commit()
            raise JobExecutionError(failure.message) from None

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
    prepare_database(settings)
    if _queue_backend(settings) == "db":
        return _run_db_worker(settings, burst=burst, max_jobs=max_jobs)
    queue = get_scan_queue(settings, connection=connection)
    worker = SafeWorker([queue], connection=queue.connection)
    return bool(worker.work(burst=burst, max_jobs=max_jobs, with_scheduler=True))


def _db_queue_status(settings: Settings) -> dict[str, Any]:
    prepare_database(settings)
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
    prepare_database(settings)
    return _reserve_due(settings, backend='db', limit=limit)


def _run_db_worker(settings: Settings, *, burst: bool = False, max_jobs: int | None = None) -> bool:
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
    try:
        return _execute_db_queue_task(settings, claimed.id, worker_id=worker_id)
    except JobExecutionError:
        return {"queue_task_id": claimed.id, "status": "attempt_failed"}


def _execute_db_queue_task(settings: Settings, queue_task_id: int, *, worker_id: str) -> dict[str, Any]:
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        task = storage.get_queue_task(queue_task_id)
        if task is None:
            raise QueueBackendError(f"Queue task {queue_task_id} does not exist")
        if task.status == "completed":
            return dict((task.metadata_json or {}).get("result", {}))
        if task.status != "running" or task.lease_owner != worker_id:
            raise JobExecutionError("Queue task is not owned by this worker")
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
            session.refresh(task)
            if task.status != "running" or task.lease_owner != worker_id:
                raise JobExecutionError("Queue task ownership changed during execution")
            task.metadata_json = {**(task.metadata_json or {}), "result": _result_payload(scheduled.id, result)}
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
            failure = classify_failure(exc)
            session.rollback()
            session.refresh(task)
            if task.status != "running" or task.lease_owner != worker_id:
                raise JobExecutionError("Queue task no longer owned by this worker") from None
            metadata = dict(scheduled.metadata_json or {})
            metadata["failure_code"] = failure.code
            task.metadata_json = {**(task.metadata_json or {}), "failure_code": failure.code, "retryable": failure.retryable}
            if failure.retryable and task.attempt_count < task.max_attempts:
                delay = retry_delay(settings, task.attempt_count, failure)
                next_attempt = datetime.now(UTC) + timedelta(seconds=delay)
                storage.mark_queue_task_retry(task, available_at=next_attempt, error_message=failure.message)
                metadata.update(
                    {
                        "queue_backend": "db",
                        "queue_status": "queued",
                        "worker_id": worker_id,
                        "last_error": failure.message,
                        "next_retry_at": next_attempt.isoformat(),
                    }
                )
            else:
                scheduled.enabled = False
                storage.mark_queue_task_failed(task, error_message=failure.message)
                metadata.update(
                    {
                        "queue_backend": "db",
                        "queue_status": "failed",
                        "worker_id": worker_id,
                        "completed_at": datetime.now(UTC).isoformat(),
                        "last_error": failure.message,
                    }
                )
            scheduled.metadata_json = metadata
            session.commit()
            raise JobExecutionError(failure.message) from None


def _result_payload(scheduled_id, result):
    return {"scheduled_scan_id": scheduled_id, "scan_job_id": result.scan_job_id,
            "tool_run_id": result.tool_run_id, "scanner": result.scanner, "target": result.target,
            "findings": result.findings, "finding_ids": result.finding_ids}
