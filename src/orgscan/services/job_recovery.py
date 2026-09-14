"""Explicit quarantine of expired database leases, never speculative re-execution."""
from datetime import UTC, datetime
from orgscan.db import create_session_factory
from orgscan.repositories import Storage


def recover_stale_tasks(settings, *, apply: bool = False) -> dict:
    now = datetime.now(UTC).replace(tzinfo=None)
    rows = []
    with create_session_factory(settings.database_url)() as session:
        storage = Storage(session)
        for task in storage.list_queue_tasks(backend="db", queue_name=settings.scan_queue_name, limit=None):
            if task.status != "running" or task.lease_expires_at is None or task.lease_expires_at.replace(tzinfo=None) > now:
                continue
            rows.append({"queue_task_id": task.id, "scheduled_scan_id": task.scheduled_scan_id,
                         "lease_expired_at": task.lease_expires_at.isoformat(), "action": "quarantined" if apply else "review"})
            if apply:
                storage.mark_queue_task_failed(task, error_message="Expired lease quarantined by operator; review incomplete scan jobs")
                task.metadata_json = {**(task.metadata_json or {}), "failure_code": "stale_lease", "recovered_at": datetime.now(UTC).isoformat()}
                scheduled = storage.get_scheduled_scan(task.scheduled_scan_id)
                if scheduled:
                    scheduled.enabled = False
                    scheduled.metadata_json = {**(scheduled.metadata_json or {}), "queue_status": "failed", "failure_code": "stale_lease"}
        if apply:
            session.commit()
    return {"backend": "db", "applied": apply, "stale_tasks": rows}
