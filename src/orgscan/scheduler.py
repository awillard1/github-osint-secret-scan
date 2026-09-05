from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from orgscan.repositories import Storage
from orgscan.runner import ScanExecutionResult, execute_scan


def next_run_from_cadence(cadence: str, reference: datetime | None = None) -> datetime:
    now = reference or datetime.now(UTC)
    if cadence == "hourly":
        return now + timedelta(hours=1)
    if cadence == "weekly":
        return now + timedelta(days=7)
    if cadence == "manual":
        return now
    return now + timedelta(days=1)


def run_due_scans(storage: Storage, limit: int = 10) -> list[ScanExecutionResult]:
    results: list[ScanExecutionResult] = []
    due_scans = storage.list_due_scheduled_scans()[:limit]
    for scheduled in due_scans:
        metadata = scheduled.metadata_json
        organization_id = metadata.get("organization_id")
        repository_id = metadata.get("repository_id")
        result = execute_scan(
            storage,
            target_path=Path(scheduled.target_value),
            scanner_name=scheduled.scanner_name,
            organization_id=int(organization_id) if organization_id is not None else None,
            repository_id=int(repository_id) if repository_id is not None else None,
        )
        storage.mark_scheduled_scan_run(
            scheduled,
            next_run_from_cadence(scheduled.cadence),
            enabled=False if scheduled.cadence == "manual" else None,
        )
        results.append(result)
    return results
