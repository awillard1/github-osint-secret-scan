from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from orgscan.config import Settings
from orgscan.mirroring import scan_repository_mirror_refs
from orgscan.repositories import Storage
from orgscan.reporting import build_summary, deliver_report_webhook, finding_rows, scheduled_report_output_path, write_export
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


@dataclass(frozen=True)
class ScheduledReportExecutionResult:
    scheduled_report_id: int
    output_path: str
    output_format: str
    delivered: bool
    tool_run_id: int


def run_due_scans(storage: Storage, limit: int = 10, *, settings: Settings | None = None) -> list[ScanExecutionResult]:
    results: list[ScanExecutionResult] = []
    due_scans = storage.list_due_scheduled_scans()[:limit]
    for scheduled in due_scans:
        metadata = scheduled.metadata_json or {}
        organization_id = metadata.get("organization_id")
        repository_id = metadata.get("repository_id")
        if scheduled.target_type == "mirror":
            result_batch = scan_repository_mirror_refs(
                storage,
                settings=settings or Settings(),
                repository_full_name=scheduled.target_value,
                scanner_name=scheduled.scanner_name,
                refs=[str(value) for value in metadata.get("refs", [])] if isinstance(metadata.get("refs"), list) else None,
                provider=str(metadata.get("provider") or "github"),
                clone_url=metadata.get("clone_url"),
                resync=bool(metadata.get("resync_before_run", True)),
            )
        else:
            result_batch = [
                execute_scan(
                    storage,
                    target_path=Path(scheduled.target_value),
                    scanner_name=scheduled.scanner_name,
                    settings=settings,
                    organization_id=int(organization_id) if organization_id is not None else None,
                    repository_id=int(repository_id) if repository_id is not None else None,
                    target_type=scheduled.target_type,
                    target_id=scheduled.target_value,
                    target_ref=str(metadata.get("target_ref") or "workspace"),
                    scope_json={"mode": scheduled.target_type, **(metadata.get("scope_json") or {})},
                )
            ]
        storage.mark_scheduled_scan_run(
            scheduled,
            next_run_from_cadence(scheduled.cadence),
            enabled=False if scheduled.cadence == "manual" else None,
        )
        results.extend(result_batch)
    return results


def run_due_reports(storage: Storage, limit: int = 10, *, settings: Settings) -> list[ScheduledReportExecutionResult]:
    results: list[ScheduledReportExecutionResult] = []
    due_reports = storage.list_due_scheduled_reports()[:limit]
    for scheduled in due_reports:
        tenant_keys = [scheduled.target_value] if scheduled.target_type == "tenant" and scheduled.target_value else None
        summary = build_summary(storage, tenant_keys=tenant_keys)
        rows = finding_rows(storage, limit=500, tenant_keys=tenant_keys)
        output_path = scheduled_report_output_path(
            settings,
            schedule_id=scheduled.id,
            export_format=scheduled.output_format,
            configured_path=scheduled.output_path,
        )
        tool_run = storage.create_tool_run(
            tool_name="scheduled-report",
            target=scheduled.target_value or "global",
            command_line=f"orgscan run-scheduled-reports --limit {limit}",
            artifact_type=scheduled.output_format,
            artifact_path=str(output_path),
            status="pending",
        )
        storage.mark_tool_run_running(tool_run)
        storage.session.commit()
        delivered = False
        metadata = dict(scheduled.metadata_json or {})
        try:
            write_export(output_path, scheduled.output_format, summary, rows)
            if scheduled.webhook_url:
                deliver_report_webhook(
                    scheduled.webhook_url,
                    timeout=settings.http_timeout_seconds,
                    payload={
                        "scheduled_report_id": scheduled.id,
                        "target_type": scheduled.target_type,
                        "target_value": scheduled.target_value,
                        "output_format": scheduled.output_format,
                        "output_path": str(output_path),
                        "summary": summary,
                    },
                )
                delivered = True
            storage.mark_scheduled_report_run(
                scheduled,
                next_run_from_cadence(scheduled.cadence),
                enabled=False if scheduled.cadence == "manual" else None,
            )
            metadata.update(
                {
                    "last_output_path": str(output_path),
                    "last_delivery_status": "delivered" if delivered else "generated",
                    "last_error": None,
                    "last_run_at": datetime.now(UTC).isoformat(),
                }
            )
            scheduled.metadata_json = metadata
            storage.mark_tool_run_completed(
                tool_run,
                stdout_log=f"report_format={scheduled.output_format} delivered={delivered}",
            )
            storage.session.commit()
            results.append(
                ScheduledReportExecutionResult(
                    scheduled_report_id=scheduled.id,
                    output_path=str(output_path),
                    output_format=scheduled.output_format,
                    delivered=delivered,
                    tool_run_id=tool_run.id,
                )
            )
        except Exception as exc:
            metadata.update(
                {
                    "last_output_path": str(output_path),
                    "last_delivery_status": "failed",
                    "last_error": str(exc),
                    "last_run_at": datetime.now(UTC).isoformat(),
                }
            )
            scheduled.metadata_json = metadata
            storage.mark_tool_run_failed(tool_run, stderr_log=str(exc))
            storage.session.commit()
            raise
    return results
