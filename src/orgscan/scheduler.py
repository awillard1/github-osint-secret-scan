from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from orgscan.config import Settings
from orgscan.mirroring import scan_repository_mirror_refs
from orgscan.repositories import Storage
from orgscan.reporting import deliver_report_webhook, scheduled_report_output_path, write_export
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


def execute_scheduled_scan(storage: Storage, scheduled, *, settings: Settings | None = None) -> list[ScanExecutionResult]:
    from orgscan.services.scan_plan import ScanPlan, resolve_scan_plan
    from orgscan.services.scan_service import execute_plan
    metadata = scheduled.metadata_json or {}
    if metadata.get("scan_plan"):
        plan = ScanPlan.model_validate(metadata["scan_plan"])
    else:
        plan = resolve_scan_plan(target=scheduled.target_value, target_type=scheduled.target_type,
                                 scanners=[scheduled.scanner_name], settings=settings,
                                 refs=metadata.get("refs"), organization_id=metadata.get("organization_id"),
                                 repository_id=metadata.get("repository_id"), scope=metadata.get("scope_json") or {})
    execution = {}
    if plan.target_type == "mirror":
        execution = dict(provider=str(metadata.get("provider") or "github"), clone_url=metadata.get("clone_url"),
                         resync=bool(metadata.get("resync_before_run", True)))
    else:
        execution = dict(target_ref=str(metadata.get("target_ref") or "workspace")) if plan.target_type != "domain" else {}
    return execute_plan(storage, plan, settings=settings, **execution)


def run_due_scans(storage: Storage, limit: int = 10, *, settings: Settings | None = None) -> list[ScanExecutionResult]:
    results: list[ScanExecutionResult] = []
    due_scans = storage.list_due_scheduled_scans()[:limit]
    for scheduled in due_scans:
        result_batch = execute_scheduled_scan(storage, scheduled, settings=settings)
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
        from orgscan.services.report_service import query_report
        payload = query_report(storage, limit=500, tenant_keys=tenant_keys)
        summary, rows = payload["summary"], payload["findings"]
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
        metadata["job_type"] = "REPORT"
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
            from orgscan.redaction import safe_error
            message = safe_error(exc)
            storage.session.rollback()
            metadata.update(
                {
                    "last_output_path": str(output_path),
                    "last_delivery_status": "failed",
                    "last_error": message,
                    "last_run_at": datetime.now(UTC).isoformat(),
                }
            )
            scheduled.metadata_json = metadata
            storage.mark_tool_run_failed(tool_run, stderr_log=message)
            storage.session.commit()
            raise RuntimeError(message) from None
    return results
