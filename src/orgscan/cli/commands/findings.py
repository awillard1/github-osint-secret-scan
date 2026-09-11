from __future__ import annotations

import json
from datetime import date, datetime
from enum import StrEnum

import typer

from orgscan.cli.dependencies import _settings
from orgscan.db import create_session_factory, init_db
from orgscan.models import Finding
from orgscan.services.finding_service import (
    FindingDecision,
    FindingQuery,
    FindingService,
    TriageUpdate,
)


class FindingWorkflowStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


def _serialize_finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "source_tool": finding.source_tool,
        "title": finding.title,
        "fingerprint": finding.fingerprint,
        "organization_id": finding.organization_id,
        "domain_id": finding.domain_id,
        "repository_id": finding.repository_id,
        "scan_job_id": finding.scan_job_id,
        "risk_score": finding.risk_score,
        "triage_state": finding.triage_state,
        "triage_owner": finding.triage_owner,
        "triage_notes": finding.triage_notes,
        "remediation_due_date": finding.remediation_due_date.isoformat() if finding.remediation_due_date else None,
        "detected_at": finding.detected_at.isoformat(),
    }


def _parse_due_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter("Due dates must use YYYY-MM-DD format.") from exc


def _parse_datetime(value: str | None, *, option_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter(f"{option_name} must use ISO 8601 datetime format.") from exc


def findings(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of findings to display."),
    status: str | None = typer.Option(None, "--status", help="Optional finding status filter."),
    category: str | None = typer.Option(None, "--category", help="Optional finding category filter."),
    severity: str | None = typer.Option(None, "--severity", help="Optional finding severity filter."),
    confidence: str | None = typer.Option(None, "--confidence", help="Optional finding confidence filter."),
    source_tool: str | None = typer.Option(None, "--source-tool", help="Optional source tool filter."),
    triage_state: str | None = typer.Option(None, "--triage-state", help="Optional triage state filter."),
    organization_id: int | None = typer.Option(None, "--organization-id", help="Optional organization id filter."),
    domain_id: int | None = typer.Option(None, "--domain-id", help="Optional domain id filter."),
    repository_id: int | None = typer.Option(None, "--repository-id", help="Optional repository id filter."),
    scan_job_id: int | None = typer.Option(None, "--scan-job-id", help="Optional scan job id filter."),
    risk_score_min: float | None = typer.Option(None, "--risk-score-min", help="Optional minimum risk score filter."),
    risk_score_max: float | None = typer.Option(None, "--risk-score-max", help="Optional maximum risk score filter."),
    detected_after: str | None = typer.Option(None, "--detected-after", help="Optional ISO 8601 lower bound for detected_at."),
    detected_before: str | None = typer.Option(None, "--detected-before", help="Optional ISO 8601 upper bound for detected_at."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    service = _finding_service()
    detected_after_value = _parse_datetime(detected_after, option_name="--detected-after")
    detected_before_value = _parse_datetime(detected_before, option_name="--detected-before")
    rows = service.list_findings(FindingQuery(
        limit=limit, status=status, category=category, severity=severity, confidence=confidence,
        source_tool=source_tool, triage_state=triage_state, organization_id=organization_id,
        domain_id=domain_id, repository_id=repository_id, scan_job_id=scan_job_id,
        risk_score_min=risk_score_min, risk_score_max=risk_score_max,
        detected_after=detected_after_value, detected_before=detected_before_value,
    ))
    if json_output:
        typer.echo(json.dumps([_serialize_finding(row) for row in rows], indent=2, default=str))
        return
    if not rows:
        typer.echo("No findings found.")
        return
    for row in rows:
        typer.echo(
            f"[{row.severity}/{row.confidence}] {row.title} "
            f"(id={row.id}, category={row.category}, status={row.status}, triage={row.triage_state})"
        )


def triage(
    finding_id: int,
    status: FindingWorkflowStatus = typer.Option(..., "--status", help="Updated workflow status for the finding."),
    triage_state: str = typer.Option("reviewed", "--triage-state", help="Free-form triage state label."),
    owner: str | None = typer.Option(None, "--owner", help="Assigned owner for remediation."),
    note: str | None = typer.Option(None, "--note", help="Triage notes for the finding."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional remediation due date (YYYY-MM-DD)."),
) -> None:
    service = _finding_service()
    try:
        finding = service.update_triage(finding_id, TriageUpdate(
            status=status.value, triage_state=triage_state, triage_owner=owner,
            triage_notes=note, remediation_due_date=_parse_due_date(due_date),
        ))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(
        f"Updated finding {finding.id}: status={finding.status}, triage_state={finding.triage_state}, "
        f"owner={finding.triage_owner or 'unassigned'}"
    )


def suppress(
    finding_id: int,
    reason: str = typer.Option(..., "--reason", help="Reason for suppressing the finding."),
    owner: str | None = typer.Option(None, "--owner", help="Owner recording the suppression."),
    note: str | None = typer.Option(None, "--note", help="Additional suppression notes."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional review date (YYYY-MM-DD)."),
) -> None:
    service = _finding_service()
    try:
        finding = service.apply_decision(
            finding_id, FindingDecision(reason=reason, owner=owner, note=note, due_date=_parse_due_date(due_date)),
            status="suppressed",
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Suppressed finding {finding.id}")


def accept_risk(
    finding_id: int,
    reason: str = typer.Option(..., "--reason", help="Reason for accepting the risk."),
    owner: str | None = typer.Option(None, "--owner", help="Owner accepting the risk."),
    note: str | None = typer.Option(None, "--note", help="Additional acceptance notes."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional review date (YYYY-MM-DD)."),
) -> None:
    service = _finding_service()
    try:
        finding = service.apply_decision(
            finding_id, FindingDecision(reason=reason, owner=owner, note=note, due_date=_parse_due_date(due_date)),
            status="accepted_risk",
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Accepted risk for finding {finding.id}")


def unsuppress(
    finding_id: int,
    note: str | None = typer.Option(None, "--note", help="Optional note explaining why the finding was reopened."),
) -> None:
    service = _finding_service()
    try:
        finding = service.reopen(finding_id, note=note)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Reopened finding {finding.id}")


def _finding_service() -> FindingService:
    settings = _settings()
    init_db(settings.database_url)
    return FindingService(create_session_factory(settings.database_url))
