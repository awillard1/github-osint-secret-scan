from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from orgscan.config import Settings
from orgscan.repositories import Storage
from orgscan.scoring import calculate_risk_score
from orgscan.schemas import CanonicalFinding
from orgscan.scanners import get_scanner
from orgscan.scanners.base import ScanContext, ScanMatch, ScanTarget
from orgscan.scanners.registry import ScannerAdapter


@dataclass(frozen=True)
class ScanExecutionResult:
    scan_job_id: int
    scanner: str
    target: str
    findings: int
    finding_ids: list[int]
    tool_run_id: int


def execute_scan(
    storage: Storage,
    *,
    target_path: Path,
    scanner_name: str,
    settings: Settings | None = None,
    organization_id: int | None = None,
    repository_id: int | None = None,
    target_type: str = "path",
    target_label: str | None = None,
    parameters_json: dict[str, Any] | None = None,
    target_id: str | None = None,
    target_ref: str | None = "workspace",
    scope_json: dict[str, object] | None = None,
    command_line: str | None = None,
    tool_target: str | None = None,
    plan=None,
    canonical_root: Path | None = None,
) -> ScanExecutionResult:
    scanner = get_scanner(scanner_name, settings=settings) if settings is not None else get_scanner(scanner_name)
    scanner_impl = ScannerAdapter(scanner, scanner_id=scanner_name, settings=settings)
    resolved_target = target_path.resolve()
    effective_target_id = target_id or target_label or str(resolved_target)
    effective_scope = scope_json or {"mode": target_type}
    effective_command_line = command_line or f"orgscan scan path {resolved_target} --scanner {scanner_name}"
    effective_tool_target = tool_target or target_label or str(resolved_target)

    from orgscan.services.scan_plan import ScanPlan
    plan = plan or ScanPlan(target=str(resolved_target), target_type=target_type, scanners=(scanner_name,),
                            organization_id=organization_id, repository_id=repository_id,
                            timeout_seconds=settings.scanner_timeout_seconds if settings else 300, scope=effective_scope)

    scan_job = storage.create_scan_job(
        target_type=target_type,
        target_id=effective_target_id,
        target_ref=target_ref,
        scanner_name=scanner_name,
        status="pending",
        parameters_json={
            "path": str(resolved_target),
            "target_ref": target_ref,
            "target_type": target_type,
            **(parameters_json or {}),
            "scan_plan": plan.serialized(),
        },
        scope_json=effective_scope,
    )
    tool_run = storage.create_tool_run(
        tool_name=scanner_name,
        tool_version=scanner_impl.metadata.version,
        target=effective_tool_target,
        scan_job_id=scan_job.id,
        command_line=effective_command_line,
        status="pending",
    )
    storage.mark_scan_job_running(scan_job)
    storage.mark_tool_run_running(tool_run)
    storage.session.commit()

    try:
        result = scanner_impl.scan(ScanContext(
            target=ScanTarget(resolved_target, kind=target_type, ref=target_ref),
            scan_job_id=scan_job.id,
            organization_id=organization_id,
            repository_id=repository_id,
            timeout_seconds=plan.timeout_seconds,
            options=effective_scope,
        ))
        matches = result.findings
        if canonical_root is not None:
            def stable(value):
                if isinstance(value, str) and (value == str(resolved_target) or value.startswith(str(resolved_target) + '/')):
                    return str(canonical_root) + value[len(str(resolved_target)):]
                if isinstance(value, dict):
                    return {key: stable(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [stable(item) for item in value]
                return value
            matches = [replace(match, path=Path(stable(str(match.path))), metadata=stable(match.metadata),
                               raw_payload=stable(match.raw_payload)) for match in matches]
        source_class = scanner_impl.source_class
        finding_ids = _persist_matches(
            storage,
            matches=matches,
            scanner_name=scanner_name,
            scan_job_id=scan_job.id,
            source_class=source_class,
            organization_id=organization_id,
            repository_id=repository_id,
        )
        storage.mark_scan_job_completed(scan_job)
        storage.mark_tool_run_completed(tool_run, stdout_log=f"findings={len(matches)}")
        storage.session.commit()
    except Exception as exc:
        storage.mark_scan_job_failed(scan_job, str(exc))
        storage.mark_tool_run_failed(tool_run, stderr_log=str(exc))
        storage.session.commit()
        raise

    return ScanExecutionResult(
        scan_job_id=scan_job.id,
        scanner=scanner_name,
        target=effective_tool_target,
        findings=len(matches),
        finding_ids=finding_ids,
        tool_run_id=tool_run.id,
    )


def record_scan_results(
    storage: Storage,
    *,
    scanner_name: str,
    source_class: str,
    target: str,
    matches: list[ScanMatch],
    target_type: str = "path",
    organization_id: int | None = None,
    repository_id: int | None = None,
    command_line: str | None = None,
) -> ScanExecutionResult:
    scan_job = storage.create_scan_job(
        target_type=target_type,
        target_id=target,
        scanner_name=scanner_name,
        status="pending",
        parameters_json={"path": target, "ingested": True},
    )
    tool_run = storage.create_tool_run(
        tool_name=scanner_name,
        target=target,
        scan_job_id=scan_job.id,
        command_line=command_line,
        status="pending",
    )
    storage.mark_scan_job_running(scan_job)
    storage.mark_tool_run_running(tool_run)
    storage.session.commit()

    try:
        finding_ids = _persist_matches(
            storage,
            matches=matches,
            scanner_name=scanner_name,
            scan_job_id=scan_job.id,
            source_class=source_class,
            organization_id=organization_id,
            repository_id=repository_id,
        )
        storage.mark_scan_job_completed(scan_job)
        storage.mark_tool_run_completed(tool_run, stdout_log=f"findings={len(matches)}")
        storage.session.commit()
    except Exception as exc:
        storage.mark_scan_job_failed(scan_job, str(exc))
        storage.mark_tool_run_failed(tool_run, stderr_log=str(exc))
        storage.session.commit()
        raise

    return ScanExecutionResult(
        scan_job_id=scan_job.id,
        scanner=scanner_name,
        target=target,
        findings=len(matches),
        finding_ids=finding_ids,
        tool_run_id=tool_run.id,
    )


def _persist_matches(
    storage: Storage,
    *,
    matches: list[ScanMatch],
    scanner_name: str,
    scan_job_id: int,
    source_class: str,
    organization_id: int | None = None,
    repository_id: int | None = None,
) -> list[int]:
    finding_ids: list[int] = []
    for match in matches:
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool=scanner_name,
                source_name=scanner_name,
                category=match.category,
                title=match.title,
                description=match.description,
                severity=match.severity,
                confidence=match.confidence,
                source_class=source_class,
                remediation_hint=match.remediation_hint,
                risk_score=calculate_risk_score(
                    severity=str(match.severity),
                    confidence=str(match.confidence),
                    source_class=source_class,
                ),
                raw_payload=match.raw_payload,
                metadata=match.metadata,
                organization_id=organization_id,
                repository_id=repository_id,
                scan_job_id=scan_job_id,
            )
        )
        storage.create_evidence(
            finding_id=finding.id,
            source=scanner_name,
            repository_path=str(match.path),
            commit_sha=match.metadata.get("commit_sha"),
            ref_name=match.metadata.get("ref_name"),
            line_start=match.line_start,
            line_end=match.line_end,
            snippet=match.snippet,
            extracted_indicator=match.indicator,
            confidence=match.confidence,
            source_class=source_class,
        )
        storage.create_risk_score(
            "finding",
            str(finding.id),
            finding.risk_score or 0,
            finding_id=finding.id,
            severity=finding.severity,
            confidence=finding.confidence,
            rationale=f"Calculated from severity={finding.severity}, confidence={finding.confidence}, source_class={source_class}.",
        )
        finding_ids.append(finding.id)
    return finding_ids


def _scan_matches(scanner_impl: object, target_path: Path, *, target_ref: str | None, scope_json: dict[str, object]) -> list[ScanMatch]:
    """Compatibility shim for callers of the old runner helper."""
    metadata = getattr(scanner_impl, "metadata", None)
    scanner_id = getattr(metadata, "scanner_id", None) or getattr(scanner_impl, "name", "scanner")
    return ScannerAdapter(scanner_impl, scanner_id=scanner_id).scan(
        ScanContext(ScanTarget(target_path, ref=target_ref), options=scope_json)
    ).findings
