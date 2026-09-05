from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from orgscan.repositories import Storage
from orgscan.scoring import calculate_risk_score
from orgscan.schemas import CanonicalFinding
from orgscan.scanners import ScannerExecutionError, get_scanner


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
    organization_id: int | None = None,
    repository_id: int | None = None,
) -> ScanExecutionResult:
    scanner_impl = get_scanner(scanner_name)
    resolved_target = target_path.resolve()

    scan_job = storage.create_scan_job(
        target_type="path",
        target_id=str(resolved_target),
        scanner_name=scanner_impl.name,
        status="pending",
        parameters_json={"path": str(resolved_target)},
    )
    tool_run = storage.create_tool_run(
        tool_name=scanner_impl.name,
        target=str(resolved_target),
        scan_job_id=scan_job.id,
        command_line=f"orgscan scan path {resolved_target} --scanner {scanner_impl.name}",
        status="pending",
    )
    storage.mark_scan_job_running(scan_job)
    storage.mark_tool_run_running(tool_run)
    storage.session.commit()

    try:
        matches = scanner_impl.scan_path(resolved_target)
        finding_ids: list[int] = []
        for match in matches:
            finding = storage.create_finding(
                CanonicalFinding(
                    source_tool=scanner_impl.name,
                    source_name=scanner_impl.name,
                    category=match.category,
                    title=match.title,
                    description=match.description,
                    severity=match.severity,
                    confidence=match.confidence,
                    remediation_hint=match.remediation_hint,
                    risk_score=calculate_risk_score(
                        severity=str(match.severity),
                        confidence=str(match.confidence),
                        source_class="internal",
                    ),
                    raw_payload=match.raw_payload,
                    metadata=match.metadata,
                    organization_id=organization_id,
                    repository_id=repository_id,
                    scan_job_id=scan_job.id,
                )
            )
            storage.create_evidence(
                finding_id=finding.id,
                source=scanner_impl.name,
                repository_path=str(match.path),
                line_start=match.line_start,
                line_end=match.line_end,
                snippet=match.snippet,
                extracted_indicator=match.indicator,
                confidence=match.confidence,
                source_class="internal",
            )
            storage.create_risk_score(
                "finding",
                str(finding.id),
                finding.risk_score or 0,
                finding_id=finding.id,
                severity=finding.severity,
                confidence=finding.confidence,
                rationale=f"Calculated from severity={finding.severity}, confidence={finding.confidence}, source_class=internal.",
            )
            finding_ids.append(finding.id)
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
        scanner=scanner_impl.name,
        target=str(resolved_target),
        findings=len(matches),
        finding_ids=finding_ids,
        tool_run_id=tool_run.id,
    )
