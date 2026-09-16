from __future__ import annotations

from orgscan.redaction import redact, safe_error

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from orgscan.config import Settings
from orgscan.repositories import Storage
from orgscan.scoring import calculate_risk_score
from orgscan.schemas import CanonicalFinding
from orgscan.scanners import get_scanner
from orgscan.scanners.base import ScanContext, ScanMatch, ScanTarget, ScannerExecutionError
from orgscan.scanners.registry import ScannerAdapter


@dataclass(frozen=True)
class ScanExecutionResult:
    scan_job_id: int
    scanner: str
    target: str
    findings: int
    finding_ids: list[int]
    tool_run_id: int
    status: str = "completed"
    skip_reason: str | None = None

    def __post_init__(self):
        object.__setattr__(self, 'target', redact(self.target))


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
    storage.session.info['secret_settings'] = settings or Settings()
    scanner = get_scanner(scanner_name, settings=settings) if settings is not None else get_scanner(scanner_name)
    scanner_impl = ScannerAdapter(scanner, scanner_id=scanner_name, settings=settings)
    from orgscan.scanners.files import validate_scan_target
    resolved_target = validate_scan_target(target_path)
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
            "location_root": str(canonical_root or (resolved_target if resolved_target.is_dir() else resolved_target.parent)),
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
        tool_run.tool_version = scanner_impl.metadata.version
        matches = result.findings
        if canonical_root is not None:
            source_root = resolved_target if resolved_target.is_dir() else resolved_target.parent
            def stable(value):
                if isinstance(value, str) and (value == str(source_root) or value.startswith(str(source_root) + '/')):
                    return str(canonical_root) + value[len(str(source_root)):]
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
        message = safe_error(exc)
        storage.session.rollback()
        storage.mark_scan_job_failed(scan_job, message)
        storage.mark_tool_run_failed(tool_run, stderr_log=message)
        storage.session.commit()
        raise ScannerExecutionError(message) from None

    return ScanExecutionResult(
        scan_job_id=scan_job.id,
        scanner=scanner_name,
        target=effective_tool_target,
        findings=len(matches),
        finding_ids=finding_ids,
        tool_run_id=tool_run.id,
    )


def record_skipped_scan(storage: Storage, *, plan, scanner_name: str, ref_name: str, scope: dict, reason: str) -> ScanExecutionResult:
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    job = storage.create_scan_job('mirror', plan.target, scanner_name, target_ref=ref_name, status='skipped',
                                  parameters_json={'scan_plan': plan.serialized()}, scope_json=scope, completed_at=now)
    run = storage.create_tool_run(scanner_name, f'{plan.target}@{ref_name}', scan_job_id=job.id,
                                   status='skipped', stdout_log=reason, completed_at=now)
    storage.session.commit()
    return ScanExecutionResult(job.id, scanner_name, run.target, 0, [], run.id, 'skipped', reason)


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
        message = safe_error(exc)
        storage.session.rollback()
        storage.mark_scan_job_failed(scan_job, message)
        storage.mark_tool_run_failed(tool_run, stderr_log=message)
        storage.session.commit()
        raise ScannerExecutionError(message) from None

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
    from orgscan.services.correlation import finding_identity, evidence_identity, detector_id
    finding_ids: list[int] = []
    from orgscan.redaction import sanitize_matches
    from orgscan.services.secret_evidence import preservation_context
    with preservation_context(storage.session.info.get('secret_settings')):
        sanitized = sanitize_matches(matches)
    for match in sanitized:
        identity = finding_identity(
            match, scanner_name, organization_id=organization_id, repository_id=repository_id
        )
        finding = storage.upsert_correlated_finding(
            CanonicalFinding(
                normalized_hash=identity,
                fingerprint=identity,
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
            ),
            protected_candidates=match.protected_candidates,
        )
        storage.upsert_scanner_evidence(
            finding_id=finding.id,
            observation_fingerprint=evidence_identity(finding.id, scanner_name, match),
            metadata_json={
                "detector_id": detector_id(match), "scanner_metadata": match.metadata,
                "last_scan_job_id": scan_job_id, "severity": str(match.severity),
                "confidence": str(match.confidence), "title": match.title,
            },
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
