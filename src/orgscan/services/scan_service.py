"""Execute resolved plans using existing scanner, mirror and provider engines."""
from pathlib import Path

from orgscan.config import Settings
from orgscan.repositories import Storage
from orgscan.runner import ScanExecutionResult, execute_scan
from orgscan.services.scan_plan import ScanPlan, validate_plan_scanners
from orgscan.services.job_policy import classify_failure, ClassifiedJobError


def execute_plan(storage: Storage, plan: ScanPlan, *, settings: Settings | None = None, **execution) -> list[ScanExecutionResult]:
    validate_plan_scanners(plan, settings=settings)
    if plan.target_type == 'domain':
        from orgscan.providers import get_domain_provider
        job = storage.create_scan_job('domain', plan.target, plan.discovery_provider, parameters_json={'scan_plan': plan.serialized()})
        run = storage.create_tool_run(tool_name=plan.discovery_provider, target=plan.target, scan_job_id=job.id, command_line='orgscan scan-plan')
        storage.mark_scan_job_running(job)
        storage.mark_tool_run_running(run)
        storage.session.commit()
        try:
            outcome = get_domain_provider(plan.discovery_provider, settings).discover(storage, plan.target)
            if getattr(outcome, "failure", None):
                # Keep partial observations/request provenance before a deferred retry.
                storage.session.commit()
                raise ClassifiedJobError(outcome.failure)
            storage.mark_scan_job_completed(job)
            storage.mark_tool_run_completed(run)
            storage.session.commit()
        except Exception as exc:
            failure = classify_failure(exc)
            storage.session.rollback()
            storage.mark_scan_job_failed(job, 'Domain discovery failed')
            storage.mark_tool_run_failed(run, stderr_log='Domain discovery failed')
            storage.session.commit()
            raise ClassifiedJobError(failure) from None
        return [ScanExecutionResult(job.id, plan.discovery_provider, plan.target, 0, [], run.id)]
    if plan.target_type == 'mirror':
        from orgscan.mirroring import scan_repository_mirror_refs
        return scan_repository_mirror_refs(storage, settings=settings or Settings(), repository_full_name=plan.target,
                                           scanner_name=plan.scanners[0], refs=list(plan.refs), plan=plan, **execution)
    if plan.mode == 'incremental':
        raise ValueError('Incremental execution requires mirror orchestration')
    return [execute_scan(storage, target_path=Path(plan.target), scanner_name=name, settings=settings,
                         organization_id=plan.organization_id, repository_id=plan.repository_id,
                         target_type=plan.target_type, scope_json={'mode': plan.target_type, 'history_mode': plan.history_policy, **plan.scope},
                         plan=plan, **execution) for name in plan.scanners]


def result_payload(results: list[ScanExecutionResult]) -> dict:
    """Retain single-scan response fields; batches additionally expose each run."""
    from dataclasses import asdict
    payload = asdict(results[0])
    if len(results) > 1:
        payload['results'] = [asdict(result) for result in results]
        payload['findings'] = sum(result.findings for result in results)
        payload['finding_ids'] = [value for result in results for value in result.finding_ids]
    return payload
