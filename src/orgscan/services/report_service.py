"""One canonical report query for CLI, HTTP and scheduled format adapters."""
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit, urlunsplit

from orgscan.reports.redaction import redact
from orgscan.repositories import Storage


def _location(path, root):
    if not path:
        return None
    candidate = PurePosixPath(path.replace('\\', '/'))
    if candidate.is_absolute() or (candidate.parts and candidate.parts[0].endswith(":")):
        if not root:
            return None
        try:
            candidate = candidate.relative_to(PurePosixPath(root.replace('\\', '/')))
        except ValueError:
            return None
    if str(candidate) == '.' or '..' in candidate.parts or ':' in candidate.parts[0]:
        return None
    return str(candidate)


def evidence_location(path, root, params):
    if root:
        return _location(path, root)
    # Legacy records predate location_root. Never expose arbitrary absolute paths.
    candidate = PurePosixPath((path or '').replace('\\', '/'))
    if len(candidate.parts) > 3 and candidate.parts[1] == 'orgscan-artifacts':
        return _location(str(PurePosixPath(*candidate.parts[3:])), None)
    target = (params or {}).get('path')
    if target:
        base = PurePosixPath(target.replace('\\', '/'))
        return _location(path, str(base.parent if candidate == base else base))
    return _location(path, None)


def _source_url(value):
    try:
        parts = urlsplit(value or '')
        if parts.scheme not in {'http', 'https'} or not parts.hostname:
            return None
        return urlunsplit((parts.scheme, parts.hostname, parts.path, '', ''))
    except ValueError:
        return None


def query_report(storage, *, limit=500, tenant_keys=None, lifecycle_state=None):
    if tenant_keys is not None:
        from orgscan.storage.sources import scoped_reader
        with scoped_reader(storage, tenant_keys) as scoped:
            return _query_report(scoped, limit=limit, tenant_keys=tenant_keys, lifecycle_state=lifecycle_state)
    return _query_report(storage, limit=limit, tenant_keys=tenant_keys, lifecycle_state=lifecycle_state)


def _query_report(storage, *, limit=500, tenant_keys=None, lifecycle_state=None):
    from orgscan.reporting import finding_row
    if limit is not None and limit < 0:
        raise ValueError('Report limit must be nonnegative')
    findings = storage.list_findings(limit=limit, tenant_keys=tenant_keys,
                                     lifecycle_state=lifecycle_state, include_evidence=True)
    evidence_job_ids = {(e.metadata_json or {}).get('last_scan_job_id') for f in findings for e in f.evidence_items}
    evidence_jobs = storage.get_scan_jobs_by_ids([identity for identity in evidence_job_ids if isinstance(identity, int)]) if evidence_job_ids else {}
    def location(evidence, root, params, repository_root):
        job = evidence_jobs.get((evidence.metadata_json or {}).get('last_scan_job_id'))
        if job:
            params = job.parameters_json or {}
            root = params.get('location_root') or repository_root
        return evidence_location(evidence.repository_path, root, params)
    rows = []
    for finding in findings:
        row = finding_row(finding)
        repository_root = finding.repository.mirror_path if finding.repository else None
        root = repository_root
        params = finding.scan_job.parameters_json if finding.scan_job else {}
        root = (params or {}).get('location_root') or root
        row['repository'] = finding.repository.full_name if finding.repository else None
        row['remediation_hint'] = finding.remediation_hint
        row['evidence'] = [{
            'scanner': evidence.source, 'path': location(evidence, root, params, repository_root),
            'line_start': evidence.line_start, 'line_end': evidence.line_end,
            'commit_sha': evidence.commit_sha, 'ref_name': evidence.ref_name,
            'source_url': _source_url(evidence.source_url), 'query_used': evidence.query_used,
            'observed_at': evidence.observed_at.isoformat(), 'confidence': evidence.confidence,
            'observation_fingerprint': evidence.observation_fingerprint,
        } for evidence in sorted(finding.evidence_items, key=lambda e: (e.observed_at, e.id), reverse=True)]
        rows.append(row)
    summary = storage.report_summary(tenant_keys=tenant_keys)
    for collection, field in (('recent_scan_jobs', 'target_id'), ('recent_tool_runs', 'target')):
        for row in summary.get(collection, []):
            value = PurePosixPath(str(row[field]).replace('\\', '/'))
            if value.is_absolute():
                row[field] = value.name
    summary['report_scope'] = {'included_findings': len(rows), 'limit': limit, 'lifecycle_state': lifecycle_state,
                               'summary_scope': 'all authorized findings'}
    return {'summary': redact(summary), 'findings': redact(rows)}


class ReportService:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def query(self, **options):
        with self.session_factory() as session:
            return query_report(Storage(session), **options)

    def export_bytes(self, export_format, **options):
        from orgscan.reporting import write_export
        payload = self.query(**options)
        with TemporaryDirectory(prefix='orgscan-report-') as workspace:
            output = write_export(Path(workspace)/'report', export_format, payload['summary'], payload['findings'])
            return output.read_bytes()
