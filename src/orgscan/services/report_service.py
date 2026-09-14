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
    if candidate.is_absolute():
        if not root:
            return None
        try:
            candidate = candidate.relative_to(PurePosixPath(root))
        except ValueError:
            return None
    if str(candidate) == '.' or '..' in candidate.parts or ':' in candidate.parts[0]:
        return None
    return str(candidate)


def _source_url(value):
    try:
        parts = urlsplit(value or '')
        if parts.scheme not in {'http', 'https'} or not parts.hostname:
            return None
        return urlunsplit((parts.scheme, parts.hostname, parts.path, '', ''))
    except ValueError:
        return None


def query_report(storage, *, limit=500, tenant_keys=None, lifecycle_state=None):
    from orgscan.reporting import build_summary, finding_rows
    rows = finding_rows(storage, limit=None, tenant_keys=tenant_keys)
    if lifecycle_state:
        rows = [row for row in rows if row['lifecycle_state'] == lifecycle_state]
    rows = rows[:limit]
    for row in rows:
        finding = storage.get_finding(row['id'])
        root = finding.repository.mirror_path if finding.repository else None
        row['repository'] = finding.repository.full_name if finding.repository else None
        row['remediation_hint'] = finding.remediation_hint
        row['evidence'] = [{
            'scanner': evidence.source, 'path': _location(evidence.repository_path, root),
            'line_start': evidence.line_start, 'line_end': evidence.line_end,
            'commit_sha': evidence.commit_sha, 'ref_name': evidence.ref_name,
            'source_url': _source_url(evidence.source_url), 'query_used': evidence.query_used,
            'observed_at': evidence.observed_at.isoformat(), 'confidence': evidence.confidence,
            'observation_fingerprint': evidence.observation_fingerprint,
        } for evidence in storage.list_finding_evidence(finding.id)]
    summary = build_summary(storage, tenant_keys=tenant_keys)
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
