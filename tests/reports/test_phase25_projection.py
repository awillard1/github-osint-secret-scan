"""Legacy source context survives complete report projection, never decryption."""
import base64
from datetime import UTC, datetime
import io
import html
import json
import os

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import func, inspect, select, update

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.models import Finding, Evidence, Relationship, SecretEvidence, SecretRevealAudit
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.reporting import write_export
from orgscan.security_context import AuthContext
from orgscan.services.secret_evidence import SecretEvidenceService
from orgscan.services.report_service import query_report, ReportService

SECRET = 'AuditLegacyOpaque987654!'
FORMATS = ('json', 'csv', 'html', 'pdf', 'sarif')


@pytest.fixture
def legacy(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path / "legacy.db"}',
        data_dir=tmp_path, app_env='production', scan_queue_backend='db', preserve_secrets=True,
        secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        session.info['secret_settings'] = settings
        storage = Storage(session)
        org = storage.create_organization('Public organization', tenant_key='a')
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture', title='Public title',
            description='Public description', category='secret', organization_id=org.id,
            metadata={'password': SECRET}))
        evidence = storage.create_evidence(finding.id, 'fixture', repository_path='config.txt', line_start=4)
        relation = storage.create_relationship('finding', str(finding.id), 'organization', str(org.id), 'observed')
        session.commit()
        protected = session.scalars(select(SecretEvidence)).one()
        ids = finding.id, evidence.id, relation.id, protected.id
        original = {c.key: getattr(protected, c.key) for c in inspect(protected).mapper.columns}
    # SQL deliberately bypasses the ORM guard. Even protected legacy findings
    # require defensive presentation, without repairing the fixture while reading.
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(Finding).where(Finding.id == ids[0]).values(
            metadata_json={'password': SECRET}, remediation_hint='Rotate '+SECRET))
        connection.execute(update(Evidence).where(Evidence.id == ids[1]).values(
            metadata_json={'password': SECRET}, query_used='Observed '+SECRET))
        connection.execute(update(Relationship).where(Relationship.id == ids[2]).values(
            metadata_json={'notes': 'Source contained '+SECRET}))
    return settings, factory, ids, original


def output_text(content, fmt):
    if fmt == 'pdf':
        return '\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(content)).pages)
    return html.unescape(content.decode()) if fmt == 'html' else content.decode()


def audit_count(factory):
    with factory() as session:
        return session.scalar(select(func.count()).select_from(SecretRevealAudit))


def assert_protected_unchanged(legacy):
    _, factory, ids, original = legacy
    with factory() as session:
        row = session.get(SecretEvidence, ids[3])
        assert {c.key: getattr(row, c.key) for c in inspect(row).mapper.columns} == original
        assert SECRET in session.get(Finding, ids[0]).remediation_hint
    assert audit_count(factory) == 0


def test_exact_gate_reproduction_all_formats_and_reveal(legacy, tmp_path, monkeypatch):
    settings, factory, ids, _ = legacy
    with monkeypatch.context() as patch:
        patch.setattr('orgscan.services.secret_evidence.AESGCM.decrypt', lambda *a, **k: pytest.fail('Report decrypted'))
        with factory() as session:
            payload = query_report(Storage(session), tenant_keys=['a'])
        assert SECRET not in json.dumps(payload)
        assert 'Rotate ' in payload['findings'][0]['remediation_hint']
        assert payload['findings'][0]['evidence'][0]['path'] == 'config.txt'
        for fmt in FORMATS:
            path = write_export(tmp_path / ('report.'+fmt), fmt, payload['summary'], payload['findings'])
            result = output_text(path.read_bytes(), fmt)
            assert SECRET not in result and '<redacted>' in result
    assert_protected_unchanged(legacy)
    analyst = AuthContext('analyst', 'analyst', ('a',), True, capabilities=('secrets:reveal',))
    assert SecretEvidenceService(settings).reveal(ids[0], ids[3], analyst) == SECRET
    assert audit_count(factory) == 1


@pytest.mark.parametrize('knowledge', ['finding', 'evidence-metadata', 'evidence-snippet', 'evidence-indicator'])
@pytest.mark.parametrize('limit', [0, 1])
def test_cross_field_context_and_summary_without_detail_rows(legacy, knowledge, limit):
    _, factory, ids, _ = legacy
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(Finding).where(Finding.id == ids[0]).values(
            metadata_json={'password': SECRET} if knowledge == 'finding' else {}, title='Copied '+SECRET))
        connection.execute(update(Evidence).where(Evidence.id == ids[1]).values(
            metadata_json={'password': SECRET} if knowledge == 'evidence-metadata' else {},
            snippet='password="'+SECRET+'"' if knowledge == 'evidence-snippet' else None,
            extracted_indicator=SECRET if knowledge == 'evidence-indicator' else None))
    with factory() as session:
        payload = query_report(Storage(session), tenant_keys=['a'], limit=limit)
        assert SECRET not in json.dumps(payload)
        assert len(payload['findings']) == limit
    assert_protected_unchanged(legacy)


@pytest.mark.parametrize('role', ['reader', 'analyst', 'admin'])
def test_http_reports_never_reveal_for_any_role(legacy, role):
    settings, factory, _, _ = legacy
    settings.api_tokens_json = json.dumps([{'name': role, 'token': 'report-test', 'role': role,
        'tenants': ['a'], 'capabilities': ['secrets:reveal'] if role == 'analyst' else []}])
    with TestClient(create_app(settings.database_url, settings=settings)) as client:
        for fmt in FORMATS:
            response = client.get('/reports/export/'+fmt, headers={'X-Orgscan-Token': 'report-test'})
            assert response.status_code == 200
            assert SECRET not in output_text(response.content, fmt)
    assert_protected_unchanged(legacy)


def test_scheduled_report_and_webhook_share_safe_projection(legacy, tmp_path, monkeypatch):
    from orgscan.scheduler import run_due_reports
    settings, factory, _, _ = legacy
    sent = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr('orgscan.reporting.urlopen', lambda request, **kwargs: (sent.append(request.data) or Response()))
    with factory() as session:
        storage = Storage(session)
        for fmt in FORMATS:
            storage.create_scheduled_report('tenant', datetime.now(UTC), target_value='a', cadence='manual',
                output_format=fmt, output_path=str(tmp_path/('scheduled.'+fmt)), webhook_url='https://hook.example/report')
        session.commit()
        results = run_due_reports(storage, settings=settings)
        assert len(results) == 5
    for fmt in FORMATS:
        assert SECRET not in output_text((tmp_path/('scheduled.'+fmt)).read_bytes(), fmt)
    assert len(sent) == 5 and all(SECRET.encode() not in item for item in sent)
    assert_protected_unchanged(legacy)


def queued_export(database_url, fmt):
    # There is no built-in queued-report job type; an RQ caller can enqueue
    # this service invocation without reconstructing the report DTO in a worker.
    return ReportService(create_session_factory(database_url)).export_bytes(fmt, tenant_keys=['a'])


def test_rq_service_export_uses_same_projection(legacy):
    import fakeredis
    from rq import Queue, SimpleWorker
    settings, _, _, _ = legacy
    connection = fakeredis.FakeRedis()
    queue = Queue('report-probe', connection=connection)
    jobs = [queue.enqueue(queued_export, settings.database_url, fmt) for fmt in FORMATS]
    SimpleWorker([queue], connection=connection).work(burst=True)
    for job, fmt in zip(jobs, FORMATS):
        job.refresh()
        assert job.is_finished
        assert SECRET not in output_text(job.return_value(), fmt)
    assert_protected_unchanged(legacy)


def test_context_overflow_fails_closed(legacy, monkeypatch):
    from orgscan.redaction import SanitizationLimitError
    monkeypatch.setattr('orgscan.reports.projection.MAX_CONTEXT_ROWS', 0)
    with legacy[1]() as session:
        with pytest.raises(SanitizationLimitError, match='context row limit'):
            query_report(Storage(session))


def test_legacy_report_without_protected_evidence(legacy):
    _, factory, ids, _ = legacy
    with factory.kw['bind'].begin() as connection:
        connection.execute(SecretEvidence.__table__.delete().where(SecretEvidence.id == ids[3]))
    service = ReportService(factory)
    for fmt in FORMATS:
        assert SECRET not in output_text(service.export_bytes(fmt, tenant_keys=['a']), fmt)
    assert audit_count(factory) == 0


def test_summary_custom_hint_context_outside_priority_and_detail_limits(legacy):
    _, factory, ids, _ = legacy
    with factory() as session:
        storage = Storage(session)
        owner = session.get(Finding, ids[0]).organization_id
        for i in range(12):
            storage.create_finding(CanonicalFinding(source_tool='fixture', category='secret', title=f'Priority {i}',
                description='Public', organization_id=owner, risk_score=100))
        session.commit()
    with factory.kw['bind'].begin() as connection:
        connection.execute(Relationship.__table__.delete().where(Relationship.id == ids[2]))
    with factory() as session:
        payload = query_report(Storage(session), limit=0, tenant_keys=['a'])
    assert ids[0] not in [row['id'] for row in payload['summary']['top_risky_findings']]
    assert payload['summary']['counts']['findings'] == 13
    assert SECRET not in json.dumps(payload)


def test_compatibility_finding_rows_share_evidence_context(legacy):
    from orgscan.reporting import finding_rows
    _, factory, ids, _ = legacy
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(Finding).where(Finding.id == ids[0]).values(
            title='Copied '+SECRET, metadata_json={}))
    with factory() as session:
        rows = finding_rows(Storage(session), tenant_keys=['a'])
    assert SECRET not in json.dumps(rows)
    assert_protected_unchanged(legacy)


def test_new_persistence_already_removes_report_copies(legacy):
    settings, factory, ids, _ = legacy
    with factory() as session:
        session.info['secret_settings'] = settings
        storage = Storage(session)
        owner = session.get(Finding, ids[0]).organization_id
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture', category='secret',
            title='New finding', description='Public', metadata={'password': SECRET},
            remediation_hint='Rotate '+SECRET, organization_id=owner))
        evidence = storage.create_evidence(finding.id, 'fixture', metadata_json={'password': SECRET},
                                           query_used='Observed '+SECRET)
        session.commit()
        for record in (finding, evidence):
            assert all(SECRET not in str(getattr(record, c.key)) for c in inspect(record).mapper.columns)
        assert session.scalar(select(func.count()).select_from(SecretEvidence).where(SecretEvidence.finding_id == finding.id)) == 1
