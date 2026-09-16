import json
from pathlib import Path

import pytest
from pypdf import PdfReader
from sqlalchemy import event

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.models import Finding
from orgscan.repositories import Storage
from orgscan.reporting import finding_rows, write_export
from orgscan.runner import execute_scan
from orgscan.schemas import CanonicalFinding
from orgscan.services.report_service import query_report


@pytest.mark.parametrize('target_kind', ['path', 'artifact', 'mirror', 'file'])
def test_logical_locations_survive_all_report_formats(tmp_path, target_kind):
    url = f'sqlite:///{tmp_path / "locations.db"}'
    init_db(url)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    sample = workspace / 'config.txt'
    sample.write_text('api_key = "prod-token-1234567890abcdef"')
    with create_session_factory(url)() as session:
        storage = Storage(session)
        repo = storage.create_repository('org/repo', mirror_path='/cache/repo') if target_kind == 'mirror' else None
        root = Path('/orgscan-artifacts/stablehash') if target_kind == 'artifact' else Path('/cache/repo') if repo else None
        execute_scan(storage, target_path=sample if target_kind == 'file' else workspace, scanner_name='custom-patterns',
                     target_type='path' if target_kind == 'file' else target_kind, canonical_root=root,
                     repository_id=repo.id if repo else None)
        payload = query_report(storage)
    assert payload['findings'][0]['evidence'][0]['path'] == 'config.txt'
    for format in ['json', 'html', 'pdf', 'pdf-technical', 'sarif']:
        output = write_export(tmp_path / f'report.{format}', format, payload['summary'], payload['findings'])
        text = '\n'.join(p.extract_text() for p in PdfReader(output).pages) if format.startswith('pdf') else output.read_text()
        assert 'config.txt' in text
        assert str(workspace) not in text
        assert 'prod-token-1234567890abcdef' not in text


def test_large_report_filters_and_limits_are_sql_and_evidence_is_batched(tmp_path):
    url = f'sqlite:///{tmp_path / "large.db"}'
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        a, _ = storage.get_or_create_organization('A', tenant_key='a')
        b, _ = storage.get_or_create_organization('B', tenant_key='b')
        for number in range(300):
            f = storage.create_finding(CanonicalFinding(source_tool='fixture', title=f'Issue {number}', category='secret',
                description='Redacted observation', organization_id=a.id if number % 2 else b.id,
                fingerprint=f'fixture-{number}'))
            storage.create_evidence(f.id, 'fixture', repository_path=f'src/file{number}.py')
        session.commit()
    statements, loaded = [], []
    engine = factory.kw['bind']
    def record(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(engine, 'before_cursor_execute', record)
    try:
        with factory() as session:
            event.listen(session, 'loaded_as_persistent', lambda session, instance: loaded.append(instance) if isinstance(instance, Finding) else None)
            storage = Storage(session)
            payload = query_report(storage, limit=7, tenant_keys=['a'], lifecycle_state='NEW')
            assert len(payload['findings']) == 7
            assert payload['summary']['counts']['findings'] == 150
            assert payload['summary']['counts']['evidence'] == 150
            assert all(int(row['title'].split()[-1]) % 2 for row in payload['findings'])
            assert all(row['evidence'] for row in payload['findings'])
            assert len(loaded) <= 17  # Seven details plus at most ten summary priorities.
            evidence_selects = [q for q in statements if 'FROM evidence' in q and 'count(' not in q.lower()]
            assert len(evidence_selects) == 1
            assert any('LIMIT' in q and 'findings.lifecycle_state =' in q for q in statements)
            assert len(finding_rows(storage, tenant_keys=['a'], limit=3)) == 3
            assert query_report(storage, limit=0)['findings'] == []
            with pytest.raises(ValueError):
                query_report(storage, limit=-1)
    finally:
        event.remove(engine, 'before_cursor_execute', record)


def test_report_aggregates_preserve_request_authorization(tmp_path):
    from orgscan.security_context import AuthContext, current_auth
    from orgscan.storage.authorization import authorized_session_factory
    url = f'sqlite:///{tmp_path / "authorized.db"}'
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        for tenant in ('a', 'b'):
            org = storage.create_organization(tenant, tenant_key=tenant)
            f = storage.create_finding(CanonicalFinding(source_tool='fixture', title=tenant, category='secret', description='safe', organization_id=org.id))
            storage.create_evidence(f.id, 'fixture', repository_path=f'{tenant}.txt')
        session.commit()
    token = current_auth.set(AuthContext('reader', 'reader', ('a',), True))
    try:
        with authorized_session_factory(factory)() as session:
            payload = query_report(Storage(session), limit=10)
            assert [r['title'] for r in payload['findings']] == ['a']
            assert payload['summary']['counts']['findings'] == 1
            assert payload['summary']['counts']['evidence'] == 1
            assert payload['summary']['organizations'] == ['a']
    finally:
        current_auth.reset(token)


def test_evidence_location_uses_its_own_job_and_preserves_legacy_roots(tmp_path):
    url = f'sqlite:///{tmp_path / "old-evidence.db"}'
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        old = storage.create_scan_job('path', '/old/root', 'fixture', parameters_json={'path':'/old/root'})
        new = storage.create_scan_job('path', '/new/root', 'fixture', parameters_json={'location_root':'/new/root'})
        f = storage.create_finding(CanonicalFinding(source_tool='fixture', title='A', category='secret', description='safe', scan_job_id=new.id))
        storage.create_evidence(f.id, 'fixture', repository_path='/old/root/src/old.py', metadata_json={'last_scan_job_id':old.id})
        storage.create_evidence(f.id, 'fixture', repository_path='/new/root/src/new.py', metadata_json={'last_scan_job_id':new.id})
        session.commit()
        paths = {e['path'] for e in query_report(storage)['findings'][0]['evidence']}
        assert paths == {'src/old.py', 'src/new.py'}
