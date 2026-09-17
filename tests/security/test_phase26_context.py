"""Context completeness must be independent of display and include evidence."""
import base64
from datetime import UTC, datetime
import html
import io
import json
import os

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import event, inspect, select, update, func

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.models import Finding, Evidence, SecretEvidence, SecretRevealAudit, Relationship
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.services.report_service import query_report
from orgscan.services.secret_evidence import SecretEvidenceService
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.reporting import write_export
from orgscan.redaction import SanitizationLimitError

SECRET = 'AuditLegacyOpaque987654!'
FORMATS = ('json', 'csv', 'html', 'pdf', 'sarif')


@pytest.fixture
def legacy(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path/"context.db"}', data_dir=tmp_path,
        app_env='production', scan_queue_backend='db', preserve_secrets=True,
        secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        session.info['secret_settings'] = settings
        storage = Storage(session)
        org = storage.create_organization('Tenant A', tenant_key='a')
        storage.create_organization('Tenant B', tenant_key='b')
        source = storage.create_finding(CanonicalFinding(source_tool='fixture', category='secret',
            title='Source', description='Public', risk_score=1, organization_id=org.id, metadata={'password':SECRET}))
        evidence = storage.create_evidence(source.id, 'fixture', repository_path='config.txt')
        session.commit()
        protected = session.scalars(select(SecretEvidence)).one()
        snapshot = {c.key:getattr(protected,c.key) for c in inspect(protected).mapper.columns}
        ids = org.id, source.id, evidence.id, protected.id
    return settings, factory, ids, snapshot


def audit_count(factory):
    with factory() as session:
        return session.scalar(select(func.count()).select_from(SecretRevealAudit))


def assert_reveal(legacy):
    settings, factory, ids, snapshot = legacy
    with factory() as session:
        protected = session.get(SecretEvidence, ids[3])
        assert {c.key:getattr(protected,c.key) for c in inspect(protected).mapper.columns} == snapshot
    assert audit_count(factory) == 0
    service = SecretEvidenceService(settings)
    for auth in (AuthContext('reader','reader',('a',),True), AuthContext('ungranted','analyst',('a',),True),
                 AuthContext('foreign','admin',('b',),True)):
        with pytest.raises(AuthorizationError): service.reveal(ids[1], ids[3], auth)
    auth = AuthContext('analyst','analyst',('a',),True,capabilities=('secrets:reveal',))
    assert service.reveal(ids[1],ids[3],auth) == SECRET
    assert audit_count(factory) == 1


def render_text(path, fmt):
    if fmt == 'pdf': return '\n'.join(p.extract_text() for p in PdfReader(path).pages)
    return html.unescape(path.read_text())


@pytest.mark.parametrize('knowledge', ['finding', 'evidence'])
@pytest.mark.parametrize('copied_field', ['source_tool', 'title', 'category', 'query', 'provenance'])
def test_report_sources_outside_all_display_selections(legacy, tmp_path, monkeypatch, knowledge, copied_field):
    settings,factory,ids,_=legacy
    with factory() as session:
        storage=Storage(session)
        repo=storage.create_repository('a/public',organization_id=ids[0])
        for i in range(12):
            last=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title=f'Priority {i}',
                description='Public',risk_score=100,organization_id=ids[0]))
        evidence=storage.create_evidence(last.id,'fixture',repository_path='new.txt')
        relation=storage.create_relationship('organization',str(ids[0]),'repository',str(repo.id),'owns')
        session.commit();last_id,other_evidence,relation_id=last.id,evidence.id,relation.id
    with factory.kw['bind'].begin() as c:
        c.execute(update(Finding).where(Finding.id==ids[1]).values(metadata_json={'password':SECRET} if knowledge=='finding' else {},remediation_hint=None))
        c.execute(update(Evidence).where(Evidence.id==ids[2]).values(metadata_json={'password':SECRET} if knowledge=='evidence' else {}))
        if copied_field in ('source_tool','category'):
            c.execute(update(Finding).where(Finding.id==ids[1]).values(**{copied_field:'Copied '+SECRET}))
        elif copied_field=='title':
            c.execute(update(Finding).where(Finding.id==last_id).values(title='Copied '+SECRET))
        elif copied_field=='query':
            c.execute(update(Evidence).where(Evidence.id==other_evidence).values(query_used='Observed '+SECRET))
        else:
            c.execute(update(Relationship).where(Relationship.id==relation_id).values(metadata_json={'notes':'Source contained '+SECRET}))
    with monkeypatch.context() as patch:
        patch.setattr('orgscan.services.secret_evidence.AESGCM.decrypt',lambda *a,**k:pytest.fail('Report decrypted'))
        with factory() as session:
            payload=query_report(Storage(session),tenant_keys=['a'],limit=1)
            from orgscan.reporting import finding_rows
            assert SECRET not in json.dumps(finding_rows(Storage(session), tenant_keys=['a'], limit=1))
        assert ids[1] not in [f['id'] for f in payload['findings']+payload['summary']['top_risky_findings']]
        assert payload['summary']['counts']['findings']==13
        assert SECRET not in json.dumps(payload)
        for fmt in FORMATS:
            path=write_export(tmp_path/('out.'+fmt),fmt,payload['summary'],payload['findings'])
            assert SECRET not in render_text(path,fmt)
    assert_reveal(legacy)


@pytest.mark.parametrize('role', ['reader','ungranted','analyst','admin'])
def test_generic_finding_evidence_context_and_exact_reveal(legacy,role,monkeypatch):
    settings,factory,ids,_=legacy
    settings.api_tokens_json=json.dumps([{'name':role,'token':'gate','role':'analyst' if role in ('analyst','ungranted') else role,
        'tenants':['a'],'capabilities':['secrets:reveal'] if role=='analyst' else []}])
    with factory.kw['bind'].begin() as c:
        c.execute(update(Finding).where(Finding.id==ids[1]).values(title='Copied '+SECRET,description='Copied '+SECRET,metadata_json={},risk_score=100))
        c.execute(update(Evidence).where(Evidence.id==ids[2]).values(metadata_json={'password':SECRET},query_used='Observed '+SECRET))
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        with monkeypatch.context() as patch:
            patch.setattr('orgscan.services.secret_evidence.AESGCM.decrypt',lambda *a,**k:pytest.fail('Generic read decrypted'))
            for url in ('/findings',f'/findings/{ids[1]}','/dashboard',f'/dashboard/findings/{ids[1]}',
                        f'/findings/{ids[1]}/evidence','/summary','/operator/overview'):
                response=client.get(url,headers={'X-Orgscan-Token':'gate'})
                assert response.status_code==200, url
                assert SECRET not in html.unescape(response.text), url
        if role in ('reader','ungranted'):
            assert client.post(f'/findings/{ids[1]}/secrets/{ids[3]}/reveal',headers={'X-Orgscan-Token':'gate'}).status_code==403
    with factory() as session:
        assert SECRET in session.get(Finding,ids[1]).title  # Presentation did the work.
    assert_reveal(legacy)


def test_report_context_scope_is_intersection_not_requested_scope_alone(legacy):
    from orgscan.storage.authorization import authorized_session_factory
    from orgscan.storage.sources import scoped_reader
    from orgscan.storage.credential_context import build_report_context
    _,factory,ids,_=legacy
    with factory.kw['bind'].begin() as c:
        c.execute(update(Finding).where(Finding.id==ids[1]).values(metadata_json={'password':SECRET}))
    auth_token=current_auth.set(AuthContext('b','reader',('b',),True))
    try:
        with authorized_session_factory(factory)() as session:
            with scoped_reader(Storage(session),['a']) as scoped:
                ctx=build_report_context(scoped,tenant_keys=['a'])
                assert ctx.sanitize({'copy':SECRET})['copy']==SECRET  # A's knowledge was not read.
                payload=query_report(scoped,tenant_keys=['a'])
                assert payload['summary']['counts']['findings']==0
    finally:current_auth.reset(auth_token)


@pytest.mark.parametrize('kind', ['report','finding'])
def test_complete_context_overflow_is_safe(legacy,monkeypatch,kind):
    _,factory,ids,_=legacy
    with factory.kw['bind'].begin() as c:
        c.execute(Evidence.__table__.insert(),[{'finding_id':ids[1],'source':'fixture','metadata_json':{'password':SECRET}} for _ in range(1000)])
    if kind=='finding':
        monkeypatch.setenv('ORGSCAN_FINDING_CONTEXT_MAX_ROWS','1000')
    else:
        monkeypatch.setattr('orgscan.reports.projection.MAX_CONTEXT_ROWS',1000)
    with factory() as session:
        with pytest.raises(SanitizationLimitError,match='context row limit') as exc:
            if kind=='report':query_report(Storage(session),tenant_keys=['a'],limit=1)
            else:Storage(session).list_findings(limit=1)
        assert SECRET not in str(exc.value)
    assert_reveal(legacy)


def test_missing_detached_context_fails_closed(legacy):
    from orgscan.presentation import safe_finding_fields
    with legacy[1]() as session:
        finding=session.get(Finding,legacy[2][1])
    with pytest.raises(SanitizationLimitError,match='context is required'):
        safe_finding_fields(finding,{'title':finding.title})


@pytest.mark.parametrize('size',[10,100,300])
def test_context_queries_are_constant_and_page_scoped(legacy,size):
    from orgscan.storage.credential_context import build_report_context
    _,factory,ids,_=legacy
    with factory() as session:
        storage=Storage(session)
        for i in range(size-1):
            f=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title=f'Finding {i}',description='Public',organization_id=ids[0]))
            storage.create_evidence(f.id,'fixture')
        session.commit()
    statements=[]
    engine=factory.kw['bind']
    def track(conn,cursor,sql,params,ctx,many):
        if sql.lstrip().upper().startswith('SELECT'):statements.append(sql)
    event.listen(engine,'before_cursor_execute',track)
    try:
        with factory() as session:
            Storage(session).list_findings(limit=7)
        assert len(statements)==2
        assert sum('UNION ALL' in s for s in statements)==1
        assert 'LIMIT' in statements[-1]
        statements.clear()
        with factory() as session:build_report_context(Storage(session),tenant_keys=['a'])
        assert len(statements)==1 and 'UNION ALL' in statements[0]
        assert 'secret_evidence' not in statements[0]
        print(f'context findings={size}: page=2 SELECTs; report-context=1 SELECT')
    finally:event.remove(engine,'before_cursor_execute',track)
