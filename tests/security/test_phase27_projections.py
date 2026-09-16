"""Derived text must retain ordinary source knowledge without ever decrypting."""
import base64
from datetime import UTC, datetime
import html
import json
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, inspect, select, update

from orgscan.api import create_app, OrgscanApiService
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.services.secret_evidence import SecretEvidenceService
from orgscan.redaction import SanitizationLimitError
from orgscan.storage.credential_context import build_projection_context

SECRET = 'AuditLegacyOpaque987654!'


@pytest.fixture
def legacy(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path/"projection.db"}',
        app_env='production', data_dir=tmp_path, scan_queue_backend='db', preserve_secrets=True,
        secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        session.info['secret_settings'] = settings
        st = Storage(session)
        org = st.create_organization('Tenant A', tenant_key='a')
        foreign = st.create_organization('Tenant B', tenant_key='b')
        repo = st.create_repository('a/public', organization_id=org.id)
        account = st.create_account('public-user', organization_id=org.id)
        domain = st.create_domain('example.test', organization_id=org.id)
        job = st.create_scan_job('repository', str(repo.id), 'fixture', status='failed')
        tool = st.create_tool_run('fixture', 'public-target', scan_job_id=job.id)
        finding = st.create_finding(CanonicalFinding(source_tool='fixture', title='Public',
            description='Public', category='secret', severity='high', confidence='likely', risk_score=90,
            organization_id=org.id, repository_id=repo.id, scan_job_id=job.id, metadata={'password':SECRET}))
        evidence = st.create_evidence(finding.id, 'fixture')
        relation = st.create_relationship('organization', str(org.id), 'repository', str(repo.id), 'owns')
        schedule = st.create_scheduled_scan('repository',str(repo.id),'fixture',datetime.now(UTC),cadence='manual')
        session.commit()
        protected = session.scalars(select(m.SecretEvidence)).one()
        snapshot = {c.key:getattr(protected,c.key) for c in inspect(protected).mapper.columns}
        ids = {name:obj.id for name,obj in locals().copy().items()
               if isinstance(obj,(m.Organization,m.Repository,m.Account,m.Domain,m.ScanJob,m.ToolRun,
                                  m.Finding,m.Evidence,m.Relationship,m.ScheduledScan,m.SecretEvidence))}
    return settings,factory,ids,snapshot


def audits(factory):
    with factory() as s:return s.scalar(select(func.count()).select_from(m.SecretRevealAudit))


def reveal(legacy, role='analyst'):
    settings,factory,ids,snapshot=legacy
    assert audits(factory)==0
    with factory() as s:
        row=s.get(m.SecretEvidence,ids['protected'])
        assert {c.key:getattr(row,c.key) for c in inspect(row).mapper.columns}==snapshot
    service=SecretEvidenceService(settings)
    for auth in (AuthContext('reader','reader',('a',),True),AuthContext('ungranted','analyst',('a',),True),
                 AuthContext('foreign','admin',('b',),True)):
        with pytest.raises(AuthorizationError):service.reveal(ids['finding'],ids['protected'],auth)
    auth=AuthContext(role,role,('a',),True,capabilities=('secrets:reveal',) if role=='analyst' else ())
    assert service.reveal(ids['finding'],ids['protected'],auth)==SECRET
    assert audits(factory)==1


def unsafe(factory, model, identity, **values):
    with factory.kw['bind'].begin() as c:c.execute(update(model).where(model.id==identity).values(**values))


def seed_case(legacy,case):
    _,factory,ids,_=legacy
    copy='Copied '+SECRET
    model,identity,values={
        'job':(m.ScanJob,ids['job'],dict(scanner_name=copy,parameters_json={'password':SECRET})),
        'job-error':(m.ScanJob,ids['job'],dict(error_message=copy,parameters_json={'token':SECRET})),
        'tool':(m.ToolRun,ids['tool'],dict(tool_name=copy,stdout_log='password='+SECRET)),
        'repository':(m.Repository,ids['repo'],dict(full_name=copy,metadata_json={'password':SECRET})),
        'provider':(m.Repository,ids['repo'],dict(provider=copy,metadata_json={'token':SECRET})),
        'account':(m.Account,ids['account'],dict(username=copy,metadata_json={'password':SECRET})),
        'domain':(m.Domain,ids['domain'],dict(name=copy,discovery_sources=[{'token':SECRET}])),
        'organization':(m.Organization,ids['org'],dict(name=copy,metadata_json={'password':SECRET})),
        'relationship':(m.Relationship,ids['relation'],dict(relation_type=copy,source=copy,metadata_json={'password':SECRET})),
        'severity':(m.Finding,ids['finding'],dict(severity=copy,metadata_json={'password':SECRET})),
        'category':(m.Finding,ids['finding'],dict(category=copy,metadata_json={'password':SECRET})),
        'source-tool':(m.Finding,ids['finding'],dict(source_tool=copy,metadata_json={'password':SECRET})),
        'schedule':(m.ScheduledScan,ids['schedule'],dict(scanner_name=copy,metadata_json={'password':SECRET})),
    }[case]
    unsafe(factory,model,identity,**values)
    return model,identity,values


CASES=('job','job-error','tool','repository','provider','account','domain','organization',
       'relationship','severity','category','source-tool','schedule')


@pytest.mark.parametrize('case',CASES)
def test_legacy_derived_surfaces_and_exact_reveal(legacy,monkeypatch,case):
    settings,factory,ids,_=legacy
    model,identity,values=seed_case(legacy,case)
    settings.api_tokens_json=json.dumps([{'name':'reader','token':'gate','role':'reader','tenants':['a']}])
    urls=('/operator/overview','/dashboard','/relationships/graph','/dashboard/graph','/trends/findings',
          '/summary','/repositories','/accounts','/domains','/organizations','/scheduled-scans',
          f'/scan-jobs/{ids["job"]}',f'/dashboard/scan-jobs/{ids["job"]}',
          f'/repositories/{ids["repo"]}',f'/domains/{ids["domain"]}',f'/accounts/{ids["account"]}',
          f'/organizations/{ids["org"]}',f'/findings/{ids["finding"]}')
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        with monkeypatch.context() as patch:
            patch.setattr('orgscan.services.secret_evidence.AESGCM.decrypt',lambda *a,**k:pytest.fail('Generic decryption'))
            for url in urls:
                r=client.get(url,headers={'X-Orgscan-Token':'gate'})
                assert r.status_code==200,url
                assert SECRET not in html.unescape(r.text),url
        assert client.post(f'/findings/{ids["finding"]}/secrets/{ids["protected"]}/reveal',headers={'X-Orgscan-Token':'gate'}).status_code==403
    with factory() as s:
        row=s.get(model,identity)
        assert all(getattr(row,key)==value for key,value in values.items()) # SQL legacy source remains unsafe.
    reveal(legacy,role='admin' if case=='repository' else 'analyst')


@pytest.mark.parametrize('family',('operator','jobs','assets','graph','trends','schedules'))
def test_projection_context_never_learns_other_tenant(legacy,family):
    settings,factory,ids,_=legacy
    unsafe(factory,m.Repository,ids['repo'],metadata_json={'password':SECRET})
    unsafe(factory,m.Finding,ids['finding'],metadata_json={'password':SECRET})
    with factory() as s:
        st=Storage(s)
        st.create_repository('Coincidental '+SECRET,organization_id=ids['foreign'])
        task=st.create_queue_task(ids['schedule'],backend='db',queue_name='public',status='failed',
            max_attempts=1,available_at=datetime.now(UTC))
        s.commit();task_id=task.id
    unsafe(factory,m.QueueTask,task_id,metadata_json={'password':SECRET})
    from orgscan.storage.authorization import authorized_session_factory
    token=current_auth.set(AuthContext('b','reader',('b',),True))
    try:
        with authorized_session_factory(factory)() as s:
            context=build_projection_context(Storage(s),family=family)
            assert context.sanitize({'label':'Coincidental '+SECRET})=={'label':'Coincidental '+SECRET}
    finally:current_auth.reset(token)
    reveal(legacy)


@pytest.mark.parametrize('family',('operator','jobs','assets','graph','trends','schedules'))
def test_context_overflow_never_emits_partial_projection(legacy,monkeypatch,family):
    _,factory,_,_=legacy
    with factory() as s:
        assert Storage(s).safe_projection({'label':'Public'},family=family)=={'label':'Public'}
    monkeypatch.setenv('ORGSCAN_PROJECTION_CONTEXT_MAX_ROWS','1')
    with factory() as s:
        with pytest.raises(SanitizationLimitError,match='context row limit') as e:
            Storage(s).safe_projection({'label':'Copied '+SECRET},family=family)
        assert SECRET not in str(e.value)
    reveal(legacy)


@pytest.mark.parametrize('field',('severity','category','source_tool','status'))
def test_storage_aggregate_keys_and_compatibility_helpers(legacy,field):
    from orgscan.reporting import remediation_suggestions,organization_comparison
    _,factory,ids,_=legacy
    unsafe(factory,m.Finding,ids['finding'],**{field:'Copied '+SECRET,'metadata_json':{'password':SECRET},'remediation_hint':'Rotate '+SECRET})
    method={'severity':'finding_counts_by_severity','category':'finding_counts_by_category',
            'source_tool':'finding_counts_by_source_tool','status':'finding_counts_by_status'}[field]
    with factory() as s:
        st=Storage(s)
        assert SECRET not in json.dumps(getattr(st,method)())
        assert SECRET not in json.dumps(st.finding_trends_by_day())
        assert SECRET not in json.dumps(remediation_suggestions(st))
        assert SECRET not in json.dumps(organization_comparison(st))
    reveal(legacy)


@pytest.mark.parametrize('size',(10,100,300))
def test_projection_query_counts_are_batched(legacy,monkeypatch,size):
    from orgscan.reporting import relationship_graph,finding_trends
    from orgscan.services.dashboard_service import DashboardService
    settings,factory,ids,_=legacy
    # This fixture has multiple source populations per item, exceeding the default
    # 1000-row report budget at 300 items. Keep the explicit fail-closed contract.
    monkeypatch.setattr('orgscan.reports.projection.MAX_CONTEXT_ROWS',2000)
    with factory() as s:
        st=Storage(s)
        for i in range(size-1):
            repo=st.create_repository(f'a/repo-{i}',organization_id=ids['org'])
            st.create_scan_job('repository',str(repo.id),'fixture',status='failed')
            st.create_relationship('organization',str(ids['org']),'repository',str(repo.id),'owns')
            finding=st.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title=f'Finding {i}',
                description='Public',organization_id=ids['org'],repository_id=repo.id,risk_score=80))
            st.create_evidence(finding.id,'fixture')
        s.commit()
    statements=[];engine=factory.kw['bind']
    def record(conn,cursor,sql,params,context,many):
        if sql.lstrip().upper().startswith('SELECT'):statements.append(sql)
    event.listen(engine,'before_cursor_execute',record)
    try:
        totals={}
        def check(name,maximum,context_count):
            assert len(statements)<=maximum,(name,len(statements))
            assert sum(' AS kind' in sql for sql in statements)==context_count
            assert all('secret_evidence' not in sql for sql in statements)
            totals[name]=len(statements);statements.clear()
        DashboardService(factory).overview(limit=7);check('operator',15,1)
        service=OrgscanApiService(settings.database_url,settings);service.session_factory=factory
        service._tooling_payload=lambda:{'scanner_readiness':[]}
        service._dashboard_html(limit=7);check('dashboard',55,3)
        with factory() as s:relationship_graph(Storage(s),limit=7)
        check('graph',4,1)
        with factory() as s:finding_trends(Storage(s))
        check('trends',2,1)
        print(f'Phase27 size={size} SELECTs={totals}; context SELECTs operator=1 dashboard=3 graph=1 trends=1')
    finally:event.remove(engine,'before_cursor_execute',record)


def test_current_job_asset_persistence_already_redacts(legacy):
    _,factory,ids,_=legacy
    with factory() as s:
        st=Storage(s)
        repo=st.create_repository('Copied '+SECRET,organization_id=ids['org'],metadata_json={'password':SECRET})
        job=st.create_scan_job('repository',str(repo.id),'Copied '+SECRET,parameters_json={'password':SECRET},error_message='Observed '+SECRET)
        s.commit()
        for row in (repo,job):
            assert all(SECRET not in str(getattr(row,c.key)) for c in inspect(row).mapper.columns)
    reveal(legacy)


def test_cli_jobs_and_queue_diagnostics_retain_context(legacy):
    from typer.testing import CliRunner
    from orgscan.cli import app
    settings,factory,ids,_=legacy
    seed_case(legacy,'tool')
    with factory() as s:
        task=Storage(s).create_queue_task(ids['schedule'],backend='db',queue_name='public',status='failed',max_attempts=1,available_at=datetime.now(UTC))
        s.commit();identity=task.id
    unsafe(factory,m.QueueTask,identity,queue_name='Copied '+SECRET,metadata_json={'password':SECRET})
    result=CliRunner().invoke(app,['jobs','--json'],env={
        'ORGSCAN_DATABASE_URL':settings.database_url,'ORGSCAN_APP_ENV':'production',
        'ORGSCAN_DATA_DIR':str(settings.data_dir)})
    assert result.exit_code==0,result.output
    assert SECRET not in result.output
    assert '<redacted>' in result.output
    reveal(legacy)
