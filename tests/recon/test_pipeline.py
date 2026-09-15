import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from sqlalchemy import select
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.recon.adapters import Adapter,ReconError
from orgscan.recon.observations import Observation,ObservationStore,url,scoped_host
from orgscan.recon.pipeline import run_pipeline
from orgscan.services.assessments.discovery_progress import DiscoveryProgress
from orgscan.services.assessments.recon import profile_options
from orgscan.services.assessments.workbench import AssessmentWorkbench
from tests.assessments.test_foundation import service


def test_profile_requires_active_choice_and_missing_tools(service,monkeypatch):
    monkeypatch.setattr('orgscan.services.assessments.recon.provider_readiness',lambda settings:[{'name':n,'status':'ok'} for n in ('httpx','katana','crtsh')])
    with pytest.raises(ValueError,match='authorization'):profile_options(service.settings,{'name':'custom','providers':['httpx']})
    with pytest.raises(ValueError,match='Passive profiles'):profile_options(service.settings,{'name':'passive-only','providers':['httpx'],'active_authorized':True})
    with pytest.raises(ValueError,match='unavailable'):profile_options(service.settings,{'name':'custom','providers':['subfinder']})
    result=profile_options(service.settings,{'name':'custom','providers':['subfinder','crtsh'],'run_available_only':True})
    assert result['providers']==['crtsh'] and result['unavailable_providers']==['subfinder']
    with pytest.raises(ValueError,match='upstream'):profile_options(service.settings,{'name':'custom','providers':['katana'],'active_authorized':True})


def test_adapter_normalization_and_scope(service):
    adapter=Adapter(service.settings)
    rows=adapter.parse('httpx','example.gov',json.dumps({'url':'https://api.example.gov/admin?token=ignored','status_code':200,'title':'Console','tech':['nginx']})+'\n'+json.dumps({'url':'https://evil-example.gov/admin'}))
    assert len(rows)==1 and rows[0].value=='https://api.example.gov/admin'
    assert rows[0].attributes['status']==200
    assert not scoped_host('example.gov.evil.com','example.gov')
    assert url('https://user:pass@example.gov') is None
    with pytest.raises(ReconError,match='malformed'):adapter.parse('dnsx','example.gov','{bad')
    records=adapter.parse('dnsx','example.gov',json.dumps({'host':'api.example.gov','a':['192.0.2.1'],'mx':['mx.example.gov']}))
    assert [r.kind for r in records]==['domain','ip_address']


def test_correlated_pipeline_and_results(service,monkeypatch):
    assessment=service.create('a','Recon')
    outputs={
      'subfinder':[Observation('domain','api.example.gov','subfinder')],
      'dnsx':[Observation('domain','api.example.gov','dnsx',{'dns':{'a':['192.0.2.1']}}),Observation('ip_address','192.0.2.1','dnsx',{'hostname':'api.example.gov'})],
      'httpx':[Observation('http_service','https://api.example.gov/','httpx',{'status':200,'title':'Console'})],
      'wayback':[Observation('endpoint','https://api.example.gov/admin','wayback')],
      'katana':[Observation('endpoint','https://api.example.gov/admin','katana')],
      'naabu':[Observation('ip_address','192.0.2.1','naabu',{'hostname':'api.example.gov'}),Observation('network_service','192.0.2.1:443/tcp','naabu',{'hostname':'api.example.gov','ip':'192.0.2.1','port':443})],
    }
    seen=[]
    def run(self,tool,root,inputs,**kwargs):
        seen.append((tool,list(inputs)))
        return outputs[tool]
    monkeypatch.setattr(Adapter,'run',run)
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',lambda *a,**k:{'ready':True,'version':'1.0.0'})
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);storage=Storage(session)
        parent=storage.create_domain('example.gov',organization_id=a.organization_id)
        for _ in range(2):
            run_pipeline(storage,a,parent,{'providers':list(outputs),'active_authorized':True},service.settings,DiscoveryProgress(storage))
            session.commit()
        assert len(list(session.scalars(select(m.Domain))))==2
        endpoint=session.scalar(select(m.ReconAsset).where(m.ReconAsset.name=='https://api.example.gov/admin'))
        assert set(endpoint.metadata_json['observations'])=={'wayback','katana'}
    assert ('httpx',['api.example.gov']) in seen
    assert ('katana',['https://api.example.gov/']) in seen
    work=AssessmentWorkbench(service.settings)
    assert work.recon_results(a.id,tab='hosts')['total']==1
    assert work.recon_results(a.id,tab='web')['total']==2
    graph=work.graph(a.id)
    assert any(e['relation_type']=='resolves_to' for e in graph['edges'])
    assert any(n['entity_type']=='recon_asset' for n in graph['nodes'])


def test_empty_upstream_and_limits(service,monkeypatch):
    assessment=service.create('a','Empty')
    seen=[]
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',lambda *a,**k:{'ready':True,'version':'1.0.0'})
    monkeypatch.setattr(Adapter,'run',lambda self,tool,*a,**k:seen.append(tool) or [])
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);storage=Storage(session)
        parent=storage.create_domain('example.gov',organization_id=a.organization_id)
        progress=DiscoveryProgress(storage)
        with pytest.raises(ReconError):run_pipeline(storage,a,parent,{'providers':['dnsx','httpx','katana'],'active_authorized':True},service.settings,progress)
        assert seen==['dnsx'] and progress.states['httpx']['status']=='blocked'
        service.settings.recon_max_domains=1
        monkeypatch.setattr(Adapter,'run',lambda *a,**k:[Observation('domain','a.example.gov','subfinder'),Observation('domain','b.example.gov','subfinder')])
        with pytest.raises(ReconError):run_pipeline(storage,a,parent,{'providers':['subfinder']},service.settings,progress)
        assert progress.states['subfinder']['status']=='limit_reached'


def test_template_policy(service,tmp_path):
    from orgscan.recon.templates import validated_templates
    template=tmp_path/'check.yaml'
    template.write_text('id: fixture\ninfo: {name: Fixture, severity: info}\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/health"]\n    matchers: [{type: status, status: [200]}]\n')
    assert validated_templates(tmp_path)==[template]
    template.write_text('id: fixture\ncode: [dangerous]\n')
    with pytest.raises(ValueError):validated_templates(tmp_path)


def test_observation_projection_complete_context(service):
    assessment=service.create('a','Projection')
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);ingest=ObservationStore(Storage(session),a,service.settings)
        ingest.ingest(Observation('endpoint','https://example.gov/admin','wayback',{'title':'safe'}));session.commit()
        row=session.scalar(select(m.ReconAsset))
        from sqlalchemy import text
        session.execute(text('UPDATE recon_assets SET name=:name, metadata_json=:metadata WHERE id=:id'),
            {'name':'legacy-copy-secret','metadata':json.dumps({'api_key':'legacy-copy-secret'}),'id':row.id})
        session.commit()
    result=AssessmentWorkbench(service.settings).recon_results(assessment['id'],tab='web')
    assert 'legacy-copy-secret' not in json.dumps(result,default=str)


def test_upgrade_preserves_0014(tmp_path):
    from orgscan.db import _alembic_config,current_db_revision
    from alembic import command
    from sqlalchemy import create_engine,text,inspect
    database='sqlite:///'+str(tmp_path/'migration.db')
    command.upgrade(_alembic_config(database),'20260915_0014')
    engine=create_engine(database)
    with engine.begin() as c:
        c.execute(text("INSERT INTO organizations (name,tenant_key,display_name,metadata_json,created_at,updated_at) VALUES ('fixture','a','Fixture','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    command.upgrade(_alembic_config(database),'head')
    with engine.connect() as c:assert c.execute(text('SELECT name FROM organizations')).scalar()=='fixture'
    assert 'recon_assets' in inspect(engine).get_table_names()
    assert current_db_revision(database)=='20260915_0015'


def test_repository_metadata_never_executes_code(service):
    from orgscan.services.assessments.recon import ReconIngestor
    def repo():
        return {'full_name':'org/repo','html_url':'https://github.com/org/repo','private':False,'visibility':'public','owner':{'login':'org','type':'Organization'},'default_branch':'trunk'}
    assessment=service.create('a','Metadata');connection=service.create_connection('a',name='Public')
    calls=[]
    class Client:
        def _request_json(self,path):
            calls.append(path)
            if path.endswith('/languages'):return {'Python':123}
            return {'tree':[{'path':'.github/workflows/build.yml'},{'path':'infra/main.tf'},{'path':'Dockerfile'}],'truncated':False}
        def pages(self,path,**kwargs):
            calls.append(path);return [{'name':'trunk','protected':True}]
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,assessment['id']),s.get(m.GitHubConnection,connection['id']),Client())
        row=ingest.repository(repo());ingest.repository_metadata(row,repo(),{'max_pages':2})
        assert row.metadata_json['languages']=={'Python':123}
        assert row.metadata_json['file_indicators']['ci_cd']
        assert row.metadata_json['file_indicators']['terraform']
        assert row.metadata_json['branches'][0]['name']=='trunk'
    assert all('/contents/' not in path for path in calls)


def test_adapter_rejects_out_of_scope_before_spawn(service,monkeypatch):
    monkeypatch.setattr('orgscan.recon.adapters.processes.run',lambda *a,**k:pytest.fail('Must not execute'))
    with pytest.raises(ReconError,match='scope'):Adapter(service.settings).run('katana','example.gov',['https://third-party.com/'])
    with pytest.raises(ReconError,match='input'):Adapter(service.settings).run('httpx','example.gov',['example.gov\nthird-party.com'])


def test_tool_timeout_and_output_are_safe(service,monkeypatch):
    from orgscan import processes
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.binary',lambda *a:'/fixture/subfinder')
    for error in (processes.TimeoutExpired('secret',1,output='credential'),processes.OutputLimitExceeded('credential')):
        def fail(*a,**k):raise error
        monkeypatch.setattr('orgscan.recon.adapters.processes.run',fail)
        with pytest.raises(ReconError) as captured:Adapter(service.settings).run('subfinder','example.gov',['example.gov'])
        assert 'credential' not in str(captured.value)


def test_nuclei_produces_canonical_finding(service,monkeypatch):
    assessment=service.create('a','Templates')
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',lambda *a,**k:{'ready':True,'version':'1.0.0'})
    def run(self,tool,*a,**k):
        if tool=='httpx':return [Observation('http_service','https://example.gov/','httpx',{'status':200})]
        return [Observation('finding','https://example.gov/admin','nuclei',{'title':'Exposed admin','severity':'medium','template_id':'fixture'})]
    monkeypatch.setattr(Adapter,'run',run)
    with service.factory() as s:
        a=s.get(m.Assessment,assessment['id']);storage=Storage(s)
        parent=storage.create_domain('example.gov',organization_id=a.organization_id)
        for _ in range(2):
            run_pipeline(storage,a,parent,{'providers':['httpx','nuclei'],'active_authorized':True},service.settings,DiscoveryProgress(storage));s.commit()
        findings=list(s.scalars(select(m.Finding)))
        assert len(findings)==1 and findings[0].metadata_json['template_id']=='fixture'
        assert s.scalar(select(m.Evidence)) is not None


def test_legacy_provider_deadline_prevents_requests(service,monkeypatch):
    from orgscan.providers import provider_budget,_request_json,DomainProviderError,DnsDomainProvider
    monkeypatch.setattr('orgscan.providers.urlopen',lambda *a,**k:pytest.fail('Expired provider must not send a request'))
    monkeypatch.setattr('orgscan.providers.dns.resolver.resolve',lambda *a,**k:pytest.fail('Expired provider must not query DNS'))
    with provider_budget(0):
        with pytest.raises(DomainProviderError,match='LIMIT REACHED'):_request_json('https://example.gov',settings=service.settings)
        with pytest.raises(DomainProviderError,match='LIMIT REACHED'):DnsDomainProvider(service.settings)._resolve_records('example.gov','A')


def test_securitytxt_disables_target_redirects(service,monkeypatch):
    from orgscan import providers
    class Response:
        headers={}
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,*args):return b''
    def opener(handler):
        assert handler.redirect_request(None,None,None,None,None,None) is None
        return SimpleNamespace(open=lambda request,**kwargs:Response())
    monkeypatch.setattr(providers,'build_opener',opener)
    monkeypatch.setattr(providers,'_stdlib_urlopen',lambda *a,**k:pytest.fail('Must use scoped redirect policy'))
    assert providers.SecurityTxtDomainProvider(service.settings)._fetch_securitytxt('example.gov')[0]==''
