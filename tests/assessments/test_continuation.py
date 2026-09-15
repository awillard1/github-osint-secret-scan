import json
import pytest
from sqlalchemy import select,func
from orgscan import models as m
from orgscan.services.assessments.artifacts import AssessmentArtifacts
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.services.assessments.workbench import AssessmentWorkbench
from orgscan.security_context import AuthContext,current_auth,AuthorizationError
from tests.assessments.test_foundation import service


def test_connection_edit_disable_and_tenant_boundary(service):
    c=service.create_connection('a',name='Original')
    result=service.update_connection(c['id'],'a',name='Renamed',enabled=False)
    assert result['name']=='Renamed' and not result['enabled']
    assert service.update_connection(c['id'],'a',name='Again',enabled=True)['enabled']
    with pytest.raises(ValueError):service.update_connection(c['id'],'a',name='Bad',credential_env='ORGSCAN_GITHUB_CONNECTION_FOREIGN_TOKEN')
    marker=current_auth.set(AuthContext('foreign','admin',('b',),True))
    try:
        with pytest.raises(AuthorizationError):service.update_connection(c['id'],'a',name='Forbidden')
    finally:current_auth.reset(marker)


def test_preview_is_read_only_and_pending_progress(service):
    a=service.create('a','Preview')
    AssessmentArtifacts(service.settings).upload(a['id'],'fixture.txt',b'inert')
    jobs=AssessmentJobs(service.settings)
    preview=jobs.preview(a['id'],options={'profile':'quick'})
    assert preview['repositories']==1 and not preview['history_enabled']
    with service.factory() as s:assert s.scalar(select(m.ScheduledScan)) is None
    jobs.launch(a['id'],'scan',options={'profile':'quick'})
    progress=jobs.progress(a['id'])
    assert progress['states']=={'pending':1}
    assert progress['repository_jobs']['total']==1 and progress['repository_jobs']['completed']==0


@pytest.mark.parametrize('format',['json','html','csv','pdf','sarif'])
def test_reports_retain_assessment_scope(service,format):
    a=service.create('a','Scope report')
    service.import_targets(a['id'],'example.gov')
    content=AssessmentWorkbench(service.settings).export(a['id'],format)
    assert content
    if format!='pdf':assert b'example.gov' in content and b'Scope report' in content
    if format=='json':assert json.loads(content)['assessment']['scope']['targets']['total']==1


def test_three_host_search_correlates_without_mixing_connections(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from orgscan.services.github_search import GitHubSearchService
    from tests.assessments.test_recon import repo
    a=service.create('a','Three hosts')
    connections=[service.create_connection('a',name=name,connection_type=kind,web_base_url=web,api_base_url=api) for name,kind,web,api in (
        ('public','github','https://github.com','https://api.github.com'),
        ('A','ghes','https://a.example','https://a.example/api/v3'),
        ('B','ghes','https://b.example','https://b.example/api/v3'))]
    with service.factory() as s:
        assessment=s.get(m.Assessment,a['id']);storage=Storage(s)
        for data in connections:
            c=s.get(m.GitHubConnection,data['id']);ingest=ReconIngestor(storage,assessment,c,SimpleNamespace())
            record=repo(c.web_base_url)
            official=ingest.repository(record,source='organization',signals={'official_owner':True})
            def request(path,expected=dict):return {'items':[record] if '/search/repositories?' in path else []}
            search=GitHubSearchService(service.settings,request,lambda:{},ingestion=ingest,authenticated=False)
            for _ in range(2):search.search(storage,'org',target_type='organization',target_context=s.get(m.Organization,a['organization_id']))
            link=s.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==a['id'],m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.entity_id==official.id))
            assert link.confidence=='verified' and set(link.metadata_json['sources'])=={'organization','github-search'}
            assert link.metadata_json['first_seen']<=link.metadata_json['last_seen']
        s.commit()
        assert s.scalar(select(__import__('sqlalchemy').func.count()).select_from(m.Repository))==3
        assert s.scalar(select(__import__('sqlalchemy').func.count()).select_from(m.Finding))==3
        assert s.scalar(select(__import__('sqlalchemy').func.count()).select_from(m.Domain))==1
    assert AssessmentWorkbench(service.settings).assets(a['id'],source='github-search')['total']==3
    graph=AssessmentWorkbench(service.settings).graph(a['id'],limit=2)
    assert graph['total']>2 and len(graph['edges'])==2
    node=graph['nodes'][0]
    selected=AssessmentWorkbench(service.settings).graph(a['id'],entity_type=node['entity_type'],entity_id=node['entity_id'])
    assert all(node['id'] in (edge['from'],edge['to']) for edge in selected['edges'])


def test_purge_upload_revokes_scope_and_retains_observations(service):
    a=service.create('a','Purge');artifacts=AssessmentArtifacts(service.settings)
    target=artifacts.upload(a['id'],'fixture.txt',b'inert')['target']
    path=next((service.settings.data_dir/'assessment-artifacts').glob('*.enc'))
    service.remove_target(a['id'],target['id'])
    assert not path.exists()
    assert service.targets(a['id'])['items'][0]['validation_status']=='purged'
    assert not AssessmentWorkbench(service.settings).assets(a['id'])['items'][0]['included']
    with pytest.raises(ValueError):AssessmentJobs(service.settings).launch(a['id'],'scan',options={'profile':'quick'})


def test_http_observation_and_unlinked_commit_identity(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor,correlate_domains
    from tests.assessments.test_recon import repo
    a=service.create('a','Correlated');c=service.create_connection('a',name='Public')
    with service.factory() as s:
        storage=Storage(s);assessment=s.get(m.Assessment,a['id'])
        client=SimpleNamespace(pages=lambda path,**kw: [{'author':None,'commit':{'author':{'email':'unlinked@example.gov'}}}] if path.endswith('/commits') else [])
        ingest=ReconIngestor(storage,assessment,s.get(m.GitHubConnection,c['id']),client)
        repository=ingest.repository(repo())
        for _ in range(2):ingest.expand(repository,repo(),{'max_pages':2})
        identities=list(s.scalars(select(m.Account).where(m.Account.account_type=='commit-identity')))
        assert len(identities)==1 and identities[0].email is None
        parent,_=storage.get_or_create_domain('example.gov',organization_id=assessment.organization_id)
        parent.discovered_subdomains=['api.example.gov']
        storage.create_domain_exposure(parent.id,'projectdiscovery',source_name='httpx',result_summary='HTTP service for api.example.gov: status=200 https://api.example.gov',evidence_url='https://api.example.gov',normalized_hash='http-fixture')
        correlate_domains(storage,assessment,parent,service.settings);s.commit()
    rows=AssessmentWorkbench(service.settings).assets(a['id'],'domain')['items']
    child=next(row for row in rows if row['entity']['name']=='api.example.gov')
    assert child['metadata_json']['http_status']==200
    assert 'httpx' in child['entity']['discovery_sources']


def test_foreign_finding_relationship_is_not_visible(service):
    from orgscan.repositories import Storage
    from orgscan.schemas import CanonicalFinding
    from orgscan.storage.assessments import AssessmentStorage
    a=service.create('a','A');b=service.create('b','B')
    with service.factory() as s:
        storage=Storage(s);assessment=s.get(m.Assessment,a['id'])
        repository,_=storage.get_or_create_repository('org/repository',organization_id=a['organization_id'])
        finding=storage.create_finding(CanonicalFinding(source_tool='test',category='test',title='Foreign',description='inert',organization_id=b['organization_id']))
        edge,_=storage.upsert_relationship_provenance('finding',str(finding.id),'repository',str(repository.id),'observed_in',source='test',confidence='verified',provenance={'reason':'inert'})
        with pytest.raises(AuthorizationError):AssessmentStorage(s).link(assessment,'relationship',edge.id)


def test_complete_scope_form_filters_and_saved_profiles(service):
    from fastapi.testclient import TestClient
    from orgscan.api import create_app
    service.settings.api_tokens_json=json.dumps([{'name':'admin','role':'admin','tenants':['a'],'token':'test-token'}])
    browser=TestClient(create_app(service.settings.database_url,settings=service.settings),headers={'X-Orgscan-Token':'test-token'})
    a=service.create('a','Forms');root=f'/dashboard/assessments/{a["id"]}'
    assert browser.get(root+'/repositories',params={'archived':'','fork':'false','scanned':'','updated_after':''}).status_code==200
    assert browser.get(root+'/findings',params={'account_id':'','domain_id':'','organization_id':''}).status_code==200
    invalid=browser.get(root+'/repositories',params={'updated_after':'invalid'})
    assert invalid.status_code==422 and 'text/html' in invalid.headers['content-type']
    result=browser.post(root+'/launch/discovery',data={'profile':'custom','profile_name':'Reusable','action':'save_profile'},follow_redirects=False)
    assert result.status_code==303
    assert 'Reusable' in browser.get(root+'/discovery').text
    assert browser.post(root+'/selection',data={'selection_mode':'checked'}).status_code==422
    service.import_targets(a['id'],'example.gov')
    AssessmentJobs(service.settings).launch(a['id'],'discovery')
    assert browser.post(root+'/edit',data={'name':'Renamed','description':'Updated'},follow_redirects=False).status_code==303
    assert service.detail(a['id'])['status']=='active'


def test_public_repository_ownership_does_not_assert_target_association(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    a=service.create('a','Weak association');c=service.create_connection('a',name='Public')
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,c['id']),SimpleNamespace())
        ingest.repository(repo(),source='github-search')
        s.commit()
    work=AssessmentWorkbench(service.settings)
    assert work.assets(a['id'],'account')['items'][0]['confidence']=='unverified'
    assert work.assets(a['id'],'organization')['items'][0]['confidence']=='unverified'
    assert any(edge['relation_type']=='owns' and edge['confidence']=='verified' for edge in work.graph(a['id'])['edges'])


def test_report_includes_targets_beyond_first_page(service):
    a=service.create('a','Large report')
    service.import_targets(a['id'],'\n'.join(f'host{i}.example.gov' for i in range(601)))
    report=json.loads(AssessmentWorkbench(service.settings).export(a['id'],'json'))
    targets=report['assessment']['scope']['targets']
    assert targets['total']==601 and len(targets['items'])==601
    assert not targets['truncated']
    assert targets['items'][-1]['normalized_value']=='host600.example.gov'


def test_private_target_scope_is_explicit_and_never_broadens_other_targets(service,monkeypatch):
    from urllib.parse import urlsplit
    from orgscan.services.assessments.github import ConnectionClient
    from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
    from tests.assessments.test_recon import repo
    reference='ORGSCAN_GITHUB_CONNECTION_PRIVATE_TOKEN'
    service.settings.github_connection_credentials_json=json.dumps({'a':[reference]})
    monkeypatch.setenv(reference,'inert-connection-credential')
    service.create_connection('a',name='Public')
    service.create_connection('a',name='Private',connection_type='ghes',web_base_url='https://private.example',api_base_url='https://private.example/api/v3',credential_env=reference,allow_private=True)
    calls=[]
    def request(client,path):
        calls.append((client.web_url,path))
        route=urlsplit(path).path
        def record(owner,name,private):
            return {**repo(client.web_url,private),'full_name':owner+'/'+name,'html_url':client.web_url+'/'+owner+'/'+name,'owner':{'login':owner,'type':'User'}}
        if route=='/users/alice/repos':return [record('alice','public',False)]
        if route=='/user/repos':return [record('alice','private',True),record('unrelated','private',True)]
        raise AssertionError(route)
    monkeypatch.setattr(ConnectionClient,'_request_json',request)
    a=service.create('a','Mixed visibility')
    service.import_targets(a['id'],'https://github.com/user/alice\nhttps://private.example/user/alice')
    targets=service.targets(a['id'])['items']
    service.target_visibility(a['id'],targets[0]['id'],'public')
    service.target_visibility(a['id'],targets[1]['id'],'private')
    jobs=AssessmentJobs(service.settings);jobs.launch(a['id'],'discovery')
    enqueue_due_scheduled_scans(service.settings,limit=10);run_worker(service.settings,burst=True,max_jobs=10)
    assert jobs.progress(a['id'])['states']=={'completed':2}
    rows=AssessmentWorkbench(service.settings).assets(a['id'])['items']
    assert len(rows)==3
    assert all('unrelated' not in row['entity']['full_name'] for row in rows)
    assert sum(row['entity']['is_private'] for row in rows)==1
    assert all(web=='https://private.example' for web,path in calls if path.startswith('/user/repos'))
    # A later public-only restriction narrows already-queued private discovery.
    b=service.create('a','Narrow queued scope')
    service.import_targets(b['id'],'https://private.example/user/alice')
    target=service.targets(b['id'])['items'][0]
    service.target_visibility(b['id'],target['id'],'private');jobs.launch(b['id'],'discovery')
    service.update(b['id'],status='paused');service.target_visibility(b['id'],target['id'],'public');service.update(b['id'],status='ready')
    calls.clear();enqueue_due_scheduled_scans(service.settings,limit=10);run_worker(service.settings,burst=True,max_jobs=10)
    assert all(not path.startswith('/user/repos') for _,path in calls)
    assert all(not row['entity']['is_private'] for row in AssessmentWorkbench(service.settings).assets(b['id'])['items'])


def test_private_metadata_is_never_labelled_public(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    a=service.create('a','Visibility');c=service.create_connection('a',name='Allowed',allow_private=True)
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,c['id']),SimpleNamespace())
        row=ingest.repository({**repo(private=True),'visibility':'public'},include_private=True)
        assert row.is_private and row.metadata_json['visibility']=='private'


def test_private_fork_parent_requires_independent_target_scope(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    a=service.create('a','Fork scope');c=service.create_connection('a',name='Allowed',allow_private=True)
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,c['id']),SimpleNamespace())
        parent={**repo(private=True),'full_name':'outside/private','html_url':'https://github.com/outside/private','owner':{'login':'outside','type':'Organization'}}
        child=ingest.repository({**repo(private=True),'fork':True,'parent':parent},include_private=True)
        assert s.scalar(select(func.count()).select_from(m.Repository))==1
        assert not list(s.scalars(select(m.Relationship).where(m.Relationship.relation_type=='fork_of')))
        # Independently selected discovery can subsequently establish the edge.
        ingest.repository(parent,include_private=True);ingest.correlate_forks();s.commit()
        assert len(list(s.scalars(select(m.Relationship).where(m.Relationship.relation_type=='fork_of'))))==1


def test_partial_search_metadata_preserves_repository_detail(service):
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    a=service.create('a','Metadata');c=service.create_connection('a',name='Public')
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,c['id']),SimpleNamespace())
        first=ingest.repository({**repo(),'updated_at':'2026-09-01T00:00:00Z','topics':['governance']})
        row=ingest.repository({'full_name':'org/repo','html_url':'https://github.com/org/repo','private':False},source='github-search')
        assert row.id==first.id and row.default_branch=='trunk'
        assert row.metadata_json['updated_at']=='2026-09-01T00:00:00Z'
        assert row.metadata_json['topics']==['governance']
        assert 'api.example.gov' in row.metadata_json['description']


def test_metadata_ingestion_retains_credential_context_through_derived_assets(service,monkeypatch):
    import base64,os
    from types import SimpleNamespace
    from orgscan.repositories import Storage
    from orgscan.schemas import CanonicalFinding
    from orgscan.services.assessments.recon import ReconIngestor
    from orgscan.services.secret_evidence import SecretEvidenceService
    from tests.assessments.test_recon import repo
    service.settings=type(service.settings)(**service.settings.model_dump(exclude={'preserve_secrets'}),preserve_secrets=True,secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())
    a=service.create('a','Protected metadata');c=service.create_connection('a',name='Public')
    secret='metadatafixturecredential984'
    with service.factory() as s:
        s.info['secret_settings']=service.settings
        finding=Storage(s).create_finding(CanonicalFinding(source_tool='test',category='secret',title='password="'+secret+'"',description='Inert fixture',organization_id=a['organization_id']))
        s.commit();finding_id=finding.id
        protected=s.scalar(select(m.SecretEvidence).where(m.SecretEvidence.finding_id==finding_id));secret_id=protected.id;ciphertext=protected.encrypted_value
        with monkeypatch.context() as patch:
            patch.setattr(SecretEvidenceService,'reveal',lambda *args,**kwargs:pytest.fail('Ingestion must never reveal'))
            ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,c['id']),SimpleNamespace())
            row=ingest.repository({**repo(),'description':'password="'+secret+'" https://'+secret+'.example.gov','homepage':'https://safe.example.gov/'+secret})
            s.commit()
            assert secret not in str(row.metadata_json)
            assert all(secret not in domain.name for domain in s.scalars(select(m.Domain)))
            assert secret not in str(AssessmentWorkbench(service.settings).report(a['id']))
        assert s.get(m.SecretEvidence,secret_id).encrypted_value==ciphertext
    assert SecretEvidenceService(service.settings).reveal(finding_id,secret_id,AuthContext('admin','admin',('a',),True))==secret


def test_target_visibility_update_sanitizes_before_replacing_context(service):
    a=service.create('a','Target context');service.create_connection('a',name='Public')
    service.import_targets(a['id'],'https://github.com/org')
    target=service.targets(a['id'])['items'][0];secret='TargetContextFixture965!'
    with service.factory() as s:
        s.execute(m.AssessmentTarget.__table__.update().where(m.AssessmentTarget.id==target['id']).values(notes='Copied '+secret,metadata_json={'visibility_mode':'password='+secret}));s.commit()
    result=service.target_visibility(a['id'],target['id'],'public')
    assert secret not in str(result) and secret not in str(service.targets(a['id']))
