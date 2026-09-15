import os
import json
from types import SimpleNamespace
from datetime import UTC,datetime
import pytest
from sqlalchemy import select
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.services.assessments.recon import ReconIngestor,association,discover_target
from orgscan.services.assessments.github import ConnectionClient
from orgscan.services.assessments.jobs import AssessmentJobs
from test_foundation import service


def repo(web='https://github.com',private=False):
    return {'full_name':'org/repo','html_url':web+'/org/repo','private':private,'visibility':'private' if private else 'public',
        'owner':{'login':'org','type':'Organization'},'default_branch':'trunk','description':'Service https://api.example.gov','fork':False}


def test_connection_assets_and_private_scope_do_not_mix(service):
    a=service.create('a','A')
    connections=[service.create_connection('a',name=name,connection_type=kind,web_base_url=web,api_base_url=api) for name,kind,web,api in (
        ('public','github','https://github.com','https://api.github.com'),
        ('enterprise','ghes','https://git.example','https://git.example/api/v3'))]
    with service.factory() as s:
        assessment=s.get(m.Assessment,a['id'])
        names=[]
        for data in connections:
            connection=s.get(m.GitHubConnection,data['id'])
            ingest=ReconIngestor(Storage(s),assessment,connection,SimpleNamespace())
            row=ingest.repository(repo(connection.web_base_url),signals={'official_owner':True})
            names.append(row.full_name)
            assert ingest.repository(repo(connection.web_base_url,True)) is None
            assert ingest.repository({'full_name':'org/missing'}) is None
            assert ingest.repository({**repo(connection.web_base_url),'visibility':'internal'}) is None
        s.commit()
        assert len(set(names))==2
        assert len(list(s.scalars(select(m.Domain))))==1
        assert len(list(s.scalars(select(m.Repository))))==2


def test_credential_and_rate_limit_namespaces(service,monkeypatch):
    refs=[]
    service.settings.github_connection_credentials_json=json.dumps({t:['ORGSCAN_GITHUB_CONNECTION_'+t.upper()+'_TOKEN'] for t in ('a','b')})
    for tenant in ('a','b'):
        env='ORGSCAN_GITHUB_CONNECTION_'+tenant.upper()+'_TOKEN'
        monkeypatch.setenv(env,'fixture-'+tenant)
        data=service.create_connection(tenant,name=tenant,credential_env=env)
        with service.factory() as s:
            client=ConnectionClient(service.settings,s.get(m.GitHubConnection,data['id']))
            assert client.token=='fixture-'+tenant
            assert 'fixture-' not in str(data)
            refs.append(client.scope)
    assert refs[0]!=refs[1]


def test_discovery_existing_queue_and_replay(service,monkeypatch):
    from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
    a=service.create('a','Queued')
    service.create_connection('a',name='Public')
    service.import_targets(a['id'],'https://github.com/org')
    monkeypatch.setattr(ConnectionClient,'_request_json',lambda self,path:{'type':'Organization'} if path.startswith('/users/') else [repo()])
    jobs=AssessmentJobs(service.settings)
    assert jobs.launch(a['id'],'discovery')['scheduled']==1
    assert len(enqueue_due_scheduled_scans(service.settings))==1
    assert run_worker(service.settings,burst=True,max_jobs=1)
    result=jobs.progress(a['id'])
    assert result['states']=={'completed':1}
    assert result['items'][0]['scan_job_id']
    with service.factory() as s:
        assert len(list(s.scalars(select(m.Repository))))==1
    assert jobs.launch(a['id'],'discovery')['scheduled']==1
    enqueue_due_scheduled_scans(service.settings)
    run_worker(service.settings,burst=True,max_jobs=1)
    with service.factory() as s:assert len(list(s.scalars(select(m.Repository))))==1


def test_deterministic_association_explains_limits():
    confidence,reasons=association({'contributions':417})
    assert confidence=='likely' and 'not employment' in reasons[0]
    assert association({'official_owner':True})[0]=='verified'


def test_cross_tenant_credential_reference_rejected(service):
    env='ORGSCAN_GITHUB_CONNECTION_B_TOKEN'
    service.settings.github_connection_credentials_json=json.dumps({'b':[env]})
    with pytest.raises(ValueError,match='exclusively provisioned'):
        service.create_connection('a',name='wrong',credential_env=env)


def test_rate_limit_failure_preserves_retry_delay(service,monkeypatch):
    from urllib.error import HTTPError
    from orgscan.services.job_policy import classify_failure
    c=service.create_connection('a',name='Public')
    with service.factory() as s:client=ConnectionClient(service.settings,s.get(m.GitHubConnection,c['id']))
    def fail(*args,**kwargs):raise HTTPError('https://api.github.com',429,'limited',{'retry-after':'60'},None)
    monkeypatch.setattr(client.opener,'open',fail)
    with pytest.raises(ValueError) as exc:client._request_json('/repos/org/repo')
    failure=classify_failure(exc.value)
    assert failure.retryable and failure.retry_after>=60 and failure.code=='rate_limited'


def test_provider_domain_correlation_reuses_one_entity(service):
    from orgscan.services.assessments.recon import correlate_domains
    a=service.create('a','Domains')
    with service.factory() as s:
        storage=Storage(s);assessment=s.get(m.Assessment,a['id'])
        parent=storage.create_domain('example.gov',organization_id=assessment.organization_id)
        child=storage.create_domain('api.example.gov',organization_id=assessment.organization_id,discovery_sources=['repository-metadata'])
        parent.discovered_subdomains=['api.example.gov','api.example.gov','evil-example.gov']
        for source in ('subfinder','crtsh','httpx'):
            storage.create_domain_exposure(parent.id,source='fixture',source_name=source,result_summary='Observed api.example.gov',normalized_hash=source)
        correlate_domains(storage,assessment,parent,service.settings)
        correlate_domains(storage,assessment,parent,service.settings)
        s.commit()
        assert len(list(s.scalars(select(m.Domain))))==2
        assert set(child.discovery_sources)=={'repository-metadata','subfinder','crtsh','httpx'}
        assert len(list(s.scalars(select(m.Relationship))))==1


def test_local_path_discovery_and_scan_use_existing_queue(service,tmp_path):
    from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
    service.settings.assessment_allow_local_paths=True
    path=tmp_path/'local';path.mkdir();(path/'readme.txt').write_text('Inert fixture')
    a=service.create('a','Local')
    assert service.import_targets(a['id'],'path:'+str(path))['counts']['added']==1
    jobs=AssessmentJobs(service.settings)
    jobs.launch(a['id'],'discovery');enqueue_due_scheduled_scans(service.settings);run_worker(service.settings,burst=True,max_jobs=1)
    assert jobs.progress(a['id'])['states']=={'completed':1}
    assert jobs.launch(a['id'],'scan',options={'profile':'quick'})['scheduled']==1
    enqueue_due_scheduled_scans(service.settings);run_worker(service.settings,burst=True,max_jobs=1)
    assert jobs.progress(a['id'])['states']=={'completed':2}
