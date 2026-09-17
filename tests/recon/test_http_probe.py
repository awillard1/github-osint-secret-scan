"""Browser HTTPX follow-up uses scoped durable jobs and the recon pipeline."""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from orgscan import models as m
from orgscan.api import create_app
from orgscan.queueing import run_worker
from orgscan.recon.adapters import Adapter
from orgscan.recon.observations import Observation
from orgscan.repositories import Storage
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.services.assessments.workbench import AssessmentWorkbench
from orgscan.storage.assessments import AssessmentStorage
from tests.assessments.test_foundation import service


def linked_domain(service, assessment_id, name):
    with service.factory() as session:
        assessment=session.get(m.Assessment,assessment_id)
        row,_=Storage(session).get_or_create_domain(name,organization_id=assessment.organization_id)
        AssessmentStorage(session).link(assessment,'domain',row.id,source='subfinder',confidence='likely')
        session.commit()
        return row.id


def ready(monkeypatch):
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',
        lambda *args,**kwargs:{'ready':True,'status':'ok','version':'1.0','missing':[]})


def test_http_probe_is_scoped_authorized_and_durable(service,monkeypatch):
    ready(monkeypatch)
    assessment=service.create('a','Web follow-up')['id']
    foreign=service.create('b','Other tenant')['id']
    service.import_targets(assessment,'example.gov')
    service.import_targets(foreign,'foreign.test')
    root=linked_domain(service,assessment,'example.gov')
    linked_domain(service,assessment,'api.example.gov')
    unrelated=linked_domain(service,assessment,'unrelated.test')
    alien=linked_domain(service,foreign,'foreign.test')
    jobs=AssessmentJobs(service.settings)
    with pytest.raises(ValueError,match='Authorize active'):
        jobs.launch_http_probe(assessment,domain_ids=[root])
    with pytest.raises(ValueError,match='outside this assessment'):
        jobs.launch_http_probe(assessment,domain_ids=[alien],active_authorized=True)
    with pytest.raises(ValueError,match='outside saved domain target scope'):
        jobs.launch_http_probe(assessment,domain_ids=[unrelated],active_authorized=True)
    marker=current_auth.set(AuthContext('reader','reader',('a',),True))
    try:
        with pytest.raises(AuthorizationError):jobs.launch_http_probe(assessment,active_authorized=True)
    finally:current_auth.reset(marker)
    assert jobs.launch_http_probe(assessment,active_authorized=True)['scheduled']==2
    with pytest.raises(ValueError,match='No unprobed'):
        jobs.launch_http_probe(assessment,active_authorized=True)
    assert jobs.publish(assessment,kind='http_probe')['published']==2
    seen=[]
    def fake_run(self,tool,root,inputs,**kwargs):
        seen.append((tool,root,list(inputs)))
        return [Observation('http_service','https://'+root+'/','httpx',{'status':200,'title':'Web'})]
    monkeypatch.setattr(Adapter,'run',fake_run)
    assert run_worker(service.settings,burst=True,max_jobs=2)
    assert seen==[('httpx','example.gov',['example.gov']),('httpx','api.example.gov',['api.example.gov'])]
    assert jobs.progress(assessment,kind='http_probe')['states']=={'completed':2}
    results=AssessmentWorkbench(service.settings).recon_results(assessment,tab='web')
    assert results['total']==2
    domains=AssessmentWorkbench(service.settings).recon_results(assessment,tab='domains')
    assert sum(row['metadata_json'].get('http_status')==200 for row in domains['items'])==2


def test_http_probe_worker_rechecks_saved_target(service,monkeypatch):
    ready(monkeypatch)
    assessment=service.create('a','Revoked scope')['id']
    service.import_targets(assessment,'example.gov')
    linked_domain(service,assessment,'api.example.gov')
    jobs=AssessmentJobs(service.settings)
    assert jobs.launch_http_probe(assessment,active_authorized=True)['scheduled']==1
    jobs.publish(assessment,kind='http_probe')
    target_id=service.targets(assessment)['items'][0]['id']
    jobs.pause(assessment)
    service.remove_target(assessment,target_id)
    service.update(assessment,status='ready')
    seen=[]
    monkeypatch.setattr(Adapter,'run',lambda *args,**kwargs:seen.append(args) or [])
    run_worker(service.settings,burst=True,max_jobs=1)
    assert not seen
    assert jobs.progress(assessment,kind='http_probe')['states']=={'failed':1}


def test_http_probe_browser_requires_analyst_and_ready_tool(service,monkeypatch):
    assessment=service.create('a','Browser probe')['id']
    service.import_targets(assessment,'example.gov')
    linked_domain(service,assessment,'example.gov')
    service.settings.api_tokens_json=json.dumps([
        {'name':'reader','token':'reader-token','role':'reader','tenants':['a']},
        {'name':'analyst','token':'analyst-token','role':'analyst','tenants':['a']}])
    client=TestClient(create_app(service.settings.database_url,settings=service.settings),
        headers={'X-Orgscan-Token':'reader-token'})
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.binary',lambda *args:None)
    path=f'/dashboard/assessments/{assessment}/recon-results'
    unavailable=client.get(path+'?tab=domains').text
    assert 'class="app-shell"' in unavailable
    assert 'HTTPX is unavailable' in unavailable
    assert client.post(path+'/http-probe',data={'active_authorized':'true'}).status_code==403
    client.headers['X-Orgscan-Token']='analyst-token'
    assert client.post(path+'/http-probe').status_code==422
    assert client.post(path+'/http-probe',data={'active_authorized':'true'}).status_code==422
    ready(monkeypatch)
    monkeypatch.setattr('orgscan.queueing.run_db_schedule_batch',lambda settings,ids:None)
    response=client.post(path+'/http-probe',data={'active_authorized':'true'},follow_redirects=False)
    assert response.status_code==303
    assert 'tab=domains' in response.headers['location']
    page=client.get(path+'?tab=domains')
    assert 'HTTPX follow-up jobs' in page.text and 'Queued' in page.text
    assert client.post(path+'/http-probe/publish',follow_redirects=False).status_code==303
    client.headers['X-Orgscan-Token']='reader-token'
    assert client.post(path+'/http-probe/publish').status_code==403
    with service.factory() as session:
        run=session.scalar(select(m.AssessmentRun))
        assert run.kind=='http_probe'
        run_id=run.id
    client.headers['X-Orgscan-Token']='analyst-token'
    cancelled=client.post(f'/dashboard/assessments/{assessment}/runs/{run_id}/cancel',follow_redirects=False)
    assert cancelled.status_code==303 and 'recon-results?tab=domains' in cancelled.headers['location']
