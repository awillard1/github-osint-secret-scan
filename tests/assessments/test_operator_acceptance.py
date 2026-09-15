"""Browser operator acceptance with disposable storage and external service fakes."""
import base64
import hashlib
import json
import os
import re
from types import SimpleNamespace
from urllib.parse import urlsplit
from fastapi.testclient import TestClient
from sqlalchemy import select,func
from orgscan import models as m
from orgscan.api import create_app
from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
from orgscan.schemas import CanonicalFinding
from orgscan.runner import ScanExecutionResult
from orgscan.services.assessments.github import ConnectionClient
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.services.assessments.workbench import AssessmentWorkbench
from orgscan.ai.ollama import OllamaProvider
from tests.assessments.test_foundation import service
from tests.assessments.test_recon import repo
from tests.assessments.test_local_ai import ADVICE


def test_complete_browser_operator_workflow(service,monkeypatch,caplog):
    settings=type(service.settings)(**service.settings.model_dump(exclude={'preserve_secrets','api_tokens_json'}),preserve_secrets=True,
        secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(),
        api_tokens_json=json.dumps([{'name':'operator','token':'acceptance-token','role':'admin','tenants':['a']}]))
    service.settings=settings
    browser=TestClient(create_app(settings.database_url,settings=settings),base_url='https://testserver')
    challenge=re.search(r'name="csrf_token" value="([^"]+)"',browser.get('/login').text)[1]
    assert browser.post('/login',data={'token':'acceptance-token','csrf_token':challenge},follow_redirects=False).status_code==303
    csrf=browser.get('/auth/me').json()['csrf_token']
    def post(path,data=None,**kwargs):return browser.post(path,data={**(data or {}),'csrf_token':csrf},follow_redirects=False,**kwargs)
    response=post('/dashboard/assessments/new',{'tenant':'a','name':'Comprehensive Organization Assessment'})
    assert response.status_code==303
    identity=int(response.headers['location'].split('/')[3]);root=f'/dashboard/assessments/{identity}'
    hosts=[('Public','github','https://github.com','https://api.github.com'),('GHES A','ghes','https://a.example','https://a.example/api/v3'),('GHES B','ghes','https://b.example','https://b.example/api/v3')]
    for name,kind,web,api in hosts:
        assert post('/dashboard/settings/github',dict(tenant='a',name=name,connection_type=kind,web_base_url=web,api_base_url=api)).status_code==303
    locations=['https://github.com/org','https://github.com/user/alice','https://github.com/org/direct','https://a.example/org','https://a.example/user/alice','https://b.example/org','example.gov','cms.gov']
    # The separate many-target boundary test covers 151 unique locations.
    response=post(root+'/targets',{'text':'\n'.join(locations+locations+['invalid target'])})
    assert response.status_code==200
    assert service.targets(identity)['total']==8
    touched=set()
    def request(self,path):
        touched.add(self.web_url)
        route=urlsplit(path).path
        def record(full='org/repo',**extra):
            return {**repo(self.web_url),'full_name':full,'html_url':self.web_url+'/'+full,'owner':{'login':full.split('/')[0],'type':'Organization' if full.startswith('org/') else 'User'},**extra}
        if route.startswith('/search/'):
            return {'items':[record('search/project')] if '/repositories' in route else [],'total_count':1}
        if route.endswith('/contributors'):return [{'login':'alice','contributions':417}]
        if route.endswith('/commits'):return [{'sha':'abc','author':{'login':'alice'},'commit':{'author':{'email':'alice@example.gov'}}}]
        if route.endswith('/forks'):return [record('outsider/fork',fork=True)] if route.startswith('/repos/org/repo/') else []
        if route.endswith('/members'):return [{'login':'alice'}]
        if route.startswith('/orgs/') and route.endswith('/repos'):return [record(),record('org/skip',archived=True)]
        if route.startswith('/users/') and route.endswith('/repos'):return [record('alice/tool')]
        if route.startswith('/users/'):return {'type':'Organization'}
        if route.startswith('/repos/'):return record(route[len('/repos/'):])
        raise AssertionError(route)
    monkeypatch.setattr(ConnectionClient,'_request_json',request)
    readiness=[{'name':name,'status':'ok','missing':[]} for name in ('local-metadata','crtsh','securitytxt')]
    monkeypatch.setattr('orgscan.services.assessments.recon.provider_readiness',lambda settings:readiness)
    from orgscan.providers import DomainProviderResult
    class Provider:
        def __init__(self,name):self.name=name
        def discover_context(self,storage,context):
            domain=storage.get_domain(context.domain_id);child='api.'+domain.name
            domain.discovered_subdomains=list(set(domain.discovered_subdomains or [])|{child})
            storage.create_domain_exposure(domain.id,self.name,source_name=self.name,result_summary=child,normalized_hash=hashlib.sha256((self.name+child).encode()).hexdigest())
            return DomainProviderResult([child],[])
    monkeypatch.setattr('orgscan.providers.get_domain_provider',lambda name,settings:Provider(name))
    assert post(root+'/launch/discovery',{'profile':'organization-comprehensive'}).status_code==303
    enqueue_due_scheduled_scans(settings,limit=100);run_worker(settings,burst=True,max_jobs=100)
    jobs=AssessmentJobs(settings);progress=jobs.progress(identity,limit=100)
    assert progress['states']=={'completed':8},progress
    assert touched=={web for _,_,web,_ in hosts}
    work=AssessmentWorkbench(settings)
    assert work.assets(identity,'account')['total']>=3
    domains=work.assets(identity,'domain')['items']
    correlated=[row for row in domains if row['entity']['name']=='api.example.gov']
    assert len(correlated)==1
    assert {'local-metadata','crtsh','securitytxt'}<=set(correlated[0]['entity']['discovery_sources'])
    assert work.graph(identity)['edges']
    for tab in ('repositories','accounts','domains','relationships','discovery'):
        assert browser.get(root+'/'+tab).status_code==200
    assert post(root+'/selection',{'archived':'true','included':'false'}).status_code==303
    excluded={r['entity_id'] for r in work.assets(identity,archived=True)['items']}
    assert excluded and all(not r['included'] for r in work.assets(identity,archived=True)['items'])
    secret='AcceptanceProtectedCredential798!'
    seen_plans=[]
    monkeypatch.setattr('orgscan.services.assessments.jobs.get_registry',lambda:SimpleNamespace(get=lambda *a,**k:SimpleNamespace(readiness=lambda:SimpleNamespace(ready=True))))
    def execute(storage,plan,**kwargs):
        assert plan.profile=='comprehensive' and len(plan.scanners)==8
        assert plan.repository_id not in excluded
        seen_plans.append(plan.serialized());storage.session.info['secret_settings']=settings
        results=[]
        for scanner in plan.scanners:
            job=storage.create_scan_job('repository',str(plan.repository_id),scanner,parameters_json={'scan_plan':plan.serialized()})
            digest=hashlib.sha256(str(plan.repository_id).encode()).hexdigest()
            finding=storage.upsert_correlated_finding(CanonicalFinding(source_tool=scanner,category='secret',title='password="'+secret+'"',description='Credential in configuration',severity='high',confidence='verified',repository_id=plan.repository_id,organization_id=plan.organization_id,scan_job_id=job.id,fingerprint=digest,normalized_hash=digest))
            storage.upsert_scanner_evidence(finding.id,scanner,observation_fingerprint=hashlib.sha256((digest+scanner).encode()).hexdigest(),metadata_json={},repository_path='config.txt',line_start=1)
            storage.mark_scan_job_completed(job)
            results.append(ScanExecutionResult(job.id,scanner,plan.target,1,[finding.id],None))
        storage.session.commit();return results
    monkeypatch.setattr('orgscan.services.assessments.jobs.execute_plan',execute)
    response=post(root+'/launch/scan',{'profile':'comprehensive'})
    assert response.status_code==200 and '8 scanners' in response.text,response.text
    assert post(root+'/launch/scan',{'profile':'comprehensive','action':'confirmed'}).status_code==303
    enqueue_due_scheduled_scans(settings,limit=100);run_worker(settings,burst=True,max_jobs=100)
    progress=jobs.progress(identity,limit=100)
    assert progress['repository_jobs']['completed']==len(seen_plans)>0,progress
    findings=work.findings(identity,category='secret')['items']
    assert len(findings)==len(seen_plans)
    assert all(len(row['observed_by'])==8 for row in findings)
    finding_id=findings[0]['id']
    detail=browser.get(root+f'/findings/{finding_id}')
    assert detail.status_code==200 and secret not in detail.text and 'data-reveal' in detail.text,detail.text
    metadata=browser.get(f'/findings/{finding_id}/secrets').json()
    secret_id=metadata['secrets'][0]['id']
    response=browser.post(f'/findings/{finding_id}/secrets/{secret_id}/reveal',headers={'X-CSRF-Token':csrf})
    assert response.status_code==200 and response.json()['value']==secret
    assert post(f'/dashboard/findings/{finding_id}/workflow',{'action':'triage','owner':'operator','note':'Analyst Confirmed: reviewed fixture'}).status_code==200
    for format in ('json','html','csv','pdf','sarif'):
        response=browser.get(f'/assessments/{identity}/reports/{format}')
        assert response.status_code==200 and secret.encode() not in response.content
    assert post('/dashboard/settings/local-ai',{'tenant':'a','enabled':'true','base_url':'http://localhost:11434','model':'fixture'}).status_code==200
    requests=[]
    def generate(self,text):requests.append(text);assert secret not in text;return ADVICE
    monkeypatch.setattr(OllamaProvider,'generate',generate)
    assert post(root+'/launch/ai',{'purpose':'summary'}).status_code==303
    enqueue_due_scheduled_scans(settings,limit=100);run_worker(settings,burst=True,max_jobs=100)
    assert len(requests)==1
    with service.factory() as session:
        assert session.scalar(select(func.count()).select_from(m.SecretRevealAudit))==1
        assert all(secret not in str(row.output_json) for row in session.scalars(select(m.AIAdvice)))
    assert secret not in caplog.text
