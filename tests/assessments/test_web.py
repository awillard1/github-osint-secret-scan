import json
import pytest
from fastapi.testclient import TestClient
from orgscan.api import create_app
from orgscan.services.assessments.workbench import AssessmentWorkbench
from tests.assessments.test_foundation import service


@pytest.fixture
def client(service):
    service.settings.api_tokens_json=json.dumps([{'name':r,'token':r+'-token','role':r,'tenants':['a']} for r in ('reader','analyst','admin')])
    return TestClient(create_app(service.settings.database_url,settings=service.settings),headers={'X-Orgscan-Token':'admin-token'})


def test_wizard_pages_reports_and_permissions(service,client):
    r=client.post('/assessments',json={'tenant':'a','name':'Web assessment'})
    assert r.status_code==200,r.text
    identity=r.json()['id']
    assert client.post(f'/assessments/{identity}/targets',json={'text':'example.com\ninvalid input'}).json()['counts']=={'added':1,'invalid':1,'duplicates':0}
    for path in ['/dashboard/assessments','/dashboard/assessments/new','/dashboard/settings/github',
                 '/dashboard/settings/recon-tools','/dashboard/settings/local-ai']+[
                 f'/dashboard/assessments/{identity}/{tab}' for tab in
                 ('overview','targets','discovery','recon-results','repositories','accounts','domains',
                  'relationships','scans','findings','reports','ai')]:
        response=client.get(path)
        assert response.status_code==200,(path,response.text)
        assert 'class="app-shell"' in response.text,path
    for path in ('/dashboard/graph', f'/dashboard/assessments/{identity}/relationships'):
        page=client.get(path).text
        assert 'class="app-shell"' in page and 'Evidence map' in page
    for fmt in ('json','csv','html','pdf','sarif'):
        response=client.get(f'/assessments/{identity}/reports/{fmt}')
        assert response.status_code==200,(fmt,response.text)
    client.headers['X-Orgscan-Token']='reader-token'
    assert client.post(f'/assessments/{identity}/launch/discovery',json={'options':{}}).status_code==403
    assert client.patch(f'/assessments/{identity}',json={'name':'Denied'}).status_code==403
    assert client.post('/assessments',json={'tenant':'b','name':'Forbidden'}).status_code==403


def test_pasted_github_repositories_can_be_saved_and_reach_scanners(service,client,monkeypatch):
    from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
    from orgscan.services.assessments.github import ConnectionClient
    from orgscan.services.assessments.jobs import AssessmentJobs
    from tests.assessments.test_recon import repo

    identity=service.create('a','Repository import')['id']
    root=f'/dashboard/assessments/{identity}'
    foreign=service.create('b','Other tenant')['id']
    assert client.post(f'/dashboard/assessments/{foreign}/targets/github-connection').status_code==403
    page=client.get(root+'/targets')
    assert 'GitHub.com connection required' in page.text
    assert 'Enable public GitHub.com targets' in page.text
    unavailable=client.post(root+'/targets',data={'text':'https://github.com/org/repo'})
    assert unavailable.status_code==200 and '1 invalid' in unavailable.text
    assert 'Enable a GitHub connection for this host' in unavailable.text
    assert service.targets(identity)['total']==0
    client.headers['X-Orgscan-Token']='analyst-token'
    assert client.post(root+'/targets/github-connection').status_code==403
    client.headers['X-Orgscan-Token']='admin-token'
    enabled=client.post(root+'/targets/github-connection',follow_redirects=False)
    assert enabled.status_code==303
    connection=service.connections('a')['items'][0]
    assert connection['credential_env'] is None and connection['allow_private'] is False
    assert 'GitHub.com connection required' not in client.get(root+'/targets').text

    saved=client.post(root+'/targets',data={'text':'https://github.com/org/repo\nhttps://github.com/org/second'})
    assert saved.status_code==200
    assert '2 added' in saved.text and 'Resolve saved targets with discovery' in saved.text
    assert service.targets(identity)['total']==2
    assert {row['target_type'] for row in service.targets(identity)['items']}=={'github-repository'}
    empty_scans=client.get(root+'/scans')
    assert 'TruffleHog' in empty_scans.text or 'trufflehog' in empty_scans.text
    assert 'Save repository URLs' in empty_scans.text

    def request(self,path):
        name=path.removeprefix('/repos/')
        assert name in ('org/repo','org/second')
        return {**repo(),'full_name':name,'html_url':'https://github.com/'+name}
    monkeypatch.setattr(ConnectionClient,'_request_json',request)
    jobs=AssessmentJobs(service.settings)
    assert jobs.launch(identity,'discovery',options={'name':'quick-organization'})['scheduled']==2
    assert len(enqueue_due_scheduled_scans(service.settings))==2
    assert run_worker(service.settings,burst=True,max_jobs=2)
    assert AssessmentWorkbench(service.settings).assets(identity,'repository')['total']==2
    assert 'Review scan launch' in client.get(root+'/scans').text

    # Saving another URL after discovery requires no pause and does not alter
    # the already completed discovery jobs.
    later=client.post(root+'/targets',data={'text':'https://github.com/org/third'})
    assert later.status_code==200 and '1 added' in later.text
    assert service.targets(identity)['total']==3
    assert jobs.progress(identity,kind='discovery')['states']=={'completed':2}
    client.headers['X-Orgscan-Token']='reader-token'
    assert client.post(root+'/targets',data={'text':'https://github.com/org/forbidden'}).status_code==403


def test_workbench_empty_and_invalid_filters(service):
    a=service.create('a','Empty');work=AssessmentWorkbench(service.settings)
    assert work.findings(a['id'])['items']==[]
    assert work.assets(a['id'])['items']==[]
    assert work.graph(a['id'])['nodes']==[]
    with pytest.raises(ValueError):work.assets(a['id'],limit=-1)


def test_assessment_index_escapes_names(service, client):
    service.create('a', '<img src=x onerror=alert(1)>')
    response = client.get('/dashboard/assessments')
    assert response.status_code == 200
    assert '&lt;img src=x onerror=alert(1)&gt;' in response.text
    assert '<img src=x onerror=alert(1)>' not in response.text


def test_selection_filters_and_scanplan(service,client):
    from types import SimpleNamespace
    from orgscan import models as m
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    from sqlalchemy import select
    a=service.create('a','Scope');connection=service.create_connection('a',name='GitHub')
    with service.factory() as s:
        ingest=ReconIngestor(Storage(s),s.get(m.Assessment,a['id']),s.get(m.GitHubConnection,connection['id']),SimpleNamespace())
        one=ingest.repository(repo(),signals={'official_owner':True})
        two=ingest.repository({**repo(),'full_name':'org/two','html_url':'https://github.com/org/two','archived':True},signals={'fork':True})
        s.commit();one_id=one.id;two_id=two.id
    work=AssessmentWorkbench(service.settings)
    assert work.select_repositories(a['id'],included=False,filters={'archived':True})['updated']==1
    assert work.assets(a['id'],archived=True)['items'][0]['included'] is False
    assert work.assets(a['id'],scanned=False)['total']==2
    options={'profile':'quick','branch_policy':'selected','refs':'trunk, release','mode':'incremental','scanners':'custom-patterns'}
    response=client.post(f'/dashboard/assessments/{a["id"]}/launch/scan',data=options,follow_redirects=False)
    assert response.status_code==200 and '1 repositories' in response.text
    with service.factory() as s:assert s.scalar(select(m.ScheduledScan)) is None
    response=client.post(f'/dashboard/assessments/{a["id"]}/launch/scan',data={**options,'action':'confirmed'},follow_redirects=False)
    assert response.status_code==303,response.text
    with service.factory() as s:
        schedule=s.scalar(select(m.ScheduledScan))
        plan=schedule.metadata_json['scan_plan']
        assert plan['repository_id']==one_id and plan['repository_id']!=two_id
        assert plan['refs']==['trunk','release'] and plan['mode']=='incremental'
        assert plan['scanners']==['custom-patterns'] and plan['tenant_key']=='a'


def test_scan_console_scope_review_and_read_only_controls(service,client):
    from types import SimpleNamespace
    from orgscan import models as m
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    identity=service.create('a','Scan console')['id']
    path=f'/dashboard/assessments/{identity}/scans'
    empty=client.get(path)
    assert empty.status_code==200
    assert 'class="app-shell"' in empty.text and 'No repositories selected' in empty.text
    connection=service.create_connection('a',name='GitHub')
    with service.factory() as session:
        ingest=ReconIngestor(Storage(session),session.get(m.Assessment,identity),
            session.get(m.GitHubConnection,connection['id']),SimpleNamespace())
        ingest.repository(repo(),signals={'official_owner':True})
        session.commit()
    page=client.get(path)
    assert '1</strong><span>Repositories in scope' in page.text
    assert 'Review scan launch' in page.text and 'Scanner override' in page.text
    assert 'name="scanners"' in page.text
    review=client.post(f'/dashboard/assessments/{identity}/launch/scan',
        data={'profile':'quick','scanners':'custom-patterns','branch_policy':'selected','refs':'main,release','mode':'incremental'})
    assert review.status_code==200 and 'Confirm and create scan jobs' in review.text
    assert 'main,release' in review.text and 'class="app-shell"' in review.text
    with service.factory() as session:
        assert session.query(m.ScheduledScan).count()==0
    client.headers['X-Orgscan-Token']='reader-token'
    read_only=client.get(path)
    assert read_only.status_code==200 and 'Review scan launch' not in read_only.text
    assert client.post(f'/dashboard/assessments/{identity}/scans/publish').status_code==403


def test_scan_console_browser_queue_controls(service,client,monkeypatch):
    from types import SimpleNamespace
    from orgscan import models as m
    from orgscan.repositories import Storage
    from orgscan.services.assessments.recon import ReconIngestor
    from tests.assessments.test_recon import repo
    from sqlalchemy import select
    identity=service.create('a','Queue console')['id']
    connection=service.create_connection('a',name='GitHub')
    with service.factory() as session:
        ingest=ReconIngestor(Storage(session),session.get(m.Assessment,identity),
            session.get(m.GitHubConnection,connection['id']),SimpleNamespace())
        ingest.repository(repo(),signals={'official_owner':True})
        session.commit()
    service.settings.scan_queue_backend='db'
    path=f'/dashboard/assessments/{identity}/scans'
    launch=client.post(f'/dashboard/assessments/{identity}/launch/scan',
        data={'profile':'quick','action':'confirmed'},follow_redirects=False)
    assert launch.status_code==303 and launch.headers['location']==path
    page=client.get(path)
    assert page.status_code==200 and 'Execute queued jobs' in page.text
    assert 'Open job details' not in page.text
    assert 'Queued' in page.text and 'Stop run' in page.text
    executed=[]
    monkeypatch.setattr('orgscan.queueing.run_db_schedule_batch',lambda settings,ids:executed.append(set(ids)))
    response=client.post(path+'/execute',follow_redirects=False)
    assert response.status_code==303 and response.headers['location']==path
    with service.factory() as session:
        schedule_id=session.scalar(select(m.AssessmentRun.scheduled_scan_id).where(m.AssessmentRun.assessment_id==identity))
    assert executed==[{schedule_id}]


def test_discovery_results_remain_readable_after_large_target_import(service,client):
    from orgscan import models as m
    identity=service.create('a','Large discovery')['id']
    with service.factory() as session:
        session.execute(m.AssessmentTarget.__table__.insert(),[
            {'assessment_id':identity,'identity':f'{index:064x}',
             'raw_input':f'host-{index}.example.test','normalized_value':f'host-{index}.example.test',
             'target_type':'domain','validation_status':'valid','notes':'','metadata_json':{}}
            for index in range(2100)])
        session.commit()
    response=client.get(f'/dashboard/assessments/{identity}/recon-results')
    assert response.status_code==200 and 'Discovery Results' in response.text


def test_browser_csrf_and_ai_settings(service,client):
    import re
    from orgscan.api.authentication import CSRF_COOKIE
    browser=TestClient(client.app,base_url='https://testserver')
    challenge=re.search(r'name="csrf_token" value="([^"]+)"',browser.get('/login').text)[1]
    assert browser.post('/login',data={'token':'admin-token','csrf_token':challenge},follow_redirects=False).status_code==303
    csrf=browser.get('/auth/me').json()['csrf_token']
    data={'tenant':'a','name':'Browser'}
    assert browser.post('/dashboard/assessments/new',data=data).status_code==403
    response=browser.post('/dashboard/assessments/new',data={**data,'csrf_token':csrf},follow_redirects=False)
    assert response.status_code==303
    assert f'name="csrf_token" value="{csrf}"' in browser.get(response.headers['location']).text
    assert browser.get('/dashboard/settings/local-ai').status_code==200
    assert browser.post('/dashboard/settings/local-ai',data={'tenant':'a','base_url':'http://localhost:11434','model':'test','csrf_token':csrf}).status_code==200


def test_navigation_and_local_ai_test_feedback(service,client,monkeypatch):
    from orgscan.ai.ollama import OllamaProvider, AIUnavailable
    identity=service.create('a','AI navigation')['id']
    def current(path,label):
        response=client.get(path)
        assert response.status_code==200,response.text
        assert f'>{label}</a>' in response.text
        assert f'aria-current="page">{label}</a>' in response.text
        return response.text
    current('/dashboard','Overview')
    current('/dashboard?high_signal_only=true','Findings')
    current('/dashboard/settings/local-ai','Connections &amp; tools')
    current('/dashboard/settings/recon-tools','Connections &amp; tools')
    current('/dashboard/graph','Relationships')
    page=current(f'/dashboard/assessments/{identity}/relationships','Assessments')
    assert 'aria-current="page">Relationships</a>' in page
    page=current(f'/dashboard/assessments/{identity}/overview','Assessments')
    assert 'aria-current="page">Overview</a>' in page
    assert 'Choose an assessment' in client.get('/dashboard/settings/local-ai').text
    settings={'tenant':'a','enabled':'true','base_url':'http://localhost:11434','model':'test','action':'test'}
    monkeypatch.setattr(OllamaProvider,'health',lambda self:{'status':'ready','models':[{'name':'test','size':1}]})
    monkeypatch.setattr(OllamaProvider,'generate',lambda self,text:{'classification':'review','confidence':'low','explanation':'ok','suggested_tags':[]})
    success=client.post('/dashboard/settings/local-ai',data=settings)
    assert success.status_code==200 and 'Test passed.' in success.text
    assert 'Generate advice' in client.get(f'/dashboard/assessments/{identity}/ai').text
    launch=client.post(f'/dashboard/assessments/{identity}/launch/ai',data={'purpose':'summary'},follow_redirects=False)
    assert launch.status_code==303 and launch.headers['location'].endswith('/ai')
    service.import_targets(identity,'example.gov')
    target_id=service.targets(identity)['items'][0]['id']
    target_launch=client.post(f'/dashboard/assessments/{identity}/launch/ai',data={
        'purpose':'target','entity_type':'assessment_target','entity_id':str(target_id)},follow_redirects=False)
    assert target_launch.status_code==303 and target_launch.headers['location'].endswith('/ai')
    activity=client.get(f'/dashboard/assessments/{identity}/ai')
    assert 'Recent AI jobs' in activity.text and 'Advisory job #' in activity.text
    from orgscan import models as m
    with service.factory() as session:
        session.add(m.AIAdvice(assessment_id=identity,purpose='summary',provider='ollama',model='test',
            policy_version='assessment-advice-v3',fingerprint='browser-safe-advice',output_json={
                'classification':'review','confidence':'low','explanation':'Review the supplied evidence.',
                'suggested_tags':['review'],'observed_facts':['A safe metadata fact'],
                'mitigation':'Review configuration','limitations':['Coverage is partial'],
                'input_coverage':{'may_be_partial':True,'omitted':{'findings':2}}}))
        session.commit()
    rendered=client.get(f'/dashboard/assessments/{identity}/ai')
    assert rendered.status_code==200,rendered.text
    assert 'Observed facts' in rendered.text and 'A safe metadata fact' in rendered.text
    assert 'Partial input selection' in rendered.text and 'findings' in rendered.text
    monkeypatch.setattr(OllamaProvider,'generate',lambda self,text:(_ for _ in ()).throw(AIUnavailable('sensitive diagnostic')))
    failed=client.post('/dashboard/settings/local-ai',data=settings)
    assert 'Generation test failed.' in failed.text
    assert 'Generation failed</span>' in failed.text
    assert 'sensitive diagnostic' not in failed.text
    monkeypatch.setattr(OllamaProvider,'health',lambda self:{'status':'model-missing','models':[{'name':'other','size':1}]})
    missing=client.post('/dashboard/settings/local-ai',data=settings)
    assert 'selected model is not installed' in missing.text and 'other' in missing.text


def test_findings_filter_accepts_empty_optional_form_fields(service,client):
    a=service.create('a','Filters')
    response=client.get(f'/dashboard/assessments/{a["id"]}/findings',params={'repository_id':'','severity':'high','confidence':'','status':'','source_tool':'','category':'','lifecycle_state':''})
    assert response.status_code==200,response.text
    assert 'value="high"' in response.text
