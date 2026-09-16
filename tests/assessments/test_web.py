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
    for path in ['/dashboard/assessments','/dashboard/assessments/new','/dashboard/settings/github']+[f'/dashboard/assessments/{identity}/{tab}' for tab in ('overview','targets','discovery','repositories','accounts','domains','relationships','scans','findings','reports')]:
        response=client.get(path)
        assert response.status_code==200,(path,response.text)
    for fmt in ('json','csv','html','pdf','sarif'):
        response=client.get(f'/assessments/{identity}/reports/{fmt}')
        assert response.status_code==200,(fmt,response.text)
    client.headers['X-Orgscan-Token']='reader-token'
    assert client.post(f'/assessments/{identity}/launch/discovery',json={'options':{}}).status_code==403
    assert client.patch(f'/assessments/{identity}',json={'name':'Denied'}).status_code==403
    assert client.post('/assessments',json={'tenant':'b','name':'Forbidden'}).status_code==403


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


def test_findings_filter_accepts_empty_optional_form_fields(service,client):
    a=service.create('a','Filters')
    response=client.get(f'/dashboard/assessments/{a["id"]}/findings',params={'repository_id':'','severity':'high','confidence':'','status':'','source_tool':'','category':'','lifecycle_state':''})
    assert response.status_code==200,response.text
    assert 'value="high"' in response.text
