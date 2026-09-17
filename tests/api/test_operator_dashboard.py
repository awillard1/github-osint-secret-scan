import json
from fastapi.testclient import TestClient

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_dashboard_queues_escape_and_scope(tmp_path):
    url = f"sqlite:///{tmp_path / 'dashboard.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        for tenant in ('a','b'):
            org = storage.create_organization(tenant, tenant_key=tenant)
            storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret', title=f'{tenant}<script>alert(1)</script>', description='safe', organization_id=org.id, risk_score=90))
        session.commit()
    settings = Settings(database_url=url,api_tokens_json=json.dumps([{'name':'reader','token':'reader-token','role':'reader','tenants':['a']}]))
    client = TestClient(create_app(url,settings=settings))
    assert client.get('/operator/overview').status_code == 401
    assert client.get('/static/css/app.css').status_code == 200
    client.headers['X-Orgscan-Token'] = 'reader-token'
    overview = client.get('/operator/overview').json()
    assert overview['queues']['triage']['count'] == 1
    for path in ('/dashboard','/dashboard/queues/triage','/dashboard/queues/high-risk'):
        page = client.get(path)
        assert page.status_code == 200
        assert 'a&lt;script&gt;' in page.text
        assert 'b&lt;script&gt;' not in page.text
        assert '<script>alert' not in page.text
    assert 'Operator queue' in client.get('/dashboard/queues/triage').text
    assert client.get('/static/css/app.css').status_code == 200
    detail = client.get('/dashboard/findings/1')
    assert detail.status_code == 200
    assert 'Record a decision' not in detail.text
    assert client.get('/dashboard/queues/missing').status_code == 404
    assert client.get('/operator/overview?days=0').status_code == 422
    assert client.post('/dashboard/findings/1/workflow',data={'action':'triage'}).status_code == 403


def test_new_asset_queue_links_open_authorized_html_details(tmp_path):
    url=f"sqlite:///{tmp_path / 'assets.db'}"
    init_db(url)
    ids={}
    with create_session_factory(url)() as session:
        storage=Storage(session)
        for tenant in ('a','b'):
            org=storage.create_organization(tenant,tenant_key=tenant)
            domain=storage.create_domain(f'{tenant}.example.com',organization_id=org.id)
            account=storage.create_account(f'{tenant}-operator',organization_id=org.id)
            repository=storage.create_repository(f'{tenant}/repository',organization_id=org.id)
            ids[tenant]={'organizations':org.id,'domains':domain.id,
                         'accounts':account.id,'repositories':repository.id}
        session.commit()
    settings=Settings(database_url=url,api_tokens_json=json.dumps([
        {'name':'reader','token':'reader-token','role':'reader','tenants':['a']}]))
    client=TestClient(create_app(url,settings=settings),headers={'X-Orgscan-Token':'reader-token'})
    queue=client.get('/operator/overview').json()['queues']['new-assets']
    expected={f'/dashboard/{kind}/{identity}' for kind,identity in ids['a'].items()}
    assert {item['href'] for item in queue['items']}==expected
    for path in expected:
        page=client.get(path)
        assert page.status_code==200,(path,page.text)
        assert 'class="app-shell"' in page.text and 'Asset detail' in page.text
    domain_page=client.get(f"/dashboard/domains/{ids['a']['domains']}")
    assert 'Domain observations' in domain_page.text
    assert client.get(f"/domains/{ids['a']['domains']}").headers['content-type'].startswith('application/json')
    for kind,identity in ids['b'].items():
        assert client.get(f'/dashboard/{kind}/{identity}').status_code==404
    assert client.get('/dashboard/domains/999999').status_code==404


def test_finding_decision_returns_to_detail(tmp_path):
    url = f"sqlite:///{tmp_path / 'decision.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        org = storage.create_organization('a', tenant_key='a')
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture', category='secret', title='Review me', description='safe', organization_id=org.id))
        session.flush()
        finding_id = finding.id
        session.commit()
    settings = Settings(database_url=url, api_tokens_json=json.dumps([{'name':'analyst','token':'analyst-token','role':'analyst','tenants':['a']}]))
    client = TestClient(create_app(url, settings=settings), headers={'X-Orgscan-Token':'analyst-token'})
    detail = client.get(f'/dashboard/findings/{finding_id}')
    assert 'Record a decision' in detail.text
    assert 'data-enhance="decision"' in detail.text
    response = client.post(f'/dashboard/findings/{finding_id}/workflow', data={'action':'triage','note':'Reviewed','return_to_detail':'true'}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == f'/dashboard/findings/{finding_id}'
    assert 'Reviewed' in client.get(response.headers['location']).text
