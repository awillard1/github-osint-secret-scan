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
    client.headers['X-Orgscan-Token'] = 'reader-token'
    overview = client.get('/operator/overview').json()
    assert overview['queues']['triage']['count'] == 1
    for path in ('/dashboard','/dashboard/queues/triage','/dashboard/queues/high-risk'):
        page = client.get(path)
        assert page.status_code == 200
        assert 'a&lt;script&gt;' in page.text
        assert 'b&lt;script&gt;' not in page.text
        assert '<script>alert' not in page.text
    assert client.get('/dashboard/queues/missing').status_code == 404
    assert client.get('/operator/overview?days=0').status_code == 422
    assert client.post('/dashboard/findings/1/workflow',data={'action':'triage'}).status_code == 403
