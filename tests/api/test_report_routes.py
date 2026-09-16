import json
from fastapi.testclient import TestClient
from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_exports_use_authorized_service_and_state_filter(tmp_path):
    url = f"sqlite:///{tmp_path / 'reports.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        for tenant in ('a','b'):
            org = storage.create_organization(tenant,tenant_key=tenant)
            storage.create_finding(CanonicalFinding(source_tool='test',category='secret',title=f'Private-{tenant}',description='safe',organization_id=org.id))
        session.commit()
    settings = Settings(database_url=url,api_tokens_json=json.dumps([{'name':'reader','token':'reader-token','role':'reader','tenants':['a']}]))
    client = TestClient(create_app(url,settings=settings))
    assert client.get('/reports/export/json').status_code == 401
    client.headers['X-Orgscan-Token'] = 'reader-token'
    for format in ('json','csv','html','sarif'):
        response = client.get(f'/reports/export/{format}')
        assert response.status_code == 200
        assert 'Private-a' in response.text and 'Private-b' not in response.text
        assert 'attachment' in response.headers['content-disposition']
    assert client.get('/reports/export/pdf-technical').content.startswith(b'%PDF')
    assert client.get('/reports/export/json?lifecycle_state=REMEDIATED').json()['findings'] == []
    assert client.get('/reports/export/bogus').status_code == 422
