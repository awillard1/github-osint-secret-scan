from datetime import UTC, datetime, timedelta
import json
import re

from fastapi.testclient import TestClient
import pytest

from orgscan.api import create_app
from orgscan.api.authentication import SESSION_COOKIE, CSRF_COOKIE
from orgscan.auth import create_db_session_token, hash_token
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


@pytest.fixture
def auth_app(tmp_path):
    url = f"sqlite:///{tmp_path / 'auth.db'}"
    init_db(url)
    factory = create_session_factory(url)
    ids = {}
    with factory() as session:
        storage = Storage(session)
        for tenant in ('a','b'):
            org = storage.create_organization(f'org-{tenant}',tenant_key=tenant)
            repo = storage.create_repository(f'{tenant}/repo',organization_id=org.id)
            domain = storage.create_domain(f'{tenant}.example',organization_id=org.id)
            account = storage.create_account(f'user-{tenant}',organization_id=org.id)
            job = storage.create_scan_job('organization',str(org.id),'test',scope_json={'private':tenant})
            finding = storage.create_finding(CanonicalFinding(source_tool='test',category='secret',title=f'private-{tenant}',description='secret',confidence='likely',organization_id=org.id,repository_id=repo.id,domain_id=domain.id,account_id=account.id,scan_job_id=job.id))
            storage.create_evidence(finding.id,'test',snippet=f'evidence-{tenant}')
            ids[tenant] = {'organization':org.id,'repository':repo.id,'domain':domain.id,'account':account.id,'job':job.id,'finding':finding.id}
        storage.create_relationship('organization',str(ids['a']['organization']),'repository',str(ids['b']['repository']),'cross-tenant')
        session.commit()
    tokens = [{'name':role,'token':role+'-token','role':role,'tenants':['a']} for role in ('reader','analyst','admin')]
    tokens.append({'name':'root','token':'root-token','role':'admin','tenants':['*']})
    settings = Settings(database_url=url,api_tokens_json=json.dumps(tokens),browser_cookie_secure=True)
    app = create_app(url,settings=settings)
    return app, factory, ids


def login(client,token):
    page = client.get('/login')
    challenge = re.search(r'name="csrf_token" value="([^"]+)"',page.text)[1]
    return client.post('/login',data={'token':token,'csrf_token':challenge},follow_redirects=False)


@pytest.mark.parametrize('role',['reader','analyst','admin'])
def test_role_and_tenant_matrix_covers_json_html_details_and_mutations(auth_app,role):
    app, factory, ids = auth_app
    client = TestClient(app,base_url='https://testserver',headers={'X-Orgscan-Token':role+'-token'})
    for path in ('/findings','/summary','/organizations','/repositories','/domains','/accounts','/risk-summary','/relationships/graph','/trends/findings','/scheduled-scans','/dashboard'):
        response = client.get(path)
        assert response.status_code == 200, (path,response.text)
        assert 'private-b' not in response.text
        assert 'org-b' not in response.text
    for path,key in (('findings','finding'),('organizations','organization'),('repositories','repository'),('domains','domain'),('accounts','account'),('scan-jobs','job')):
        assert client.get(f'/{path}/{ids["b"][key]}').status_code == 404
    assert client.get(f'/findings/{ids["b"]["finding"]}/evidence').status_code == 404
    own_history = client.get(f'/findings/{ids["a"]["finding"]}').json()['history']
    assert own_history and all(event['scan_job_id'] in (None, ids['a']['job']) for event in own_history)
    assert client.get(f'/dashboard/findings/{ids["b"]["finding"]}').status_code == 404
    allowed = client.patch(f'/findings/{ids["a"]["finding"]}',json={'triage_notes':'reviewed'})
    assert allowed.status_code == (403 if role == 'reader' else 200)
    denied = client.patch(f'/findings/{ids["b"]["finding"]}',json={'triage_notes':'forbidden'})
    assert denied.status_code in (403,404)
    assert client.get('/users').status_code == 403
    assert client.post('/artifact-scans',data={'organization':'org-b'},files={'artifact':('x.txt',b'hello')}).status_code == 403


def test_browser_session_cookie_csrf_logout_and_common_context(auth_app):
    app, factory, ids = auth_app
    client = TestClient(app,base_url='https://testserver')
    assert client.get('/findings').status_code == 401
    assert client.get('/dashboard',follow_redirects=False).headers['location'] == '/login'
    assert client.post('/login',data={'token':'analyst-token'}).status_code == 403
    response = login(client,'analyst-token')
    assert response.status_code == 303
    cookies = response.headers.get_list('set-cookie')
    assert all('HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=strict' in cookie for cookie in cookies[:2])
    me = client.get('/auth/me').json()
    assert me['role'] == 'analyst' and me['tenants'] == ['a'] and me['source'] == 'browser-session'
    csrf = me['csrf_token']
    page = client.get('/dashboard')
    assert f'name="csrf_token" value="{csrf}"' in page.text
    path = f'/findings/{ids["a"]["finding"]}'
    assert client.patch(path,json={'triage_notes':'missing'}).status_code == 403
    assert client.patch(path,json={'triage_notes':'valid'},headers={'X-CSRF-Token':csrf}).status_code == 200
    assert client.patch(path,json={'triage_notes':'cross-origin'},headers={'X-CSRF-Token':csrf,'Origin':'https://elsewhere.example'}).status_code == 403
    workflow = client.post(f'/dashboard/findings/{ids["a"]["finding"]}/workflow',data={'action':'triage','note':'browser','csrf_token':csrf})
    assert workflow.status_code == 200, workflow.text
    upload = client.post('/dashboard/artifact-scans',data={'organization':'org-a','scanner':'custom-patterns','csrf_token':csrf},files={'artifact':('safe.txt',b'no credentials here')})
    assert upload.status_code == 200, upload.text
    assert client.post('/logout').status_code == 403
    raw_cookie = client.cookies.get(SESSION_COOKIE)
    assert client.post('/logout',data={'csrf_token':csrf},follow_redirects=False).status_code == 303
    assert client.get('/findings').status_code == 401
    with factory() as session:
        assert Storage(session).get_user_session_by_hash(hash_token(raw_cookie)).revoked_at is not None
    assert TestClient(app,headers={'Authorization':'Bearer analyst-token'}).get('/findings').status_code == 200


def test_global_admin_user_management_and_parent_revocation(auth_app):
    app, factory, ids = auth_app
    admin = TestClient(app,headers={'X-Orgscan-Token':'root-token'})
    assert admin.get(f'/findings/{ids["b"]["finding"]}').status_code == 200
    assert admin.post('/users',json={'username':'alice'}).status_code == 201
    assert admin.post('/users/alice/memberships',json={'tenant':'a','role':'analyst'}).status_code == 200
    issued = admin.post('/users/alice/sessions',json={})
    assert issued.status_code == 200
    assert issued.headers['cache-control'].startswith('no-store')
    token = issued.json()['token']
    browser = TestClient(app,base_url='https://testserver')
    assert login(browser,token).status_code == 303
    assert browser.get('/auth/me').json()['role'] == 'analyst'
    assert admin.post('/users/alice/memberships',json={'tenant':'a','role':'reader'}).status_code == 200
    assert browser.get('/auth/me').json()['role'] == 'reader'
    with factory() as session:
        Storage(session).revoke_user_session(issued.json()['session_id'])
        session.commit()
    assert browser.get('/auth/me').status_code == 401
    assert admin.patch('/users/alice',json={'is_active':False}).status_code == 200
    assert TestClient(app,headers={'X-Orgscan-Token':token}).get('/findings').status_code == 401


def test_browser_expiry_and_login_csrf_origin(auth_app):
    app, factory, ids = auth_app
    client = TestClient(app,base_url='https://testserver')
    page = client.get('/login')
    csrf = re.search(r'name="csrf_token" value="([^"]+)"',page.text)[1]
    assert client.post('/login',data={'token':'reader-token','csrf_token':csrf},headers={'Origin':'https://attacker.example'}).status_code == 403
    assert login(client,'reader-token').status_code == 303
    with factory() as session:
        row = Storage(session).get_user_session_by_hash(hash_token(client.cookies.get(SESSION_COOKIE)))
        row.expires_at = datetime.now(UTC)-timedelta(seconds=1)
        session.commit()
    assert client.get('/auth/me').status_code == 401


def test_authentication_configuration_and_storage_fail_closed(tmp_path,monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    url = f"sqlite:///{tmp_path / 'required.db'}"
    client = TestClient(create_app(url,settings=Settings(api_tokens_json='',api_auth_required=True)))
    assert client.get('/health').status_code == 200
    assert client.get('/findings').status_code == 401
    local = TestClient(create_app(url,settings=Settings(api_tokens_json='',api_auth_required=False)))
    assert local.get('/findings').status_code == 200
    def unavailable(self):
        raise SQLAlchemyError('private database details')
    monkeypatch.setattr(Storage,'has_auth_users',unavailable)
    response = local.get('/findings')
    assert response.status_code == 503
    assert 'private database details' not in response.text
