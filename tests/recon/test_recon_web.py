import json
from fastapi.testclient import TestClient
from orgscan.api import create_app
from tests.assessments.test_foundation import service


def test_settings_and_results_are_real_readiness(service,monkeypatch):
    service.settings.api_tokens_json=json.dumps([{'name':'admin','token':'admin-token','role':'admin','tenants':['a']},
        {'name':'platform','token':'platform-token','role':'admin','tenants':['*']}])
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.binary',lambda *a:None)
    client=TestClient(create_app(service.settings.database_url,settings=service.settings),headers={'X-Orgscan-Token':'admin-token'})
    response=client.get('/dashboard/settings/recon-tools')
    assert response.status_code==200
    assert 'Recon Tools' in response.text and 'Missing' in response.text
    assert 'Install Recommended Passive Tools' not in response.text
    assert client.post('/recon-tools/subfinder/install').status_code==403
    client.headers['X-Orgscan-Token']='platform-token'
    response=client.get('/dashboard/settings/recon-tools')
    assert 'Install Recommended Passive Tools' in response.text and 'Install Active Recon Tools' in response.text
    assert 'name="tool_id"' not in response.text
    assessment=service.create('a','Network')
    for tab in ('overview','domains','hosts','services','web'):
        response=client.get(f'/dashboard/assessments/{assessment["id"]}/recon-results?tab={tab}')
        assert response.status_code==200 and 'Discovery Results' in response.text
    client.headers['X-Orgscan-Token']='admin-token'
    assert client.post('/assessments/'+str(assessment['id'])+'/launch/discovery',json={'options':{'name':'custom','providers':['httpx']}}).status_code==422
