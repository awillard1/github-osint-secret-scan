"""Operator configuration, review and correlated provenance regressions."""
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from orgscan import models as m
from orgscan.api import create_app
from orgscan.recon.configuration import approved_templates,save_template_locations,template_locations
from orgscan.recon.observations import Observation,ObservationStore
from orgscan.repositories import Storage
from orgscan.services.assessments.workbench import AssessmentWorkbench
from tests.assessments.test_foundation import service


def test_multiple_template_directories_and_fail_closed(service,tmp_path):
    fixture=Path('tests/fixtures/recon/nuclei/local-health.yaml').read_text()
    directories=[]
    for index in range(2):
        directory=tmp_path/str(index);directory.mkdir()
        (directory/'health.yaml').write_text(fixture)
        directories.append(str(directory))
    assert save_template_locations(service.settings,directories)['templates']==2
    assert template_locations(service.settings)==directories
    assert len(approved_templates(service.settings,tmp_path/'snapshot'))==2
    bad=tmp_path/'bad';bad.mkdir();(bad/'bad.yaml').write_text('code: []')
    with pytest.raises(ValueError):save_template_locations(service.settings,[str(bad)])
    assert template_locations(service.settings)==directories
    save_template_locations(service.settings,[])
    with pytest.raises(ValueError,match='Configure'):approved_templates(service.settings)


def test_template_ui_platform_authorization(service,monkeypatch):
    service.settings.api_tokens_json=json.dumps([
        {'name':'tenant','token':'tenant-token','role':'admin','tenants':['a']},
        {'name':'platform','token':'platform-token','role':'admin','tenants':['*']}])
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.binary',lambda *a:None)
    client=TestClient(create_app(service.settings.database_url,settings=service.settings),headers={'X-Orgscan-Token':'tenant-token'})
    endpoint='/dashboard/settings/recon-tools/nuclei/templates'
    assert client.post(endpoint,data={'locations':''}).status_code==403
    client.headers['X-Orgscan-Token']='platform-token'
    assert client.post(endpoint,data={'locations':str(Path('tests/fixtures/recon/nuclei').resolve())},follow_redirects=False).status_code==303
    page=client.get('/dashboard/settings/recon-tools').text
    assert 'Template locations' in page and 'Templates: Ready' in page
    client.headers['X-Orgscan-Token']='tenant-token'
    assert str(Path('tests/fixtures/recon/nuclei').resolve()) not in client.get('/dashboard/settings/recon-tools').text


def test_active_review_does_not_schedule_until_confirmed(service,monkeypatch):
    service.settings.api_tokens_json=json.dumps([{'name':'operator','token':'operator-token','role':'admin','tenants':['a']}])
    monkeypatch.setattr('orgscan.services.assessments.recon.provider_readiness',lambda settings:[{'name':'httpx','status':'ok'}])
    assessment=service.create('a','Review')
    service.import_targets(assessment['id'],'example.gov')
    client=TestClient(create_app(service.settings.database_url,settings=service.settings),headers={'X-Orgscan-Token':'operator-token'})
    endpoint=f'/dashboard/assessments/{assessment["id"]}/launch/discovery'
    data={'profile':'custom','providers':['httpx'],'active_authorized':'true'}
    response=client.post(endpoint,data=data)
    assert response.status_code==200 and 'Start Active Validation' in response.text
    with service.factory() as session:assert session.scalar(select(m.AssessmentRun)) is None
    assert client.post(endpoint,data={**data,'action':'confirmed'},follow_redirects=False).status_code==303
    with service.factory() as session:
        schedule=session.scalar(select(m.ScheduledScan))
        assert schedule.metadata_json['discovery_options']['authorized_by']=='operator'


def test_domain_observations_preserve_provider_attributes(service):
    assessment=service.create('a','Provenance')
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);store=ObservationStore(Storage(session),a,service.settings)
        store.ingest(Observation('domain','api.example.gov','dnsx',{'dns':{'a':['192.0.2.1']}}))
        store.ingest(Observation('domain','api.example.gov','httpx',{'http_status':200,'tech':['nginx']}))
        session.commit()
    result=AssessmentWorkbench(service.settings).recon_results(assessment['id'],tab='domains')
    assert result['total']==1
    observations=result['items'][0]['metadata_json']['observations']
    assert observations['dnsx']['attributes']['dns']['a']==['192.0.2.1']
    assert observations['httpx']['attributes']['tech']==['nginx']


def test_hundreds_of_mixed_targets_across_three_connections(service):
    assessment=service.create('a','Many targets')
    hosts=['github.com','ghes-a.example','ghes-b.example']
    for index,host in enumerate(hosts):
        service.create_connection('a',name=host,connection_type='github' if index==0 else 'ghes',
            web_base_url='https://'+host,api_base_url='https://api.github.com' if index==0 else 'https://'+host+'/api/v3')
    locations=[]
    for index in range(40):
        for host in hosts:
            locations.extend([f'https://{host}/org{index}',f'https://{host}/user/user{index}',f'https://{host}/org{index}/repo'])
        locations.append(f'domain{index}.example')
    result=service.import_targets(assessment['id'],'\n'.join(locations+locations))
    assert result['counts']=={'added':400,'duplicates':400,'invalid':0}
    page=service.targets(assessment['id'],limit=500)
    assert page['total']==400
    assert len({row['connection_id'] for row in page['items'] if row['connection_id']})==3


def test_thousand_observations_reuse_hundred_canonical_domains(service):
    from sqlalchemy import event
    assessment=service.create('a','Correlation scale')
    service.import_targets(assessment['id'],'\n'.join(f'host{i}.example' for i in range(100)))
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);store=ObservationStore(Storage(session),a,service.settings)
        rows=[Observation('domain',f'host{i}.example',f'provider{provider}',{'record':i}) for provider in range(10) for i in range(100)]
        queries=[]
        def count(connection,cursor,statement,*args):
            if statement.lstrip().upper().startswith('SELECT'):queries.append(statement)
        event.listen(session.bind,'before_cursor_execute',count)
        try:store.ingest_many(rows)
        finally:event.remove(session.bind,'before_cursor_execute',count)
        assert len(queries)<1000, len(queries)
        assert store.control._entity_cache is None
        session.commit()
        domains=list(session.scalars(select(m.Domain)))
        assert len(domains)==100
        assert all(len(d.discovery_sources)==10 for d in domains)
    result=AssessmentWorkbench(service.settings).recon_results(assessment['id'],tab='domains')
    assert result['total']==100 and len(result['items'])==50
    assert len(result['items'][0]['metadata_json']['observations'])==10


def test_nuclei_binary_and_template_readiness_are_separate(service,monkeypatch):
    from types import SimpleNamespace
    from orgscan.recon.registry import get_registry
    registry=get_registry()
    def run(args,**kwargs):
        output=' '.join(registry.get('nuclei').required_flags) if '-h' in args else 'nuclei v3.11.1'
        return SimpleNamespace(returncode=0,stdout=output,stderr='')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',run)
    missing=registry.readiness('nuclei',service.settings,binary='/fixture/nuclei')
    assert missing['binary_ready'] and not missing['ready']
    save_template_locations(service.settings,[str(Path('tests/fixtures/recon/nuclei').resolve())])
    ready=registry.readiness('nuclei',service.settings,binary='/fixture/nuclei')
    assert ready['ready'] and ready['templates_status']=='Ready'


def test_prior_passive_domains_seed_active_pipeline_with_causality(service,monkeypatch):
    from orgscan.recon.pipeline import run_pipeline
    from orgscan.recon.adapters import Adapter
    from orgscan.services.assessments.discovery_progress import DiscoveryProgress
    assessment=service.create('a','Sequential recon')
    seen=[]
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',lambda *a,**k:{'ready':True,'version':'fixture'})
    monkeypatch.setattr(Adapter,'run',lambda self,tool,root,inputs,**kw:seen.extend(inputs) or [])
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);storage=Storage(session)
        store=ObservationStore(storage,a,service.settings)
        _,parent=store.ingest(Observation('domain','example.gov','operator'))
        store.ingest(Observation('domain','api.example.gov','subfinder'))
        store.ingest(Observation('domain','unrelated.gov','repository'))
        session.commit()
        progress=DiscoveryProgress(storage)
        run_pipeline(storage,a,parent,{'providers':['dnsx'],'active_authorized':True},service.settings,progress)
        assert seen==['api.example.gov','example.gov']
        assert len(progress.states['dnsx']['input_entities'])==2
        assert len(progress.states['dnsx']['input_digest'])==64


def test_template_symlinks_fail_closed(service,tmp_path):
    from orgscan.recon.configuration import configuration_file
    directory=tmp_path/'alias'
    directory.symlink_to(Path('tests/fixtures/recon/nuclei').resolve(),target_is_directory=True)
    service.settings.nuclei_templates_path=str(directory)
    with pytest.raises(ValueError,match='Unsafe'):approved_templates(service.settings)
    path=configuration_file(service.settings);path.parent.mkdir(parents=True)
    path.symlink_to(tmp_path/'nonexistent.json')
    with pytest.raises(ValueError,match='Unsafe'):template_locations(service.settings)


def test_amass_passive_contract_and_cross_provider_correlation(service,tmp_path):
    from orgscan.recon.adapters import Adapter
    adapter=Adapter(service.settings)
    command=adapter.command('amass','/fixture/amass','example.gov',tmp_path/'inputs',tmp_path)
    assert '-passive' in command and '-active' not in command
    rows=adapter.parse('amass','example.gov','api.example.gov\napi.example.gov\nthird-party.example\n')
    assessment=service.create('a','Amass correlation')
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);store=ObservationStore(Storage(session),a,service.settings)
        store.ingest_many([*rows,Observation('domain','api.example.gov','subfinder'),Observation('domain','api.example.gov','crtsh')])
        session.commit()
        domains=list(session.scalars(select(m.Domain)))
        assert len(domains)==1 and set(domains[0].discovery_sources)=={'amass','subfinder','crtsh'}
