"""Continuation regressions for canonical reuse and bounded configuration."""
import pytest
from sqlalchemy import select,func
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.recon.observations import Observation,ObservationStore
from orgscan.recon.configuration import save_template_locations,template_locations
from orgscan.services.assessments.recon import discover_target
from orgscan.storage.assessments import AssessmentStorage
from orgscan.security_context import AuthorizationError
from tests.assessments.test_foundation import service


def test_observation_refresh_retains_provider_attributes_and_reasons(service):
    assessment=service.create('a','Retention')
    with service.factory() as session:
        a=session.get(m.Assessment,assessment['id']);store=ObservationStore(Storage(session),a,service.settings)
        _,domain=store.ingest(Observation('domain','api.example.gov','dnsx',{'dns':{'a':['192.0.2.1']}}))
        link=store.control.link(a,'domain',domain.id,source='dnsx',confidence='verified',reasons=['Resolver response'])
        first=link.metadata_json['observations']['dnsx']['first_seen']
        store.ingest(Observation('domain','api.example.gov','dnsx'))
        observation=link.metadata_json['observations']['dnsx']
        assert observation['attributes']=={'dns':{'a':['192.0.2.1']}}
        assert observation['confidence']=='verified'
        assert 'Resolver response' in observation['reasons']
        assert observation['first_seen']==first


def test_same_tenant_assessments_reuse_root_without_reassigning_owner(service):
    first=service.create('a','First');second=service.create('a','Second')
    for assessment in (first,second):service.import_targets(assessment['id'],'example.gov')
    with service.factory() as session:
        storage=Storage(session)
        for value in (first,second):
            assessment=session.get(m.Assessment,value['id'])
            target=session.scalar(select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==assessment.id))
            discover_target(storage,assessment,target,service.settings,configuration={'name':'custom','providers':['local-metadata']})
            session.commit()
        assert session.scalar(select(func.count()).select_from(m.Domain))==1
        domain=session.scalar(select(m.Domain))
        assert domain.organization_id==first['organization_id']
        links=list(session.scalars(select(m.AssessmentEntity).where(m.AssessmentEntity.entity_type=='domain')))
        assert {link.assessment_id for link in links}=={first['id'],second['id']}
        plans=[job.parameters_json['scan_plan'] for job in session.scalars(select(m.ScanJob))]
        assert all(plan['organization_id']==first['organization_id'] for plan in plans)


def test_foreign_tenant_root_gets_independent_association(service):
    first=service.create('a','First');second=service.create('b','Second')
    service.import_targets(second['id'],'example.gov')
    with service.factory() as session:
        storage=Storage(session)
        original=storage.create_domain('example.gov',organization_id=first['organization_id'])
        session.commit()
        assessment=session.get(m.Assessment,second['id'])
        target=session.scalar(select(m.AssessmentTarget))
        discover_target(storage,assessment,target,service.settings,configuration={'name':'custom','providers':['local-metadata']})
        assert original.organization_id==first['organization_id']
        link=session.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==second['id'],m.AssessmentEntity.entity_type=='domain'))
        assert link.entity_id != original.id
        other=session.get(m.Domain,link.entity_id)
        assert other.identity_id==original.identity_id and other.tenant_key=='b'
        assert session.scalar(select(func.count()).select_from(m.DomainIdentity))==1


def test_template_configuration_write_limit_matches_reader(service,monkeypatch):
    save_template_locations(service.settings,[])
    monkeypatch.setattr('orgscan.recon.templates.validated_templates',lambda *a:['fixture.yaml'])
    paths=['/'+('/'.join(['segment']*110))+f'/templates{i}' for i in range(20)]
    with pytest.raises(ValueError,match='configuration.*limit'):
        save_template_locations(service.settings,paths)
    assert template_locations(service.settings)==[]


def test_unassigned_domain_remains_private_legacy_association(service):
    assessment=service.create('a','Legacy unassigned')
    service.import_targets(assessment['id'],'example.gov')
    with service.factory() as session:
        storage=Storage(session)
        domain=storage.create_domain('example.gov')
        original_id=domain.id
        session.commit()
        a=session.get(m.Assessment,assessment['id'])
        target=session.scalar(select(m.AssessmentTarget))
        discover_target(storage,a,target,service.settings,configuration={'name':'custom','providers':['local-metadata']})
        session.commit()
        assert domain.id==original_id and domain.organization_id is None
        assert session.scalar(select(func.count()).select_from(m.Domain))==2
