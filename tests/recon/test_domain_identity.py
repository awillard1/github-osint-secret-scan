"""Cross-tenant identity shares no observation or authorization boundary."""
import pytest
from sqlalchemy import select, func, event
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.recon.observations import Observation, ObservationStore
from orgscan.storage.assessments import AssessmentStorage
from orgscan.storage.visibility import visibility_ids
from orgscan.security_context import AuthorizationError
from tests.assessments.test_foundation import service


def test_shared_identity_private_observations_and_assessment_links(service):
    aa=service.create('a','A');ab=service.create('a','A2');bb=service.create('b','B');cc=service.create('c','C')
    with service.factory() as session:
        st=Storage(session)
        rows=[]
        for assessment,providers in ((aa,['subfinder','httpx']),(ab,['dnsx']),(bb,['crtsh'])):
            a=session.get(m.Assessment,assessment['id'])
            store=ObservationStore(st,a,service.settings)
            for provider in providers:
                _,row=store.ingest(Observation('domain','api.example.com',provider,{'title':assessment['tenant_key']+' private'}))
            rows.append(row)
        session.commit()
        assert rows[0].id==rows[1].id!=rows[2].id
        assert rows[0].identity_id==rows[2].identity_id
        assert session.scalar(select(func.count()).select_from(m.DomainIdentity))==1
        assert rows[0].discovery_sources==['dnsx','httpx','subfinder']
        assert rows[2].discovery_sources==['crtsh']
        for tenant,expected in (('a',rows[0].id),('b',rows[2].id),('c',None)):
            visible=list(session.scalars(select(m.Domain.id).where(m.Domain.id.in_(visibility_ids([tenant])[m.Domain]))))
            assert visible==([expected] if expected else [])
        for assessment,foreign in ((aa,rows[2]),(bb,rows[0]),(cc,rows[0])):
            with pytest.raises(AuthorizationError):
                AssessmentStorage(session).entity(session.get(m.Assessment,assessment['id']),'domain',foreign.id)
        with pytest.raises(ValueError,match='context'):st.get_domain_by_name('api.example.com')


def test_identity_mutation_cannot_move_private_data(service):
    a=service.create('a','A');b=service.create('b','B')
    with service.factory() as session:
        st=Storage(session);row=st.create_domain('EXAMPLE.com.',organization_id=a['organization_id']);session.commit()
        assert row.name=='example.com'
        row.tenant_key='b'
        with pytest.raises(ValueError,match='immutable'):session.flush()
        session.rollback()
        row.organization_id=b['organization_id']
        with pytest.raises(ValueError,match='immutable'):session.flush()


def test_two_tenants_large_overlapping_observation_batches(service):
    assessments=[service.create(t,t) for t in ('a','b')]
    for a in assessments:
        result=service.import_targets(a['id'],'\n'.join(f'd{i}.example.com' for i in range(400)))
    with service.factory() as session:
        queries=[]
        def count(conn,cursor,statement,parameters,context,many):
            if statement.lstrip().upper().startswith('SELECT'):queries.append(statement)
        event.listen(session.bind,'before_cursor_execute',count)
        for a in assessments:
            store=ObservationStore(Storage(session),session.get(m.Assessment,a['id']),service.settings)
            store.ingest_many([Observation('domain',f'd{i%400}.example.com',f'provider-{i//400}') for i in range(1000)])
        event.remove(session.bind,'before_cursor_execute',count)
        assert session.scalar(select(func.count()).select_from(m.DomainIdentity))==400
        assert session.scalar(select(func.count()).select_from(m.Domain))==800
        assert session.scalar(select(func.count()).select_from(m.AssessmentTarget))==800
        # Bounded per-distinct-domain work; repeat provider observations reuse IDs.
        assert len(queries)<8000
        print(f"Cross-tenant correlation: {len(queries)} SELECTs for 2,000 observations / 800 associations")
        assert sum(len(row.metadata_json["observations"]) for row in session.scalars(select(m.AssessmentEntity).where(m.AssessmentEntity.entity_type=="domain")))==2000
        for tenant in ('a','b'):
            assert session.scalar(select(func.count()).select_from(m.Domain).where(m.Domain.id.in_(visibility_ids([tenant])[m.Domain])))==400


def test_provider_hashes_and_findings_are_association_scoped(service):
    from orgscan.schemas import CanonicalFinding
    assessments=[service.create(t,t) for t in ('a','b')]
    with service.factory() as session:
        st=Storage(session);domains=[];exposures=[];findings=[]
        for a in assessments:
            d=st.create_domain('same.example.com',organization_id=a['organization_id']);domains.append(d)
            exposures.append(st.create_domain_exposure(d.id,'fixture',source_name='fixture',result_summary=a['tenant_key']+' private',normalized_hash='e'*64))
            findings.append(st.create_finding(CanonicalFinding(domain_id=d.id,source_tool='fixture',category='exposure',title=a['tenant_key']+' private',description='Private',normalized_hash='f'*64,fingerprint='f'*64)))
        assert exposures[0].id!=exposures[1].id and findings[0].id!=findings[1].id
        assert exposures[0].result_summary=='a private' and findings[0].title=='a private'
        for d,e,f in zip(domains,exposures,findings):
            assert st.create_domain_exposure(d.id,'fixture',source_name='fixture',result_summary=e.result_summary,normalized_hash='e'*64).id==e.id
            assert st.create_finding(CanonicalFinding(domain_id=d.id,source_tool='fixture',category='exposure',title=f.title,description='Private',normalized_hash='f'*64,fingerprint='f'*64)).id==f.id
        with pytest.raises(ValueError,match='context'):st.get_or_create_domain('same.example.com')


def test_all_provider_pipeline_reuses_identity_without_cross_tenant_results(service,monkeypatch):
    from orgscan.recon.adapters import Adapter
    from orgscan.recon.pipeline import run_pipeline
    from orgscan.services.assessments.discovery_progress import DiscoveryProgress
    from orgscan.services.assessments.workbench import AssessmentWorkbench
    observations={
        'subfinder':[Observation('domain','api.example.com','subfinder')],
        'amass':[Observation('domain','api.example.com','amass')],
        'dnsx':[Observation('domain','api.example.com','dnsx',{'dns':{'a':['127.0.0.1']}}),Observation('ip_address','127.0.0.1','dnsx',{'hostname':'api.example.com'})],
        'httpx':[Observation('http_service','https://api.example.com/','httpx',{'status':200,'title':'Lab'})],
        'katana':[Observation('endpoint','https://api.example.com/admin','katana')],
        'naabu':[Observation('network_service','127.0.0.1:443/tcp','naabu',{'ip':'127.0.0.1','hostname':'api.example.com','port':443})],
        'nuclei':[Observation('finding','https://api.example.com/admin','nuclei',{'template_id':'owned-lab','severity':'info','title':'Lab finding'})],
    }
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.readiness',lambda *a,**k:{'ready':True,'version':'fixture'})
    monkeypatch.setattr(Adapter,'run',lambda self,tool,*a,**kw:observations[tool])
    assessments=[service.create(t,t) for t in ('a','b')]
    with service.factory() as session:
        st=Storage(session)
        for a in assessments:
            assessment=session.get(m.Assessment,a['id'])
            parent=st.create_domain('example.com',organization_id=a['organization_id'])
            for _ in range(2):
                run_pipeline(st,assessment,parent,{'providers':list(observations),'active_authorized':True},service.settings,DiscoveryProgress(st))
                session.commit()
        assert session.scalar(select(func.count()).select_from(m.DomainIdentity))==2
        assert session.scalar(select(func.count()).select_from(m.Domain))==4
        assert session.scalar(select(func.count()).select_from(m.Finding))==2
        for tenant in ('a','b'):
            ids=visibility_ids([tenant])
            assert session.scalar(select(func.count()).select_from(m.Domain).where(m.Domain.id.in_(ids[m.Domain])))==2
            assert session.scalar(select(func.count()).select_from(m.Finding).where(m.Finding.id.in_(ids[m.Finding])))==1
    work=AssessmentWorkbench(service.settings)
    graphs=[work.graph(a['id']) for a in assessments]
    assert {r['id'] for r in graphs[0]['nodes']}.isdisjoint({r['id'] for r in graphs[1]['nodes']})


def test_pipeline_rejects_foreign_association_before_any_provider(service,monkeypatch):
    from orgscan.recon.pipeline import run_pipeline
    from orgscan.services.assessments.discovery_progress import DiscoveryProgress
    a=service.create('a','A');b=service.create('b','B')
    with service.factory() as session:
        st=Storage(session);parent=st.create_domain('example.com',organization_id=a['organization_id'])
        with pytest.raises(AuthorizationError):
            run_pipeline(st,session.get(m.Assessment,b['id']),parent,{'providers':['subfinder']},service.settings,DiscoveryProgress(st))
        assert session.scalar(select(func.count()).select_from(m.ScanJob))==0


def test_global_identity_insert_rolls_back_with_private_association(service):
    a=service.create('a','A')
    with service.factory() as session:
        Storage(session).create_domain('rollback.example.com',organization_id=a['organization_id'])
        session.rollback()
    with service.factory() as session:
        assert session.scalar(select(func.count()).select_from(m.DomainIdentity))==0
        assert session.scalar(select(func.count()).select_from(m.Domain))==0


@pytest.mark.parametrize('through_storage',[True,False])
def test_legacy_organization_claim_cannot_change_domain_scope(service,through_storage):
    with service.factory() as session:
        st=Storage(session);org=st.create_organization('Legacy organization')
        domain=st.create_domain('legacy.example.com',organization_id=org.id)
        session.commit();identity=domain.id
        with pytest.raises(ValueError,match='immutable'):
            if through_storage:st.get_or_create_organization(org.name,tenant_key='a')
            else:
                org.tenant_key='a';session.flush()
        session.rollback()
        assert session.get(m.Domain,identity).tenant_key is None
        assert st.get_organization(org.id).tenant_key is None
