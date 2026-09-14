from contextlib import contextmanager

import pytest

from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.storage.authorization import authorized_session_factory


@contextmanager
def as_actor(role='reader',tenant='a'):
    token = current_auth.set(AuthContext('actor',role,(tenant,),True))
    try:
        yield
    finally:
        current_auth.reset(token)


def seed(tmp_path):
    url = f"sqlite:///{tmp_path / 'authorized.db'}"
    init_db(url)
    factory = create_session_factory(url)
    ids = {}
    with factory() as session:
        storage = Storage(session)
        for tenant in ('a','b'):
            org = storage.create_organization(tenant,tenant_key=tenant)
            repository = storage.create_repository(f'{tenant}/repo',organization_id=org.id)
            job = storage.create_scan_job('organization',str(org.id),'test')
            finding = storage.create_finding(CanonicalFinding(source_tool='test',category='secret',title=f'{tenant}-private',description='test',organization_id=org.id,repository_id=repository.id,scan_job_id=job.id))
            storage.create_evidence(finding.id,'test',snippet=f'{tenant}-evidence')
            ids[tenant] = (org.id,repository.id,job.id,finding.id)
        storage.create_relationship('organization',str(ids['a'][0]),'repository',str(ids['b'][1]),'cross-tenant')
        session.commit()
    return factory, ids


def test_tenant_scope_covers_details_counts_lazy_loads_graph_and_jobs(tmp_path):
    factory, ids = seed(tmp_path)
    scoped = authorized_session_factory(factory)
    for tenant in ('a','b','a'):
        other = 'b' if tenant == 'a' else 'a'
        with as_actor(tenant=tenant), scoped() as session:
            storage = Storage(session)
            assert [f.title for f in storage.list_findings()] == [f'{tenant}-private']
            assert storage.get_finding(ids[other][3]) is None
            assert storage.list_finding_evidence(ids[other][3]) == []
            assert storage.get_scan_job(ids[other][2]) is None
            assert storage.counts()['findings'] == 1
            assert [repo.full_name for repo in storage.list_organizations()[0].repositories] == [f'{tenant}/repo']
            assert storage.list_relationships() == []
            assert len(storage.list_entity_risk_profiles(min_confidence='unverified')) == 2


def test_services_cannot_write_as_reader_or_outside_tenant(tmp_path):
    factory, ids = seed(tmp_path)
    scoped = authorized_session_factory(factory)
    with as_actor(), scoped() as session:
        with pytest.raises(AuthorizationError):
            Storage(session).update_finding_triage(ids['a'][3],triage_notes='not allowed')
    with as_actor('analyst'), scoped() as session:
        storage = Storage(session)
        assert storage.update_finding_triage(ids['a'][3],triage_notes='allowed')
        session.commit()
        with pytest.raises(AuthorizationError):
            storage.create_repository('new/repo',organization_id=ids['b'][0])
    with factory() as session:
        assert Storage(session).get_finding(ids['a'][3]).triage_notes == 'allowed'
