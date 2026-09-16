from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.queueing import enqueue_due_scheduled_scans, run_worker
from orgscan.repositories import Storage
from orgscan.scheduler import execute_scheduled_scan
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan
from orgscan.services.target_service import resolve_asset_context


def test_domain_sync_schedule_queue_keep_context_and_stable_job_identity(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "domains.db"}'
    init_db(url)
    settings = Settings(database_url=url, scan_queue_backend='db', app_env='production')
    seen = []
    def discover(storage, context):
        domain = storage.get_domain(context.domain_id)
        assert domain.organization_id == context.organization_id
        assert storage.get_organization(context.organization_id).tenant_key == context.tenant_key
        seen.append(context)
        return SimpleNamespace(failure=None)
    monkeypatch.setattr('orgscan.providers.get_domain_provider', lambda *args: SimpleNamespace(discover_context=discover))
    with create_session_factory(url)() as session:
        storage = Storage(session)
        org, _ = storage.get_or_create_organization('Example', tenant_key='tenant-a')
        plan = resolve_scan_plan(target='example.org', target_type='domain', organization_id=org.id, tenant_key='tenant-a')
        direct = execute_plan(storage, plan, settings=settings)[0]
        schedule = storage.create_scheduled_scan('domain', plan.target, 'local-metadata', datetime.now(UTC), cadence='manual',
            metadata_json={'scan_plan': plan.serialized()})
        scheduled = execute_scheduled_scan(storage, schedule, settings=settings)[0]
        # The legacy schedule also reconstructs a valid domain plan.
        legacy = storage.create_scheduled_scan('domain', plan.target, 'local-metadata', datetime.now(UTC), cadence='manual',
            metadata_json={'organization_id': org.id, 'tenant_key': 'tenant-a'})
        execute_scheduled_scan(storage, legacy, settings=settings)
        legacy.enabled = False
        session.commit()
    assert len(enqueue_due_scheduled_scans(settings)) == 1
    assert run_worker(settings, burst=True, max_jobs=1)
    assert len(seen) == 4 and all(context == seen[0] for context in seen)
    with create_session_factory(url)() as session:
        jobs = Storage(session).list_scan_jobs()
        assert len(jobs) == 4
        assert all(job.target_id == str(seen[0].domain_id) for job in jobs)
        assert all(job.parameters_json['scan_plan']['tenant_key'] == 'tenant-a' for job in jobs)
    # HTTP exposes the same stable domain identity; API has no domain execution endpoint.
    import json
    settings.api_tokens_json = json.dumps([{'token':'tenant-a-reader', 'name':'a', 'role':'reader', 'tenants':['tenant-a']},
                                          {'token':'tenant-b-reader', 'name':'b', 'role':'reader', 'tenants':['tenant-b']}])
    with TestClient(create_app(url, settings=settings)) as client:
        for identity in (direct.scan_job_id, scheduled.scan_job_id):
            assert client.get(f'/scan-jobs/{identity}', headers={'X-Orgscan-Token':'tenant-a-reader'}).json()['scan_job']['target_id'] == str(seen[0].domain_id)
            assert client.get(f'/scan-jobs/{identity}', headers={'X-Orgscan-Token':'tenant-b-reader'}).status_code == 404


@pytest.mark.parametrize('mismatch', ['tenant', 'organization', 'domain'])
def test_domain_context_mismatch_fails_before_provider(tmp_path, monkeypatch, mismatch):
    url = f'sqlite:///{tmp_path / "scope.db"}'
    init_db(url)
    monkeypatch.setattr('orgscan.providers.get_domain_provider', lambda *a: pytest.fail('Provider must not run'))
    with create_session_factory(url)() as session:
        storage = Storage(session)
        a, _ = storage.get_or_create_organization('A', tenant_key='a')
        b, _ = storage.get_or_create_organization('B', tenant_key='b')
        domain, _ = storage.get_or_create_domain('example.org', organization_id=a.id)
        opts = dict(organization_id=a.id, tenant_key='a', domain_id=domain.id)
        opts.update({'tenant_key':'b'} if mismatch == 'tenant' else {'organization_id':b.id, 'tenant_key':'b'} if mismatch == 'organization' else {'domain_id':9999})
        with pytest.raises((ValueError, PermissionError)):
            execute_plan(storage, resolve_scan_plan(target=domain.name, target_type='domain', **opts))
        assert domain.organization_id == a.id
        assert storage.list_scan_jobs() == []


def test_shared_asset_resolution_derives_repository_organization(tmp_path):
    url = f'sqlite:///{tmp_path / "assets.db"}'
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        org, repo = resolve_asset_context(storage, organization='A', repository='a/repo', provider='github', tenant_key='a')
        assert resolve_asset_context(storage, organization=None, repository='a/repo', provider='github') == (org, repo)
        with pytest.raises(PermissionError, match='Tenant scope'):
            resolve_asset_context(storage, organization=None, repository='a/repo', provider='github', tenant_key='b')
        with pytest.raises(ValueError, match='ownership conflict'):
            resolve_asset_context(storage, organization='B', repository='a/repo', provider='github', tenant_key='b')
