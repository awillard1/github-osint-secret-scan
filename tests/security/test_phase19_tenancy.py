from datetime import UTC, datetime
from pathlib import Path
import json

import pytest
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_domain_plan
from orgscan.scheduler import execute_scheduled_scan, run_due_reports
from orgscan.queueing import enqueue_due_scheduled_scans, run_worker
from orgscan.schemas import CanonicalFinding
from orgscan.services.report_service import query_report
from orgscan.reporting import build_summary, write_export
from orgscan.services.github_search import GitHubSearchService


@pytest.mark.parametrize('execution', ['sync', 'scheduled', 'queued'])
@pytest.mark.parametrize('provider_name', ['local-metadata', 'all'])
def test_domain_sources_are_scoped_across_adapters_and_nested_providers(tmp_path, monkeypatch, execution, provider_name):
    from orgscan.providers import DomainProviderResult, ProjectDiscoveryDomainProvider, CrtShDomainProvider, WhoisDomainProvider, DnsDomainProvider
    # Nested local-metadata remains real; only external I/O is faked.
    for provider in (ProjectDiscoveryDomainProvider, CrtShDomainProvider, WhoisDomainProvider, DnsDomainProvider):
        monkeypatch.setattr(provider, 'discover', lambda *args:DomainProviderResult([], []))
    url = f'sqlite:///{tmp_path / "tenants.db"}'
    init_db(url)
    settings = Settings(_env_file=None, database_url=url, app_env='production', scan_queue_backend='db')
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        organizations = {key:storage.create_organization(key,tenant_key=key) for key in ('a','b')}
        for key, org in organizations.items():
            storage.create_repository(f'{key}/private-repo',organization_id=org.id,is_private=True,metadata_json={'customer':'a.example'})
            storage.create_account(f'{key}-person',organization_id=org.id,email=f'{key}@a.example')
        plan = resolve_scan_plan(target='a.example',target_type='domain',organization_id=organizations['a'].id,tenant_key='a',discovery_provider=provider_name)
        if execution == 'sync':
            execute_domain_plan(storage,plan,settings=settings)
        else:
            scheduled = storage.create_scheduled_scan('domain',plan.target,provider_name,datetime.now(UTC),cadence='manual',metadata_json={'scan_plan':plan.serialized()})
            session.commit()
            if execution == 'scheduled':
                execute_scheduled_scan(storage,scheduled,settings=settings)
        session.commit()
    if execution == 'queued':
        assert len(enqueue_due_scheduled_scans(settings)) == 1
        run_worker(settings,burst=True,max_jobs=1)
    with factory() as session:
        storage = Storage(session)
        domain = storage.get_domain_by_name('a.example')
        summaries = str([row.result_summary for row in storage.list_domain_exposures(domain_id=domain.id)])
        accounts = [row.username for row in storage.list_identity_correlations(domain_id=domain.id)]
        assert 'a/private-repo' in summaries and 'b/private-repo' not in summaries
        assert accounts == ['a-person']


@pytest.mark.parametrize('format', ['json','csv','html','pdf','sarif'])
def test_reports_use_authoritative_ownership_and_both_endpoints(tmp_path, format):
    url = f'sqlite:///{tmp_path / "reports.db"}'
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        a = storage.create_organization('A',tenant_key='a')
        b = storage.create_organization('B',tenant_key='b')
        repo = storage.create_repository('b/repo',organization_id=b.id)
        storage.create_finding(CanonicalFinding(source_tool='github-search',category='public-reference',title='A-only-investigation',description='A-only-investigation',organization_id=a.id,repository_id=repo.id,fingerprint='a'*64))
        storage.create_relationship('organization',str(a.id),'repository',str(repo.id),'mentions',metadata_json={'case':'A-only-investigation'})
        payload = query_report(storage,tenant_keys=['b'])
        assert payload['findings'] == []
        assert payload['summary']['relationship_graph']['edges'] == []
        assert 'A-only-investigation' not in str(build_summary(storage,tenant_keys=['b']))
        output = write_export(tmp_path / ('report.'+format),format,payload['summary'],payload['findings'])
        if format == 'pdf':
            from pypdf import PdfReader
            content = '\n'.join(page.extract_text() for page in PdfReader(output).pages)
        else:
            content = output.read_text()
        assert 'A-only-investigation' not in content


@pytest.mark.parametrize('flags,accepted', [
    ({'private':False,'visibility':'public'}, True), ({'private':False}, True),
    ({'visibility':'public'}, True), ({'private':True},False),
    ({'visibility':'private'},False), ({'visibility':'internal'},False), ({},False),
    ({'private':True,'visibility':'public'},False), ({'private':False,'visibility':'private'},False),
    ({'private':None},False), ({'private':'false'},False),
])
@pytest.mark.parametrize('kind', ['repositories','code','issues'])
def test_public_search_rejects_private_ambiguous_and_contradictory_results(tmp_path, flags, accepted, kind):
    from urllib.parse import parse_qs, urlsplit
    url = f'sqlite:///{tmp_path / "search.db"}'
    init_db(url)
    queries = []
    def request(endpoint, **kwargs):
        queries.append(parse_qs(urlsplit(endpoint).query)['q'][0])
        repo = {'full_name':'outside/repo',**flags}
        item = repo if kind == 'repositories' else {'repository':repo,'path':'.env','number':5,'html_url':'https://github.com/outside/repo/issues/5'}
        if kind == 'code' and endpoint.startswith('/search/repositories?'):
            return {'items':[{'full_name':'outside/repo','private':False}]}
        return {'items':[item]} if endpoint.startswith('/search/'+kind+'?') else {'items':[]}
    service = GitHubSearchService(Settings(_env_file=None,github_token='synthetic-private-capable-token'),request,lambda:{})
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = service.search(storage,'Tenant A',target_type='organization',tenant_key='a')
        findings = [row for row in storage.list_findings() if '/search/'+kind+'?' in row.metadata_json.get('endpoint','')]
        assert bool(findings) == accepted
        assert all('is:public' in query or 'repo:outside/repo' in query for query in queries)
        if accepted:
            assert findings[0].metadata_json['verified_public'] is True
        else:
            if kind != 'code':
                assert storage.list_repositories() == []
                assert not result.exposures


def test_scheduled_report_and_webhook_exclude_foreign_provenance(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "scheduled.db"}'
    init_db(url)
    deliveries = []
    monkeypatch.setattr('orgscan.scheduler.deliver_report_webhook',lambda *a,**k:deliveries.append(k['payload']))
    settings = Settings(_env_file=None,database_url=url,data_dir=tmp_path)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        a = storage.create_organization('A',tenant_key='a')
        b = storage.create_organization('B',tenant_key='b')
        repo = storage.create_repository('b/repo',organization_id=b.id)
        storage.create_finding(CanonicalFinding(source_tool='fixture',category='exposure',title='A-only-webhook',description='A-only-webhook',organization_id=a.id,repository_id=repo.id))
        storage.create_relationship('organization',str(a.id),'repository',str(repo.id),'mentions',metadata_json={'case':'A-only-webhook'})
        storage.create_scheduled_report(target_type='tenant',target_value='b',output_format='json',next_run_at=datetime.now(UTC),cadence='manual',webhook_url='https://hook.example/')
        session.commit()
        results = run_due_reports(storage,settings=settings)
        assert len(deliveries) == len(results) == 1
        assert 'A-only-webhook' not in str(deliveries)
        assert 'A-only-webhook' not in Path(results[0].output_path).read_text()


def test_request_and_report_visibility_agree_with_cached_foreign_assets(tmp_path):
    from orgscan.security_context import AuthContext,current_auth
    from orgscan.storage.authorization import authorized_session_factory
    from orgscan.models import Finding
    url = f'sqlite:///{tmp_path / "ownership.db"}'
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        a = storage.create_organization('A',tenant_key='a')
        b = storage.create_organization('B',tenant_key='b')
        repo = storage.create_repository('b/private-name',organization_id=b.id,is_private=True)
        owned = storage.create_finding(CanonicalFinding(source_tool='fixture',category='exposure',title='Owned by A',description='safe',organization_id=a.id,repository_id=repo.id))
        session.commit()
        # The original session already caches B's repository; scoped report readers must not reuse it.
        report = query_report(storage,tenant_keys=['a'])
        assert report['findings'][0]['repository'] is None
        assert 'b/private-name' not in str(report)
        finding_id = owned.id
    token = current_auth.set(AuthContext('B reader','reader',('b',),True))
    try:
        with authorized_session_factory(factory)() as session:
            assert session.get(Finding,finding_id) is None
            assert query_report(Storage(session),tenant_keys=['a'])['findings'] == []
    finally:
        current_auth.reset(token)
