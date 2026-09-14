from io import BytesIO
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.providers import GitHubSearchDomainProvider
from orgscan.repositories import Storage
from orgscan.services.github_search import build_queries, GitHubSearchService


def test_query_builder_bounds_and_pairs_sensitive_files():
    queries = build_queries(('example.org','Acme Corp'))
    assert len(queries) == 12
    assert all('"example.org"' in q.query or '"Acme Corp"' in q.query for q in queries)
    assert len([q for q in queries if q.sensitive_filename]) == 6
    for identifiers in ((), ('x" OR org:other',), ('a','b','c','d')):
        with pytest.raises(ValueError):
            build_queries(identifiers)


def test_search_deduplicates_normal_entities_findings_and_evidence(tmp_path):
    url = f"sqlite:///{tmp_path / 'search.db'}"
    init_db(url)
    requests = []
    def request(path, **kwargs):
        requests.append(path)
        kind = urlsplit(path).path.rsplit('/',1)[-1]
        repository = {'full_name':'outside/repo','owner':{'login':'outside'}}
        item = repository if kind == 'repositories' else {'repository':repository, 'path':'.env'}
        if kind == 'issues':
            item = {'repository_url':'https://api.github.com/repos/outside/repo','number':5,'user':{'login':'person'}}
        return {'items':[item], 'total_count':1, 'incomplete_results':False}
    service = GitHubSearchService(Settings(github_token='test-token'), request, lambda:{'rate_limit':{'x-ratelimit-remaining':'9'}})
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = service.search(storage,'example.org')
        assert len(result.exposures) == 3
        assert len(storage.list_findings()) == 3
        assert all(f.confidence == 'heuristic' for f in storage.list_findings())
        assert storage.get_repository_by_full_name('outside/repo').organization_id is None
        first = storage.counts()
        service.search(storage,'example.org')
        second = storage.counts()
        for key in ('findings','evidence','repositories','accounts','relationships','domain_exposures'):
            assert first[key] == second[key]
        job = storage.list_scan_jobs()[0]
        assert len(job.scope_json['pages']) == 6
        assert all(p['searched_at'] and p['query'] and p['rate_limit'] for p in job.scope_json['pages'])
        assert all(parse_qs(urlsplit(path).query)['per_page'] == ['10'] for path in requests)
        assert 'test-token' not in repr(job.scope_json)
        domain_id = storage.get_domain_by_name('example.org').id
        assert all(r.confidence == 'heuristic' for r in storage.list_relationships() if r.to_entity_type == 'domain' and r.to_entity_id == str(domain_id))


def test_pagination_and_rate_limit_stop_are_recorded(tmp_path):
    url = f"sqlite:///{tmp_path / 'limits.db'}"
    init_db(url)
    calls = []
    def request(path, **kwargs):
        calls.append(path)
        return {'items':[{'full_name':'outside/repo'}], 'total_count':100}
    service = GitHubSearchService(Settings(github_token='test'), request,
                                  lambda:{'has_next':True,'rate_limit':{'x-ratelimit-remaining':'0','x-ratelimit-reset':'2000000000'}})
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = service.search(storage,'Acme',target_type='organization',pages=3,per_page=1)
        assert len(calls) == 1
        assert result.warnings
        assert storage.list_scan_jobs()[0].status == 'failed'
        assert storage.list_findings()[0].organization_id == storage.get_organization_by_name('Acme').id
        assert storage.get_repository_by_full_name('outside/repo').organization_id is None


def test_transport_authentication_and_rate_limit_failure_metadata(monkeypatch, tmp_path):
    headers_seen = []
    def request(req, **kwargs):
        headers_seen.append(req.get_header('Authorization'))
        raise HTTPError(req.full_url,429,'limited',{'Retry-After':'60'},BytesIO(b'private response content'))
    monkeypatch.setattr('orgscan.providers.urlopen',request)
    monkeypatch.setattr('orgscan.providers.wait_for_rate_limit',lambda *a,**k:None)
    url = f"sqlite:///{tmp_path / 'http.db'}"
    init_db(url)
    provider = GitHubSearchDomainProvider(Settings(github_token='fake-private-token'))
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = provider.discover(storage,'example.org')
        assert headers_seen == ['Bearer fake-private-token']
        assert result.warnings
        metadata = storage.list_scan_jobs()[0].scope_json
        assert metadata['pages'][0]['rate_limit']['retry-after'] == '60'
        assert metadata['pages'][0]['http_status'] == 429
        assert 'fake-private-token' not in repr(metadata)
        assert 'private response content' not in repr(result)


def test_no_token_skips_code_search_and_records_empty_searches(tmp_path):
    url = f"sqlite:///{tmp_path / 'anonymous.db'}"
    init_db(url)
    calls = []
    def request(path, **kwargs):
        calls.append(path)
        return {'items':[]}
    service = GitHubSearchService(Settings(github_token=None),request,lambda:{})
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = service.search(storage,'example.org')
        assert len(calls) == 2
        assert all('/search/code?' not in path for path in calls)
        assert result.warnings == ['Code search skipped: configure ORGSCAN_GITHUB_TOKEN.']
        assert len(storage.list_scan_jobs()[0].scope_json['pages']) == 2


def test_multi_page_search_obeys_ceiling_and_records_queries(tmp_path):
    url = f"sqlite:///{tmp_path / 'pages.db'}"
    init_db(url)
    calls = []
    def request(path, **kwargs):
        calls.append(path)
        page = parse_qs(urlsplit(path).query)['page'][0]
        return {'items':[{'full_name':f'outside/repo{page}'}], 'total_count':100, 'incomplete_results':True}
    service = GitHubSearchService(Settings(github_token=None),request,lambda:{'has_next':True})
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = service.search(storage,'example.org',pages=2,per_page=1)
        assert len(calls) == 4  # two anonymous query types, each capped at two pages
        assert {parse_qs(urlsplit(path).query)['page'][0] for path in calls} == {'1','2'}
        assert 'GitHub reported incomplete search results.' in result.warnings
        assert len(storage.list_scan_jobs()[0].scope_json['pages']) == 4
