"""Direct service coverage for trusted intake and legacy discovery adapters."""
from types import SimpleNamespace

import pytest

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.discovery import DiscoveryError, GitHubAccountRecord, GitHubRepositoryRecord
from orgscan.providers import DomainProviderResult
from orgscan.repositories import Storage
from orgscan.security_context import AuthContext, AuthorizationError, LOCAL_CONTEXT, current_auth
from orgscan.services.discovery_service import DiscoveryService
from orgscan.services.job_policy import Failure
from orgscan.services.target_service import TargetIntakeService


@pytest.fixture
def boundary(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'discovery.db'}", data_dir=tmp_path / 'data')
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    return settings, factory


@pytest.mark.parametrize('kind,value', [
    ('organization', 'example-org'), ('domain', 'Example.ORG.'),
    ('repository', 'example-org/repo'), ('account', 'example-user'),
])
def test_target_intake_and_duplicate_reuse(boundary, kind, value):
    _, factory = boundary
    service = TargetIntakeService(factory, auth=LOCAL_CONTEXT)
    first = service.add(kind, value, organization='example-org' if kind == 'domain' else None)
    again = service.add(kind, value, organization='example-org' if kind == 'domain' else None)
    assert first.created and not again.created and first.identity == again.identity
    assert first.value == ('example.org' if kind == 'domain' else value)


def test_tenant_isolated_domains_and_unauthorized_intake(boundary):
    _, factory = boundary
    local = TargetIntakeService(factory, auth=LOCAL_CONTEXT)
    first = local.add('domain', 'example.org', organization='alpha', tenant_key='a')
    second = local.add('domain', 'example.org', organization='beta', tenant_key='b')
    assert first.identity != second.identity
    scoped = TargetIntakeService(factory, auth=AuthContext('analyst', 'analyst', ('a',), True))
    with pytest.raises(AuthorizationError):
        scoped.add('organization', 'foreign', tenant_key='b')
    with pytest.raises(AuthorizationError):
        scoped.add('domain', 'other.example.org')
    with pytest.raises(ValueError, match='require an organization'):
        local.add('repository', 'alpha/repo', tenant_key='a')


def test_intake_rejects_missing_or_conflicting_caller_context(boundary):
    _, factory = boundary
    with pytest.raises(AuthorizationError):
        TargetIntakeService(factory, auth=None).add('organization', 'example')
    marker = current_auth.set(AuthContext('reader', 'reader', ('a',), True))
    try:
        with pytest.raises(AuthorizationError, match='does not match'):
            TargetIntakeService(factory, auth=LOCAL_CONTEXT).add('organization', 'example', tenant_key='a')
    finally:
        current_auth.reset(marker)


def _repo(name='example/repo'):
    return GitHubRepositoryRecord(name, f'https://github.com/{name}', 'main', False,
                                  name.split('/')[0], 'Organization')


class FakeClient:
    base_url = 'https://api.github.com'

    def __init__(self, records=None):
        self.records = records or [_repo()]
        self.requested = []

    def fetch_repository(self, name):
        self.requested.append(('repository', name))
        return _repo(name)

    def fetch_organization_repositories(self, name, limit=20):
        self.requested.append(('organization', name, limit))
        return self.records

    def fetch_repository_contributors(self, name, limit=20):
        return [GitHubAccountRecord('contributor', 'User')]

    def fetch_repository_forks(self, name, limit=20):
        return [_repo('fork/fork')]

    def fetch_repository_commits(self, name, limit=20):
        return []


def test_repository_discovery_persists_owner_and_deduplicates(boundary):
    settings, factory = boundary
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT, client=FakeClient())
    first = service.discover('repository', 'example/repo').payload
    second = service.discover('repository', 'example/repo').payload
    assert first == second and first['repositories'] == ['example/repo']
    with factory() as session:
        storage = Storage(session)
        repo = storage.get_repository_by_full_name('example/repo')
        org = storage.get_organization_by_name('example')
        assert repo.organization_id == org.id
        assert len(storage.list_relationships()) == 1


def test_organization_discovery_honors_result_limit(boundary):
    settings, factory = boundary
    client = FakeClient([_repo(f'example/repo{i}') for i in range(5)])
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT, client=client)
    result = service.discover('organization', 'example', limit=2).payload
    assert result['repositories'] == ['example/repo0', 'example/repo1']
    assert client.requested == [('organization', 'example', 2)]
    with pytest.raises(ValueError, match='limit'):
        service.discover('organization', 'example', limit=101)


def test_tenant_scoped_discovery_does_not_create_unowned_user_repository(boundary):
    settings, factory = boundary
    user_repo = GitHubRepositoryRecord('user/repo', 'https://github.com/user/repo', 'main',
                                       False, 'user', 'User')
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT,
                               client=FakeClient([user_repo]))
    with pytest.raises(AuthorizationError, match='organization owner'):
        service.discover('organization', 'example', tenant_key='a')
    with factory() as session:
        assert Storage(session).get_repository_by_full_name('user/repo') is None


def test_domain_provider_persists_job_and_reuses_domain(boundary):
    settings, factory = boundary
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT)
    first = service.discover('domain', 'example.org', provider='local-metadata')
    second = service.discover('domain', 'example.org', provider='local-metadata')
    assert first.status == second.status == 'completed'
    assert first.payload['target_type'] == 'domain'
    with factory() as session:
        storage = Storage(session)
        assert storage.get_domain_by_name('example.org') is not None
        assert len(storage.list_domains()) == 1


def test_unavailable_provider_and_scoped_github_rejected(boundary):
    settings, factory = boundary
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT)
    with pytest.raises(ValueError):
        service.discover('domain', 'example.org', provider='missing-provider')
    scoped = DiscoveryService(factory, settings,
                              auth=AuthContext('analyst', 'analyst', ('a',), True), client=FakeClient())
    with pytest.raises(AuthorizationError, match='connection'):
        scoped.discover('repository', 'example/repo', tenant_key='a')
    with pytest.raises(AuthorizationError, match='connection'):
        scoped.expand('repository', 'example/repo', tenant_key='a')


def test_legacy_github_discovery_uses_public_client_and_rejects_private_records(boundary):
    settings, factory = boundary
    configured = settings.model_copy(update={'github_token': 'nonempty'})
    assert DiscoveryService(factory, configured, auth=LOCAL_CONTEXT).client.client.token is None
    private = GitHubRepositoryRecord('example/private', 'https://github.com/example/private',
                                     'main', True, 'example', 'Organization')
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT,
                               client=FakeClient([private]))
    with pytest.raises(AuthorizationError, match='Private GitHub'):
        service.discover('organization', 'example')
    with factory() as session:
        assert Storage(session).get_repository_by_full_name('example/private') is None
    client = FakeClient()
    client.fetch_repository_forks = lambda *args, **kwargs: [private]
    expansion = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT, client=client)
    with pytest.raises(AuthorizationError, match='Private GitHub'):
        expansion.expand('repository', 'example/repo')
    with factory() as session:
        assert Storage(session).get_repository_by_full_name('example/repo') is None


def test_legacy_client_failure_does_not_expose_diagnostic_payload(boundary):
    settings, factory = boundary
    client = FakeClient()
    marker = 'UNTRUSTED_DIAGNOSTIC'
    def fail(*args, **kwargs):
        raise DiscoveryError(marker)
    client.fetch_repository = fail
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT, client=client)
    with pytest.raises(DiscoveryError) as exc:
        service.discover('repository', 'example/repo')
    assert marker not in str(exc.value) and exc.value.__cause__ is None


@pytest.mark.parametrize('failure,exposures,status,retryable', [
    (Failure('rate_limited', True, 'Upstream rate limit; retry deferred', 30), ['reference'], 'partial', True),
    (Failure('permanent', False, 'Provider unavailable'), [], 'failed', False),
    (None, ['reference'], 'completed', False),
])
def test_search_provider_outcome_classification_and_safe_diagnostics(
    boundary, monkeypatch, failure, exposures, status, retryable,
):
    settings, factory = boundary
    marker = 'REDACTION_PROBE'
    provider = SimpleNamespace(search_target=lambda *args, **kwargs: DomainProviderResult(
        exposures, [], ['password=' + marker], failure,
    ))
    monkeypatch.setattr('orgscan.services.discovery_service.get_domain_provider', lambda *args: provider)
    outcome = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT).discover(
        'organization', 'example', provider='github-search',
    )
    assert (outcome.status, outcome.retryable) == (status, retryable)
    assert marker not in str(outcome.payload)


def test_expansion_relationship_provenance_and_repeat_deduplication(boundary):
    settings, factory = boundary
    service = DiscoveryService(factory, settings, auth=LOCAL_CONTEXT, client=FakeClient())
    first = service.expand('repository', 'example/repo', limit=2)
    second = service.expand('repository', 'example/repo', limit=2)
    assert first['relationships'] > 0 and second['relationships'] == 0
    with factory() as session:
        edges = Storage(session).list_relationships()
        assert {edge.relation_type for edge in edges} >= {'owns', 'contributes_to', 'fork_of'}
        assert {edge.confidence for edge in edges} >= {'verified', 'likely'}
        assert all(edge.source == 'github-api' for edge in edges)
