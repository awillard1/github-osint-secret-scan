"""Reusable legacy discovery and expansion workflows for trusted adapters."""
from dataclasses import dataclass

from orgscan.config import Settings
from orgscan.discovery import DiscoveryError, GitHubDiscoveryClient
from orgscan.providers import get_domain_provider
from orgscan.repositories import Storage
from orgscan.redaction import redact
from orgscan.security_context import AuthorizationError, LOCAL_CONTEXT
from orgscan.services.relationship_service import GitHubExpansionEngine
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_domain_plan
from orgscan.services.target_service import discovery_scope, normalize_intake_target


class _PublicGitHubClient:
    """Keep standalone discovery on public endpoints, even with a global token configured."""

    def __init__(self, client):
        self.client = client
        self.base_url = client.base_url

    @staticmethod
    def _public(record):
        if record.private:
            raise AuthorizationError('Private GitHub discovery requires an assessment connection')
        return record

    def _call(self, method, *args, **kwargs):
        try:
            return method(*args, **kwargs)
        except DiscoveryError:
            raise DiscoveryError(
                'Public GitHub discovery failed; review the target or rate limit. '
                'Credentialed discovery requires an assessment connection'
            ) from None

    def fetch_repository(self, name):
        return self._public(self._call(self.client.fetch_repository, name))

    def fetch_organization_repositories(self, name, limit=20):
        return [self._public(row) for row in self._call(self.client.fetch_organization_repositories, name, limit=limit)]

    def fetch_repository_forks(self, name, limit=20):
        return [self._public(row) for row in self._call(self.client.fetch_repository_forks, name, limit=limit)]

    def fetch_repository_contributors(self, name, limit=20):
        return self._call(self.client.fetch_repository_contributors, name, limit=limit)

    def fetch_repository_commits(self, name, limit=20):
        return self._call(self.client.fetch_repository_commits, name, limit=limit)


@dataclass(frozen=True)
class DiscoveryOutcome:
    payload: dict[str, object]
    status: str = 'completed'
    retryable: bool = False


class DiscoveryService:
    """Coordinate existing provider, plan, persistence and relationship services."""

    def __init__(self, session_factory, settings: Settings, *, auth, client=None):
        self.session_factory = session_factory
        self.settings = settings
        self.auth = auth
        public_settings = settings.model_copy(update={'github_token': None})
        self.client = _PublicGitHubClient(client or GitHubDiscoveryClient(public_settings))

    def discover(self, target_type: str, value: str, *, limit: int = 10,
                 provider: str = 'local-metadata', tenant_key: str | None = None) -> DiscoveryOutcome:
        if not 1 <= limit <= 100:
            raise ValueError('Discovery limit must be between 1 and 100')
        if target_type not in {'organization', 'repository', 'domain'}:
            raise ValueError('Unsupported discovery target')
        value = normalize_intake_target(target_type, value)
        with discovery_scope(self.auth, tenant_key):
            if provider == 'github-search' and self.auth is not LOCAL_CONTEXT:
                raise AuthorizationError('GitHub search requires an authorized connection')
            if target_type == 'organization' and provider == 'github-search':
                with self.session_factory() as session:
                    result = get_domain_provider(provider, self.settings).search_target(
                        Storage(session), value, target_type='organization', tenant_key=tenant_key,
                    )
                    session.commit()
                failure = result.failure
                return DiscoveryOutcome(
                    redact({'target_type': target_type, 'value': value, 'references': result.exposures,
                            'accounts': result.identity_correlations, 'warnings': result.warnings or []},
                           preserve_root_keys=True),
                    'partial' if failure and (result.exposures or result.identity_correlations)
                    else 'failed' if failure else 'completed',
                    bool(failure and failure.retryable),
                )
            if target_type == 'domain':
                with self.session_factory() as session:
                    plan = resolve_scan_plan(target=value, target_type='domain', discovery_provider=provider,
                                             tenant_key=tenant_key, settings=self.settings)
                    _, result = execute_domain_plan(Storage(session), plan, settings=self.settings)
                    session.commit()
                return DiscoveryOutcome(
                    redact({'target_type': target_type, 'value': value,
                            'domain_exposures': result.exposures,
                            'identity_correlations': result.identity_correlations,
                            'warnings': result.warnings or []}, preserve_root_keys=True),
                )
            # The legacy GitHub client has no tenant-bound connection policy. Keep
            # this path local; assessment discovery uses its connection-aware service.
            if self.auth is not LOCAL_CONTEXT:
                raise AuthorizationError('GitHub discovery requires an authorized connection')
            records = ([self.client.fetch_repository(value)] if target_type == 'repository'
                       else self.client.fetch_organization_repositories(value, limit=limit))
            records = records[:limit]
            if tenant_key is not None and any(
                record.owner_type.lower() != 'organization' or not record.owner_login
                for record in records
            ):
                raise AuthorizationError('Tenant-scoped repository discovery requires an organization owner')
            with self.session_factory() as session:
                discovered = GitHubExpansionEngine(self.client, Storage(session)).ingest_repository_records(
                    records, endpoint=(f'/repos/{value}' if target_type == 'repository'
                                       else f'/orgs/{value}/repos?per_page={limit}'), tenant_key=tenant_key,
                )
                session.commit()
        return DiscoveryOutcome(redact({'target_type': target_type, 'value': value,
                                        'repositories': discovered['repositories'],
                                        'accounts': discovered['accounts'],
                                        'organizations': sorted(discovered['organizations'])},
                                       preserve_root_keys=True))

    def expand(self, target_type: str, value: str, *, limit: int = 20,
               tenant_key: str | None = None) -> dict[str, object]:
        if target_type not in {'organization', 'repository'}:
            raise ValueError('Unsupported expansion target')
        if not 1 <= limit <= 100:
            raise ValueError('GitHub expansion limit must be between 1 and 100')
        value = normalize_intake_target(target_type, value)
        with discovery_scope(self.auth, tenant_key):
            if self.auth is not LOCAL_CONTEXT:
                raise AuthorizationError('GitHub expansion requires an authorized connection')
            with self.session_factory() as session:
                engine = GitHubExpansionEngine(self.client, Storage(session))
                result = (engine.expand_repository(value, limit=limit) if target_type == 'repository'
                          else engine.expand_organization(value, limit=limit))
                session.commit()
        return redact({'target_type': target_type, 'value': value,
                       'repositories': result.repositories, 'accounts': result.accounts,
                       'relationships': result.relationships}, preserve_root_keys=True)
