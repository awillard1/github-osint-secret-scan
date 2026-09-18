"""Resolve asset ownership consistently before executing or scheduling work."""
from dataclasses import dataclass
from contextlib import contextmanager
import re
from orgscan.security_context import AuthorizationError, current_auth, LOCAL_CONTEXT
from orgscan.services.relationship_service import public_domain


@contextmanager
def discovery_scope(auth, tenant_key=None):
    """Bind an explicit caller identity to storage and provider operations."""
    if auth is None:
        raise AuthorizationError('Discovery requires an authorization context')
    active = current_auth.get()
    if active is not None and active.authenticated and active != auth:
        raise AuthorizationError('Discovery authorization context does not match caller')
    if auth is not LOCAL_CONTEXT and (
        not auth.authenticated or not auth.allows_role('analyst') or
        tenant_key is None or not auth.allows_tenant(tenant_key)
    ):
        raise AuthorizationError('Discovery tenant scope is not authorized')
    marker = current_auth.set(auth)
    try:
        yield
    finally:
        current_auth.reset(marker)


def normalize_intake_target(target_type: str, value: str) -> str:
    """Validate the legacy CLI asset identity without requiring an assessment connection."""
    value = value.strip()
    if not value or len(value) > 253 or any(ord(char) < 32 for char in value):
        raise ValueError('Invalid target identity')
    if target_type == 'domain':
        domain = public_domain(value)
        if domain is None:
            raise ValueError('Invalid domain target')
        return domain
    segment = r'[A-Za-z0-9_.-]+'
    pattern = segment + '/' + segment if target_type == 'repository' else segment
    if target_type not in {'organization', 'repository', 'account'} or not re.fullmatch(pattern, value):
        raise ValueError('Invalid target identity')
    if any(part in {'.', '..'} for part in value.split('/')):
        raise ValueError('Invalid target identity')
    return value


@dataclass(frozen=True)
class IntakeResult:
    target_type: str
    value: str
    identity: int
    created: bool


class TargetIntakeService:
    def __init__(self, session_factory, *, auth):
        self.session_factory = session_factory
        self.auth = auth

    def add(self, target_type: str, value: str, *, organization: str | None = None,
            provider: str = 'github', tenant_key: str | None = None) -> IntakeResult:
        from orgscan.repositories import Storage
        normalized = normalize_intake_target(target_type, value)
        organization = normalize_intake_target('organization', organization) if organization else None
        if tenant_key is not None and (not tenant_key.strip() or len(tenant_key) > 253):
            raise ValueError('Invalid tenant scope')
        if target_type != 'organization' and tenant_key is not None and organization is None:
            raise ValueError('Tenant-scoped assets require an organization')
        with discovery_scope(self.auth, tenant_key):
            with self.session_factory() as session:
                storage = Storage(session)
                organization_id = None
                if organization:
                    org, _ = storage.get_or_create_organization(organization, tenant_key=tenant_key)
                    organization_id = org.id
                if target_type == 'organization':
                    record, created = storage.get_or_create_organization(normalized, tenant_key=tenant_key)
                elif target_type == 'domain':
                    record, created = storage.get_or_create_domain(normalized, organization_id=organization_id)
                elif target_type == 'repository':
                    record, created = storage.get_or_create_repository(normalized, organization_id=organization_id, provider=provider)
                else:
                    record, created = storage.get_or_create_account(normalized, organization_id=organization_id, provider=provider)
                identity = record.id
                session.commit()
        return IntakeResult(target_type, normalized, identity, created)


def resolve_asset_context(storage, *, organization, repository, provider, tenant_key=None):
    auth = current_auth.get()
    org = storage.get_organization_by_name(organization) if organization else None
    repo = storage.get_repository_by_full_name(repository) if repository else None
    if auth is not None and "*" not in auth.tenants:
        if (organization and org is None) or (repository and repo is None) or (org is None and repo is None):
            raise AuthorizationError("Select an existing organization or repository in your tenant scope")
        if org is not None and repo is not None and repo.organization_id != org.id:
            raise AuthorizationError("Repository and organization scopes do not match")
    else:
        if organization:
            org, _ = storage.get_or_create_organization(organization, tenant_key=tenant_key)
        if repository:
            repo, _ = storage.get_or_create_repository(repository, organization_id=org.id if org else None, provider=provider)
    owner = org or (storage.get_organization(repo.organization_id) if repo and repo.organization_id else None)
    if tenant_key is not None and (owner is None or owner.tenant_key != tenant_key):
        raise AuthorizationError('Tenant scope does not match')
    if auth is not None and not auth.allows_tenant(owner.tenant_key if owner else None):
        raise AuthorizationError('Asset is outside the authorized tenant scope')
    return org.id if org else repo.organization_id if repo else None, repo.id if repo else None


@dataclass(frozen=True)
class DomainContext:
    domain_id: int
    name: str
    organization_id: int | None
    tenant_key: str | None


def resolve_domain_context(storage, plan):
    scope = {}
    if plan.organization_id is not None:
        scope['organization_id'] = plan.organization_id
    elif plan.tenant_key is not None:
        scope['tenant_key'] = plan.tenant_key
    domain = (storage.get_domain(plan.domain_id) if plan.domain_id is not None
              else storage.get_domain_by_name(plan.target, **scope))
    if plan.domain_id is not None and (domain is None or domain.name != plan.target):
        raise ValueError("Domain identity does not match target")
    organization_id = plan.organization_id if plan.organization_id is not None else domain.organization_id if domain else None
    org = storage.get_organization(organization_id) if organization_id is not None else None
    if organization_id is not None and org is None:
        raise AuthorizationError("Organization is not available in this scope")
    if plan.tenant_key is not None and (org is None or org.tenant_key != plan.tenant_key):
        raise AuthorizationError("Domain organization does not match tenant scope")
    if domain is not None and plan.domain_id is not None and domain.organization_id is None and organization_id is not None:
        raise AuthorizationError('Legacy domain associations cannot be claimed through a scan plan')
    if domain is not None and domain.organization_id is not None:
        original = storage.get_organization(domain.organization_id)
        if original is None or org is None or original.tenant_key != org.tenant_key:
            raise AuthorizationError('Domain association does not match tenant scope')
    auth = current_auth.get()
    if auth is not None and not auth.allows_tenant(org.tenant_key if org else None):
        raise AuthorizationError('Domain is outside the authorized tenant scope')
    domain, _ = storage.get_or_create_domain(plan.target, organization_id=organization_id)
    return DomainContext(domain.id, domain.name, domain.organization_id, org.tenant_key if org else None)
