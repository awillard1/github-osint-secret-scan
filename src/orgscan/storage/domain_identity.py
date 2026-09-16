"""Global name resolution with private, stable tenant association IDs.

Only canonical DNS names enter the shared table. All observations and authorization
continue to reference Domain (the historical tenant association), never its identity.
"""
from contextlib import contextmanager
import re
from sqlalchemy import select, or_
from orgscan import models as m
from orgscan.security_context import AuthorizationError, current_auth

UNSPECIFIED = object()


def normalize_name(value):
    try:
        name = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, AttributeError):
        raise ValueError('Invalid domain identity') from None
    if len(name) > 253 or not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
        raise ValueError('Invalid domain identity')
    return name


def prepare_domain(session, row):
    """Use Core for the identity only; it has no private fields or public browse API."""
    name = normalize_name(row.name)
    org = m.Organization.__table__
    tenant = None
    if row.organization_id is not None:
        owner = session.connection().execute(select(org.c.tenant_key).where(org.c.id == row.organization_id)).first()
        if owner is None:
            raise AuthorizationError('Domain organization is unavailable')
        tenant = owner[0]
    auth = current_auth.get()
    if auth is not None and not auth.allows_tenant(tenant):
        raise AuthorizationError('Domain is outside the authorized tenant scope')
    if row.tenant_key is not None and row.tenant_key != tenant:
        raise AuthorizationError('Domain tenant does not match organization')
    table = m.DomainIdentity.__table__
    connection = session.connection()
    identity = connection.scalar(select(table.c.id).where(table.c.normalized_name == name))
    if identity is None:
        # Both supported backends arbitrate the global-name race atomically.
        # Avoid SQLite SAVEPOINT release accidentally committing an outer read-only
        # transaction before the private association has been inserted.
        if connection.dialect.name == 'sqlite':
            from sqlalchemy.dialects.sqlite import insert
        elif connection.dialect.name == 'postgresql':
            from sqlalchemy.dialects.postgresql import insert
        else:
            raise ValueError('Unsupported domain identity database backend')
        identity = connection.execute(insert(table).values(normalized_name=name)
            .on_conflict_do_nothing(index_elements=['normalized_name']).returning(table.c.id)).scalar_one_or_none()
        if identity is None:
            identity = connection.scalar(select(table.c.id).where(table.c.normalized_name == name))
    if row.identity_id is not None and row.identity_id != identity:
        raise ValueError('Domain identity is immutable')
    row.name, row.identity_id, row.tenant_key = name, identity, tenant


@contextmanager
def domain_scope(storage, context):
    domain = storage.get_domain(context.domain_id)
    auth = current_auth.get()
    if (domain is None or domain.name != normalize_name(context.name)
            or domain.organization_id != context.organization_id or domain.tenant_key != context.tenant_key
            or (auth is not None and not auth.allows_tenant(context.tenant_key))):
        raise AuthorizationError('Provider domain context is outside the tenant association')
    previous = getattr(storage, '_domain_context', None)
    storage._domain_context = context
    try:
        yield
    finally:
        storage._domain_context = previous


def find_domain(storage, name, *, organization_id=UNSPECIFIED, tenant_key=UNSPECIFIED):
    name = normalize_name(name)
    context = getattr(storage, '_domain_context', None)
    if organization_id is UNSPECIFIED and context is not None:
        organization_id = context.organization_id
    query = select(m.Domain).where(m.Domain.name == name)
    if organization_id is not UNSPECIFIED and organization_id is not None:
        owner = storage.get_organization(organization_id)
        if owner is None:
            raise AuthorizationError('Domain organization is unavailable')
        auth = current_auth.get()
        if auth is not None and not auth.allows_tenant(owner.tenant_key):
            raise AuthorizationError('Domain is outside the authorized tenant scope')
        query = query.where(m.Domain.tenant_key == owner.tenant_key)
    elif organization_id is None or context is not None:
        query = query.where(m.Domain.tenant_key.is_(None), m.Domain.organization_id.is_(None))
    if tenant_key is not UNSPECIFIED:
        query = query.where(m.Domain.tenant_key == tenant_key)
    rows = list(storage.session.scalars(query.limit(2)))
    if len(rows) > 1:
        raise ValueError('Domain lookup requires tenant or association context')
    return rows[0] if rows else None


def resolve_domain(storage, name, **kwargs):
    """Resolve in explicit ownership context, without claiming legacy private data."""
    context = getattr(storage, '_domain_context', None)
    if 'organization_id' not in kwargs and context is not None:
        kwargs['organization_id'] = context.organization_id
    organization_id = kwargs.get('organization_id')
    if 'organization_id' not in kwargs and context is None:
        owned = storage.session.scalar(select(m.Domain.id).where(
            m.Domain.name == normalize_name(name), m.Domain.organization_id.is_not(None)).limit(1))
        if owned is not None:
            raise ValueError('Tenant domain provider execution requires association context')
    existing = find_domain(storage, name, organization_id=organization_id)
    if existing is not None:
        for key, value in kwargs.items():
            # Reuse within a tenant without moving the original organization anchor.
            if key not in ('organization_id', 'identity_id', 'tenant_key', 'name') and value is not None:
                setattr(existing, key, value)
        storage.session.flush()
        return existing, False
    return storage.create_domain(normalize_name(name), **kwargs), True


def validate_organization_domain_anchor(session, organization_id, tenant_key):
    """Changing an organization cannot implicitly transfer its domain associations."""
    table = m.Domain.__table__
    different = table.c.tenant_key.is_not(None) if tenant_key is None else or_(
        table.c.tenant_key.is_(None), table.c.tenant_key != tenant_key)
    if session.connection().scalar(select(table.c.id).where(
            table.c.organization_id == organization_id, different).limit(1)) is not None:
        raise ValueError('Domain tenant associations are immutable; organization reassignment requires reconciliation')
