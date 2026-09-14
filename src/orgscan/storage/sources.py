"""Read-only tenant-owned source assets for discovery, including legacy providers."""
from contextlib import contextmanager
from sqlalchemy import event, false
from sqlalchemy.orm import Session, with_loader_criteria
from orgscan import models as m
from orgscan.security_context import AuthorizationError, current_auth
from orgscan.storage.visibility import visibility_ids


@contextmanager
def scoped_reader(storage, tenant_keys):
    ids = visibility_ids(tenant_keys)
    # Keep a narrower request scope when a report explicitly requests another scope.
    auth = storage.session.info.get('auth_context') or current_auth.get()
    parent_ids = visibility_ids(auth.tenants) if auth and '*' not in auth.tenants else None
    with Session(storage.session.connection(), autoflush=False, join_transaction_mode="rollback_only") as session:
        options = []
        for mapper in m.Base.registry.mappers:
            model = mapper.class_
            predicate = model.id.in_(ids[model]) if model in ids else false()
            if parent_ids is not None:
                predicate &= model.id.in_(parent_ids[model]) if model in parent_ids else false()
            options.append(with_loader_criteria(model, predicate, include_aliases=True))
        @event.listens_for(session, 'do_orm_execute')
        def scoped(state):
            if not state.is_select or not state.is_orm_statement:
                raise AuthorizationError('Source sessions are read-only and scoped')
            state.statement = state.statement.options(*options)
        @event.listens_for(session, 'before_flush')
        def readonly(*args):
            raise AuthorizationError('Source sessions are read-only')
        from orgscan.repositories import Storage
        yield Storage(session)


@contextmanager
def domain_sources(storage, domain):
    organization = storage.get_organization(domain.organization_id) if domain.organization_id else None
    tenants = (organization.tenant_key if organization else None,)
    with scoped_reader(storage, tenants) as sources:
        yield sources
