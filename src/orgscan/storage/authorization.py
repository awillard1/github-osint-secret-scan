"""Tenant filtering and write checks for request-owned SQLAlchemy sessions.

Core subqueries describe permitted IDs; ORM loader criteria also protect lazy
relationships, aggregates and detail lookups. Raw trusted CLI/worker sessions
retain their existing behavior. No unfiltered HTTP session is reused for auth.
"""
from sqlalchemy import event, false, select
from sqlalchemy.orm import with_loader_criteria

from orgscan import models as m
from orgscan.security_context import AuthorizationError, current_auth, LOCAL_CONTEXT


def _allowed_ids(auth):
    from orgscan.storage.visibility import visibility_ids
    return visibility_ids(auth.tenants)


def authorized_session_factory(factory):
    def create_session():
        session = factory()
        auth = current_auth.get() or LOCAL_CONTEXT
        session.info["auth_context"] = auth
        unrestricted = "*" in auth.tenants
        ids = {} if unrestricted else _allowed_ids(auth)
        options = [] if unrestricted else [
            with_loader_criteria(mapper.class_, mapper.class_.id.in_(ids[mapper.class_]) if mapper.class_ in ids else false(),
                                 include_aliases=True, propagate_to_loaders=False)
            for mapper in m.Base.registry.mappers
        ]

        @event.listens_for(session, "do_orm_execute")
        def constrain(state):
            if not state.is_select:
                raise AuthorizationError("Bulk mutation is not permitted in a request session")
            if not state.is_orm_statement:
                raise AuthorizationError("Unscoped queries are not permitted in a request session")
            if options:
                state.statement = state.statement.options(*options)

        def permitted(model, identity):
            if identity is None or model not in ids:
                return False
            table = model.__table__
            return session.connection().execute(select(table.c.id).where(table.c.id == identity, table.c.id.in_(ids[model]))).first() is not None

        def writable(record):
            if isinstance(record, (m.Assessment, m.GitHubConnection, m.ReconProfile, m.LocalAIConfiguration)):
                return auth.allows_tenant(record.tenant_key)
            if isinstance(record, (m.AssessmentTarget, m.AssessmentEntity, m.AssessmentRun, m.AIAdvice)):
                return permitted(m.Assessment, record.assessment_id)
            if isinstance(record, m.Organization):
                return auth.allows_tenant(record.tenant_key)
            if isinstance(record,(m.Repository,m.Domain,m.Account,m.ReconAsset)):
                return permitted(m.Organization,record.organization_id)
            if isinstance(record,m.Finding):
                references = ((m.Repository,record.repository_id),(m.Domain,record.domain_id),(m.Account,record.account_id))
                if any(identity is not None and not permitted(model,identity) for model,identity in references):
                    return False
                return permitted(m.Organization,record.organization_id) if record.organization_id is not None else any(permitted(model,identity) for model,identity in references)
            if isinstance(record,(m.Evidence,m.Suppression,m.FindingHistory)):
                return permitted(m.Finding,record.finding_id)
            if isinstance(record,(m.SecretEvidence,m.SecretRevealAudit)):
                return auth.allows_tenant(record.tenant_key) and permitted(m.Finding,record.finding_id)
            if isinstance(record,m.ToolRun):
                return permitted(m.ScanJob,record.scan_job_id)
            if isinstance(record,m.RiskScore):
                return permitted(m.Finding,record.finding_id)
            if isinstance(record,m.ScanJob):
                plan = (record.parameters_json or {}).get("scan_plan", {})
                references = ((m.Organization,plan.get("organization_id")),(m.Repository,plan.get("repository_id")))
                if any(identity is not None for _,identity in references):
                    return all(identity is None or permitted(model,identity) for model,identity in references)
                model = {"organization":m.Organization,"repository":m.Repository,"domain":m.Domain}.get(record.target_type)
                return model is not None and str(record.target_id).isdigit() and permitted(model,int(record.target_id))
            return False

        @event.listens_for(session, "before_flush")
        def authorize_changes(session, flush_context, instances):
            changes = set(session.new) | set(session.dirty) | set(session.deleted)
            if changes and not auth.allows_role("analyst"):
                raise AuthorizationError("Analyst role is required for mutations")
            if not unrestricted and any(not writable(record) for record in changes):
                raise AuthorizationError("The requested data is outside the authorized tenant scope")
        return session
    return create_session
