"""Tenant filtering and write checks for request-owned SQLAlchemy sessions.

Core subqueries describe permitted IDs; ORM loader criteria also protect lazy
relationships, aggregates and detail lookups. Raw trusted CLI/worker sessions
retain their existing behavior. No unfiltered HTTP session is reused for auth.
"""
from sqlalchemy import and_, cast, event, false, or_, select, String
from sqlalchemy.orm import with_loader_criteria

from orgscan import models as m
from orgscan.security_context import AuthorizationError, current_auth, LOCAL_CONTEXT


def _allowed_ids(auth):
    org = m.Organization.__table__
    orgs = select(org.c.id).where(org.c.tenant_key.in_(auth.tenants))
    ids = {m.Organization: orgs}
    for model in (m.Repository, m.Domain, m.Account):
        table = model.__table__
        ids[model] = select(table.c.id).where(table.c.organization_id.in_(orgs))
    finding = m.Finding.__table__
    finding_scope = or_(
        finding.c.organization_id.in_(orgs),
        and_(finding.c.organization_id.is_(None), or_(
            finding.c.repository_id.in_(ids[m.Repository]), finding.c.domain_id.in_(ids[m.Domain]),
            finding.c.account_id.in_(ids[m.Account]),
        )),
    )
    ids[m.Finding] = select(finding.c.id).where(finding_scope)
    job = m.ScanJob.__table__
    plan = job.c.parameters_json["scan_plan"]
    job_scope = or_(
        plan["organization_id"].as_integer().in_(orgs),
        plan["repository_id"].as_integer().in_(ids[m.Repository]),
        job.c.id.in_(select(finding.c.scan_job_id).where(finding_scope)),
    )
    for kind, model in (("organization",m.Organization),("domain",m.Domain),("repository",m.Repository)):
        job_scope = or_(job_scope, and_(job.c.target_type == kind, job.c.target_id.in_(select(cast(ids[model].subquery().c.id,String)))))
    # Do not expose a legacy mixed-tenant job through one permitted finding.
    foreign_jobs = select(finding.c.scan_job_id).where(finding_scope.is_not(True), finding.c.scan_job_id.is_not(None))
    ids[m.ScanJob] = select(job.c.id).where(
        job_scope, job.c.id.not_in(foreign_jobs),
        or_(plan["organization_id"].as_integer().is_(None),plan["organization_id"].as_integer().in_(orgs)),
        or_(plan["repository_id"].as_integer().is_(None),plan["repository_id"].as_integer().in_(ids[m.Repository])),
    )
    for model, column, parent in (
        (m.FindingHistory,"finding_id",m.Finding), (m.Evidence,"finding_id",m.Finding), (m.Suppression,"finding_id",m.Finding),
        (m.ToolRun,"scan_job_id",m.ScanJob), (m.DomainExposure,"domain_id",m.Domain),
        (m.IdentityCorrelation,"domain_id",m.Domain),
    ):
        table = model.__table__
        ids[model] = select(table.c.id).where(table.c[column].in_(ids[parent]))

    def entity_scope(kind, value):
        return or_(*(and_(kind == name, value.in_(select(cast(ids[model].subquery().c.id,String))))
                     for name,model in (("organization",m.Organization),("repository",m.Repository),("domain",m.Domain),("account",m.Account))))

    relationship = m.Relationship.__table__
    ids[m.Relationship] = select(relationship.c.id).where(
        entity_scope(relationship.c.from_entity_type,relationship.c.from_entity_id),
        entity_scope(relationship.c.to_entity_type,relationship.c.to_entity_id),
    )
    risk = m.RiskScore.__table__
    ids[m.RiskScore] = select(risk.c.id).where(or_(
        risk.c.finding_id.in_(ids[m.Finding]),
        and_(risk.c.finding_id.is_(None), entity_scope(risk.c.entity_type,risk.c.entity_id)),
    ))
    scheduled = m.ScheduledScan.__table__
    ids[m.ScheduledScan] = select(scheduled.c.id).where(or_(
        scheduled.c.metadata_json["organization_id"].as_integer().in_(orgs),
        scheduled.c.metadata_json["repository_id"].as_integer().in_(ids[m.Repository]),
        scheduled.c.metadata_json["scan_plan"]["organization_id"].as_integer().in_(orgs),
        scheduled.c.metadata_json["scan_plan"]["repository_id"].as_integer().in_(ids[m.Repository]),
    ))
    report = m.ScheduledReport.__table__
    ids[m.ScheduledReport] = select(report.c.id).where(report.c.target_type == "tenant", report.c.target_value.in_(auth.tenants))
    return ids


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
            if isinstance(record, m.Organization):
                return auth.allows_tenant(record.tenant_key)
            if isinstance(record,(m.Repository,m.Domain,m.Account)):
                return permitted(m.Organization,record.organization_id)
            if isinstance(record,m.Finding):
                references = ((m.Repository,record.repository_id),(m.Domain,record.domain_id),(m.Account,record.account_id))
                if any(identity is not None and not permitted(model,identity) for model,identity in references):
                    return False
                return permitted(m.Organization,record.organization_id) if record.organization_id is not None else any(permitted(model,identity) for model,identity in references)
            if isinstance(record,(m.Evidence,m.Suppression,m.FindingHistory)):
                return permitted(m.Finding,record.finding_id)
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
