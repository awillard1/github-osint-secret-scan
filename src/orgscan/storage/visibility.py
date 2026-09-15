"""Authoritative tenant visibility for HTTP, reports and discovery sources."""
from sqlalchemy import and_, cast, false, or_, select, String
from orgscan import models as m


def visibility_ids(tenant_keys):
    org = m.Organization.__table__
    orgs = select(org.c.id).where(or_(org.c.tenant_key.in_([key for key in tenant_keys if key is not None]), org.c.tenant_key.is_(None) if None in tenant_keys else false()))
    ids = {m.Organization: orgs}
    for model in (m.Repository, m.Domain, m.Account):
        table = model.__table__
        ids[model] = select(table.c.id).where(or_(table.c.organization_id.in_(orgs), table.c.organization_id.is_(None) if None in tenant_keys else false()))
    finding = m.Finding.__table__
    finding_scope = or_(
        finding.c.organization_id.in_(orgs),
        and_(finding.c.organization_id.is_(None), or_(
            finding.c.repository_id.in_(ids[m.Repository]), finding.c.domain_id.in_(ids[m.Domain]),
            finding.c.account_id.in_(ids[m.Account]),
        )),
    )
    ids[m.Finding] = select(finding.c.id).where(finding_scope)
    for model in (m.SecretEvidence, m.SecretRevealAudit):
        table = model.__table__
        ids[model] = select(table.c.id).where(table.c.finding_id.in_(ids[m.Finding]), table.c.tenant_key.in_(tenant_keys))
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
                     for name,model in (("organization",m.Organization),("repository",m.Repository),("domain",m.Domain),("account",m.Account),("finding",m.Finding))))

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
    ids[m.ScheduledReport] = select(report.c.id).where(report.c.target_type == "tenant", report.c.target_value.in_(tenant_keys))
    task = m.QueueTask.__table__
    ids[m.QueueTask] = select(task.c.id).where(task.c.scheduled_scan_id.in_(ids[m.ScheduledScan]))
    for model in (m.Assessment, m.GitHubConnection, m.ReconProfile, m.LocalAIConfiguration):
        table = model.__table__
        ids[model] = select(table.c.id).where(table.c.tenant_key.in_(tenant_keys))
    for model in (m.AssessmentTarget, m.AssessmentEntity, m.AssessmentRun, m.AIAdvice):
        table = model.__table__
        ids[model] = select(table.c.id).where(table.c.assessment_id.in_(ids[m.Assessment]))
    return ids
