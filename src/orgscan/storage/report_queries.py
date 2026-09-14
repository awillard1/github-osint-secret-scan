"""Report aggregates and bounded detail queries; no full finding materialization."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select, or_, cast, String

from orgscan import models as m


def report_summary(storage, *, tenant_keys=None):
    session = storage.session
    scope = storage.finding_tenant_scope(tenant_keys)
    finding_ids = select(m.Finding.id).where(scope)
    orgs = select(m.Organization.id)
    if tenant_keys is not None:
        orgs = orgs.where(m.Organization.tenant_key.in_(tenant_keys))
    conditions = {m.Organization: m.Organization.id.in_(orgs)}
    for model in (m.Repository, m.Domain, m.Account):
        conditions[model] = model.organization_id.in_(orgs)
    if tenant_keys is None:
        conditions = {}
    conditions[m.Finding] = scope
    conditions[m.Evidence] = m.Evidence.finding_id.in_(finding_ids)
    domains = select(m.Domain.id).where(conditions.get(m.Domain, True))
    for model in (m.DomainExposure, m.IdentityCorrelation):
        conditions[model] = model.domain_id.in_(domains) if tenant_keys is not None else True
    repos = select(m.Repository.id).where(conditions.get(m.Repository, True))
    if tenant_keys is not None:
        plan = m.ScanJob.parameters_json['scan_plan']
        conditions[m.ScanJob] = or_(m.ScanJob.id.in_(select(m.Finding.scan_job_id).where(scope)),
            plan['organization_id'].as_integer().in_(orgs), plan['repository_id'].as_integer().in_(repos),
            (m.ScanJob.target_type == 'domain') & m.ScanJob.target_id.in_(select(cast(m.Domain.id, String)).where(m.Domain.id.in_(domains))))
        conditions[m.ToolRun] = m.ToolRun.scan_job_id.in_(select(m.ScanJob.id).where(conditions[m.ScanJob]))
        metadata = m.ScheduledScan.metadata_json
        conditions[m.ScheduledScan] = or_(metadata['organization_id'].as_integer().in_(orgs),
            metadata['repository_id'].as_integer().in_(repos), metadata['scan_plan']['organization_id'].as_integer().in_(orgs),
            metadata['scan_plan']['domain_id'].as_integer().in_(domains))
        conditions[m.ScheduledReport] = or_(m.ScheduledReport.target_type == 'global',
            (m.ScheduledReport.target_type == 'tenant') & m.ScheduledReport.target_value.in_(tenant_keys))
        entity_conditions = []
        for kind, model in [('organization', m.Organization), ('repository', m.Repository), ('domain', m.Domain), ('account', m.Account)]:
            ids = select(cast(model.id, String)).where(conditions.get(model, True))
            entity_conditions.append((m.Relationship.from_entity_type == kind) & m.Relationship.from_entity_id.in_(ids))
            entity_conditions.append((m.Relationship.to_entity_type == kind) & m.Relationship.to_entity_id.in_(ids))
        conditions[m.Relationship] = or_(*entity_conditions)

    def rows(model, limit=None):
        query = select(model).where(conditions.get(model, True)).order_by(model.id.desc())
        return list(session.scalars(query.limit(limit) if limit is not None else query))

    def count(model, extra=True):
        return session.scalar(select(func.count(model.id)).where(conditions.get(model, True), extra))

    def aggregate(column):
        return dict(session.execute(select(column, func.count(m.Finding.id)).where(scope).group_by(column)).all())

    models = [m.Organization, m.Domain, m.Repository, m.Account, m.ScanJob, m.Finding, m.Evidence,
              m.DomainExposure, m.IdentityCorrelation, m.Relationship, m.ScheduledScan, m.ScheduledReport, m.ToolRun]
    counts = {model.__tablename__: count(model) for model in models}
    counts.update(risk_scores=count(m.Finding, m.Finding.risk_score.is_not(None)), suppressions=0)
    organizations, repositories, accounts = rows(m.Organization), rows(m.Repository), rows(m.Account)
    labels = {('organization', str(o.id)): o.name for o in organizations}
    labels.update({('repository', str(r.id)): r.full_name for r in repositories})
    labels.update({('account', str(a.id)): a.username for a in accounts})
    labels.update({('domain', str(d.id)): d.name for d in rows(m.Domain)})
    graph = {'nodes': [], 'edges': [], 'summary': {}}
    nodes, relations = {}, {}
    for relation in rows(m.Relationship, 200):
        endpoints = []
        for side in ('from', 'to'):
            kind, identity = getattr(relation, side+'_entity_type'), getattr(relation, side+'_entity_id')
            key = f'{kind}:{identity}'
            node = nodes.setdefault(key, dict(id=key, entity_type=kind, entity_id=identity, label=labels.get((kind, identity), identity), degree=0))
            node['degree'] += 1
            endpoints.append(key)
        graph['edges'].append(dict(id=str(relation.id), **{'from': endpoints[0], 'to': endpoints[1]},
            relation_type=relation.relation_type, confidence=relation.confidence, source=relation.source or '', provenance=relation.metadata_json))
        relations[relation.relation_type] = relations.get(relation.relation_type, 0) + 1
    graph['nodes'] = list(nodes.values())
    graph['summary'] = dict(node_count=len(nodes), edge_count=len(graph['edges']), relation_breakdown=relations,
                           entity_breakdown={kind: sum(n['entity_type'] == kind for n in nodes.values()) for kind in sorted({n['entity_type'] for n in nodes.values()})})
    from orgscan.lifecycle import MANAGED_STATES, HIGH_RISK_THRESHOLD
    high = case((m.Finding.severity.in_(['critical', 'high']), 1), else_=0)
    opened = case((m.Finding.status == 'open', 1), else_=0)
    org_label = func.coalesce(m.Organization.name, 'unassigned')
    comparison = session.execute(select(org_label, func.count(m.Finding.id), func.sum(high), func.sum(opened), func.avg(m.Finding.risk_score))
        .select_from(m.Finding).outerjoin(m.Organization, m.Finding.organization_id == m.Organization.id)
        .where(scope).group_by(org_label).order_by(func.count(m.Finding.id).desc(), org_label).limit(10)).all()
    remediation = session.execute(select(m.Finding.category, m.Finding.remediation_hint, func.count(m.Finding.id), func.sum(high), func.sum(opened))
        .where(scope).group_by(m.Finding.category, m.Finding.remediation_hint)
        .order_by(func.sum(high).desc(), func.count(m.Finding.id).desc(), m.Finding.category).limit(10)).all()
    from orgscan.reporting import _default_remediation_hint
    cutoff = (datetime.now(UTC) - timedelta(days=29)).date().isoformat()
    # ISO date cast works with SQLite and PostgreSQL datetime representations.
    day = func.substr(cast(m.Finding.detected_at, String), 1, 10)
    trends = {}
    for date, severity, total in session.execute(select(day, m.Finding.severity, func.count(m.Finding.id))
            .where(scope, day >= cutoff).group_by(day, m.Finding.severity).order_by(day)):
        entry = trends.setdefault(date, dict(date=date, total=0, by_severity={}))
        entry['total'] += total
        entry['by_severity'][severity] = total
    top = session.scalars(select(m.Finding).where(scope).order_by(func.coalesce(m.Finding.risk_score, 0).desc(), m.Finding.detected_at.desc(), m.Finding.id.desc()).limit(10))
    repo_label = func.coalesce(m.Repository.full_name, 'unassigned')
    risky_assets = session.execute(select(repo_label, func.count(m.Finding.id)).select_from(m.Finding)
        .outerjoin(m.Repository, m.Finding.repository_id == m.Repository.id).where(scope).group_by(repo_label)
        .order_by(func.count(m.Finding.id).desc(), repo_label).limit(10)).all()
    return dict(
        counts=counts,
        severity_breakdown=aggregate(m.Finding.severity), category_breakdown=aggregate(m.Finding.category),
        source_tool_breakdown=aggregate(m.Finding.source_tool), workflow_breakdown=aggregate(m.Finding.status),
        lifecycle_breakdown=aggregate(m.Finding.lifecycle_state),
        actionable_high_risk_count=count(m.Finding, m.Finding.lifecycle_state.not_in(MANAGED_STATES) & (m.Finding.risk_score >= HIGH_RISK_THRESHOLD)),
        organizations=[o.name for o in organizations], repositories=[r.full_name for r in repositories], accounts=[a.username for a in accounts],
        domain_exposures=[e.result_summary for e in rows(m.DomainExposure)],
        identity_correlations=[dict(domain_id=c.domain_id, email=c.email, username=c.username, relation_type=c.relation_type) for c in rows(m.IdentityCorrelation)],
        finding_trends=list(trends.values()), relationship_graph=graph,
        organization_comparison=[dict(organization=o, findings=n, critical_high=h, open_findings=op, average_risk_score=round(avg or 0, 1)) for o,n,h,op,avg in comparison],
        remediation_suggestions=[dict(category=c, suggestion=hint or _default_remediation_hint(c), findings=n, critical_high=h, open_findings=op) for c,hint,n,h,op in remediation],
        recent_scan_jobs=[dict(id=j.id, target_type=j.target_type, target_id=j.target_id, scanner_name=j.scanner_name, status=j.status) for j in rows(m.ScanJob, 25)],
        recent_tool_runs=[dict(id=r.id, tool_name=r.tool_name, target=r.target, status=r.status) for r in rows(m.ToolRun, 25)],
        top_risky_findings=[dict(id=f.id, title=f.title, severity=f.severity, confidence=f.confidence, risk_score=f.risk_score or 0, source_tool=f.source_tool, status=f.status) for f in top],
        top_risky_assets=[dict(repository=name, findings=n) for name,n in risky_assets],
        scheduled_scans=[dict(id=s.id, target_type=s.target_type, target_value=s.target_value, scanner_name=s.scanner_name, cadence=s.cadence, enabled=s.enabled) for s in rows(m.ScheduledScan)],
    )
