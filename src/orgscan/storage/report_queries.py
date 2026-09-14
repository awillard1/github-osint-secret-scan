"""Report aggregates and bounded detail queries; no full finding materialization."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select, cast, String

from orgscan import models as m


def report_summary(storage, *, tenant_keys=None, source_context=None):
    from orgscan.reports.projection import safe_report_projection, MAX_CONTEXT_ROWS
    from orgscan.storage.credential_context import build_report_context
    session = storage.session
    scope = storage.finding_tenant_scope(tenant_keys)
    from orgscan.storage.visibility import visibility_ids
    conditions = {} if tenant_keys is None else {model: model.id.in_(ids) for model, ids in visibility_ids(tenant_keys).items()}
    conditions[m.Finding] = scope

    def rows(model, limit=200):
        query = select(model).where(conditions.get(model, True)).order_by(model.id.desc())
        result = list(session.scalars(query.limit(limit) if limit is not None else query))
        return result

    def count(model, extra=True):
        return session.scalar(select(func.count(model.id)).where(conditions.get(model, True), extra))

    def aggregate(column):
        return dict(session.execute(select(column, func.count(m.Finding.id)).where(scope).group_by(column).order_by(func.count(m.Finding.id).desc(), column).limit(200)).all())

    models = [m.Organization, m.Domain, m.Repository, m.Account, m.ScanJob, m.Finding, m.Evidence,
              m.DomainExposure, m.IdentityCorrelation, m.Relationship, m.ScheduledScan, m.ScheduledReport, m.ToolRun]
    counts = {model.__tablename__: count(model) for model in models}
    counts.update(risk_scores=count(m.Finding, m.Finding.risk_score.is_not(None)), suppressions=0)
    organizations, repositories, accounts = rows(m.Organization), rows(m.Repository), rows(m.Account)
    relationships = rows(m.Relationship, 200)
    endpoint_ids = {}
    for relation in relationships:
        for side in ('from', 'to'):
            kind, identity = getattr(relation, side+'_entity_type'), getattr(relation, side+'_entity_id')
            endpoint_ids.setdefault(kind, set()).add(identity)
    labels = {}
    for kind, model, label in (('organization', m.Organization, m.Organization.name),
                               ('repository', m.Repository, m.Repository.full_name),
                               ('account', m.Account, m.Account.username), ('domain', m.Domain, m.Domain.name)):
        if endpoint_ids.get(kind):
            endpoints = list(session.scalars(select(model).where(conditions.get(model, True),
                cast(model.id, String).in_(endpoint_ids[kind]))))
            labels.update({(kind, str(row.id)): getattr(row, label.key) for row in endpoints})
    graph = {'nodes': [], 'edges': [], 'summary': {}}
    nodes, relations = {}, {}
    for relation in relationships:
        endpoints = []
        for side in ('from', 'to'):
            kind, identity = getattr(relation, side+'_entity_type'), getattr(relation, side+'_entity_id')
            key = f'{kind}:{identity}'
            node = nodes.setdefault(key, dict(id=key, entity_type=kind, entity_id=identity, label=labels.get((kind, identity), key), degree=0))
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
    from orgscan.reporting import _default_remediation_hint
    categories = ('secret', 'governance', 'supply-chain', 'code-policy',
                  'infrastructure-exposure', 'domain-exposure', 'org-exposure')
    default_hint = case(*[(m.Finding.category == category, _default_remediation_hint(category))
                          for category in categories], else_=_default_remediation_hint('other'))
    effective_hint = func.coalesce(func.nullif(m.Finding.remediation_hint, ''), default_hint)
    remediation = session.execute(select(m.Finding.category, effective_hint, func.count(m.Finding.id), func.sum(high), func.sum(opened))
        .where(scope).group_by(m.Finding.category, effective_hint)
        .order_by(func.sum(high).desc(), func.count(m.Finding.id).desc(), m.Finding.category, effective_hint).limit(10)).all()
    trends = finding_trends(storage, tenant_keys=tenant_keys)
    top = list(session.scalars(select(m.Finding).where(scope).order_by(func.coalesce(m.Finding.risk_score, 0).desc(), m.Finding.detected_at.desc(), m.Finding.id.desc()).limit(10)))
    repo_label = func.coalesce(m.Repository.full_name, 'unassigned')
    risky_assets = session.execute(select(repo_label, func.count(m.Finding.id)).select_from(m.Finding)
        .outerjoin(m.Repository, m.Finding.repository_id == m.Repository.id).where(scope).group_by(repo_label)
        .order_by(func.count(m.Finding.id).desc(), repo_label).limit(10)).all()
    from orgscan.reports.limits import bounded_summary
    projection = dict(
        counts=counts,
        severity_breakdown=aggregate(m.Finding.severity), category_breakdown=aggregate(m.Finding.category),
        source_tool_breakdown=aggregate(m.Finding.source_tool), workflow_breakdown=aggregate(m.Finding.status),
        lifecycle_breakdown=aggregate(m.Finding.lifecycle_state),
        actionable_high_risk_count=count(m.Finding, m.Finding.lifecycle_state.not_in(MANAGED_STATES) & (m.Finding.risk_score >= HIGH_RISK_THRESHOLD)),
        organizations=[o.name for o in organizations], repositories=[r.full_name for r in repositories], accounts=[a.username for a in accounts],
        domain_exposures=[e.result_summary for e in rows(m.DomainExposure)],
        identity_correlations=[dict(domain_id=c.domain_id, email=c.email, username=c.username, relation_type=c.relation_type) for c in rows(m.IdentityCorrelation)],
        finding_trends=trends, relationship_graph=graph,
        organization_comparison=[dict(organization=o, findings=n, critical_high=h, open_findings=op, average_risk_score=round(avg or 0, 1)) for o,n,h,op,avg in comparison],
        remediation_suggestions=[dict(category=c, suggestion=hint or _default_remediation_hint(c), findings=n, critical_high=h, open_findings=op) for c,hint,n,h,op in remediation],
        recent_scan_jobs=[dict(id=j.id, target_type=j.target_type, target_id=j.target_id, scanner_name=j.scanner_name, status=j.status) for j in rows(m.ScanJob, 25)],
        recent_tool_runs=[dict(id=r.id, tool_name=r.tool_name, target=r.target, status=r.status) for r in rows(m.ToolRun, 25)],
        top_risky_findings=[dict(id=f.id, title=f.title, severity=f.severity, confidence=f.confidence, risk_score=f.risk_score or 0, source_tool=f.source_tool, status=f.status) for f in top],
        top_risky_assets=[dict(repository=name, findings=n) for name,n in risky_assets],
        scheduled_scans=[dict(id=s.id, target_type=s.target_type, target_value=s.target_value, scanner_name=s.scanner_name, cadence=s.cadence, enabled=s.enabled) for s in rows(m.ScheduledScan)],
    )
    context = source_context or build_report_context(storage, tenant_keys=tenant_keys, max_rows=MAX_CONTEXT_ROWS)
    return bounded_summary(safe_report_projection(projection, context))


def finding_trends(storage, *, days=30, tenant_keys=None):
    session = storage.session
    scope = storage.finding_tenant_scope(tenant_keys)
    cutoff = (datetime.now(UTC) - timedelta(days=max(days, 1)-1)).date().isoformat()
    # ISO date cast works with SQLite and PostgreSQL datetime representations.
    day = func.substr(cast(m.Finding.detected_at, String), 1, 10)
    trends = {}
    for date, severity, total in session.execute(select(day, m.Finding.severity, func.count(m.Finding.id))
            .where(scope, day >= cutoff).group_by(day, m.Finding.severity).order_by(day)):
        entry = trends.setdefault(date, dict(date=date, total=0, by_severity={}))
        entry['total'] += total
        entry['by_severity'][severity] = total
    return list(trends.values())
