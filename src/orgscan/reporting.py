from __future__ import annotations

import csv
import html
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from orgscan.config import Settings
from orgscan.repositories import Storage


def _scoped_assets(storage: Storage, tenant_keys: list[str] | None = None) -> dict[str, Any]:
    organizations = list(storage.list_organizations())
    if tenant_keys is not None:
        organizations = [org for org in organizations if org.tenant_key in tenant_keys]
    organization_ids = {org.id for org in organizations}

    repositories = [repo for repo in storage.list_repositories() if tenant_keys is None or repo.organization_id in organization_ids]
    repository_ids = {repo.id for repo in repositories}

    domains = [domain for domain in storage.list_domains() if tenant_keys is None or domain.organization_id in organization_ids]
    domain_ids = {domain.id for domain in domains}

    accounts = [account for account in storage.list_accounts() if tenant_keys is None or account.organization_id in organization_ids]
    account_ids = {account.id for account in accounts}

    findings = [
        finding
        for finding in storage.list_findings(limit=None)
        if tenant_keys is None
        or finding.organization_id in organization_ids
        or finding.repository_id in repository_ids
        or finding.domain_id in domain_ids
        or finding.account_id in account_ids
    ]
    finding_ids = {finding.id for finding in findings}
    scan_job_ids = {finding.scan_job_id for finding in findings if finding.scan_job_id is not None}

    domain_exposures = [
        exposure for exposure in storage.list_domain_exposures(limit=None) if tenant_keys is None or exposure.domain_id in domain_ids
    ]
    identity_correlations = [
        correlation
        for correlation in storage.list_identity_correlations()
        if tenant_keys is None or correlation.domain_id in domain_ids
    ]

    relationships = list(storage.list_relationships(limit=None))
    if tenant_keys is not None:
        allowed_ids = {
            'organization': {str(value) for value in organization_ids},
            'repository': {str(value) for value in repository_ids},
            'domain': {str(value) for value in domain_ids},
            'account': {str(value) for value in account_ids},
        }
        relationships = [
            relationship
            for relationship in relationships
            if relationship.from_entity_id in allowed_ids.get(relationship.from_entity_type, set())
            or relationship.to_entity_id in allowed_ids.get(relationship.to_entity_type, set())
        ]

    scan_jobs = [job for job in storage.list_scan_jobs(limit=None) if tenant_keys is None or job.id in scan_job_ids]
    tool_runs = [run for run in storage.list_tool_runs(limit=None) if tenant_keys is None or run.scan_job_id in scan_job_ids]
    scheduled_scans = [
        scheduled
        for scheduled in storage.list_scheduled_scans()
        if tenant_keys is None
        or (scheduled.metadata_json or {}).get('organization_id') in organization_ids
        or (scheduled.metadata_json or {}).get('repository_id') in repository_ids
    ]
    scheduled_reports = [
        scheduled
        for scheduled in storage.list_scheduled_reports()
        if tenant_keys is None
        or scheduled.target_type == "global"
        or (scheduled.target_type == "tenant" and scheduled.target_value in tenant_keys)
    ]

    return {
        'organizations': organizations,
        'organization_ids': organization_ids,
        'repositories': repositories,
        'repository_ids': repository_ids,
        'domains': domains,
        'domain_ids': domain_ids,
        'accounts': accounts,
        'account_ids': account_ids,
        'findings': findings,
        'finding_ids': finding_ids,
        'scan_jobs': scan_jobs,
        'scan_job_ids': scan_job_ids,
        'tool_runs': tool_runs,
        'scheduled_scans': scheduled_scans,
        'scheduled_reports': scheduled_reports,
        'domain_exposures': domain_exposures,
        'identity_correlations': identity_correlations,
        'relationships': relationships,
    }


def _filtered_findings(
    storage: Storage,
    *,
    tenant_keys: list[str] | None = None,
    status: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
) -> list[Any]:
    findings = list(_scoped_assets(storage, tenant_keys)['findings'])
    if status:
        findings = [finding for finding in findings if finding.status == status]
    if category:
        findings = [finding for finding in findings if finding.category == category]
    if severity:
        findings = [finding for finding in findings if finding.severity == severity]
    if confidence:
        findings = [finding for finding in findings if finding.confidence == confidence]
    return findings


def build_summary(storage: Storage, *, tenant_keys: list[str] | None = None) -> dict[str, Any]:
    scope = _scoped_assets(storage, tenant_keys)
    findings = list(scope['findings'])
    severity_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}
    source_tool_breakdown: dict[str, int] = {}
    workflow_breakdown: dict[str, int] = {}
    evidence_count = 0
    risk_score_count = 0
    for finding in findings:
        severity_breakdown[finding.severity] = severity_breakdown.get(finding.severity, 0) + 1
        category_breakdown[finding.category] = category_breakdown.get(finding.category, 0) + 1
        source_tool_breakdown[finding.source_tool] = source_tool_breakdown.get(finding.source_tool, 0) + 1
        workflow_breakdown[finding.status] = workflow_breakdown.get(finding.status, 0) + 1
        evidence_count += len(finding.evidence_items)
        if finding.risk_score is not None:
            risk_score_count += 1

    top_risky_findings = sorted(
        findings,
        key=lambda finding: (finding.risk_score or 0, finding.detected_at, finding.id),
        reverse=True,
    )[:10]

    repository_names = {repo.id: repo.full_name for repo in scope['repositories']}
    repository_counts: dict[str, int] = {}
    for finding in findings:
        label = repository_names.get(finding.repository_id, 'unassigned')
        repository_counts[label] = repository_counts.get(label, 0) + 1
    repository_breakdown = sorted(repository_counts.items(), key=lambda item: (-item[1], item[0]))[:10]

    trends = finding_trends(storage, days=30, tenant_keys=tenant_keys)
    graph = relationship_graph(storage, limit=200, tenant_keys=tenant_keys)
    comparison = organization_comparison(storage, limit=10, tenant_keys=tenant_keys)
    suggestions = remediation_suggestions(storage, limit=10, tenant_keys=tenant_keys)

    return {
        'counts': {
            'organizations': len(scope['organizations']),
            'domains': len(scope['domains']),
            'repositories': len(scope['repositories']),
            'accounts': len(scope['accounts']),
            'scan_jobs': len(scope['scan_jobs']),
            'findings': len(findings),
            'evidence': evidence_count,
            'domain_exposures': len(scope['domain_exposures']),
            'identity_correlations': len(scope['identity_correlations']),
            'relationships': len(scope['relationships']),
            'risk_scores': risk_score_count,
            'scheduled_scans': len(scope['scheduled_scans']),
            'scheduled_reports': len(scope['scheduled_reports']),
            'suppressions': 0,
            'tool_runs': len(scope['tool_runs']),
        },
        'severity_breakdown': severity_breakdown,
        'category_breakdown': category_breakdown,
        'source_tool_breakdown': source_tool_breakdown,
        'workflow_breakdown': workflow_breakdown,
        'organizations': [org.name for org in scope['organizations']],
        'repositories': [repo.full_name for repo in scope['repositories']],
        'accounts': [account.username for account in scope['accounts']],
        'domain_exposures': [exposure.result_summary for exposure in scope['domain_exposures']],
        'finding_trends': trends,
        'relationship_graph': graph,
        'organization_comparison': comparison,
        'remediation_suggestions': suggestions,
        'identity_correlations': [
            {
                'domain_id': correlation.domain_id,
                'email': correlation.email,
                'username': correlation.username,
                'relation_type': correlation.relation_type,
            }
            for correlation in scope['identity_correlations']
        ],
        'recent_scan_jobs': [
            {
                'id': job.id,
                'target_type': job.target_type,
                'target_id': job.target_id,
                'scanner_name': job.scanner_name,
                'status': job.status,
            }
            for job in scope['scan_jobs'][:25]
        ],
        'recent_tool_runs': [
            {
                'id': run.id,
                'tool_name': run.tool_name,
                'target': run.target,
                'status': run.status,
            }
            for run in scope['tool_runs'][:25]
        ],
        'top_risky_findings': [
            {
                'id': finding.id,
                'title': finding.title,
                'severity': finding.severity,
                'confidence': finding.confidence,
                'risk_score': finding.risk_score or 0,
                'source_tool': finding.source_tool,
                'status': finding.status,
            }
            for finding in top_risky_findings
        ],
        'top_risky_assets': [
            {'repository': repository_name, 'findings': count}
            for repository_name, count in repository_breakdown
        ],
        'scheduled_scans': [
            {
                'id': scan.id,
                'target_type': scan.target_type,
                'target_value': scan.target_value,
                'scanner_name': scan.scanner_name,
                'cadence': scan.cadence,
                'enabled': scan.enabled,
            }
            for scan in scope['scheduled_scans']
        ],
    }


def finding_rows(
    storage: Storage,
    limit: int = 500,
    *,
    tenant_keys: list[str] | None = None,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    confidence: str | None = None,
) -> list[dict[str, Any]]:
    return [
        {
            'id': finding.id,
            'title': finding.title,
            'description': finding.description,
            'category': finding.category,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'status': finding.status,
            'triage_state': finding.triage_state,
            'triage_owner': finding.triage_owner,
            'triage_notes': finding.triage_notes,
            'remediation_due_date': finding.remediation_due_date.isoformat() if finding.remediation_due_date else None,
            'source_tool': finding.source_tool,
            'source_name': finding.source_name,
            'repository_id': finding.repository_id,
            'scan_job_id': finding.scan_job_id,
            'detected_at': finding.detected_at.isoformat(),
            'fingerprint': finding.fingerprint,
        }
        for finding in _filtered_findings(
            storage,
            tenant_keys=tenant_keys,
            status=status,
            severity=severity,
            category=category,
            confidence=confidence,
        )[:limit]
    ]


def finding_trends(storage: Storage, days: int = 30, *, tenant_keys: list[str] | None = None) -> list[dict[str, Any]]:
    cutoff_date = (datetime.now(UTC) - timedelta(days=max(days, 1) - 1)).date()
    series: dict[str, dict[str, Any]] = {}
    for finding in _filtered_findings(storage, tenant_keys=tenant_keys):
        detected_date = finding.detected_at.date()
        if detected_date < cutoff_date:
            continue
        day = detected_date.isoformat()
        entry = series.setdefault(day, {'date': day, 'total': 0, 'by_severity': {}})
        entry['total'] += 1
        entry['by_severity'][finding.severity] = entry['by_severity'].get(finding.severity, 0) + 1
    return [series[day] for day in sorted(series)]


def relationship_graph(storage: Storage, limit: int = 200, *, tenant_keys: list[str] | None = None) -> dict[str, Any]:
    scope = _scoped_assets(storage, tenant_keys)
    relationships = list(scope['relationships'])[:limit]
    repositories = {str(repo.id): repo.full_name for repo in scope['repositories']}
    organizations = {str(org.id): org.name for org in scope['organizations']}
    accounts = {str(account.id): account.username for account in scope['accounts']}
    domain_names = {str(domain.id): domain.name for domain in scope['domains']}

    nodes: dict[tuple[str, str], dict[str, str]] = {}
    degrees: dict[str, int] = {}
    relation_breakdown: dict[str, int] = {}

    def resolve_label(entity_type: str, entity_id: str) -> str:
        if entity_type == 'repository':
            return repositories.get(entity_id, f'repository:{entity_id}')
        if entity_type == 'organization':
            return organizations.get(entity_id, f'organization:{entity_id}')
        if entity_type == 'account':
            return accounts.get(entity_id, f'account:{entity_id}')
        if entity_type == 'domain':
            return domain_names.get(entity_id) or f'domain:{entity_id}'
        return f'{entity_type}:{entity_id}'

    edges: list[dict[str, str]] = []
    for relationship in relationships:
        from_key = (relationship.from_entity_type, relationship.from_entity_id)
        to_key = (relationship.to_entity_type, relationship.to_entity_id)
        nodes.setdefault(
            from_key,
            {
                'id': f'{relationship.from_entity_type}:{relationship.from_entity_id}',
                'entity_type': relationship.from_entity_type,
                'entity_id': relationship.from_entity_id,
                'label': resolve_label(relationship.from_entity_type, relationship.from_entity_id),
            },
        )
        nodes.setdefault(
            to_key,
            {
                'id': f'{relationship.to_entity_type}:{relationship.to_entity_id}',
                'entity_type': relationship.to_entity_type,
                'entity_id': relationship.to_entity_id,
                'label': resolve_label(relationship.to_entity_type, relationship.to_entity_id),
            },
        )
        edges.append(
            {
                'id': str(relationship.id),
                'from': f'{relationship.from_entity_type}:{relationship.from_entity_id}',
                'to': f'{relationship.to_entity_type}:{relationship.to_entity_id}',
                'relation_type': relationship.relation_type,
                'confidence': relationship.confidence,
                'source': relationship.source or '',
            }
        )
        from_id = f'{relationship.from_entity_type}:{relationship.from_entity_id}'
        to_id = f'{relationship.to_entity_type}:{relationship.to_entity_id}'
        degrees[from_id] = degrees.get(from_id, 0) + 1
        degrees[to_id] = degrees.get(to_id, 0) + 1
        relation_breakdown[relationship.relation_type] = relation_breakdown.get(relationship.relation_type, 0) + 1

    for node in nodes.values():
        node['degree'] = str(degrees.get(node['id'], 0))

    return {
        'nodes': list(nodes.values()),
        'edges': edges,
        'summary': {
            'node_count': len(nodes),
            'edge_count': len(edges),
            'relation_breakdown': relation_breakdown,
            'entity_breakdown': {
                entity_type: sum(1 for node in nodes.values() if node['entity_type'] == entity_type)
                for entity_type in sorted({node['entity_type'] for node in nodes.values()})
            },
        },
    }


def organization_comparison(storage: Storage, limit: int = 10, *, tenant_keys: list[str] | None = None) -> list[dict[str, Any]]:
    findings = _filtered_findings(storage, tenant_keys=tenant_keys)
    organizations = {org.id: org.name for org in storage.list_organizations()}
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        label = organizations.get(finding.organization_id or -1, 'unassigned')
        entry = grouped.setdefault(
            label,
            {'organization': label, 'findings': 0, 'critical_high': 0, 'open_findings': 0, 'average_risk_score': 0.0, '_risk_values': []},
        )
        entry['findings'] += 1
        if finding.severity in {'critical', 'high'}:
            entry['critical_high'] += 1
        if finding.status == 'open':
            entry['open_findings'] += 1
        if finding.risk_score is not None:
            entry['_risk_values'].append(float(finding.risk_score))
    rows = []
    for entry in grouped.values():
        risk_values = entry.pop('_risk_values')
        entry['average_risk_score'] = round(sum(risk_values) / len(risk_values), 1) if risk_values else 0.0
        rows.append(entry)
    rows.sort(key=lambda item: (-int(item['findings']), str(item['organization'])))
    return rows[:limit]


def remediation_suggestions(storage: Storage, limit: int = 10, *, tenant_keys: list[str] | None = None) -> list[dict[str, Any]]:
    findings = _filtered_findings(storage, tenant_keys=tenant_keys)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        hint = finding.remediation_hint or _default_remediation_hint(finding.category)
        key = (finding.category, hint)
        entry = grouped.setdefault(
            key,
            {
                'category': finding.category,
                'suggestion': hint,
                'findings': 0,
                'critical_high': 0,
                'open_findings': 0,
            },
        )
        entry['findings'] += 1
        if finding.severity in {'critical', 'high'}:
            entry['critical_high'] += 1
        if finding.status == 'open':
            entry['open_findings'] += 1
    suggestions = list(grouped.values())
    suggestions.sort(key=lambda item: (-int(item['critical_high']), -int(item['findings']), str(item['category'])))
    return suggestions[:limit]


def _default_remediation_hint(category: str) -> str:
    if category == 'secret':
        return 'Rotate exposed credentials, remove them from source control, and move them into managed secret storage.'
    if category in {'governance', 'supply-chain', 'code-policy'}:
        return 'Tighten repository governance and workflow controls, then verify that risky configuration paths are minimized.'
    if category in {'infrastructure-exposure', 'domain-exposure', 'org-exposure'}:
        return 'Reduce publicly exposed internal identifiers, hosts, and environment references where they are not required.'
    return 'Review the finding, validate impact, and track a remediation action with ownership and due date.'


def write_json(output_path: Path, payload: Any) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return output_path


def write_csv(output_path: Path, rows: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else ['id', 'title', 'category', 'severity', 'confidence', 'status']
    with output_path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def write_export(output_path: Path, export_format: str, summary: dict[str, Any], rows: list[dict[str, Any]]) -> Path:
    normalized = export_format.lower()
    if normalized == "json":
        return write_json(output_path, {"summary": summary, "findings": rows})
    if normalized == "csv":
        return write_csv(output_path, rows)
    if normalized == "pdf":
        return write_pdf(output_path, summary, rows)
    return write_html(output_path, summary, rows)


def scheduled_reports_directory(settings: Settings) -> Path:
    path = settings.ensure_data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def scheduled_report_output_path(settings: Settings, *, schedule_id: int, export_format: str, configured_path: str | None = None) -> Path:
    if configured_path:
        return Path(configured_path)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    extension = export_format.lower()
    return scheduled_reports_directory(settings) / f"scheduled-report-{schedule_id}-{timestamp}.{extension}"


def deliver_report_webhook(
    webhook_url: str,
    *,
    timeout: int,
    payload: dict[str, Any],
) -> None:
    request = Request(
        webhook_url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "orgscan/0.1.0",
        },
    )
    try:
        with urlopen(request, timeout=timeout):
            return
    except HTTPError as exc:
        raise RuntimeError(f"alert delivery failed with status {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"alert delivery failed: {exc.reason}") from exc


def render_dashboard_html(
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    trends: list[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
    filters: dict[str, Any] | None = None,
    live: bool = False,
) -> str:
    def items(mapping: dict[str, Any]) -> str:
        return "".join(f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>" for key, value in mapping.items())

    def list_items(values: list[str]) -> str:
        return "".join(f"<li>{html.escape(value)}</li>" for value in values) or "<li>None</li>"

    def severity_items(values: dict[str, Any]) -> str:
        return ", ".join(f"{html.escape(str(key))}={html.escape(str(value))}" for key, value in values.items()) or "none"

    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['id']))}</td>"
        f"<td>{html.escape(str(row['title']))}</td>"
        f"<td>{html.escape(str(row['category']))}</td>"
        f"<td>{html.escape(str(row['severity']))}</td>"
        f"<td>{html.escape(str(row['confidence']))}</td>"
        f"<td>{html.escape(str(row['status']))}</td>"
        "</tr>"
        for row in findings
    )
    top_findings = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['id']))}</td>"
        f"<td>{html.escape(str(row['title']))}</td>"
        f"<td>{html.escape(str(row['source_tool']))}</td>"
        f"<td>{html.escape(str(row['risk_score']))}</td>"
        f"<td>{html.escape(str(row['status']))}</td>"
        "</tr>"
        for row in summary["top_risky_findings"]
    )
    risky_assets = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['repository']))}</td>"
        f"<td>{html.escape(str(row['findings']))}</td>"
        "</tr>"
        for row in summary["top_risky_assets"]
    )
    trend_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['date']))}</td>"
        f"<td>{html.escape(str(row['total']))}</td>"
        f"<td>{severity_items(row['by_severity'])}</td>"
        "</tr>"
        for row in (trends or [])
    ) or "<tr><td colspan='3'>No recent findings</td></tr>"
    edge_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(edge['from']))}</td>"
        f"<td>{html.escape(str(edge['relation_type']))}</td>"
        f"<td>{html.escape(str(edge['to']))}</td>"
        f"<td>{html.escape(str(edge['confidence']))}</td>"
        "</tr>"
        for edge in (graph or {}).get("edges", [])
    ) or "<tr><td colspan='4'>No relationships</td></tr>"
    graph_summary = (graph or {}).get("summary", {})
    graph_nodes = graph_summary.get("node_count", len((graph or {}).get("nodes", [])))
    graph_edges = graph_summary.get("edge_count", len((graph or {}).get("edges", [])))
    comparison_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['organization']))}</td>"
        f"<td>{html.escape(str(row['findings']))}</td>"
        f"<td>{html.escape(str(row['critical_high']))}</td>"
        f"<td>{html.escape(str(row['open_findings']))}</td>"
        f"<td>{html.escape(str(row['average_risk_score']))}</td>"
        "</tr>"
        for row in summary.get("organization_comparison", [])
    ) or "<tr><td colspan='5'>No organization comparison data</td></tr>"
    remediation_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['category']))}</td>"
        f"<td>{html.escape(str(row['findings']))}</td>"
        f"<td>{html.escape(str(row['critical_high']))}</td>"
        f"<td>{html.escape(str(row['open_findings']))}</td>"
        f"<td>{html.escape(str(row['suggestion']))}</td>"
        "</tr>"
        for row in summary.get("remediation_suggestions", [])
    ) or "<tr><td colspan='5'>No remediation suggestions</td></tr>"
    identity_labels = [
        f"{item['username'] or 'unknown'} / {item['email'] or 'unknown'} ({item['relation_type']})"
        for item in summary["identity_correlations"]
    ]
    trend_json = json.dumps(trends or []).replace("</", "<\\/")
    graph_json = json.dumps(graph or {}).replace("</", "<\\/")
    live_header = """
    <section>
      <h2>Live filters</h2>
      <form method="get" action="/dashboard" class="filters">
        <label>Status <input type="text" name="status" value="{status}"></label>
        <label>Severity <input type="text" name="severity" value="{severity}"></label>
        <label>Category <input type="text" name="category" value="{category}"></label>
        <label>Confidence <input type="text" name="confidence" value="{confidence}"></label>
        <label>Limit <input type="number" min="1" max="500" name="limit" value="{limit}"></label>
        <label>Trend days <input type="number" min="1" max="365" name="days" value="{days}"></label>
        <button type="submit">Refresh</button>
      </form>
      <p><a href="/summary">summary json</a> · <a href="/findings?limit={limit}">findings json</a> · <a href="/relationships/graph">graph json</a> · <a href="/trends/findings?days={days}">trends json</a></p>
    </section>
    """.format(
        status=html.escape(str((filters or {}).get("status", ""))),
        severity=html.escape(str((filters or {}).get("severity", ""))),
        category=html.escape(str((filters or {}).get("category", ""))),
        confidence=html.escape(str((filters or {}).get("confidence", ""))),
        limit=html.escape(str((filters or {}).get("limit", 100))),
        days=html.escape(str((filters or {}).get("days", 30))),
    ) if live else ""
    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>orgscan dashboard</title>
    <style>
      body {{ font-family: sans-serif; margin: 2rem; background: #f8fafc; color: #0f172a; }}
      .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.5rem; }}
      .hero {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
      .card, section {{ background: white; border: 1px solid #dbe3ef; border-radius: 12px; padding: 1rem; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06); }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #dbe3ef; padding: 0.5rem; text-align: left; }}
      th {{ background: #eff6ff; }}
      h1, h2, h3 {{ margin-top: 0; }}
      .filters {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.75rem; align-items: end; }}
      label {{ display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.95rem; }}
      input {{ padding: 0.45rem; border: 1px solid #cbd5e1; border-radius: 8px; }}
      button {{ padding: 0.6rem 1rem; border: 0; border-radius: 8px; background: #2563eb; color: white; cursor: pointer; }}
      .chart-shell {{ display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .chart-card {{ border: 1px solid #dbe3ef; border-radius: 12px; padding: 0.75rem; background: #f8fbff; }}
      .bar-row {{ display: grid; grid-template-columns: 7rem 1fr 3rem; gap: 0.75rem; align-items: center; margin: 0.35rem 0; }}
      .bar {{ height: 0.9rem; border-radius: 999px; background: linear-gradient(90deg, #2563eb, #60a5fa); }}
      .graph-canvas {{ width: 100%; min-height: 420px; border: 1px solid #dbe3ef; border-radius: 12px; background: linear-gradient(180deg, #ffffff, #f8fbff); }}
      .graph-legend {{ display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.9rem; color: #334155; }}
      .muted {{ color: #475569; font-size: 0.95rem; }}
      @media (max-width: 900px) {{
        body {{ margin: 1rem; }}
        .grid, .hero, .filters, .chart-shell {{ grid-template-columns: 1fr; }}
        table {{ display: block; overflow-x: auto; }}
      }}
    </style>
  </head>
  <body>
    <h1>orgscan dashboard</h1>
    {live_header}
    <div class=\"hero\">
      <div class=\"card\"><h3>Findings</h3><p>{html.escape(str(summary['counts'].get('findings', 0)))}</p></div>
      <div class=\"card\"><h3>Repositories</h3><p>{html.escape(str(summary['counts'].get('repositories', 0)))}</p></div>
      <div class=\"card\"><h3>Domains</h3><p>{html.escape(str(summary['counts'].get('domains', 0)))}</p></div>
      <div class=\"card\"><h3>Scheduled scans</h3><p>{html.escape(str(summary['counts'].get('scheduled_scans', 0)))}</p></div>
    </div>
    <div class=\"grid\">
      <section>
        <h2>Entity counts</h2>
        <ul>{items(summary['counts'])}</ul>
      </section>
      <section>
        <h2>Severity breakdown</h2>
        <ul>{items(summary['severity_breakdown'])}</ul>
      </section>
      <section>
        <h2>Category breakdown</h2>
        <ul>{items(summary['category_breakdown'])}</ul>
      </section>
      <section>
        <h2>Organizations</h2>
        <ul>{list_items(summary['organizations'])}</ul>
      </section>
      <section>
        <h2>Source tools</h2>
        <ul>{items(summary['source_tool_breakdown'])}</ul>
      </section>
      <section>
        <h2>Workflow status</h2>
        <ul>{items(summary['workflow_breakdown'])}</ul>
      </section>
    </div>
    <section>
      <h2>Top risky assets</h2>
      <table>
        <thead>
          <tr><th>Repository</th><th>Finding count</th></tr>
        </thead>
        <tbody>{risky_assets}</tbody>
      </table>
    </section>
    <section>
      <h2>Finding trends</h2>
      <div class="chart-card">
        <h3>Client-side trend chart</h3>
        <div id="trend-chart"></div>
      </div>
      <table>
        <thead>
          <tr><th>Date</th><th>Total findings</th><th>Severity mix</th></tr>
        </thead>
        <tbody>{trend_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Relationship graph explorer</h2>
      <p>Nodes: {html.escape(str(graph_nodes))} · Edges: {html.escape(str(graph_edges))}</p>
      <div class="graph-legend" id="graph-summary"></div>
      <svg id="graph-canvas" class="graph-canvas" viewBox="0 0 900 420" role="img" aria-label="Relationship graph visualization"></svg>
      <table>
        <thead>
          <tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr>
        </thead>
        <tbody>{edge_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Top risky findings</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Tool</th><th>Risk score</th><th>Status</th></tr>
        </thead>
        <tbody>{top_findings}</tbody>
      </table>
    </section>
    <section>
      <h2>Organization comparison</h2>
      <table>
        <thead>
          <tr><th>Organization</th><th>Findings</th><th>Critical/High</th><th>Open</th><th>Average risk</th></tr>
        </thead>
        <tbody>{comparison_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Automatic remediation suggestions</h2>
      <table>
        <thead>
          <tr><th>Category</th><th>Findings</th><th>Critical/High</th><th>Open</th><th>Suggested action</th></tr>
        </thead>
        <tbody>{remediation_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Recent findings</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Status</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    <div class=\"grid\">
      <section>
        <h2>Domain exposures</h2>
        <ul>{list_items(summary['domain_exposures'])}</ul>
      </section>
      <section>
        <h2>Identity correlations</h2>
        <ul>{list_items(identity_labels)}</ul>
      </section>
    </div>
    <script id="trend-data" type="application/json">{trend_json}</script>
    <script id="graph-data" type="application/json">{graph_json}</script>
    <script>
      const trendData = JSON.parse(document.getElementById("trend-data").textContent || "[]");
      const graphData = JSON.parse(document.getElementById("graph-data").textContent || "{{}}");
      const trendChart = document.getElementById("trend-chart");
      const maxTrend = Math.max(1, ...trendData.map((item) => Number(item.total || 0)));
      trendChart.innerHTML = trendData.map((item) => {{
        const width = Math.max(4, Math.round((Number(item.total || 0) / maxTrend) * 100));
        return `<div class="bar-row"><span>${{item.date}}</span><div class="bar" style="width:${{width}}%"></div><strong>${{item.total}}</strong></div>`;
      }}).join("") || "<p class='muted'>No trend data available.</p>";

      const graphSummary = document.getElementById("graph-summary");
      const relationBreakdown = (graphData.summary && graphData.summary.relation_breakdown) || {{}};
      graphSummary.innerHTML = Object.entries(relationBreakdown).map(([key, value]) => `<span><strong>${{key}}</strong>: ${{value}}</span>`).join("") || "<span>No graph relationships</span>";

      const svg = document.getElementById("graph-canvas");
      const nodes = graphData.nodes || [];
      const edges = graphData.edges || [];
      const width = 900;
      const height = 420;
      const radius = Math.min(width, height) / 2 - 48;
      const centerX = width / 2;
      const centerY = height / 2;
      const positioned = nodes.map((node, index) => {{
        const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1);
        return {{
          ...node,
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
        }};
      }});
      const byId = Object.fromEntries(positioned.map((node) => [node.id, node]));
      const edgeSvg = edges.map((edge) => {{
        const start = byId[edge.from];
        const end = byId[edge.to];
        if (!start || !end) return "";
        return `<line x1="${{start.x}}" y1="${{start.y}}" x2="${{end.x}}" y2="${{end.y}}" stroke="#94a3b8" stroke-width="1.5" />`;
      }}).join("");
      const nodeSvg = positioned.map((node) => {{
        const fill = node.entity_type === "organization" ? "#1d4ed8" : node.entity_type === "repository" ? "#0f766e" : node.entity_type === "domain" ? "#7c3aed" : "#475569";
        return `<g><circle cx="${{node.x}}" cy="${{node.y}}" r="18" fill="${{fill}}" opacity="0.9" /><title>${{node.label}} (degree=${{node.degree || 0}})</title><text x="${{node.x}}" y="${{node.y + 34}}" text-anchor="middle" font-size="11" fill="#0f172a">${{node.label}}</text></g>`;
      }}).join("");
      svg.innerHTML = edgeSvg + nodeSvg;
    </script>
  </body>
</html>
"""


def write_html(output_path: Path, summary: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_dashboard_html(
            summary,
            findings,
            trends=summary.get("finding_trends"),
            graph=summary.get("relationship_graph"),
        ),
        encoding="utf-8",
    )
    return output_path


def write_pdf(output_path: Path, summary: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf = canvas.Canvas(str(output_path), pagesize=letter)
    width, height = letter
    y = height - 40

    def line(text: str, *, indent: int = 0) -> None:
        nonlocal y
        if y < 50:
            pdf.showPage()
            y = height - 40
        pdf.drawString(40 + indent, y, text[:110])
        y -= 14

    pdf.setTitle("orgscan report")
    pdf.setFont("Helvetica-Bold", 16)
    line("orgscan report")
    pdf.setFont("Helvetica", 10)
    line("")
    line("Counts")
    for key, value in summary.get("counts", {}).items():
        line(f"{key}: {value}", indent=12)
    line("")
    line("Organization comparison")
    for row in summary.get("organization_comparison", []):
        line(
            f"{row['organization']}: findings={row['findings']} critical_high={row['critical_high']} "
            f"open={row['open_findings']} avg_risk={row['average_risk_score']}",
            indent=12,
        )
    line("")
    line("Remediation suggestions")
    for row in summary.get("remediation_suggestions", []):
        line(f"{row['category']}: {row['suggestion']}", indent=12)
    line("")
    line("Recent findings")
    for finding in findings[:30]:
        line(f"#{finding['id']} [{finding['severity']}] {finding['title']}", indent=12)

    pdf.save()
    return output_path
