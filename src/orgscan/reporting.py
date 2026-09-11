from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from orgscan.repositories import Storage


def build_summary(storage: Storage) -> dict[str, Any]:
    repositories = {repo.id: repo.full_name for repo in storage.list_repositories()}
    top_risky_findings = list(storage.list_top_risky_findings(limit=10))
    repository_breakdown = storage.finding_counts_by_repository(limit=10)
    trend_rows = finding_trends(storage, days=30)
    graph = relationship_graph(storage, limit=200)

    return {
        "counts": dict(storage.counts()),
        "severity_breakdown": dict(storage.finding_counts_by_severity()),
        "category_breakdown": dict(storage.finding_counts_by_category()),
        "source_tool_breakdown": dict(storage.finding_counts_by_source_tool()),
        "workflow_breakdown": dict(storage.finding_counts_by_status()),
        "organizations": [org.name for org in storage.list_organizations()],
        "repositories": list(repositories.values()),
        "accounts": [account.username for account in storage.list_accounts()],
        "domain_exposures": [exposure.result_summary for exposure in storage.list_domain_exposures()],
        "finding_trends": trend_rows,
        "relationship_graph": graph,
        "identity_correlations": [
            {
                "domain_id": correlation.domain_id,
                "email": correlation.email,
                "username": correlation.username,
                "relation_type": correlation.relation_type,
            }
            for correlation in storage.list_identity_correlations()
        ],
        "recent_scan_jobs": [
            {
                "id": job.id,
                "target_type": job.target_type,
                "target_id": job.target_id,
                "scanner_name": job.scanner_name,
                "status": job.status,
            }
            for job in storage.list_scan_jobs()
        ],
        "recent_tool_runs": [
            {
                "id": run.id,
                "tool_name": run.tool_name,
                "target": run.target,
                "status": run.status,
            }
            for run in storage.list_tool_runs()
        ],
        "top_risky_findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "risk_score": finding.risk_score or 0,
                "source_tool": finding.source_tool,
                "status": finding.status,
            }
            for finding in top_risky_findings
        ],
        "top_risky_assets": [
            {"repository": repository_name, "findings": count}
            for repository_name, count in repository_breakdown
        ],
        "scheduled_scans": [
            {
                "id": scan.id,
                "target_type": scan.target_type,
                "target_value": scan.target_value,
                "scanner_name": scan.scanner_name,
                "cadence": scan.cadence,
                "enabled": scan.enabled,
            }
            for scan in storage.list_scheduled_scans()
        ],
    }


def finding_rows(storage: Storage, limit: int = 500) -> list[dict[str, Any]]:
    return [
        {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "triage_state": finding.triage_state,
            "triage_owner": finding.triage_owner,
            "triage_notes": finding.triage_notes,
            "remediation_due_date": finding.remediation_due_date.isoformat() if finding.remediation_due_date else None,
            "source_tool": finding.source_tool,
            "source_name": finding.source_name,
            "repository_id": finding.repository_id,
            "scan_job_id": finding.scan_job_id,
            "detected_at": finding.detected_at.isoformat(),
            "fingerprint": finding.fingerprint,
        }
        for finding in storage.list_findings(limit=limit)
    ]


def finding_trends(storage: Storage, days: int = 30) -> list[dict[str, Any]]:
    series: dict[str, dict[str, Any]] = {}
    for day, severity, count in storage.finding_trends_by_day(days=days):
        entry = series.setdefault(day, {"date": day, "total": 0, "by_severity": {}})
        entry["total"] += count
        entry["by_severity"][severity] = count
    return [series[day] for day in sorted(series)]


def relationship_graph(storage: Storage, limit: int = 200) -> dict[str, Any]:
    relationships = storage.list_relationships(limit=limit)
    repositories = {str(repo.id): repo.full_name for repo in storage.list_repositories()}
    organizations = {str(org.id): org.name for org in storage.list_organizations()}
    accounts = {str(account.id): account.username for account in storage.list_accounts()}
    domain_names = {str(domain.id): domain.name for domain in storage.list_domains()}

    nodes: dict[tuple[str, str], dict[str, str]] = {}

    def resolve_label(entity_type: str, entity_id: str) -> str:
        if entity_type == "repository":
            return repositories.get(entity_id, f"repository:{entity_id}")
        if entity_type == "organization":
            return organizations.get(entity_id, f"organization:{entity_id}")
        if entity_type == "account":
            return accounts.get(entity_id, f"account:{entity_id}")
        if entity_type == "domain":
            return domain_names.get(entity_id) or f"domain:{entity_id}"
        return f"{entity_type}:{entity_id}"

    edges: list[dict[str, str]] = []
    for relationship in relationships:
        from_key = (relationship.from_entity_type, relationship.from_entity_id)
        to_key = (relationship.to_entity_type, relationship.to_entity_id)
        nodes.setdefault(
            from_key,
            {
                "id": f"{relationship.from_entity_type}:{relationship.from_entity_id}",
                "entity_type": relationship.from_entity_type,
                "entity_id": relationship.from_entity_id,
                "label": resolve_label(relationship.from_entity_type, relationship.from_entity_id),
            },
        )
        nodes.setdefault(
            to_key,
            {
                "id": f"{relationship.to_entity_type}:{relationship.to_entity_id}",
                "entity_type": relationship.to_entity_type,
                "entity_id": relationship.to_entity_id,
                "label": resolve_label(relationship.to_entity_type, relationship.to_entity_id),
            },
        )
        edges.append(
            {
                "id": str(relationship.id),
                "from": f"{relationship.from_entity_type}:{relationship.from_entity_id}",
                "to": f"{relationship.to_entity_type}:{relationship.to_entity_id}",
                "relation_type": relationship.relation_type,
                "confidence": relationship.confidence,
                "source": relationship.source or "",
            }
        )

    return {"nodes": list(nodes.values()), "edges": edges}


def write_json(output_path: Path, payload: Any) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def write_csv(output_path: Path, rows: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else ["id", "title", "category", "severity", "confidence", "status"]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def render_dashboard_html(
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    trends: list[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
    filters: dict[str, Any] | None = None,
    live: bool = False,
    artifact_scan_result: dict[str, Any] | None = None,
    artifact_scan_error: str | None = None,
) -> str:
    def items(mapping: dict[str, Any]) -> str:
        return "".join(f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>" for key, value in mapping.items())

    def list_items(values: list[str]) -> str:
        return "".join(f"<li>{html.escape(value)}</li>" for value in values) or "<li>None</li>"

    def severity_items(values: dict[str, Any]) -> str:
        return ", ".join(f"{html.escape(str(key))}={html.escape(str(value))}" for key, value in values.items()) or "none"

    def metric_card(title: str, value: Any, tone: str = "default") -> str:
        return (
            f"<div class='card metric {html.escape(tone)}'>"
            f"<h3>{html.escape(title)}</h3>"
            f"<p>{html.escape(str(value))}</p>"
            "</div>"
        )

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
    scan_job_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(job['id']))}</td>"
        f"<td>{html.escape(str(job['scanner_name']))}</td>"
        f"<td>{html.escape(str(job['target_type']))}</td>"
        f"<td>{html.escape(str(job['target_id']))}</td>"
        f"<td>{html.escape(str(job['status']))}</td>"
        "</tr>"
        for job in summary["recent_scan_jobs"][:10]
    ) or "<tr><td colspan='5'>No scan activity yet</td></tr>"
    artifact_result_banner = ""
    if artifact_scan_result is not None:
        artifact_result_banner = (
            "<div class='banner success'>"
            f"<strong>Artifact scan completed.</strong> {html.escape(str(artifact_scan_result.get('artifact_name', 'artifact')))} "
            f"produced {html.escape(str(artifact_scan_result.get('findings', 0)))} finding(s) "
            f"in scan job #{html.escape(str(artifact_scan_result.get('scan_job_id', 'n/a')))}."
            "</div>"
        )
    elif artifact_scan_error:
        artifact_result_banner = (
            "<div class='banner error'>"
            f"<strong>Artifact scan failed.</strong> {html.escape(artifact_scan_error)}"
            "</div>"
        )
    graph_nodes = len((graph or {}).get("nodes", []))
    graph_edges = len((graph or {}).get("edges", []))
    identity_labels = [
        f"{item['username'] or 'unknown'} / {item['email'] or 'unknown'} ({item['relation_type']})"
        for item in summary["identity_correlations"]
    ]
    open_findings = summary["workflow_breakdown"].get("open", 0)
    high_risk_findings = sum(1 for row in summary["top_risky_findings"] if float(row.get("risk_score", 0) or 0) >= 70)
    critical_findings = summary["severity_breakdown"].get("critical", 0)
    live_header = """
    <section>
      <div class="section-header">
        <div>
          <h2>Live filters</h2>
          <p class="subtle">Refresh the dashboard view or jump to raw API outputs for automation.</p>
        </div>
        <div class="quick-links"><a href="/summary">summary json</a><a href="/findings?limit={limit}">findings json</a><a href="/relationships/graph">graph json</a><a href="/trends/findings?days={days}">trends json</a></div>
      </div>
      <form method="get" action="/dashboard" class="filters">
        <label>Status <input type="text" name="status" value="{status}"></label>
        <label>Severity <input type="text" name="severity" value="{severity}"></label>
        <label>Category <input type="text" name="category" value="{category}"></label>
        <label>Confidence <input type="text" name="confidence" value="{confidence}"></label>
        <label>Limit <input type="number" min="1" max="500" name="limit" value="{limit}"></label>
        <label>Trend days <input type="number" min="1" max="365" name="days" value="{days}"></label>
        <button type="submit">Refresh</button>
      </form>
    </section>
    <section>
      <div class="section-header">
        <div>
          <h2>Artifact upload analysis</h2>
          <p class="subtle">Upload a file or supported archive for immediate secret-pattern analysis.</p>
        </div>
      </div>
      <form method="post" action="/dashboard/artifact-scans" enctype="multipart/form-data" class="upload-form">
        <label>Artifact file <input type="file" name="artifact" required></label>
        <label>Organization <input type="text" name="organization" placeholder="example-org"></label>
        <label>Repository <input type="text" name="repository" placeholder="example-org/app"></label>
        <label>Provider <input type="text" name="provider" value="github"></label>
        <button type="submit">Upload and scan</button>
      </form>
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
    <title>orgscan dashboard</title>
    <style>
      body {{ font-family: Inter, system-ui, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }}
      main {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
      .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.5rem; }}
      .hero {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
      .card, section {{ background: white; border: 1px solid #dbe3ef; border-radius: 16px; padding: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06); }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #dbe3ef; padding: 0.65rem; text-align: left; vertical-align: top; }}
      th {{ background: #eff6ff; }}
      tbody tr:nth-child(even) {{ background: #f8fbff; }}
      h1, h2, h3 {{ margin-top: 0; }}
      .filters, .upload-form {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.75rem; align-items: end; }}
      label {{ display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.95rem; }}
      input {{ padding: 0.55rem; border: 1px solid #cbd5e1; border-radius: 10px; }}
      button {{ padding: 0.7rem 1rem; border: 0; border-radius: 10px; background: #2563eb; color: white; cursor: pointer; font-weight: 600; }}
      .subtle {{ color: #475569; margin: 0; }}
      .section-header {{ display: flex; justify-content: space-between; gap: 1rem; align-items: center; margin-bottom: 1rem; }}
      .quick-links {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
      .quick-links a {{ text-decoration: none; color: #2563eb; font-weight: 600; }}
      .metric p {{ font-size: 2rem; font-weight: 700; margin: 0; }}
      .metric.critical {{ background: linear-gradient(180deg, #fff1f2 0%, #ffffff 100%); }}
      .metric.warning {{ background: linear-gradient(180deg, #fffbeb 0%, #ffffff 100%); }}
      .metric.info {{ background: linear-gradient(180deg, #eff6ff 0%, #ffffff 100%); }}
      .banner {{ margin: 0 0 1rem 0; padding: 0.9rem 1rem; border-radius: 12px; border: 1px solid; }}
      .banner.success {{ background: #ecfdf5; border-color: #86efac; color: #166534; }}
      .banner.error {{ background: #fef2f2; border-color: #fca5a5; color: #991b1b; }}
      @media (max-width: 1024px) {{ .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr 1fr; }} }}
      @media (max-width: 640px) {{ main {{ padding: 1rem; }} .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr; }} .section-header {{ flex-direction: column; align-items: flex-start; }} }}
    </style>
  </head>
  <body>
    <main>
    <h1>orgscan dashboard</h1>
    <p class="subtle">Analyst workspace for findings, entity risk, upload-driven artifact triage, and recent scan activity.</p>
    {artifact_result_banner}
    {live_header}
    <div class=\"hero\">
      {metric_card("Findings", summary['counts'].get('findings', 0), "critical")}
      {metric_card("Open findings", open_findings, "warning")}
      {metric_card("Critical findings", critical_findings, "critical")}
      {metric_card("High risk findings", high_risk_findings, "info")}
      {metric_card("Scheduled scans", summary['counts'].get('scheduled_scans', 0), "info")}
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
      <table>
        <thead>
          <tr><th>Date</th><th>Total findings</th><th>Severity mix</th></tr>
        </thead>
        <tbody>{trend_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Relationship graph edges</h2>
      <p>Nodes: {html.escape(str(graph_nodes))} · Edges: {html.escape(str(graph_edges))}</p>
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
      <h2>Recent scan activity</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Scanner</th><th>Target type</th><th>Target</th><th>Status</th></tr>
        </thead>
        <tbody>{scan_job_rows}</tbody>
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
    </main>
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
