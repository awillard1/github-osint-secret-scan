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
            "risk_score": finding.risk_score or 0,
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
    finding_action_result: dict[str, Any] | None = None,
    finding_action_error: str | None = None,
    scanner_options: list[dict[str, Any]] | None = None,
    access_context_note: str | None = None,
    tooling: dict[str, Any] | None = None,
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

    scanner_select = "".join(
        (
            "<option value='{name}' {selected} {disabled}>{label}</option>"
        ).format(
            name=html.escape(str(item["name"])),
            selected="selected" if item.get("selected") else "",
            disabled="" if item.get("available") else "disabled",
            label=html.escape(
                str(item["name"]) if item.get("available") else f"{item['name']} (not installed)"
            ),
        )
        for item in (scanner_options or [{"name": "custom-patterns", "available": True, "selected": True}])
    )
    tooling_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item['name']))}</td>"
        f"<td>{html.escape(str(item['category']))}</td>"
        f"<td>{html.escape('installed' if item.get('installed') else 'missing')}</td>"
        f"<td>{html.escape(str(item.get('configured_command') or ''))}</td>"
        f"<td>{html.escape(str(item.get('env_var') or 'PATH'))}</td>"
        f"<td>{html.escape(str(item.get('install_note') or ''))}</td>"
        "</tr>"
        for item in (tooling or {}).get("optional_tools", [])
    ) or "<tr><td colspan='6'>No tooling data available</td></tr>"

    def render_finding_row(row: dict[str, Any]) -> str:
        base = (
            "<tr>"
            f"<td>{html.escape(str(row['id']))}</td>"
            f"<td><a href='/dashboard/findings/{html.escape(str(row['id']))}'>{html.escape(str(row['title']))}</a></td>"
            f"<td>{html.escape(str(row['category']))}</td>"
            f"<td>{html.escape(str(row['severity']))}</td>"
            f"<td>{html.escape(str(row['confidence']))}</td>"
            f"<td>{html.escape(str(row['risk_score']))}</td>"
            f"<td>{html.escape(str(row['status']))}</td> / {html.escape(str(row['triage_state']))}"
            f"<br><span class='subtle'>{html.escape(str(row['triage_owner'] or 'unassigned'))}</span></td>"
            f"<td>{html.escape(str(row['source_tool']))}</td>"
            f"<td>{html.escape(str(row['detected_at']))}</td>"
        )
        if not live:
            return base + "</tr>"
        action_form = (
            "<td>"
            "<form method='post' action='/dashboard/findings/{id}/workflow' class='finding-action'>"
            "<input type='hidden' name='limit' value='{limit}'>"
            "<input type='hidden' name='days' value='{days}'>"
            "<input type='hidden' name='status' value='{status}'>"
            "<input type='hidden' name='severity' value='{severity}'>"
            "<input type='hidden' name='category' value='{category}'>"
            "<input type='hidden' name='confidence' value='{confidence}'>"
            "<input type='hidden' name='high_signal_only' value='{high_signal_only}'>"
            "<input type='hidden' name='min_confidence' value='{min_confidence}'>"
            "<select name='action'>"
            "<option value='triage'>triage</option>"
            "<option value='suppress'>suppress</option>"
            "<option value='accept-risk'>accept risk</option>"
            "<option value='reopen'>reopen</option>"
            "</select>"
            "<input type='text' name='owner' placeholder='owner'>"
            "<input type='text' name='note' placeholder='note or reason'>"
            "<select name='triage_state'>"
            "<option value='reviewing'>reviewing</option>"
            "<option value='validated'>validated</option>"
            "<option value='false_positive'>false_positive</option>"
            "</select>"
            "<button type='submit'>Apply</button>"
            "</form>"
            "</td>"
        ).format(
            id=html.escape(str(row["id"])),
            limit=html.escape(str((filters or {}).get("limit", 100))),
            days=html.escape(str((filters or {}).get("days", 30))),
            status=html.escape(str((filters or {}).get("status", ""))),
            severity=html.escape(str((filters or {}).get("severity", ""))),
            category=html.escape(str((filters or {}).get("category", ""))),
            confidence=html.escape(str((filters or {}).get("confidence", ""))),
            high_signal_only="true" if (filters or {}).get("high_signal_only") else "false",
            min_confidence=html.escape(str((filters or {}).get("min_confidence", "likely"))),
        )
        return base + action_form + "</tr>"

    rows = "".join(render_finding_row(row) for row in findings)
    top_findings = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['id']))}</td>"
        f"<td><a href='/dashboard/findings/{html.escape(str(row['id']))}'>{html.escape(str(row['title']))}</a></td>"
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
        f"<td><a href='/dashboard/scan-jobs/{html.escape(str(job['id']))}'>{html.escape(str(job['id']))}</a></td>"
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
    finding_result_banner = ""
    if finding_action_result is not None:
        finding_result_banner = (
            "<div class='banner success'>"
            f"<strong>Finding workflow updated.</strong> Finding #{html.escape(str(finding_action_result.get('id', 'n/a')))} "
            f"is now {html.escape(str(finding_action_result.get('status', 'updated')))}"
            f" / {html.escape(str(finding_action_result.get('triage_state', 'updated')))}."
            "</div>"
        )
    elif finding_action_error:
        finding_result_banner = (
            "<div class='banner error'>"
            f"<strong>Finding workflow update failed.</strong> {html.escape(finding_action_error)}"
            "</div>"
        )
    access_context_banner = (
        f"<div class='banner info'><strong>Access context.</strong> {html.escape(access_context_note)}</div>"
        if access_context_note
        else ""
    )
    graph_nodes = len((graph or {}).get("nodes", []))
    graph_edges = len((graph or {}).get("edges", []))
    graph_node_badges = "".join(
        f"<li><strong>{html.escape(str(node['entity_type']))}</strong>: {html.escape(str(node['label']))}</li>"
        for node in (graph or {}).get("nodes", [])[:12]
    ) or "<li>No graph nodes</li>"
    findings_header = (
        "<tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Risk</th><th>Workflow</th><th>Tool</th><th>Detected</th>"
        + ("<th>Actions</th>" if live else "")
        + "</tr>"
    )
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
        <div class="quick-links"><a href="/summary">summary json</a><a href="/scanners">scanners json</a><a href="/findings?limit={limit}">findings json</a><a href="/relationships/graph">graph json</a><a href="/trends/findings?days={days}">trends json</a><a href="/dashboard/graph">graph view</a></div>
      </div>
      <form method="get" action="/dashboard" class="filters">
        <label>Status <input type="text" name="status" value="{status}"></label>
        <label>Severity <input type="text" name="severity" value="{severity}"></label>
        <label>Category <input type="text" name="category" value="{category}"></label>
        <label>Confidence <input type="text" name="confidence" value="{confidence}"></label>
        <label>Minimum confidence
          <select name="min_confidence">
            <option value="verified" {min_confidence_verified}>verified</option>
            <option value="likely" {min_confidence_likely}>likely</option>
            <option value="heuristic" {min_confidence_heuristic}>heuristic</option>
            <option value="unverified" {min_confidence_unverified}>unverified</option>
          </select>
        </label>
        <label class="checkbox"><input type="checkbox" name="high_signal_only" value="true" {high_signal_only}>High signal only</label>
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
        <label>Scanner <select name="scanner">{scanner_select}</select></label>
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
        min_confidence_verified="selected" if (filters or {}).get("min_confidence", "likely") == "verified" else "",
        min_confidence_likely="selected" if (filters or {}).get("min_confidence", "likely") == "likely" else "",
        min_confidence_heuristic="selected" if (filters or {}).get("min_confidence", "likely") == "heuristic" else "",
        min_confidence_unverified="selected" if (filters or {}).get("min_confidence", "likely") == "unverified" else "",
        high_signal_only="checked" if (filters or {}).get("high_signal_only") else "",
        limit=html.escape(str((filters or {}).get("limit", 100))),
        days=html.escape(str((filters or {}).get("days", 30))),
        scanner_select=scanner_select,
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
      .finding-action {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem; }}
      label {{ display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.95rem; }}
      input, select {{ padding: 0.55rem; border: 1px solid #cbd5e1; border-radius: 10px; background: white; }}
      button {{ padding: 0.7rem 1rem; border: 0; border-radius: 10px; background: #2563eb; color: white; cursor: pointer; font-weight: 600; }}
      .subtle {{ color: #475569; margin: 0; }}
      .section-header {{ display: flex; justify-content: space-between; gap: 1rem; align-items: center; margin-bottom: 1rem; }}
      .quick-links {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
      .quick-links a {{ text-decoration: none; color: #2563eb; font-weight: 600; }}
      .checkbox {{ flex-direction: row; align-items: center; gap: 0.5rem; padding-bottom: 0.3rem; }}
      .checkbox input {{ width: auto; }}
      .metric p {{ font-size: 2rem; font-weight: 700; margin: 0; }}
      .metric.critical {{ background: linear-gradient(180deg, #fff1f2 0%, #ffffff 100%); }}
      .metric.warning {{ background: linear-gradient(180deg, #fffbeb 0%, #ffffff 100%); }}
      .metric.info {{ background: linear-gradient(180deg, #eff6ff 0%, #ffffff 100%); }}
      .banner {{ margin: 0 0 1rem 0; padding: 0.9rem 1rem; border-radius: 12px; border: 1px solid; }}
      .banner.success {{ background: #ecfdf5; border-color: #86efac; color: #166534; }}
      .banner.error {{ background: #fef2f2; border-color: #fca5a5; color: #991b1b; }}
      .banner.info {{ background: #eff6ff; border-color: #93c5fd; color: #1d4ed8; }}
      @media (max-width: 1024px) {{ .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr 1fr; }} }}
      @media (max-width: 640px) {{ main {{ padding: 1rem; }} .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr; }} .section-header {{ flex-direction: column; align-items: flex-start; }} }}
    </style>
  </head>
  <body>
    <main>
    <h1>orgscan dashboard</h1>
    <p class="subtle">Analyst workspace for findings, entity risk, upload-driven artifact triage, and recent scan activity.</p>
    {artifact_result_banner}
    {finding_result_banner}
    {access_context_banner}
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
      <p>Nodes: {html.escape(str(graph_nodes))} · Edges: {html.escape(str(graph_edges))} · <a href="/dashboard/graph">open graph view</a></p>
      <ul>{graph_node_badges}</ul>
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
          {findings_header}
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Open-source tooling readiness</h2>
      <table>
        <thead>
          <tr><th>Tool</th><th>Category</th><th>Status</th><th>Configured command</th><th>Configuration</th><th>Install guidance</th></tr>
        </thead>
        <tbody>{tooling_rows}</tbody>
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


def write_html(
    output_path: Path,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    tooling: dict[str, Any] | None = None,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_dashboard_html(
            summary,
            findings,
            trends=summary.get("finding_trends"),
            graph=summary.get("relationship_graph"),
            tooling=tooling,
        ),
        encoding="utf-8",
    )
    return output_path


def _render_html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{html.escape(title)}</title>
    <style>
      body {{ font-family: Inter, system-ui, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }}
      main {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
      section {{ background: white; border: 1px solid #dbe3ef; border-radius: 16px; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06); }}
      a {{ color: #2563eb; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #dbe3ef; padding: 0.65rem; text-align: left; vertical-align: top; }}
      th {{ background: #eff6ff; }}
      pre {{ background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 12px; overflow-x: auto; white-space: pre-wrap; }}
      .subtle {{ color: #475569; }}
      .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }}
      .hero {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }}
      .pill {{ display: inline-block; padding: 0.2rem 0.55rem; border-radius: 999px; background: #eff6ff; border: 1px solid #bfdbfe; margin: 0 0.35rem 0.35rem 0; }}
      @media (max-width: 800px) {{ main {{ padding: 1rem; }} .grid, .hero {{ grid-template-columns: 1fr; }} }}
    </style>
  </head>
  <body>
    <main>{body}</main>
  </body>
</html>"""


def render_finding_detail_html(payload: dict[str, Any]) -> str:
    finding = payload["finding"]
    evidence_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('source') or ''))}</td>"
        f"<td>{html.escape(str(item.get('repository_path') or ''))}</td>"
        f"<td>{html.escape(str(item.get('line_start') or ''))}</td>"
        f"<td><pre>{html.escape(str(item.get('snippet') or ''))}</pre></td>"
        "</tr>"
        for item in payload.get("evidence", [])
    ) or "<tr><td colspan='4'>No evidence available</td></tr>"
    risk_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('entity_type') or ''))}</td>"
        f"<td>{html.escape(str(item.get('entity_id') or ''))}</td>"
        f"<td>{html.escape(str(item.get('score') or ''))}</td>"
        f"<td>{html.escape(str(item.get('rationale') or ''))}</td>"
        "</tr>"
        for item in payload.get("risk_scores", [])
    ) or "<tr><td colspan='4'>No risk score records available</td></tr>"
    metadata = json.dumps(finding.get("metadata") or {}, indent=2, sort_keys=True)
    raw_payload = json.dumps(finding.get("raw_payload") or {}, indent=2, sort_keys=True)
    body = f"""
    <p><a href="/dashboard">← Back to dashboard</a></p>
    <section>
      <h1>Finding #{html.escape(str(finding['id']))}</h1>
      <p class="subtle">{html.escape(str(finding['title']))}</p>
      <div class="hero">
        <section><h3>Severity</h3><p>{html.escape(str(finding['severity']))}</p></section>
        <section><h3>Confidence</h3><p>{html.escape(str(finding['confidence']))}</p></section>
        <section><h3>Risk score</h3><p>{html.escape(str(finding.get('risk_score') or 0))}</p></section>
      </div>
    </section>
    <div class="grid">
      <section>
        <h2>Workflow</h2>
        <ul>
          <li>Status: {html.escape(str(finding['status']))}</li>
          <li>Triage: {html.escape(str(finding['triage_state']))}</li>
          <li>Owner: {html.escape(str(finding.get('triage_owner') or 'unassigned'))}</li>
          <li>Detected: {html.escape(str(finding['detected_at']))}</li>
        </ul>
      </section>
      <section>
        <h2>Context</h2>
        <ul>
          <li>Category: {html.escape(str(finding['category']))}</li>
          <li>Source tool: {html.escape(str(finding['source_tool']))}</li>
          <li>Repository ID: {html.escape(str(finding.get('repository_id') or ''))}</li>
          <li>Scan job ID: {html.escape(str(finding.get('scan_job_id') or ''))}</li>
        </ul>
      </section>
    </div>
    <section>
      <h2>Description</h2>
      <p>{html.escape(str(finding['description']))}</p>
      <p><strong>Remediation:</strong> {html.escape(str(finding.get('remediation_hint') or 'No remediation hint recorded.'))}</p>
    </section>
    <section>
      <h2>Evidence</h2>
      <table><thead><tr><th>Source</th><th>Path</th><th>Line</th><th>Snippet</th></tr></thead><tbody>{evidence_rows}</tbody></table>
    </section>
    <section>
      <h2>Risk scores</h2>
      <table><thead><tr><th>Entity type</th><th>Entity ID</th><th>Score</th><th>Rationale</th></tr></thead><tbody>{risk_rows}</tbody></table>
    </section>
    <div class="grid">
      <section><h2>Metadata</h2><pre>{html.escape(metadata)}</pre></section>
      <section><h2>Raw payload</h2><pre>{html.escape(raw_payload)}</pre></section>
    </div>
    """
    return _render_html_page(f"Finding {finding['id']}", body)


def render_scan_job_detail_html(payload: dict[str, Any]) -> str:
    scan_job = payload["scan_job"]
    tool_runs = payload.get("tool_runs", [])
    findings = payload.get("findings", [])
    tool_sections = "".join(
        f"""
        <section>
          <h3>Tool run #{html.escape(str(run['id']))} — {html.escape(str(run['tool_name']))}</h3>
          <p class="subtle">Status: {html.escape(str(run['status']))} · Target: {html.escape(str(run['target']))}</p>
          <div class="grid">
            <section><h4>stdout</h4><pre>{html.escape(str(run.get('stdout_log') or ''))}</pre></section>
            <section><h4>stderr</h4><pre>{html.escape(str(run.get('stderr_log') or ''))}</pre></section>
          </div>
        </section>
        """
        for run in tool_runs
    ) or "<section><p>No tool runs recorded for this scan job.</p></section>"
    finding_rows = "".join(
        "<tr>"
        f"<td><a href='/dashboard/findings/{html.escape(str(item['id']))}'>{html.escape(str(item['id']))}</a></td>"
        f"<td>{html.escape(str(item['title']))}</td>"
        f"<td>{html.escape(str(item['severity']))}</td>"
        f"<td>{html.escape(str(item['confidence']))}</td>"
        f"<td>{html.escape(str(item['status']))}</td>"
        "</tr>"
        for item in findings
    ) or "<tr><td colspan='5'>No findings recorded for this scan job.</td></tr>"
    parameters = json.dumps(scan_job.get("parameters_json") or {}, indent=2, sort_keys=True)
    body = f"""
    <p><a href="/dashboard">← Back to dashboard</a></p>
    <section>
      <h1>Scan job #{html.escape(str(scan_job['id']))}</h1>
      <p class="subtle">{html.escape(str(scan_job['scanner_name']))} against {html.escape(str(scan_job['target_id']))}</p>
      <div class="hero">
        <section><h3>Status</h3><p>{html.escape(str(scan_job['status']))}</p></section>
        <section><h3>Target type</h3><p>{html.escape(str(scan_job['target_type']))}</p></section>
        <section><h3>Findings</h3><p>{html.escape(str(len(findings)))}</p></section>
      </div>
    </section>
    <div class="grid">
      <section>
        <h2>Execution metadata</h2>
        <ul>
          <li>Started: {html.escape(str(scan_job.get('started_at') or ''))}</li>
          <li>Completed: {html.escape(str(scan_job.get('completed_at') or ''))}</li>
          <li>Error: {html.escape(str(scan_job.get('error_message') or ''))}</li>
        </ul>
      </section>
      <section>
        <h2>Parameters</h2>
        <pre>{html.escape(parameters)}</pre>
      </section>
    </div>
    <section>
      <h2>Findings from this scan</h2>
      <table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Status</th></tr></thead><tbody>{finding_rows}</tbody></table>
    </section>
    {tool_sections}
    """
    return _render_html_page(f"Scan job {scan_job['id']}", body)


def render_graph_html(graph: dict[str, Any]) -> str:
    node_cards = "".join(
        f"<span class='pill'>{html.escape(str(node['entity_type']))}: {html.escape(str(node['label']))}</span>"
        for node in graph.get("nodes", [])
    ) or "<p>No nodes available.</p>"
    edge_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(edge['from']))}</td>"
        f"<td>{html.escape(str(edge['relation_type']))}</td>"
        f"<td>{html.escape(str(edge['to']))}</td>"
        f"<td>{html.escape(str(edge['confidence']))}</td>"
        "</tr>"
        for edge in graph.get("edges", [])
    ) or "<tr><td colspan='4'>No relationships available.</td></tr>"
    body = f"""
    <p><a href="/dashboard">← Back to dashboard</a></p>
    <section>
      <h1>Relationship graph</h1>
      <p class="subtle">Visual inventory of the currently known entities and their relationships.</p>
      <div class="hero">
        <section><h3>Nodes</h3><p>{html.escape(str(len(graph.get('nodes', []))))}</p></section>
        <section><h3>Edges</h3><p>{html.escape(str(len(graph.get('edges', []))))}</p></section>
        <section><h3>Linked entities</h3><p>{html.escape(str(len({edge['from'] for edge in graph.get('edges', [])} | {edge['to'] for edge in graph.get('edges', [])})))} </p></section>
      </div>
    </section>
    <section>
      <h2>Nodes</h2>
      <div>{node_cards}</div>
    </section>
    <section>
      <h2>Relationships</h2>
      <table><thead><tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr></thead><tbody>{edge_rows}</tbody></table>
    </section>
    """
    return _render_html_page("Relationship graph", body)
