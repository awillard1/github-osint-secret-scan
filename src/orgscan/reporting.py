from __future__ import annotations

from orgscan.lifecycle import lifecycle_fields, is_actionable_high_risk

import csv
import html
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from orgscan.config import Settings
from orgscan.reports.redaction import redact
from orgscan.redaction import safe_output, safe_presentation
from orgscan.repositories import Storage
from orgscan.services.projection_service import derived_projection


# [...existing content omitted for brevity in the original file; only CSS/template fragments are updated here]


@safe_presentation
def render_dashboard_html(
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    trends: list[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
    filters: dict[str, Any] | None = None,
    live: bool = False,
    operations: dict[str, Any] | None = None,
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
                str(item["name"]) if item.get("available") else (
                    f"{item['name']} (not installed)" if item.get("status", "missing_binary") == "missing_binary"
                    else f"{item['name']} (not ready)"
                )
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
            f"<td>{html.escape(str(row['status']))} / {html.escape(str(row['triage_state']))}</td>"
            f"<td>{html.escape(str(row['source_tool']))}</td>"
            f"<td>{html.escape(str(row['detected_at']))}</td>"
        )
        if not live:
            locations = '; '.join(f"{item['path']}:{item.get('line_start') or ''}" for item in row.get('evidence', []) if item.get('path'))
            return base + '<td>' + html.escape(locations) + '</td></tr>'
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
        + ("<th>Actions</th>" if live else "<th>Locations</th>")
        + "</tr>"
    )
    identity_labels = [
        f"{item['username'] or 'unknown'} / {item['email'] or 'unknown'} ({item['relation_type']})"
        for item in summary["identity_correlations"]
    ]
    from orgscan.web.operator_dashboard import render_operator_queues
    operator_overview = render_operator_queues(operations) if operations else ""
    open_findings = summary["workflow_breakdown"].get("open", 0)
    high_risk_findings = operations["queues"]["high-risk"]["count"] if operations else summary.get("actionable_high_risk_count", 0)
    critical_findings = summary["severity_breakdown"].get("critical", 0)
    live_header = """
    <section class="panel">
      <div class="section-header">
        <div>
          <h2>Live filters</h2>
          <p class="subtle">Refresh the dashboard view or jump to raw API outputs for automation.</p>
        </div>
        <div class="quick-links"><a href="/summary">summary json</a><a href="/scanners">scanners json</a><a href="/findings?limit={limit}">findings json</a><a href="/relationships/graph">graph json</a></div>
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
    <section class="panel">
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
    page = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>orgscan dashboard</title>
    <style>
      body {{ font-family: Inter, system-ui, sans-serif; margin: 0; background: linear-gradient(180deg, #f8fafc 0%, #eef4ff 100%); color: #0f172a; }}
      main {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
      .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.5rem; }}
      .hero {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
      .card, section, .panel, .queue-card {{ background: rgba(255,255,255,0.96); border: 1px solid #dbe3ef; border-radius: 18px; padding: 1rem; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.06); }}
      .queue-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }}
      .queue-list {{ margin: 0; padding-left: 1rem; display: grid; gap: 0.5rem; }}
      .count-pill {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 999px; background: #eff6ff; color: #1d4ed8; font-size: 0.77rem; font-weight: 600; }}
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
      .page-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }}
      .eyebrow {{ margin: 0 0 .3rem; text-transform: uppercase; letter-spacing: 0.12em; font-size: 0.72rem; color: #475569; }}
      @media (max-width: 1024px) {{ .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr 1fr; }} }}
      @media (max-width: 640px) {{ main {{ padding: 1rem; }} .hero, .grid, .filters, .upload-form {{ grid-template-columns: 1fr; }} .section-header {{ flex-direction: column; align-items: flex-start; }} }}
    </style>
  </head>
  <body>
    <main>
    <header class="page-header">
      <div>
        <p class="eyebrow">Operations</p>
        <h1>orgscan dashboard</h1>
      </div>
      <div class="quick-links">
        <a href="/dashboard/assessments">Assessments</a>
        <a href="/dashboard/graph">Assets</a>
        <a href="/dashboard/settings/recon-tools">Tools</a>
      </div>
    </header>
    <p class="subtle">Analyst workspace for findings, entity risk, upload-driven artifact triage, and recent scan activity.</p>
    {artifact_result_banner}
    {finding_result_banner}
    {access_context_banner}
    {operator_overview}
    {live_header}
    <div class="hero">
      {metric_card("Findings", summary['counts'].get('findings', 0), "critical")}
      {metric_card("Open findings", open_findings, "warning")}
      {metric_card("Critical findings", critical_findings, "critical")}
      {metric_card("High risk findings", high_risk_findings, "info")}
      {metric_card("Scheduled scans", summary['counts'].get('scheduled_scans', 0), "info")}
    </div>
    <div class="grid">
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
      <p class="subtle">Client-side trend chart data is available from the findings trend series below.</p>
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
    <div class="grid">
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

    return _browser_html(page, full_page=True) if live else page


# Keep the existing export helper from the original module intact.

