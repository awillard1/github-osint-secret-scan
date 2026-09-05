from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from orgscan.repositories import Storage


def build_summary(storage: Storage) -> dict[str, Any]:
    findings = list(storage.list_findings(limit=500))
    repositories = {repo.id: repo.full_name for repo in storage.list_repositories()}
    findings_by_tool = Counter(finding.source_tool for finding in findings)
    workflow_breakdown = Counter(finding.status for finding in findings)
    repository_breakdown = Counter(
        repositories.get(finding.repository_id, "unassigned")
        for finding in findings
    )

    return {
        "counts": dict(storage.counts()),
        "severity_breakdown": dict(storage.finding_counts_by_severity()),
        "category_breakdown": dict(storage.finding_counts_by_category()),
        "source_tool_breakdown": dict(sorted(findings_by_tool.items())),
        "workflow_breakdown": dict(sorted(workflow_breakdown.items())),
        "organizations": [org.name for org in storage.list_organizations()],
        "repositories": list(repositories.values()),
        "accounts": [account.username for account in storage.list_accounts()],
        "domain_exposures": [exposure.result_summary for exposure in storage.list_domain_exposures()],
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
            for finding in sorted(
                findings,
                key=lambda finding: (finding.risk_score or 0, finding.detected_at),
                reverse=True,
            )[:10]
        ],
        "top_risky_assets": [
            {"repository": repository_name, "findings": count}
            for repository_name, count in repository_breakdown.most_common(10)
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


def render_dashboard_html(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    def items(mapping: dict[str, Any]) -> str:
        return "".join(f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>" for key, value in mapping.items())

    def list_items(values: list[str]) -> str:
        return "".join(f"<li>{html.escape(value)}</li>" for value in values) or "<li>None</li>"

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
    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
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
    </style>
  </head>
  <body>
    <h1>orgscan dashboard</h1>
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
      <h2>Top risky findings</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Tool</th><th>Risk score</th><th>Status</th></tr>
        </thead>
        <tbody>{top_findings}</tbody>
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
        <ul>{list_items([f"{item['username'] or 'unknown'} / {item['email'] or 'unknown'} ({item['relation_type']})" for item in summary['identity_correlations']])}</ul>
      </section>
    </div>
  </body>
</html>
"""


def write_html(output_path: Path, summary: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_dashboard_html(summary, findings), encoding="utf-8")
    return output_path
