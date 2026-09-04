from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from orgscan.repositories import Storage


def build_summary(storage: Storage) -> dict[str, Any]:
    return {
        "counts": dict(storage.counts()),
        "severity_breakdown": dict(storage.finding_counts_by_severity()),
        "category_breakdown": dict(storage.finding_counts_by_category()),
        "organizations": [org.name for org in storage.list_organizations()],
        "repositories": [repo.full_name for repo in storage.list_repositories()],
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
    }


def finding_rows(storage: Storage, limit: int = 500) -> list[dict[str, Any]]:
    return [
        {
            "id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "source_tool": finding.source_tool,
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
    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <title>orgscan dashboard</title>
    <style>
      body {{ font-family: sans-serif; margin: 2rem; }}
      .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.5rem; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
      th {{ background: #f5f5f5; }}
    </style>
  </head>
  <body>
    <h1>orgscan dashboard</h1>
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
        <ul>{''.join(f'<li>{html.escape(name)}</li>' for name in summary['organizations'])}</ul>
      </section>
    </div>
    <section>
      <h2>Recent findings</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Status</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
  </body>
</html>
"""


def write_html(output_path: Path, summary: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_dashboard_html(summary, findings), encoding="utf-8")
    return output_path
