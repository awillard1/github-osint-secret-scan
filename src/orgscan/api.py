from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from orgscan.db import create_session_factory, init_db
from orgscan.reporting import build_summary, finding_rows, finding_trends, relationship_graph, render_dashboard_html
from orgscan.repositories import Storage


class OrgscanApiService:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        init_db(self.database_url)
        self.session_factory = create_session_factory(self.database_url)

    def _summary_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            return build_summary(Storage(session))

    def _findings_payload(
        self,
        *,
        limit: int = 50,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            findings = storage.list_findings(
                limit=limit,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
            )
            return {
                "findings": [
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
                        "source_tool": finding.source_tool,
                        "source_name": finding.source_name,
                        "repository_id": finding.repository_id,
                        "scan_job_id": finding.scan_job_id,
                        "detected_at": finding.detected_at.isoformat(),
                        "fingerprint": finding.fingerprint,
                    }
                    for finding in findings
                ]
            }

    def _scheduled_scans_payload(self) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            return {
                "scheduled_scans": [
                    {
                        "id": scan.id,
                        "target_type": scan.target_type,
                        "target_value": scan.target_value,
                        "scanner_name": scan.scanner_name,
                        "cadence": scan.cadence,
                        "enabled": scan.enabled,
                        "next_run_at": scan.next_run_at.isoformat(),
                    }
                    for scan in storage.list_scheduled_scans()
                ]
            }

    def _relationship_graph_payload(self, *, limit: int = 200) -> dict[str, object]:
        with self.session_factory() as session:
            return relationship_graph(Storage(session), limit=limit)

    def _finding_trends_payload(self, *, days: int = 30) -> dict[str, object]:
        with self.session_factory() as session:
            return {"days": days, "trends": finding_trends(Storage(session), days=days)}

    def _dashboard_html(
        self,
        *,
        limit: int = 100,
        days: int = 30,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> str:
        with self.session_factory() as session:
            storage = Storage(session)
            summary = build_summary(storage)
            filtered_rows = [
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
                for finding in storage.list_findings(
                    limit=limit,
                    status=status,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                )
            ]
            return render_dashboard_html(
                summary,
                filtered_rows,
                trends=finding_trends(storage, days=days),
                graph=relationship_graph(storage, limit=200),
                filters={
                    "limit": limit,
                    "days": days,
                    "status": status or "",
                    "severity": severity or "",
                    "category": category or "",
                    "confidence": confidence or "",
                },
                live=True,
            )

    def handle(self, path: str) -> tuple[int, dict[str, object]]:
        parsed = urlparse(path)
        params = parse_qs(parsed.query)
        route = parsed.path
        if route == "/health":
            return 200, {"status": "ok"}
        if route == "/summary":
            return 200, self._summary_payload()
        if route == "/findings":
            return 200, self._findings_payload(
                limit=int(params.get("limit", ["50"])[0]),
                status=params.get("status", [None])[0],
                severity=params.get("severity", [None])[0],
                category=params.get("category", [None])[0],
                confidence=params.get("confidence", [None])[0],
            )
        if route == "/scheduled-scans":
            return 200, self._scheduled_scans_payload()
        if route == "/relationships/graph":
            return 200, self._relationship_graph_payload(limit=int(params.get("limit", ["200"])[0]))
        if route == "/trends/findings":
            return 200, self._finding_trends_payload(days=int(params.get("days", ["30"])[0]))
        return 404, {"error": f"Unknown route: {route}"}


def create_app(database_url: str) -> FastAPI:
    service = OrgscanApiService(database_url)
    app = FastAPI(title="orgscan", version="0.1.0")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/summary")
    def summary() -> dict[str, object]:
        return service._summary_payload()

    @app.get("/findings")
    def findings(
        limit: int = Query(50, ge=1, le=500),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> dict[str, object]:
        return service._findings_payload(
            limit=limit,
            status=status,
            severity=severity,
            category=category,
            confidence=confidence,
        )

    @app.get("/scheduled-scans")
    def scheduled_scans() -> dict[str, object]:
        return service._scheduled_scans_payload()

    @app.get("/relationships/graph")
    def relationships(limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
        return service._relationship_graph_payload(limit=limit)

    @app.get("/trends/findings")
    def trends(days: int = Query(30, ge=1, le=365)) -> dict[str, object]:
        return service._finding_trends_payload(days=days)

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(
        limit: int = Query(100, ge=1, le=500),
        days: int = Query(30, ge=1, le=365),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
    ) -> HTMLResponse:
        return HTMLResponse(
            service._dashboard_html(
                limit=limit,
                days=days,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
            )
        )

    return app


def serve_api(database_url: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    uvicorn.run(create_app(database_url), host=host, port=port, log_level="info")
