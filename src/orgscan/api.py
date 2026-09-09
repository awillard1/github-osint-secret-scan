from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import Depends, FastAPI, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from orgscan.auth import AuthContext, auth_dependency, resolve_requested_tenants, serialize_auth_context
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.reporting import build_summary, finding_rows, finding_trends, relationship_graph, render_dashboard_html
from orgscan.repositories import Storage


class OrgscanApiService:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        init_db(self.database_url)
        self.session_factory = create_session_factory(self.database_url)

    def _summary_payload(self, *, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            return build_summary(Storage(session), tenant_keys=tenant_keys)

    def _findings_payload(
        self,
        *,
        limit: int = 50,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        tenant_keys: list[str] | None = None,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            return {
                "findings": finding_rows(
                    Storage(session),
                    limit=limit,
                    status=status,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                    tenant_keys=tenant_keys,
                )
            }

    def _scheduled_scans_payload(self, *, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            scheduled = build_summary(Storage(session), tenant_keys=tenant_keys).get("scheduled_scans", [])
            return {"scheduled_scans": scheduled}

    def _domain_exposures_payload(
        self,
        *,
        domain_id: int | None = None,
        source_name: str | None = None,
        source_class: str | None = None,
        confidence: str | None = None,
        limit: int = 100,
        tenant_keys: list[str] | None = None,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            storage = Storage(session)
            allowed_domain_ids: set[int] | None = None
            if tenant_keys is not None:
                organization_ids = {org.id for org in storage.list_organizations() if org.tenant_key in tenant_keys}
                allowed_domain_ids = {domain.id for domain in storage.list_domains() if domain.organization_id in organization_ids}
            exposures = storage.list_domain_exposures(
                domain_id,
                source_name=source_name,
                source_class=source_class,
                confidence=confidence,
                limit=limit,
            )
            if allowed_domain_ids is not None:
                exposures = [exposure for exposure in exposures if exposure.domain_id in allowed_domain_ids]
            provider_summary: dict[str, int] = {}
            for exposure in exposures:
                provider_summary[exposure.source_name] = provider_summary.get(exposure.source_name, 0) + 1
            return {
                "exposures": [
                    {
                        "id": exposure.id,
                        "domain_id": exposure.domain_id,
                        "source": exposure.source,
                        "source_name": exposure.source_name,
                        "source_class": exposure.source_class,
                        "query_used": exposure.query_used,
                        "result_summary": exposure.result_summary,
                        "confidence": exposure.confidence,
                        "severity": exposure.severity,
                        "evidence_url": exposure.evidence_url,
                    }
                    for exposure in exposures
                ],
                "provider_summary": provider_summary,
            }

    def _relationship_graph_payload(self, *, limit: int = 200, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            return relationship_graph(Storage(session), limit=limit, tenant_keys=tenant_keys)

    def _finding_trends_payload(self, *, days: int = 30, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            return {"days": days, "trends": finding_trends(Storage(session), days=days, tenant_keys=tenant_keys)}

    def _organization_comparison_payload(self, *, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            return {"organizations": build_summary(Storage(session), tenant_keys=tenant_keys).get("organization_comparison", [])}

    def _remediation_suggestions_payload(self, *, tenant_keys: list[str] | None = None) -> dict[str, object]:
        with self.session_factory() as session:
            return {"suggestions": build_summary(Storage(session), tenant_keys=tenant_keys).get("remediation_suggestions", [])}

    def _dashboard_html(
        self,
        *,
        limit: int = 100,
        days: int = 30,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        tenant_keys: list[str] | None = None,
    ) -> str:
        with self.session_factory() as session:
            storage = Storage(session)
            summary = build_summary(storage, tenant_keys=tenant_keys)
            filtered_rows = finding_rows(
                storage,
                limit=limit,
                tenant_keys=tenant_keys,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
            )
            return render_dashboard_html(
                summary,
                filtered_rows,
                trends=finding_trends(storage, days=days, tenant_keys=tenant_keys),
                graph=relationship_graph(storage, limit=200, tenant_keys=tenant_keys),
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
            tenant = params.get("tenant_key", [None])[0]
            return 200, self._summary_payload(tenant_keys=[tenant] if tenant else None)
        if route == "/findings":
            return 200, self._findings_payload(
                limit=int(params.get("limit", ["50"])[0]),
                status=params.get("status", [None])[0],
                severity=params.get("severity", [None])[0],
                category=params.get("category", [None])[0],
                confidence=params.get("confidence", [None])[0],
                tenant_keys=[params["tenant_key"][0]] if "tenant_key" in params and params["tenant_key"][0] else None,
            )
        if route == "/scheduled-scans":
            tenant = params.get("tenant_key", [None])[0]
            return 200, self._scheduled_scans_payload(tenant_keys=[tenant] if tenant else None)
        if route == "/domain-exposures":
            return 200, self._domain_exposures_payload(
                domain_id=int(params["domain_id"][0]) if "domain_id" in params and params["domain_id"][0] else None,
                source_name=params.get("source_name", [None])[0],
                source_class=params.get("source_class", [None])[0],
                confidence=params.get("confidence", [None])[0],
                limit=int(params.get("limit", ["100"])[0]),
                tenant_keys=[params["tenant_key"][0]] if "tenant_key" in params and params["tenant_key"][0] else None,
            )
        if route == "/relationships/graph":
            return 200, self._relationship_graph_payload(
                limit=int(params.get("limit", ["200"])[0]),
                tenant_keys=[params["tenant_key"][0]] if "tenant_key" in params and params["tenant_key"][0] else None,
            )
        if route == "/trends/findings":
            return 200, self._finding_trends_payload(
                days=int(params.get("days", ["30"])[0]),
                tenant_keys=[params["tenant_key"][0]] if "tenant_key" in params and params["tenant_key"][0] else None,
            )
        if route == "/comparisons/organizations":
            tenant = params.get("tenant_key", [None])[0]
            return 200, self._organization_comparison_payload(tenant_keys=[tenant] if tenant else None)
        if route == "/remediation/suggestions":
            tenant = params.get("tenant_key", [None])[0]
            return 200, self._remediation_suggestions_payload(tenant_keys=[tenant] if tenant else None)
        return 404, {"error": f"Unknown route: {route}"}


def create_app(database_url: str) -> FastAPI:
    settings = Settings(database_url=database_url)
    service = OrgscanApiService(database_url)
    app = FastAPI(title="orgscan", version="0.1.0")
    reader_auth = auth_dependency(settings, required_role="reader")

    def _tenant_keys(auth: AuthContext, tenant_key: str | None) -> list[str] | None:
        return resolve_requested_tenants(auth, tenant_key)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/auth/context")
    def auth_context(
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return {
            "auth": serialize_auth_context(auth),
            "requested_tenant": tenant_key,
            "effective_tenants": _tenant_keys(auth, tenant_key),
        }

    @app.get("/summary")
    def summary(
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._summary_payload(tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/findings")
    def findings(
        limit: int = Query(50, ge=1, le=500),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._findings_payload(
            limit=limit,
            status=status,
            severity=severity,
            category=category,
            confidence=confidence,
            tenant_keys=_tenant_keys(auth, tenant_key),
        )

    @app.get("/scheduled-scans")
    def scheduled_scans(
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._scheduled_scans_payload(tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/domain-exposures")
    def domain_exposures(
        limit: int = Query(100, ge=1, le=500),
        domain_id: int | None = None,
        source_name: str | None = None,
        source_class: str | None = None,
        confidence: str | None = None,
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._domain_exposures_payload(
            domain_id=domain_id,
            source_name=source_name,
            source_class=source_class,
            confidence=confidence,
            limit=limit,
            tenant_keys=_tenant_keys(auth, tenant_key),
        )

    @app.get("/relationships/graph")
    def relationships(
        limit: int = Query(200, ge=1, le=1000),
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._relationship_graph_payload(limit=limit, tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/trends/findings")
    def trends(
        days: int = Query(30, ge=1, le=365),
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._finding_trends_payload(days=days, tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/comparisons/organizations")
    def organization_comparisons(
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._organization_comparison_payload(tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/remediation/suggestions")
    def remediation_suggestions_route(
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> dict[str, object]:
        return service._remediation_suggestions_payload(tenant_keys=_tenant_keys(auth, tenant_key))

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(
        limit: int = Query(100, ge=1, le=500),
        days: int = Query(30, ge=1, le=365),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        tenant_key: str | None = None,
        auth: AuthContext = Depends(reader_auth),
    ) -> HTMLResponse:
        return HTMLResponse(
            service._dashboard_html(
                limit=limit,
                days=days,
                status=status,
                severity=severity,
                category=category,
                confidence=confidence,
                tenant_keys=_tenant_keys(auth, tenant_key),
            )
        )

    return app


def serve_api(database_url: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    uvicorn.run(create_app(database_url), host=host, port=port, log_level="info")
