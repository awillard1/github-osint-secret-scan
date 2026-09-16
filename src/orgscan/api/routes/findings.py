from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from orgscan.api.schemas import (
    DashboardFindingWorkflowRequest,
    FindingDecisionRequest,
    FindingReopenRequest,
    FindingUpdateRequest,
)

if TYPE_CHECKING:
    from orgscan.api import OrgscanApiService


def create_finding_router(service: OrgscanApiService) -> APIRouter:
    """Bind the JSON and browser finding adapters to the application facade."""
    router = APIRouter()

    @router.get("/findings")
    def findings(
        limit: int = Query(50, ge=1, le=500),
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        confidence: str | None = None,
        source_tool: str | None = None,
        lifecycle_state: str | None = None,
        triage_state: str | None = None,
        organization_id: int | None = None,
        domain_id: int | None = None,
        repository_id: int | None = None,
        account_id: int | None = None,
        scan_job_id: int | None = None,
        risk_score_min: float | None = None,
        risk_score_max: float | None = None,
        detected_after: datetime | None = None,
        detected_before: datetime | None = None,
        high_signal_only: bool = False,
        min_confidence: str = Query("likely", pattern="^(verified|likely|heuristic|unverified)$"),
    ) -> dict[str, object]:
        return service._findings_payload(
            limit=limit,
            status=status,
            severity=severity,
            category=category,
            confidence=confidence,
            source_tool=source_tool,
            lifecycle_state=lifecycle_state,
            triage_state=triage_state,
            organization_id=organization_id,
            domain_id=domain_id,
            repository_id=repository_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
            detected_after=detected_after,
            detected_before=detected_before,
            high_signal_only=high_signal_only,
            min_confidence=min_confidence,
        )

    @router.get("/findings/{finding_id}")
    def finding_detail(finding_id: int) -> dict[str, object]:
        payload = service._finding_payload(finding_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return payload

    @router.patch("/findings/{finding_id}")
    def update_finding(finding_id: int, payload: FindingUpdateRequest) -> dict[str, object]:
        result = service._update_finding_triage(finding_id, payload)
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @router.post("/findings/{finding_id}/suppress")
    def suppress_finding(finding_id: int, payload: FindingDecisionRequest) -> dict[str, object]:
        result = service._apply_finding_decision(finding_id, payload, status="suppressed")
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @router.post("/findings/{finding_id}/accept-risk")
    def accept_risk_finding(finding_id: int, payload: FindingDecisionRequest) -> dict[str, object]:
        result = service._apply_finding_decision(finding_id, payload, status="accepted_risk")
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @router.post("/findings/{finding_id}/reopen")
    def reopen_finding(finding_id: int, payload: FindingReopenRequest) -> dict[str, object]:
        result = service._reopen_finding(finding_id, payload)
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @router.get("/findings/{finding_id}/evidence")
    def finding_evidence(finding_id: int) -> dict[str, object]:
        payload = service._finding_payload(finding_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {"finding_id": finding_id, "evidence": payload["evidence"]}

    @router.post("/dashboard/findings/{finding_id}/workflow", response_class=HTMLResponse)
    async def dashboard_finding_workflow(
        finding_id: int,
        action: str = Form(...),
        owner: str | None = Form(None),
        note: str | None = Form(None),
        triage_state: str | None = Form(None),
        limit: int = Form(100),
        days: int = Form(30),
        status: str | None = Form(None),
        severity: str | None = Form(None),
        category: str | None = Form(None),
        confidence: str | None = Form(None),
        high_signal_only: bool = Form(False),
        min_confidence: str = Form("likely"),
        return_to_detail: bool = Form(False),
    ) -> Response:
        try:
            result = service._dashboard_finding_workflow(
                finding_id,
                DashboardFindingWorkflowRequest(
                    action=action,
                    owner=owner,
                    note=note,
                    triage_state=triage_state,
                ),
            )
            if result is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            if return_to_detail:
                return RedirectResponse(f"/dashboard/findings/{finding_id}", status_code=303)
            return HTMLResponse(
                service._dashboard_html(
                    limit=limit,
                    days=days,
                    status=status,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                    high_signal_only=high_signal_only,
                    min_confidence=min_confidence,
                    finding_action_result=result["finding"],
                )
            )
        except HTTPException as exc:
            return HTMLResponse(
                service._dashboard_html(
                    limit=limit,
                    days=days,
                    status=status,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                    high_signal_only=high_signal_only,
                    min_confidence=min_confidence,
                    finding_action_error=str(exc.detail),
                ),
                status_code=exc.status_code,
            )

    return router
