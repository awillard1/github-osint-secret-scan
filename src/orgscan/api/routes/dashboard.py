from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from orgscan.services.dashboard_service import DashboardService, QUEUE_LABELS
from orgscan.web.render import render


def create_operator_router(session_factory):
    router = APIRouter()
    service = DashboardService(session_factory)

    @router.get("/operator/overview")
    def overview(days: int = Query(7, ge=1, le=365), limit: int = Query(10, ge=1, le=500), offset: int = Query(0, ge=0)):
        return service.overview(days=days, limit=limit, offset=offset)

    @router.get("/dashboard/queues/{name}", response_class=HTMLResponse)
    def queue(name: str, days: int = Query(7, ge=1, le=365), offset: int = Query(0, ge=0)):
        if name not in QUEUE_LABELS:
            raise HTTPException(404, "Unknown operator queue")
        payload = service.overview(days=days, limit=50, offset=offset)
        return HTMLResponse(render("pages/queues.html", title=QUEUE_LABELS[name], active_section="queues", queue=payload["queues"][name], days=days, offset=offset))
    return router
