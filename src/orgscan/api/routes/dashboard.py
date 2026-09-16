from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from orgscan.reporting import _render_html_page
from orgscan.services.dashboard_service import DashboardService, QUEUE_LABELS
from orgscan.web.operator_dashboard import render_operator_queues


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
        body = render_operator_queues(payload, selected=name)
        if offset:
            body += f'<a href="?days={days}&offset={max(0, offset-50)}">Previous</a> '
        if offset + 50 < payload['queues'][name]['count']:
            body += f'<a href="?days={days}&offset={offset+50}">Next</a>'
        return _render_html_page(QUEUE_LABELS[name], body)
    return router
