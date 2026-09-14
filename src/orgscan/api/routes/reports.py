from typing import Literal
from fastapi import APIRouter, Query, Response
from orgscan.lifecycle import LifecycleState
from orgscan.services.report_service import ReportService


def create_report_router(session_factory):
    router = APIRouter()
    service = ReportService(session_factory)

    @router.get('/reports/export/{format}')
    def export(format: Literal['json','csv','html','sarif','pdf','pdf-executive','pdf-technical'],
               limit: int = Query(500,ge=1,le=500), lifecycle_state: LifecycleState | None = None):
        content = service.export_bytes(format,limit=limit,lifecycle_state=lifecycle_state)
        extension = 'pdf' if format.startswith('pdf') else format
        media = {'json':'application/json','csv':'text/csv','html':'text/html','sarif':'application/sarif+json','pdf':'application/pdf'}[extension]
        return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="orgscan.{extension}"','Cache-Control':'no-store'})
    return router
