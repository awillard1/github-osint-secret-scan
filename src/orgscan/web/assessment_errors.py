"""Operator-friendly validation, without reflecting submitted form values."""
from fastapi.routing import APIRoute
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.responses import HTMLResponse
from orgscan.web.assessments import page,esc


class AssessmentRoute(APIRoute):
    def get_route_handler(self):
        handler=super().get_route_handler()
        async def wrapped(request):
            try:return await handler(request)
            except (HTTPException,RequestValidationError) as error:
                if not request.url.path.startswith('/dashboard/'):raise
                if isinstance(error,RequestValidationError):
                    code=422;message='Check the form fields and try again. A required value is missing or has an invalid format.'
                else:
                    code=error.status_code
                    # Deliberately avoid exception/input text at the presentation boundary.
                    message={404:'This assessment resource was not found.',403:'Your role or tenant does not permit this action.',413:'This upload exceeds the allowed size.',422:'These options could not be saved. Check the selected scope, dates, profile and tool readiness.'}.get(code,'The action could not be completed. Review configuration and retry.')
                return HTMLResponse(page('Action needs attention','<p role="alert">'+esc(message)+'</p><p>Your existing assessment data is retained. Use your browser’s Back button to review the form.</p>'),status_code=code,headers={'Cache-Control':'no-store'})
        return wrapped
