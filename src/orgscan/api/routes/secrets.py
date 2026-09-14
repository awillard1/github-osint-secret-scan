"""Explicit secret metadata and audited reveal endpoints."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from orgscan.security_context import current_auth, AuthorizationError
from orgscan.services.secret_evidence import SecretEvidenceService

HEADERS = {'Cache-Control': 'no-store, private, max-age=0', 'Pragma': 'no-cache', 'Expires': '0',
           'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}


def create_secret_router(settings):
    router = APIRouter()
    service = SecretEvidenceService(settings)
    def actor():
        auth = current_auth.get()
        if auth is None or not auth.authenticated:
            raise HTTPException(401, 'Authentication required', headers=HEADERS)
        return auth

    @router.get('/findings/{finding_id}/secrets')
    def metadata(finding_id: int):
        try:
            return JSONResponse(service.metadata(finding_id, actor()), headers=HEADERS)
        except AuthorizationError:
            raise HTTPException(403, 'Secret evidence access denied', headers=HEADERS) from None

    @router.post('/findings/{finding_id}/secrets/{secret_id}/reveal')
    def reveal(finding_id: int, secret_id: int):
        try:
            value = service.reveal(finding_id, secret_id, actor())
            return JSONResponse({'secret_id': secret_id, 'value': value}, headers=HEADERS)
        except AuthorizationError:
            raise HTTPException(403, 'Secret reveal access denied', headers=HEADERS) from None
        except ValueError:
            raise HTTPException(503, 'Protected secret is unavailable', headers=HEADERS) from None
    return router
