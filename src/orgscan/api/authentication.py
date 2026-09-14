"""ASGI authentication and browser CSRF enforcement for every HTTP adapter."""
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError

from orgscan.security_context import AuthorizationError, current_auth, current_csrf, LOCAL_CONTEXT

SESSION_COOKIE = "orgscan_session"
CSRF_COOKIE = "orgscan_csrf"
LOGIN_COOKIE = "orgscan_login_csrf"


def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return origin is None or origin == f"{request.url.scheme}://{request.url.netloc}"


def replay_body(body, original_receive=None):
    sent = False
    async def receive():
        nonlocal sent
        if sent:
            return await original_receive() if original_receive is not None else {"type":"http.disconnect"}
        sent = True
        return {"type":"http.request","body":body,"more_body":False}
    return receive


class AuthenticationMiddleware:
    def __init__(self, app, auth_service):
        self.app, self.auth = app, auth_service

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in {"/health","/login"}:
            return await self.app(scope,receive,send)
        request = Request(scope,receive)
        header = request.headers.get("x-orgscan-token")
        authorization = request.headers.get("authorization")
        if authorization and not header:
            header = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        cookie = request.cookies.get(SESSION_COOKIE)
        using_cookie = not (header or authorization) and bool(cookie)
        try:
            enabled = await run_in_threadpool(self.auth.enabled)
            context = await run_in_threadpool(self.auth.resolve, cookie if using_cookie else header, browser=using_cookie)
        except (SQLAlchemyError, RuntimeError):
            return await JSONResponse({"detail":"Authentication state is unavailable"},503)(scope,receive,send)
        if context is None:
            if enabled or cookie or header is not None or authorization is not None:
                response = (RedirectResponse("/login",303) if request.method == "GET" and
                            (request.url.path == "/" or request.url.path.startswith("/dashboard")) and not header
                            else JSONResponse({"detail":"Authentication required"},401))
                return await response(scope,receive,send)
            context = LOCAL_CONTEXT
        required = "reader" if request.method in {"GET","HEAD","OPTIONS"} or request.url.path == "/logout" else "analyst"
        if request.url.path.startswith(("/users","/dashboard/users")):
            required = "admin"
        if not context.allows_role(required):
            return await JSONResponse({"detail":"Insufficient role"},403)(scope,receive,send)
        csrf = request.cookies.get(CSRF_COOKIE) if using_cookie else None
        if using_cookie and request.method not in {"GET","HEAD","OPTIONS"}:
            supplied = request.headers.get("x-csrf-token")
            if not supplied and request.headers.get("content-type", "").split(";",1)[0] in {"application/x-www-form-urlencoded","multipart/form-data"}:
                chunks, total = [], 0
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body",b"")
                    total += len(chunk)
                    if total > 11_000_000:
                        return await JSONResponse({"detail":"Request body is too large"},413)(scope,receive,send)
                    chunks.append(chunk)
                    if not message.get("more_body",False):
                        break
                body = b"".join(chunks)
                try:
                    form = await Request(scope,replay_body(body)).form()
                    value = form.get("csrf_token")
                    supplied = value if isinstance(value,str) else None
                    await form.close()
                except Exception:
                    supplied = None
                receive = replay_body(body, receive)
            if not same_origin(request) or not await run_in_threadpool(self.auth.valid_csrf,cookie,supplied):
                return await JSONResponse({"detail":"Invalid CSRF token or origin"},403)(scope,receive,send)
        if csrf and not await run_in_threadpool(self.auth.valid_csrf,cookie,csrf):
            csrf = None
        auth_marker, csrf_marker = current_auth.set(context), current_csrf.set(csrf)
        scope.setdefault("state",{})["auth"] = context
        async def private_response(message):
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers",[]),(b"cache-control",b"no-store"),(b"x-frame-options",b"DENY")]
            await send(message)
        try:
            await self.app(scope,receive,private_response)
        except AuthorizationError:
            await JSONResponse({"detail":"The operation is not permitted in this tenant scope"},403)(scope,receive,send)
        finally:
            current_csrf.reset(csrf_marker)
            current_auth.reset(auth_marker)
