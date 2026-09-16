"""Thin login, session and administrator adapters."""
import html
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from orgscan.api.authentication import SESSION_COOKIE, CSRF_COOKIE, LOGIN_COOKIE, same_origin
from orgscan.auth import serialize_auth_context
from orgscan.reporting import _render_html_page
from orgscan.security_context import AuthorizationError, current_auth, current_csrf, LOCAL_CONTEXT


class UserCreate(BaseModel):
    username: str = Field(min_length=1,max_length=64)
    email: str | None = Field(default=None,max_length=255)


class MembershipUpdate(BaseModel):
    tenant: str = Field(min_length=1,max_length=255)
    role: str = Field(pattern="^(reader|analyst|admin)$")
    capabilities: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    is_active: bool


class SessionCreate(BaseModel):
    tenants: list[str] | None = None


def create_auth_router(service):
    router = APIRouter()
    settings = service.settings

    def actor():
        return current_auth.get() or LOCAL_CONTEXT

    def call(function,*args,**kwargs):
        try:
            return function(*args,**kwargs)
        except ValueError as exc:
            raise HTTPException(400,str(exc)) from None

    @router.get("/login",response_class=HTMLResponse)
    def login_page():
        challenge = secrets.token_urlsafe(32)
        body = f'''<section><h1>Sign in</h1><p>Use a token issued by your orgscan administrator.</p>
        <form method="post" action="/login"><label>Session token <input type="password" name="token" required autocomplete="off"></label>
        <input type="hidden" name="csrf_token" value="{challenge}"><button>Sign in</button></form></section>'''
        response = HTMLResponse(_render_html_page("Sign in",body),headers={"Cache-Control":"no-store","X-Frame-Options":"DENY"})
        response.set_cookie(LOGIN_COOKIE,challenge,max_age=300,path="/login",httponly=True,secure=settings.browser_cookie_secure,samesite="strict")
        return response

    @router.post("/login")
    def login(request: Request, token: str = Form(""), csrf_token: str = Form("")):
        challenge = request.cookies.get(LOGIN_COOKIE,"")
        if not challenge or not secrets.compare_digest(challenge,csrf_token) or not same_origin(request):
            raise HTTPException(403,"Invalid login CSRF token or origin")
        try:
            browser,csrf = service.login(token)
        except AuthorizationError:
            raise HTTPException(401,"Invalid or expired session token") from None
        response = RedirectResponse("/dashboard",303,headers={"Cache-Control":"no-store"})
        for name,value in ((SESSION_COOKIE,browser),(CSRF_COOKIE,csrf)):
            response.set_cookie(name,value,max_age=settings.browser_session_seconds,httponly=True,secure=settings.browser_cookie_secure,samesite="strict",path="/")
        response.delete_cookie(LOGIN_COOKIE,path="/login")
        return response

    @router.post("/logout")
    def logout(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            service.logout(token)
        response = RedirectResponse("/login",303)
        for name in (SESSION_COOKIE,CSRF_COOKIE):
            response.delete_cookie(name,path="/")
        return response

    @router.get("/auth/me")
    def me():
        return {**serialize_auth_context(actor()),"csrf_token":current_csrf.get()}

    @router.get("/users")
    def users():
        return {"users":service.users(actor())}

    @router.post("/users",status_code=201)
    def create_user(payload: UserCreate):
        return call(service.create_user,actor(),payload.username,email=payload.email)

    @router.post("/users/{username}/memberships")
    def membership(username: str,payload: MembershipUpdate):
        return call(service.grant,actor(),username,payload.tenant,payload.role,capabilities=payload.capabilities)

    @router.patch("/users/{username}")
    def update_user(username: str,payload: UserUpdate):
        return call(service.set_active,actor(),username,payload.is_active)

    @router.post("/users/{username}/sessions")
    def issue_session(username: str,payload: SessionCreate):
        return JSONResponse(call(service.issue_session,actor(),username,tenants=payload.tenants),headers={"Cache-Control":"no-store"})

    @router.get("/dashboard/users",response_class=HTMLResponse)
    def browser_users():
        rows = []
        for user in service.users(actor()):
            name = html.escape(user["username"])
            path = quote(user["username"],safe="")
            memberships = ", ".join(f"{m['tenant']}: {m['role']}" for m in user["memberships"])
            rows.append(f'''<section><h2>{name}</h2><p>{html.escape(memberships)} · active: {user['is_active']}</p>
            <form method="post" action="/dashboard/users/{path}/membership"><label>Tenant <input name="tenant" required></label><label>Role <select name="role"><option>reader</option><option>analyst</option><option>admin</option></select></label><button>Assign role</button></form>
            <form method="post" action="/dashboard/users/{path}/active"><input type="hidden" name="active" value="{'false' if user['is_active'] else 'true'}"><button>{'Disable' if user['is_active'] else 'Enable'} user</button></form>
            <form method="post" action="/dashboard/users/{path}/session"><button>Issue 24-hour token</button></form></section>''')
        body = '<h1>User administration</h1><form method="post" action="/dashboard/users"><label>Username <input name="username" required></label><label>Email <input name="email" type="email"></label><button>Create user</button></form>'+"".join(rows)
        return HTMLResponse(_render_html_page("Users",body))

    @router.post("/dashboard/users")
    def browser_create(username: str = Form(...),email: str = Form("")):
        call(service.create_user,actor(),username,email=email or None)
        return RedirectResponse("/dashboard/users",303)

    @router.post("/dashboard/users/{username}/membership")
    def browser_membership(username: str,tenant: str = Form(...),role: str = Form(...)):
        call(service.grant,actor(),username,tenant,role)
        return RedirectResponse("/dashboard/users",303)

    @router.post("/dashboard/users/{username}/active")
    def browser_active(username: str,active: bool = Form(...)):
        call(service.set_active,actor(),username,active)
        return RedirectResponse("/dashboard/users",303)

    @router.post("/dashboard/users/{username}/session",response_class=HTMLResponse)
    def browser_session(username: str):
        issued = call(service.issue_session,actor(),username)
        return HTMLResponse(_render_html_page("Session issued",f"<h1>Copy this token now</h1><p>It expires in 24 hours and is shown only in this response.</p><pre>{html.escape(issued['token'])}</pre><a href='/dashboard/users'>Back to users</a>"))
    return router
