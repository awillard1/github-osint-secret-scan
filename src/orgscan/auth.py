from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from fastapi import Header, HTTPException, status

from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage

ROLE_LEVELS = {
    "reader": 1,
    "analyst": 2,
    "admin": 3,
}


@dataclass(frozen=True)
class AuthContext:
    name: str
    role: str
    tenants: tuple[str, ...]
    authenticated: bool = False
    source: str = "local"
    user_id: int | None = None

    def allows_role(self, required_role: str) -> bool:
        return ROLE_LEVELS.get(self.role, 0) >= ROLE_LEVELS.get(required_role, 0)

    def allows_tenant(self, tenant_key: str | None) -> bool:
        if "*" in self.tenants:
            return True
        if tenant_key is None:
            return False
        return tenant_key in self.tenants


def hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def load_auth_contexts(settings: Settings) -> dict[str, AuthContext]:
    if not settings.api_tokens_json.strip():
        return {}
    try:
        payload = json.loads(settings.api_tokens_json)
    except json.JSONDecodeError as exc:
        raise ValueError("ORGSCAN_API_TOKENS_JSON must be valid JSON.") from exc
    if not isinstance(payload, list):
        raise ValueError("ORGSCAN_API_TOKENS_JSON must be a JSON list.")

    contexts: dict[str, AuthContext] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError("Each auth token entry must be a JSON object.")
        token = str(entry.get("token") or "").strip()
        role = str(entry.get("role") or "reader").strip().lower()
        tenants = entry.get("tenants")
        if role not in ROLE_LEVELS:
            raise ValueError(f"Unsupported auth role: {role}")
        if not token:
            raise ValueError("Each auth token entry must include a token.")
        if tenants == "*" or tenants is None:
            normalized_tenants = ("*",)
        elif isinstance(tenants, list):
            normalized_tenants = tuple(str(value).strip() for value in tenants if str(value).strip()) or ("*",)
        else:
            raise ValueError("Auth token tenants must be '*' or a JSON list of tenant keys.")
        contexts[token] = AuthContext(
            name=str(entry.get("name") or role),
            role=role,
            tenants=normalized_tenants,
            authenticated=True,
            source="env-token",
        )
    return contexts


def create_db_session_token(
    storage: Storage,
    *,
    username: str,
    session_name: str | None = None,
    role: str | None = None,
    tenants: list[str] | None = None,
    expires_at: datetime | None = None,
) -> tuple[object, str]:
    import secrets

    user = storage.get_user_by_username(username)
    if user is None:
        raise ValueError(f"Unknown user: {username}")
    membership_rows = storage.list_user_tenant_memberships(user.id)
    resolved_tenants = tenants or [row.tenant_key for row in membership_rows]
    if not resolved_tenants:
        resolved_tenants = ["*"]
    resolved_role = role or _highest_role([row.role for row in membership_rows] or ["reader"])
    if resolved_role not in ROLE_LEVELS:
        raise ValueError(f"Unsupported auth role: {resolved_role}")
    raw_token = secrets.token_urlsafe(32)
    session_row = storage.create_user_session(
        user.id,
        hash_token(raw_token),
        session_name=session_name,
        role=resolved_role,
        tenant_scopes_json=resolved_tenants,
        expires_at=expires_at,
    )
    return session_row, raw_token


def auth_dependency(settings: Settings, *, required_role: str = "reader"):
    env_contexts = load_auth_contexts(settings)

    def _resolve_context(x_orgscan_token: str | None = Header(default=None, alias="X-Orgscan-Token")) -> AuthContext:
        if x_orgscan_token and x_orgscan_token in env_contexts:
            context = env_contexts[x_orgscan_token]
            if not context.allows_role(required_role):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for requested resource.")
            return context

        db_context = _load_db_auth_context(settings, x_orgscan_token)
        if db_context is not None:
            if not db_context.allows_role(required_role):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for requested resource.")
            return db_context

        if not env_contexts and not _database_auth_enabled(settings):
            return AuthContext(name="local", role="admin", tenants=("*",), authenticated=False)
        if not x_orgscan_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Orgscan-Token header.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Orgscan-Token.")

    return _resolve_context


def resolve_requested_tenants(auth: AuthContext, requested_tenant: str | None = None) -> list[str] | None:
    if "*" in auth.tenants:
        if requested_tenant:
            return [requested_tenant]
        return None
    if requested_tenant:
        if not auth.allows_tenant(requested_tenant):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requested tenant is not permitted.")
        return [requested_tenant]
    return list(auth.tenants)


def serialize_auth_context(auth: AuthContext) -> dict[str, Any]:
    return {
        "name": auth.name,
        "role": auth.role,
        "tenants": list(auth.tenants),
        "authenticated": auth.authenticated,
        "source": auth.source,
        "user_id": auth.user_id,
    }


def _database_auth_enabled(settings: Settings) -> bool:
    try:
        init_db(settings.database_url)
        session_factory = create_session_factory(settings.database_url)
        with session_factory() as session:
            storage = Storage(session)
            return bool(storage.list_user_sessions()) or bool(storage.list_user_tenant_memberships())
    except Exception:
        return False


def _load_db_auth_context(settings: Settings, raw_token: str | None) -> AuthContext | None:
    if not raw_token:
        return None
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        session_row = storage.get_user_session_by_hash(hash_token(raw_token))
        if session_row is None or session_row.revoked_at is not None:
            return None
        if session_row.expires_at is not None and _normalize_datetime(session_row.expires_at) < datetime.now(UTC):
            return None
        user = session_row.user
        if user is None or not user.is_active:
            return None
        storage.touch_user_session(session_row)
        session.commit()
        tenants = tuple(str(value) for value in (session_row.tenant_scopes_json or ["*"])) or ("*",)
        return AuthContext(
            name=user.username,
            role=session_row.role,
            tenants=tenants,
            authenticated=True,
            source="db-session",
            user_id=user.id,
        )


def _highest_role(roles: list[str]) -> str:
    return max(roles, key=lambda role: ROLE_LEVELS.get(role, 0))


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
