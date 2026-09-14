from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from fastapi import Header, HTTPException

from orgscan.config import Settings
from orgscan.db import prepare_database
from orgscan.repositories import Storage

from orgscan.security_context import AuthContext, ROLE_LEVELS


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
            normalized_tenants = tuple(str(value).strip() for value in tenants if str(value).strip())
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
    memberships = {row.tenant_key: row.role for row in membership_rows}
    if any(role not in ROLE_LEVELS for role in memberships.values()):
        raise ValueError("Invalid stored membership role")
    resolved_tenants = tenants if tenants is not None else list(memberships)
    if not resolved_tenants or any(tenant not in memberships and "*" not in memberships for tenant in resolved_tenants):
        raise ValueError("Session scopes must have assigned tenant memberships")
    role_cap = min((memberships.get(tenant, memberships.get("*", "reader")) for tenant in resolved_tenants), key=ROLE_LEVELS.get)
    resolved_role = role or role_cap
    if ROLE_LEVELS.get(resolved_role, 0) > ROLE_LEVELS[role_cap]:
        raise ValueError("Session role exceeds the user's tenant memberships")
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
    from orgscan.services.auth_service import AuthService
    from orgscan.security_context import LOCAL_CONTEXT
    prepare_database(settings)
    service = AuthService(settings)

    def _resolve_context(x_orgscan_token: str | None = Header(default=None, alias="X-Orgscan-Token")) -> AuthContext:
        context = service.resolve(x_orgscan_token)
        if context is None:
            if x_orgscan_token is not None or service.enabled():
                raise HTTPException(status_code=401, detail="Invalid or missing X-Orgscan-Token")
            context = LOCAL_CONTEXT
        if not context.allows_role(required_role):
            raise HTTPException(status_code=403, detail="Insufficient role for requested resource")
        return context
    return _resolve_context


def resolve_requested_tenants(auth: AuthContext, requested_tenant: str | None = None) -> list[str] | None:
    if "*" in auth.tenants:
        if requested_tenant:
            return [requested_tenant]
        return None
    if requested_tenant:
        if not auth.allows_tenant(requested_tenant):
            raise HTTPException(status_code=403, detail="Requested tenant is not permitted.")
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


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
