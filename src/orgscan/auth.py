from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException, status

from orgscan.config import Settings

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

    def allows_role(self, required_role: str) -> bool:
        return ROLE_LEVELS.get(self.role, 0) >= ROLE_LEVELS.get(required_role, 0)

    def allows_tenant(self, tenant_key: str | None) -> bool:
        if "*" in self.tenants:
            return True
        if tenant_key is None:
            return False
        return tenant_key in self.tenants


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
        )
    return contexts


def auth_dependency(settings: Settings, *, required_role: str = "reader"):
    contexts = load_auth_contexts(settings)

    def _resolve_context(x_orgscan_token: str | None = Header(default=None, alias="X-Orgscan-Token")) -> AuthContext:
        if not contexts:
            return AuthContext(name="local", role="admin", tenants=("*",), authenticated=False)
        if not x_orgscan_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Orgscan-Token header.")
        context = contexts.get(x_orgscan_token)
        if context is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Orgscan-Token.")
        if not context.allows_role(required_role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for requested resource.")
        return context

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
    }
