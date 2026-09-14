"""Transport-independent authorization context propagated to application services."""
from contextvars import ContextVar
from dataclasses import dataclass

ROLE_LEVELS = {"reader": 1, "analyst": 2, "admin": 3}


@dataclass(frozen=True)
class AuthContext:
    name: str
    role: str
    tenants: tuple[str, ...]
    authenticated: bool = False
    source: str = "local"
    user_id: int | None = None

    def allows_role(self, required_role: str) -> bool:
        return required_role in ROLE_LEVELS and ROLE_LEVELS.get(self.role, 0) >= ROLE_LEVELS[required_role]

    def allows_tenant(self, tenant_key: str | None) -> bool:
        return "*" in self.tenants or (tenant_key is not None and tenant_key in self.tenants)


class AuthorizationError(PermissionError):
    pass


LOCAL_CONTEXT = AuthContext("local", "admin", ("*",))
current_auth: ContextVar[AuthContext | None] = ContextVar("orgscan_auth", default=None)
current_csrf: ContextVar[str | None] = ContextVar("orgscan_csrf", default=None)
