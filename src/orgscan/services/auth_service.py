"""Token and browser sessions share existing users, roles and revocation state."""
from datetime import UTC, datetime, timedelta
import re
import secrets

from orgscan.auth import create_db_session_token, hash_token, load_auth_contexts, _normalize_datetime
from orgscan.config import Settings
from orgscan.db import create_session_factory
from orgscan.repositories import Storage
from orgscan.security_context import AuthContext, AuthorizationError, ROLE_LEVELS


def _intersect(saved, current):
    if "*" in saved:
        return tuple(current)
    if "*" in current:
        return tuple(saved)
    return tuple(scope for scope in saved if scope in current)


def _capped_role(*roles):
    return min(roles, key=lambda role: ROLE_LEVELS.get(role, 0))


class AuthService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.factory = create_session_factory(settings.database_url)
        self.env_contexts = load_auth_contexts(settings)

    def enabled(self) -> bool:
        if self.settings.api_auth_required or self.env_contexts:
            return True
        with self.factory() as session:
            return Storage(session).has_auth_users()

    def _context_for_row(self, storage, row, *, allow_browser=True):
        now = datetime.now(UTC)
        if row is None or row.revoked_at is not None or (row.expires_at is not None and _normalize_datetime(row.expires_at) <= now):
            return None
        if row.user is None or not row.user.is_active or row.role not in ROLE_LEVELS:
            return None
        metadata = row.metadata_json or {}
        if metadata.get("kind") == "browser":
            if not allow_browser:
                return None
            if metadata.get("parent_env_hash"):
                parent = next((context for token,context in self.env_contexts.items()
                               if secrets.compare_digest(hash_token(token),metadata["parent_env_hash"])),None)
            else:
                parent = self._context_for_row(storage,storage.get_user_session(metadata.get("parent_session_id")),allow_browser=False)
            if parent is None:
                return None
            scopes = _intersect(row.tenant_scopes_json or [], parent.tenants)
            role = _capped_role(row.role,parent.role)
            source = "browser-session"
        else:
            memberships = {item.tenant_key:item.role for item in storage.list_user_tenant_memberships(row.user_id) if item.role in ROLE_LEVELS}
            saved = row.tenant_scopes_json or []
            scopes = _intersect(saved, tuple(memberships))
            roles = [memberships.get(scope,memberships.get("*","reader")) for scope in scopes]
            role = _capped_role(row.role,*roles) if roles else "reader"
            source = "db-session"
        if not scopes:
            return None
        return AuthContext(row.user.username,role,tuple(scopes),True,source,row.user_id)

    def resolve(self, raw_token: str | None, *, browser=False) -> AuthContext | None:
        if not raw_token:
            return None
        if not browser and raw_token in self.env_contexts:
            return self.env_contexts[raw_token]
        with self.factory() as session:
            storage = Storage(session)
            row = storage.get_user_session_by_hash(hash_token(raw_token))
            if browser and (row is None or (row.metadata_json or {}).get("kind") != "browser"):
                return None
            context = self._context_for_row(storage,row)
            if context is not None:
                storage.touch_user_session(row)
                session.commit()
            return context

    def login(self, credential: str) -> tuple[str,str]:
        context = self.resolve(credential)
        if context is None or context.source == "browser-session":
            raise AuthorizationError("Invalid or expired session token")
        raw_token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.factory() as session:
            storage = Storage(session)
            metadata = {"kind":"browser", "csrf_hash":hash_token(csrf)}
            if context.source == "env-token":
                user, _ = storage.get_or_create_user(f"env:{context.name}")
                metadata["parent_env_hash"] = hash_token(credential)
            else:
                parent = storage.get_user_session_by_hash(hash_token(credential))
                user = parent.user
                metadata["parent_session_id"] = parent.id
            if not user.is_active:
                raise AuthorizationError("Invalid or expired session token")
            storage.create_user_session(
                user.id,hash_token(raw_token),session_name="Browser",role=context.role,
                tenant_scopes_json=list(context.tenants),
                expires_at=datetime.now(UTC)+timedelta(seconds=self.settings.browser_session_seconds),
                metadata_json=metadata,
            )
            session.commit()
        return raw_token,csrf

    def valid_csrf(self, browser_token: str, supplied: str | None) -> bool:
        if not supplied:
            return False
        with self.factory() as session:
            row = Storage(session).get_user_session_by_hash(hash_token(browser_token))
            expected = (row.metadata_json or {}).get("csrf_hash", "") if row is not None else ""
            return bool(expected) and secrets.compare_digest(hash_token(supplied),expected)

    def logout(self, browser_token: str) -> None:
        with self.factory() as session:
            storage = Storage(session)
            row = storage.get_user_session_by_hash(hash_token(browser_token))
            if row is not None:
                storage.revoke_user_session(row.id)
                session.commit()

    @staticmethod
    def require_admin(context: AuthContext):
        if not context.allows_role("admin") or "*" not in context.tenants:
            raise AuthorizationError("Global administrator role is required for user administration")

    def users(self, context):
        self.require_admin(context)
        with self.factory() as session:
            storage = Storage(session)
            return [{"username":user.username,"email":user.email,"is_active":user.is_active,
                     "memberships":[{"tenant":m.tenant_key,"role":m.role} for m in storage.list_user_tenant_memberships(user.id)]}
                    for user in storage.list_users()]

    def create_user(self, context, username, *, email=None):
        self.require_admin(context)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}",username):
            raise ValueError("Invalid username")
        with self.factory() as session:
            storage = Storage(session)
            if storage.get_user_by_username(username) is not None:
                raise ValueError("User already exists")
            storage.create_user(username,email=email)
            session.commit()
        return {"username":username}

    def grant(self, context, username, tenant, role):
        self.require_admin(context)
        if role not in ROLE_LEVELS or not tenant or len(tenant) > 255:
            raise ValueError("Invalid tenant or role")
        with self.factory() as session:
            storage = Storage(session)
            user = storage.get_user_by_username(username)
            if user is None:
                raise ValueError("User does not exist")
            storage.grant_tenant_membership(user.id,tenant,role)
            session.commit()
        return {"username":username,"tenant":tenant,"role":role}

    def set_active(self, context, username, active):
        self.require_admin(context)
        with self.factory() as session:
            Storage(session).set_user_active(username,active)
            session.commit()
        return {"username":username,"is_active":active}

    def issue_session(self, context, username, *, tenants=None):
        self.require_admin(context)
        with self.factory() as session:
            row, token = create_db_session_token(Storage(session),username=username,tenants=tenants,
                                                 expires_at=datetime.now(UTC)+timedelta(days=1))
            session.commit()
            return {"session_id":row.id,"token":token,"expires_at":row.expires_at.isoformat()}
