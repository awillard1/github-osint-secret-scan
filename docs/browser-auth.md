# Browser authentication and user administration

The browser and JSON API now use `AuthService` and the existing `AuthContext`, user, membership and hashed-session tables. Login exchanges an existing API/session token for a separate browser session; there is no parallel password database. Existing `X-Orgscan-Token` credentials remain supported, and `Authorization: Bearer …` is accepted.

For local bootstrap:

```bash
orgscan init-db
orgscan create-user administrator
orgscan grant-tenant-role administrator '*' --role admin
orgscan create-session administrator --tenant '*' --expires-in-hours 24 --json
orgscan serve-api
```

Open `/login` and enter the issued token. A global administrator can use `/dashboard/users` or `/users` JSON routes to create users, assign tenant roles, enable/disable users and issue 24-hour tokens. Tokens appear only in the issuance response, which is not cacheable. The existing CLI can create/revoke sessions. Creating a user, configuring environment API tokens, or setting `ORGSCAN_API_AUTH_REQUIRED=true` enables HTTP authentication. With no auth configuration/users and that flag false, local development mode preserves the previous unauthenticated workflow. Generated configuration no longer supplies a known example token.

| Actor | Read data | Finding decisions / artifact scans | User administration |
| --- | --- | --- | --- |
| Reader | Authorized tenant scope | Denied | Denied |
| Analyst | Authorized tenant scope | Authorized scope | Denied |
| Tenant admin | Authorized tenant scope | Authorized scope | Denied |
| Global admin (`*`) | All data | All data | Allowed |

Database sessions cannot exceed current memberships. A token spanning different tenant roles uses the lowest applicable role; issue a token restricted to one tenant to use its higher role. Role reductions and disabled users take effect on subsequent requests. Empty/unassigned scope never becomes wildcard access. Browser sessions revalidate their parent API credential, so parent revocation/expiry or removal of an environment credential (after configuration reload) invalidates them.

Browser cookies are HttpOnly, host-only and SameSite=Strict. `ORGSCAN_BROWSER_SESSION_SECONDS` defaults to eight hours, bounded to 60 seconds–24 hours. Set `ORGSCAN_BROWSER_COOKIE_SECURE=true` when deploying behind HTTPS; false supports local HTTP development. Configure the server's trusted reverse proxy correctly so origin checks see the public scheme/host. Login has a separate CSRF challenge. Cookie-authenticated mutations require a session-bound CSRF token from generated POST forms or the `X-CSRF-Token` header; `/auth/me` exposes the token to authenticated same-origin clients. Origin mismatches are rejected. Header-token authentication does not rely on ambient cookies. Logout revokes the browser session and clears cookies. Protected responses use `Cache-Control: no-store` and deny framing.

Tenant enforcement is below presentation: request-owned SQLAlchemy sessions apply criteria to entity/finding/evidence/job/relationship reads, joins, lazy loads and counts. Writes are checked before flush. Finding services derive authorization from this session factory. A relationship must have both endpoints in scope. Explicit finding organization scope is authoritative; unassigned assets and jobs with insufficient ownership evidence are available only to wildcard operators. Scoped artifact scans require an existing authorized organization/repository; global operators provision assets. Python/CLI/worker sessions remain trusted local application interfaces, not remote authentication endpoints. The [SQLAlchemy loader-criteria mechanism](https://docs.sqlalchemy.org/en/20/orm/queryguide/api.html#sqlalchemy.orm.with_loader_criteria) is used by the storage policy.

Compatibility: configured auth is now enforced across JSON and HTML routes; missing credentials yield 401 (browser dashboard navigation redirects to login), insufficient roles yield 403, and inaccessible details yield 404. `/health`, `/login` and packaged `/static/` presentation assets are public; static assets contain no tenant data. Existing token imports and CLI commands remain. No schema migration is needed because browser/parent/CSRF metadata uses the existing session table. Automatic unscoped session issuance and over-privileged role overrides are rejected.

Tests cover role/tenant matrices, aggregate/detail/graph isolation, storage write enforcement, cookie flags, login CSRF, form/JSON/multipart CSRF, origin checks, expiry, parent revocation, membership reductions, administration and fail-closed storage errors. SQLite is exercised; PostgreSQL and production TLS/proxy configurations require deployment validation. Password login, recovery, MFA, SSO and login-abuse throttling are not implemented in this phase.
