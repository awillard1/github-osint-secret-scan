You are working in the `github-osint-secret-scan` / `orgscan` repository.

Before editing:
- read `AGENTS.md`;
- read `docs/architecture.md`;
- read `docs/development-plan.md`;
- inspect the current implementation and tests;
- run or inspect the relevant baseline tests;
- check git status and preserve unrelated user changes.

Do not blindly follow filenames in this prompt if the current code has evolved. Reuse existing abstractions when they already satisfy the requirement.

Work only on this phase. Keep the result mergeable. Do not begin the next phase.

At completion:
- run focused tests;
- run the full test suite;
- inspect the diff;
- update relevant documentation/roadmap;
- summarize exactly what changed, tests run, compatibility impact, and remaining risks.


# Phase 11 — Interactive authentication and user administration

Goal: complete authenticated browser operation using existing auth/role/tenant concepts.

Tasks:
1. Audit current `auth.py`, API token/session support, and tenant scope.
2. Reuse existing auth models rather than creating parallel user/session systems.
3. Implement login/logout and secure browser sessions.
4. Add expiry/revocation and secure cookie flags appropriate for deployment configuration.
5. Add CSRF protection/strategy for browser state-changing actions.
6. Add user administration and role/tenant assignment appropriate to existing roles.
7. Ensure HTML dashboard routes enforce authorization.
8. Keep API token support.
9. Add authorization matrix tests.

Acceptance criteria:
- Browser and API authentication produce a common authorization context.
- Reader/analyst/admin boundaries are enforced server-side.
- Tenant isolation does not rely on UI filtering.
- Full tests pass.
