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


# Phase 1 — API/CLI/service decomposition

Goal: reduce business logic inside presentation layers while preserving behavior.

Perform an incremental decomposition, not a flag-day rewrite.

Tasks:
1. Identify the highest-change, highest-duplication use cases currently shared or duplicated among `api.py`, `cli.py`, scheduler/queue code, and runner code.
2. Introduce `src/orgscan/services/` and extract coherent application services for those use cases.
3. Begin splitting FastAPI routes into `src/orgscan/api/` routers and CLI commands into `src/orgscan/cli/` modules only where doing so reduces central-module coupling.
4. Preserve `orgscan.cli:main` or provide a compatibility entry point so the console command does not break.
5. Preserve documented API routes.
6. Move tests toward service-level coverage for extracted business rules.
7. Avoid moving code solely to change filenames; each move should create a useful boundary.

Acceptance criteria:
- Existing CLI commands and API endpoints remain compatible.
- Extracted workflows have service tests.
- API/CLI adapters call services instead of duplicating business logic.
- No scanner behavior change.
- Full suite passes.

If the complete decomposition is too large for one safe change, complete the highest-value coherent slice and document the exact remaining decomposition items. Do not leave half-moved imports.
