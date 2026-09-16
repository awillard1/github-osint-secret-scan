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


# Phase 16 — `orgscan doctor` and release hardening

Goal: make local/production readiness diagnosable and prepare the project for a stable release.

Implement `orgscan doctor`.

Check:
- orgscan version;
- Python version;
- database connectivity;
- Alembic migration/current revision;
- required directories/writability;
- Redis/RQ configuration and connectivity when enabled;
- GitHub token configured state (never print token);
- scanner registry readiness and versions;
- provider readiness;
- relevant configuration warnings.

Tasks:
1. Make doctor non-destructive.
2. Human-readable default output plus JSON output if consistent with CLI conventions.
3. Distinguish required failures from optional-tool warnings in exit status.
4. Clean obvious dependency/config duplication.
5. Review installation/bootstrap docs.
6. Add an end-to-end local smoke test path.
7. Produce a `docs/release-readiness.md` checklist covering upgrade, migrations, secrets, backups, auth, worker/API startup, and test commands.

Acceptance criteria:
- a new operator can identify missing dependencies/config with one command;
- doctor never leaks token/secret values;
- complete tests pass;
- documentation is internally consistent.
