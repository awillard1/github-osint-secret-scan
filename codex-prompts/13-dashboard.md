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


# Phase 13 — Operator dashboard redesign

Goal: optimize the existing server-rendered dashboard for operator decisions.

Do not introduce React/Vue unless the existing stack cannot reasonably meet the requirements.

Dashboard priorities:
- new findings;
- highest risk;
- regressions;
- active scans;
- failed scans;
- newly discovered assets;
- findings requiring triage.

Tasks:
1. Use services rather than placing business queries in templates/routes.
2. Add summary cards/queues and drill-downs.
3. Preserve artifact upload and existing triage actions.
4. Enforce the browser authorization created in the prior phase.
5. Ensure all displayed user-controlled data is escaped appropriately.
6. Add API/HTML tests for key views and permissions.

Acceptance criteria:
- dashboard answers the operational questions above;
- no duplicated risk/lifecycle logic in templates;
- full tests pass.
