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


# Phase 5 — Incremental branch/history scan orchestration

Goal: select the minimum correct repository scope while preserving full-scan options.

Tasks:
1. Define branch policies (default-only, recent/selected, all as appropriate to existing product behavior).
2. Define full versus incremental versus history scan decision logic.
3. Record exactly which refs/commit range a scan covered.
4. Ensure failed scans do not commit successful checkpoints.
5. Handle force-push/ref deletion safely.
6. Integrate with ScanPlan.
7. Add deterministic synthetic-git tests for unchanged repo, new commits, new branch, deleted branch, force-push/divergence, first-ever scan.

Acceptance criteria:
- Unchanged targets can skip unnecessary expensive scanner execution when policy allows.
- Full/history mode still works explicitly.
- Scan records explain their scope.
- Full tests pass.
