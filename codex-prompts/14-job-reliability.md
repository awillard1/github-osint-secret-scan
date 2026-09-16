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


# Phase 14 — Job reliability, retry and rate-limit handling

Goal: make queued/scheduled work robust while staying on RQ.

Tasks:
1. Classify logical jobs: DISCOVERY, REPO_SYNC, SCAN, DOMAIN_ENRICH, REPORT (and correlation if separate).
2. Define transient versus permanent errors.
3. Implement bounded exponential backoff for transient failures.
4. Treat explicit rate-limit responses as delayed retry conditions.
5. Avoid redoing completed work when jobs are retried (idempotency where practical).
6. Detect/recover stale/incomplete jobs conservatively.
7. Improve diagnostics without logging secrets.
8. Add fakeredis/mocked tests.

Acceptance criteria:
- missing scanner/config/invalid target are not retried forever;
- network/rate-limit failures can retry;
- successful checkpoint state is not duplicated/corrupted;
- full tests pass.
