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


# Phase 12 — Finding lifecycle and regression detection

Goal: model remediation and reappearance explicitly.

Target lifecycle includes:
NEW, REVIEWING, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, SUPPRESSED, REMEDIATED, REGRESSED.

Tasks:
1. Map existing triage/suppress/accept-risk behavior without breaking compatibility.
2. Add validated transitions and an audit/history record.
3. Track first_seen, last_seen, remediated_at where appropriate.
4. When a remediated fingerprint reappears in a later scan, classify/record regression.
5. Preserve analyst notes/owner/history.
6. Update filters/reporting.
7. Add transition and regression tests.

Acceptance criteria:
- Historical state is not overwritten without trace.
- Regression is distinguishable from a brand-new issue.
- Existing triage APIs/CLI remain compatible or have a documented migration.
- Full tests pass.
