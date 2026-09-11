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


# Phase 3 — ScanPlan and profiles

Goal: create one representation of scan intent used by synchronous CLI/API execution and scheduled/queued execution.

Implement a `ScanPlan` model and profile resolver.

Initial profiles:
- quick
- standard
- comprehensive
- history
- secrets-only
- osint-only
- domain-only
- governance-only

Tasks:
1. Determine existing scan options and map them without losing behavior.
2. Define explicit profile defaults and explicit user override precedence.
3. Make CLI/API/scheduler/queue adapters construct or consume ScanPlan rather than re-implementing scanner/scope logic.
4. Persist or serialize enough resolved scan-plan information on a scan job to explain what was requested.
5. Validate incompatible combinations early.
6. Add tests for every profile and override precedence.

Acceptance criteria:
- Existing explicit scanner selection still works.
- A resolved plan is deterministic.
- Scheduled and synchronous execution can use the same plan.
- Full tests pass.
