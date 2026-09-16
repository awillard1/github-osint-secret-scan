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


# Phase 2 — Scanner contract and registry

Read `docs/scanner-contract.md` carefully.

Goal: make existing and future scanners execute through one stable contract/registry.

Tasks:
1. Audit the current scanner package, entry-point loading, runner dispatch, readiness reporting, API and CLI scanner selection.
2. Define or adapt existing types for scanner metadata, readiness, target/context, and result without unnecessary duplication.
3. Implement a registry that includes built-ins and existing Python entry-point scanner plugins.
4. Reject duplicate scanner IDs predictably.
5. Migrate existing scanner selection/readiness to registry-driven behavior.
6. Preserve all currently supported scanners and result ingestion.
7. Keep canonical finding normalization intact.
8. Add tests for registry loading, missing external binaries, duplicate IDs, and normal dispatch.

Acceptance criteria:
- Adding a future scanner should not require adding scanner-name branches to CLI and API.
- Existing scanner commands/API behavior remain compatible.
- External binaries remain optional.
- Full tests pass.
