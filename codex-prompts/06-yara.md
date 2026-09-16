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


# Phase 6 — YARA scanner

Goal: add YARA through the common scanner contract.

Tasks:
1. Add configuration for the YARA binary and local ruleset paths.
2. Implement readiness and version detection.
3. Implement scanning using explicit subprocess arguments, timeout, captured output, and controlled cwd/environment.
4. Normalize matches to canonical findings/evidence.
5. Map rule metadata to title/category/severity/confidence.
6. Ensure raw matched sensitive values are not written to logs.
7. Include fixture-based tests that do not require YARA to be installed.
8. Add documentation and dependency/readiness reporting.
9. Do not download community rules automatically.

Acceptance criteria:
- YARA appears through the scanner registry.
- Existing generic scan pathways can execute it without custom API/CLI dispatch.
- Missing YARA is a clean readiness state.
- Full tests pass.
