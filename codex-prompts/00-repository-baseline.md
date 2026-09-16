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


# Phase 0 — Repository baseline and source-of-truth reconciliation

Goal: establish an accurate baseline before structural development.

Tasks:
1. Inventory the actual implemented capabilities from source code and tests.
2. Reconcile `docs/roadmap.md` with reality. Do not claim a feature is absent if code/tests already implement it.
3. Review `projectspec.md` only as product vision; do not rewrite it into an implementation log.
4. Review the new architecture documents for contradictions with the real code and make narrow corrections if required.
5. Fix trivial metadata/dependency mistakes that are unambiguously safe (for example duplicate dependency entries), but do not perform architectural refactoring in this phase.
6. Record any pre-existing failing tests or stale documentation.
7. Add a concise "Current architecture/capability baseline" section to `docs/roadmap.md` or an equivalent clearly linked status section.

Acceptance criteria:
- Existing behavior is unchanged except harmless project metadata cleanup.
- `docs/roadmap.md` accurately describes implemented, partial, and missing capabilities.
- No new feature implementation.
- Full tests pass, or pre-existing failures are documented with evidence.

Do not decompose `api.py`/`cli.py` yet.
