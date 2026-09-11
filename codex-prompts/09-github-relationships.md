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


# Phase 9 — GitHub identity/repository relationship intelligence

Goal: make expansion explainable through provenance/confidence.

Tasks:
1. Audit current discovery/expansion/account/repository relationship storage.
2. Define explicit relationship types and provenance.
3. Correlate organizations, repositories, contributors/accounts, forks, commit email domains, and discovered domains when supported by evidence.
4. Assign confidence using documented, deterministic signals rather than opaque magic.
5. Store enough evidence to answer "why is this associated with the target?"
6. Extend graph/entity APIs/UI only through existing service boundaries.
7. Add tests with mocked GitHub responses.

Acceptance criteria:
- Every new inferred relationship has source/provenance and confidence.
- No dependency on live GitHub in tests.
- Full tests pass.
