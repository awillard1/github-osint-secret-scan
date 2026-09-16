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


# Phase 10 — GitHub public search intelligence

Goal: find organization-linked exposure outside already-known repositories.

Tasks:
1. Add a query builder/service for target organization/domain identifiers.
2. Support carefully bounded searches for domain strings, org identifiers, sensitive filenames paired with target identifiers, and similar high-signal queries.
3. Persist exact query, timestamp, source, pagination/rate-limit metadata, and provenance.
4. Respect GitHub API rate limits and authentication configuration.
5. Deduplicate discovered entities/findings into the existing model.
6. Never treat a text match alone as high-confidence ownership; represent confidence appropriately.
7. Tests must mock GitHub APIs.

Acceptance criteria:
- Search results feed normal repository/account/relationship/finding workflows.
- Operators can inspect why a result was discovered.
- Full tests pass.
