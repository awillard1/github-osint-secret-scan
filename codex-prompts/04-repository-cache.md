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


# Phase 4 — Repository mirror/cache/checkpoint engine

Goal: make repository acquisition reusable and stateful.

The repository already has `mirroring.py`; extend/refactor it rather than replacing working behavior without cause.

Tasks:
1. Define a repository mirror manager/service boundary around ensure/fetch/ref-inventory/materialization/cleanup.
2. Add persisted checkpoint/sync data needed to know whether a remote changed since a prior scan.
3. Support default branch discovery; do not assume `main`.
4. Define concurrency/locking behavior for two jobs targeting the same mirror.
5. Use safe subprocess argument arrays and timeouts.
6. Do not execute repository code.
7. Add migration(s) if persistence changes.
8. Build tests with small local synthetic git repositories, no public network dependency.

Acceptance criteria:
- A repository can be fetched/synchronized without unnecessary fresh cloning.
- Current and previous relevant OIDs/checkpoints can be compared.
- Failure does not falsely advance a scan checkpoint.
- Full tests pass.
