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


# Phase 8 — Finding correlation and evidence deduplication

Goal: avoid multiple scanners/repeated scans inflating one underlying issue into many findings.

Tasks:
1. Audit current dedup/fingerprint behavior.
2. Define a stable correlation fingerprint that never requires storing a raw secret.
3. Attach multiple scanner observations as evidence to a canonical finding when they represent the same issue.
4. Preserve scanner-specific detector IDs and metadata in evidence.
5. Avoid merging unrelated findings merely because titles/categories match.
6. Handle reasonable path/line movement across rescans.
7. Add tests for same-tool repeats, cross-tool matches, different secrets on same line/path, and genuinely separate findings.

Acceptance criteria:
- Correlation reduces duplicate finding counts without hiding separate issues.
- Evidence shows which scanners observed the issue.
- Full tests pass.
