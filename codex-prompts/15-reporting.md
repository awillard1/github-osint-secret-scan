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


# Phase 15 — SARIF and PDF reporting

Goal: add report adapters over canonical stored findings/evidence.

Tasks:
1. Audit current JSON/CSV/HTML and existing reportlab support.
2. Add SARIF output suitable for code-scanning style consumption where fields map correctly.
3. Add executive PDF and technical PDF outputs.
4. Use the same report query/service layer for all formats.
5. Redact sensitive material.
6. Include provenance, lifecycle, severity/confidence, and scanner evidence where useful.
7. Add deterministic tests that validate structure/content without brittle pixel comparisons.

Acceptance criteria:
- no separate shadow finding model;
- existing outputs still work;
- SARIF validates structurally;
- PDF generation handles zero and many findings;
- full tests pass.
