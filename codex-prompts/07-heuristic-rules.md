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


# Phase 7 — Rule-driven heuristic scanner

Goal: move extensible custom detection rules into validated data files.

Implement a rule schema supporting:
- stable ID;
- category;
- severity;
- confidence;
- regex;
- include/exclude file patterns;
- description;
- remediation guidance.

Tasks:
1. Reuse the current custom-pattern scanner where practical.
2. Add safe validated rule loading.
3. Preserve existing built-in detections through migration/compatibility where appropriate.
4. Add redacted indicators and stable non-secret fingerprints.
5. Define behavior for invalid regex/schema.
6. Add starter rules useful for internal hostnames, connection strings, keys/config files, cloud identifiers, and deployment artifacts without generating excessive obvious false positives.
7. Add comprehensive tests.

Acceptance criteria:
- Most new heuristics can be added without Python code changes.
- Invalid rules fail with actionable diagnostics.
- No raw secret values in logs.
- Full tests pass.
