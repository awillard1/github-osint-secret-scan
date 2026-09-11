# orgscan Codex Development Kit

This kit turns `github-osint-secret-scan` into an agent-friendly project and provides a controlled development sequence for Codex.

## Important rule

Do not ask Codex to "finish the roadmap" in one run.

Run one phase at a time. Each phase must leave the repository in a passing, mergeable state.

## 1. Copy this kit into the repository root

From WSL:

```bash
cd /path/to/github-osint-secret-scan
cp -a /path/to/orgscan-codex-development-kit/. .
```

If you downloaded the ZIP into Windows, for example:

```bash
cd ~/src/github-osint-secret-scan
cp -a /mnt/c/Users/<YOUR_WINDOWS_USER>/Downloads/orgscan-codex-development-kit/. .
```

The kit intentionally does not replace `projectspec.md`, `docs/roadmap.md`, or existing source files.

## 2. Create a branch

```bash
git switch main
git pull --ff-only
git switch -c codex/architecture-foundation
```

If you have local work, commit or stash it before beginning.

## 3. Run the preflight

```bash
chmod +x scripts/codex-preflight.sh
./scripts/codex-preflight.sh
```

Do not start a structural refactor if the baseline test suite is already failing. Capture the failing tests first.

## 4. Start Codex from the repository root

```bash
codex
```

For the first run, paste the contents of:

```text
codex-prompts/00-repository-baseline.md
```

You can also provide the prompt as a positional argument if your installed Codex CLI supports it:

```bash
codex "$(cat codex-prompts/00-repository-baseline.md)"
```

## 5. Recommended phase workflow

For every phase:

```bash
git status
./scripts/codex-preflight.sh
```

Then run the corresponding prompt.

After Codex finishes:

```bash
git diff --stat
git diff
pytest
```

Review the changes before committing.

Suggested commit pattern:

```bash
git add -A
git commit -m "refactor: establish service boundaries"
```

Use a new branch or worktree for high-risk phases.

## 6. Phase order

1. Repository baseline and documentation reconciliation
2. API/CLI/service decomposition
3. Scanner plugin contract and registry
4. ScanPlan and scan profiles
5. Repository mirror/cache/checkpoint engine
6. Incremental branch/history orchestration
7. YARA integration
8. Rule-driven heuristic scanner
9. Cross-scanner finding correlation/deduplication
10. GitHub identity and repository relationship intelligence
11. GitHub public search intelligence
12. Interactive authentication and user administration
13. Finding lifecycle and regression detection
14. Operator dashboard redesign
15. Job retry/backoff/rate-limit reliability
16. SARIF/PDF reporting
17. `orgscan doctor` and release hardening

Do not parallelize phases 1-6. They establish contracts used by later work.

After Phase 6, scanner integrations and some UI/reporting work can be developed in separate git worktrees.

## 7. Source-of-truth hierarchy

Use these in this order:

1. `AGENTS.md` — engineering contract
2. `docs/architecture.md` — current intended architecture
3. `docs/development-plan.md` — implementation order
4. `docs/scanner-contract.md` — scanner rules
5. `docs/testing.md` — validation rules
6. `projectspec.md` — product vision
7. `docs/roadmap.md` — status tracker; keep it reconciled with reality

If code and documentation disagree, Codex must inspect the code and tests before deciding which is stale.

## 8. Safety requirement

This project handles secrets and untrusted repositories.

Codex must never introduce behavior that:

- logs raw discovered secrets;
- executes repository-supplied code as part of scanning;
- interpolates untrusted values into shell commands;
- removes scanner timeouts;
- weakens authorization or tenant checks;
- silently follows archive paths outside extraction roots;
- stores uploaded files indefinitely without an explicit retention policy.

## 9. What success looks like

After the architecture phases, a new scanner should normally require:

- one scanner implementation;
- scanner-specific tests;
- configuration/readiness metadata;
- no scanner-specific branch in the API;
- no scanner-specific branch in the CLI;
- no duplicated scan orchestration code.

A new user-facing workflow should normally be implemented in a service once and consumed by the API, CLI, scheduler, and web UI.
