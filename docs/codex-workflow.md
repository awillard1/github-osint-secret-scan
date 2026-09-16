# Codex Workflow

## Philosophy

Use Codex for complete, bounded vertical slices.

Avoid repeated tiny prompts that cause the agent to rediscover context.

## Before each task

```bash
git status
pytest
```

Read the matching prompt under `codex-prompts/`.

## Prompt structure

Every phase prompt contains:

- goal;
- constraints;
- likely affected areas;
- acceptance criteria;
- validation;
- explicit exclusions.

Do not remove those boundaries when passing the prompt to Codex.

## Recommended review loop

Ask Codex to:

1. inspect before editing;
2. state the implementation approach;
3. make changes;
4. run focused tests;
5. run full tests;
6. inspect diff;
7. update docs;
8. summarize changes and remaining risks.

The agent may adjust filenames after inspecting the real code. It should not blindly create duplicate abstractions that already exist.

## Worktrees after architecture phases

After Phase 6, parallel work can use worktrees:

```bash
git worktree add ../orgscan-yara -b feat/yara
git worktree add ../orgscan-auth -b feat/browser-auth
```

Run Codex from the root of each worktree.

Avoid simultaneously editing shared central files such as models/migrations unless you are prepared to reconcile conflicts.

## Context recovery

If a Codex session loses context, do not recap the entire project manually.

Use:

```text
Read AGENTS.md, docs/architecture.md, docs/development-plan.md, and the current phase prompt. Then inspect git status/diff and continue only the active phase.
```

## Failed phase

If a phase becomes unstable:

```bash
git diff > /tmp/phase.patch
git status
```

Have Codex diagnose before adding more features.

Do not begin the next phase with failing tests.

## Commit discipline

Prefer one architectural phase per commit/PR.

Use semantic-ish messages:

```text
docs: establish agent engineering contract
refactor: introduce application service boundaries
refactor: centralize scanner registry
feat: add scan plans and profiles
feat: add repository checkpoint orchestration
feat: add yara scanner
feat: correlate scanner evidence
```
