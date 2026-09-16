# Codex phase prompts

Run these in numeric order.

Do not run phases 00-05 in parallel.

Each prompt instructs Codex to inspect the current repository before editing. This is intentional: the code may evolve between phases and filenames in a static plan can become stale.

Suggested usage:

```bash
codex "$(cat codex-prompts/00-repository-baseline.md)"
```

Or start interactive Codex and paste the prompt contents.

After every phase:

```bash
pytest
git diff --stat
git diff
```

Commit only after review.
