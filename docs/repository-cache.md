# Repository cache and checkpoints

Phase 4 extends `mirroring.py` through `RepositoryMirrorManager`. Existing sync/scan functions remain compatibility entry points. The cache remains a fetched working checkout for existing tooling; each scan uses a disposable detached worktree pinned to the resolved commit. Scanner paths and metadata are mapped to the stable mirror root before canonical normalization, preserving repeat-scan finding identity. The canonical hashing algorithm is unchanged.

The manager supplies sync, ref inventory, resolution, materialization and cleanup. Fetch reuses the existing clone, prunes remote branches/tags, and discovers the remote default branch via symbolic HEAD without assuming main/master. Omitted clone URLs retain the repository's recorded URL. Explicit sync refs retain their previous checkout/tracking behavior. Unavailable/empty remote HEAD fails clearly.

`Storage` owns a versioned `metadata_json.repository_state` namespace:

- `current_refs` and `previous_refs`: observed fully qualified ref-to-object-ID maps;
- `default_branch` and `observed_at`: successful sync observation;
- `checkpoints`: successful scanner/ref/configuration checkpoints containing peeled commit OID, job ID and completion time.

Fetch observations do not advance scan checkpoints. Each successful scanner run records its own checkpoint; a failed later scanner leaves earlier successful runs intact. Configuration keys hash settings and scope rather than storing credential values. Configuration changes conservatively invalidate reuse. Phase 5 consumes this state for incremental decisions; Phase 4 always executes the requested scans.

These additions reuse existing JSON and default-branch columns, so no SQL schema change or Alembic migration is required. Existing metadata is preserved and old records acquire state at the next successful sync. A regression test covers updating/reloading legacy JSON.

A per-repository POSIX advisory file lock covers sync, materialization, scanning and checkpoint commit. Concurrent jobs sharing a cache serialize; the OS releases the lock on process exit. Lock wait and Git subprocess timeout use `ORGSCAN_GIT_TIMEOUT_SECONDS` (300 by default). All participating jobs must use this manager and share a filesystem with working advisory locks; this is not a distributed lock for independent caches. Windows currently fails with explicit locking guidance. Manager operations commit successful state before releasing the lock; callers should use a dedicated service transaction.

Git runs argument arrays with captured status/output and bounded timeouts. Failures omit raw diagnostics. Hooks/fsmonitor, ext transport, terminal prompts, and system/global Git configuration are disabled; environment credentials/SSH agent access remain available. No repository scripts, dependencies or submodules are executed. Materialization removes symlinks escaping the scan root before scanning and removes/prunes worktrees on ordinary success/failure. A killed process can leave orphan worktree directories requiring operator cleanup; there is no crash-recovery sweeper yet.

Cache names must be owner/name and cannot traverse outside the managed root. Existing ordinary owner/name cache paths are retained. Names containing underscores use a hash suffix to prevent ambiguous path collisions; old caches with such names need explicit resynchronization to their new managed path. Symlink cache/worktree roots are rejected.

Remaining limits: Git output is buffered without a size cap; fetch can succeed before a later sync step fails, so database observations deliberately remain at the last fully successful sync. No scan checkpoint advances on that failure. Local synthetic Git tests cover cache reuse, changed OIDs/default branches, checkpoint separation, cleanup, stable findings, lock contention, hook suppression, symlink containment and timeout diagnostics.
