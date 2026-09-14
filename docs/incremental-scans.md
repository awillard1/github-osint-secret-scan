# Incremental repository scans

Phase 5 connects `ScanPlan` to the cache manager and successful checkpoints through `services/incremental.py`. The default mode remains `full`; incremental skipping is opt-in. No new SQL schema is required. `skipped` is an additive job/ToolRun status stored in the existing string columns.

```bash
orgscan scan-mirror owner/repo --scanner custom-patterns --mode incremental --branch-policy default-only --resync --json
orgscan scan-mirror owner/repo --profile history --mode incremental --branch-policy all --resync
orgscan schedule-mirror-scan owner/repo --profile history --mode incremental --ref release
orgscan scan-mirror owner/repo --profile history --mode history --ref release
```

The same options persist in scheduled plans and run through both queue backends. `scan-plan` accepts the same resolved JSON. Repository plans do not add an HTTP filesystem or remote-cloning endpoint; the existing artifact API accepts profiles but rejects repository-only incremental/branch intent.

| Branch policy | Selection |
| --- | --- |
| default-only | Latest successfully discovered remote default branch |
| selected | Explicit ordered, deduplicated branches/tags (`--ref`); qualified tag refs disambiguate names |
| all | All fetched remote branches in sorted order, plus deletion records from the previous observation; tags require explicit selection |
| tracked | Existing tracked refs, falling back to the remote default branch; compatibility default for no-profile mirror commands |

Profile-driven mirror plans default to default-only; explicit refs select selected policy. Existing serialized plans retain their recorded policy. There is no recency-based branch heuristic in this phase.

| Condition | Execution |
| --- | --- |
| Explicit full/history mode | Always execute the selected scanner at the pinned commit; history mode requires history capability |
| First scan or changed configuration | Full tree/history scan |
| Incremental, fingerprintable configuration, same commit and ref object | Record an unchanged skip; no scanner or worktree execution |
| Incremental, verified descendant, history adapter supports ranges | Execute the entire `previous_oid..current_oid` range |
| Changed content scanner without range semantics | Full tree scan, preserving cross-file scanner behavior |
| Diverged/force-pushed history or unavailable old commit | Full tree/history fallback |
| Previously known ref was deleted | Record ref-deleted skip; keep successful checkpoints intact |
| Unknown explicitly selected ref | Reject selection before executing any scanner |

Each job stores its resolved plan and scope: qualified ref, ref object ID, peeled commit ID, compared start/end OIDs, decision/reason, actual commit range, configuration key, coverage kind, and history limit. `coverage=none` identifies skips. Full history retains the existing configured commit cap (250 by default); that cap is explicitly recorded. Incremental history does not apply that cap, so a large range cannot silently miss older new commits and still advance the checkpoint. Process timeouts remain in force.

Git-history execution pins the commit/range rather than resolving stale local branch names. Deleted remote refs are not scanned from leftover local branches. Annotated tag changes invalidate reuse even when the peeled commit stays the same. Discovery/external rule content beyond the declared scanner contract is not inferred from Git changes.

Successful checkpoints advance only after the scanner and worktree cleanup succeed. Skips and failures never advance them. Completed earlier scanners in a multi-scanner plan keep their individual checkpoints if a later scanner fails. A crash between persisted findings and checkpoint commit causes safe re-execution; this is not exactly-once evidence ingestion. All-skipped scheduled jobs complete normally. Locks serialize concurrent jobs sharing a cache, allowing the second job to observe the first job's successful checkpoint.

Phase 18 configuration keys hash settings, scanner version, scanner source and bundled
JSON dependencies, runtime Python/regex/Pydantic versions, executable contents,
plan timeout, history policy and scope. The new contract-key version invalidates
older checkpoints once. Local JSON heuristic rules are hashed by content. YARA
literal local includes are recursively hashed (at most 100 files, 1 MB per file,
4 MB total); missing, ambiguous, unreadable includes or module imports disable reuse.
Rules and binaries must remain quiescent while a scan runs.

For Semgrep, Gitleaks, detect-secrets, TruffleHog, ripgrep and plugins, unmodelled
user/environment/remote configuration prevents deterministic reuse. Incremental
requests execute a full tree/history scan with reason
`configuration-not-fingerprintable`; no new reusable checkpoint is written. This
conservative policy trades speed for coverage. Remote configuration is never assumed
unchanged merely because Git is unchanged. Explicit full/history scans still run. Optional tools remain required for scans that execute. Skipped scans do not refresh finding last-seen times or imply automatic remediation; existing finding lifecycle behavior remains unchanged.

Inherited cache limits remain: POSIX/shared-filesystem locking, bounded captured subprocess output, and operator cleanup of crash-orphan worktrees. Normal tests use local synthetic Git repositories and fake external tools/Redis; they do not certify live tool compatibility or large-repository performance.
