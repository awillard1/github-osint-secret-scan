# Job reliability

Both Redis/RQ and database queues remain supported. Shared policy classifies scan
and discovery jobs using `job_type` in existing JSON metadata; repository sync
checkpoints record REPO_SYNC and scheduled reports record REPORT. Domain provider
jobs distinguish DISCOVERY and DOMAIN_ENRICH. Correlation remains part of SCAN,
not a separate queued task. These labels do not introduce new queue implementations.

Network connection/timeout errors, explicit transient errors, HTTP 408/425 and common
5xx responses retry. HTTP 429 and 403 with explicit quota/retry headers defer.
Other HTTP failures, missing scanners, invalid targets/configuration and unclassified
exceptions are permanent. Safe failure codes/messages are stored; original exception
text and serialized credentials are omitted from worker logs and RQ failure records.
Domain scan services preserve the classification across their error boundary. GitHub
search carries partial/deferred status into queued execution rather than reporting success.

Retry counts are clamped to 0–10 (additional attempts). Delay doubles from the first
configured interval, respects later configured interval floors, and caps ordinary
backoff at one hour. Retry-After/reset timestamps can extend that delay up to seven
days; invalid/nonfinite headers are ignored. Terminal/exhausted queue failures disable
the schedule so enqueue polling cannot restart the same failed work indefinitely.
Review the cause and create a replacement schedule after fixing it. RQ workers now
start the retry scheduler; burst mode processes currently available work only.

DB task claims use conditional SQL updates. Completed tasks return saved results on
replay; RQ completion records the execution ID and result in the schedule transaction.
Incremental repository retries reuse successful per-scanner/ref checkpoints and
canonical/evidence upserts. An explicitly full multi-step scan can repeat completed
substeps after partial failure; exactly-once execution and distributed transactions
are not claimed. Redis contains serialized worker configuration: restrict access,
use protected transport and never expose queue contents as public diagnostics.

`orgscan recover-stale-jobs` inspects expired DB leases without changes.
After verifying the affected workers have stopped, `--apply` quarantines those tasks
as failed and disables their schedules. It never launches speculative concurrent
recovery. Review incomplete ScanJobs before creating a replacement schedule. The
original worker cannot mark a quarantined task completed after refreshing ownership,
but already committed scanner substeps cannot be undone. There is no independent DB
worker heartbeat, so a lease expiring does not prove the worker is dead. RQ uses its
native started-job cleanup; schedule reconciliation after abrupt process/Redis loss
remains an operator task. These are deliberate recovery limits.

Tests use fakeredis and mocked network/scanner failures. RQ scheduler startup is
asserted while its Lua/process behavior is mocked in normal tests; live multi-worker
Redis and PostgreSQL recovery are not certified by this suite.
