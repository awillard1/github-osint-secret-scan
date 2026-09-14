# Finding lifecycle

`lifecycle_state` adds NEW, REVIEWING, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK,
SUPPRESSED, REMEDIATED and REGRESSED alongside the existing `status` and free-form
`triage_state`. Existing triage/suppress/accept-risk/reopen commands and endpoints
remain available. Legacy open decisions map to REVIEWING; new observations start
NEW. Resolved maps to REMEDIATED, triaged to REVIEWING, and managed legacy states
to their corresponding lifecycle states. Explicit FALSE_POSITIVE maps to legacy
suppressed; CONFIRMED maps to triaged. Contradictory explicit status/state updates
are rejected. Returning to NEW is forbidden; REGRESSED requires scan evidence.
All other operator state changes are permitted, including reopening a remediation.

Use `orgscan transition-finding ID CONFIRMED --note 'Reviewed'` or PATCH
`/findings/ID` with `{"lifecycle_state":"CONFIRMED"}`. Filter JSON findings with
`lifecycle_state=CONFIRMED` or CLI `findings --lifecycle-state CONFIRMED`.
Finding detail JSON and HTML expose transition history; report rows and summaries
include lifecycle states and timestamps. HTTP decisions retain role/tenant checks.

Every initial observation, state transition and change to owner/notes/deadline or
triage label records before/after values and actor in `finding_history`. Idempotent
updates add no event. Omitted fields retain earlier values; an empty note explicitly
clears the current note while history retains it. Operator-entered notes should
contain redacted descriptions, never credentials. Scan observations retain analyst
state except for a qualifying regression.

A correlated fingerprint observed by a different scan job whose start time is
later than remediation transitions from REMEDIATED to REGRESSED. The event links
the scan job, increments the regression count, and preserves owner, notes, first
seen and remediation time. Replaying an old/same job, an unchanged skip, or an
observation without a job cannot trigger regression. No-match scans do not infer
remediation. Saved-report ingestion with a newly started job counts as a new
observation; orgscan cannot infer the original report collection time. History
scanners can rediscover historical exposures, so a regression means re-observation,
not proof that a credential is currently valid.

Alembic `20260911_0007` adds columns/history. Legacy states map without changing
legacy fields. Legacy remediation time is inferred from the stored update time and
marked as inferred in migration history; earlier transitions cannot be reconstructed.
Downgrade removes the new lifecycle columns and audit table. SQLite populated upgrade
is tested; PostgreSQL integration and concurrent multi-worker transition races remain
unverified. Normal operator changes and scanner persistence use shared Storage policy,
including queued/scheduled scans; direct database edits bypass this audit contract.
