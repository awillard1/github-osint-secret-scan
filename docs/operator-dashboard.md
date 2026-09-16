# Operator dashboard

The existing server-rendered `/dashboard` now starts with an operator overview.
`DashboardService` applies shared lifecycle/risk policy over the request's authorized
storage session; templates only render the resulting counts and queues.

- New findings: first observed within the selected window (dashboard trend days).
- Highest risk: current unmanaged findings with stored risk score at least 70.
- Regressions: current REGRESSED findings, ranked by stored risk score.
- Active scans: pending, queued or running scan jobs.
- Failed scans: failed scan jobs retained in storage.
- Newly discovered assets: organizations, repositories, domains and accounts created
  within the window. This is first ingestion time, not an assertion of asset creation.
- Requires triage: NEW, REVIEWING and REGRESSED, ordered by risk.

Cards show total queue counts, with a bounded preview. Each links to a paginated
`/dashboard/queues/NAME` view and individual finding/job/asset details.
`/operator/overview?days=7&limit=10&offset=0` returns the same queues as JSON.
The main page uses its existing days filter; standalone views default to seven days.
Triage labels, artifact upload, filtering, graph and existing detail views remain.
Reader access is read-only; server authorization and CSRF remain enforced for
mutations. All data labels and link attributes are escaped.

Queue filtering, counts and pagination run in SQL through `DashboardStorage`, using
with-loader criteria from the authorized request session for both counts and rows.
Only the requested page is materialized for each queue. Newly discovered assets use
one globally ordered union of the four asset types, with timestamp, type and ID as
stable pagination keys. Risk queues break equal scores by descending finding ID;
new findings retain detected-time/ID ordering, and jobs retain created-time/ID ordering.
No frontend framework, schema, API response or CLI change is required.

This bounds operator-queue result loading; other dashboard sections retain their
existing queries. Counts and pages are separate reads, so concurrent writes can change
the result between reads or page requests. Large offsets and exact counts may still
be expensive; production-scale and PostgreSQL query performance remain unverified.
Active scans reflect recorded state, not an independent worker heartbeat; queue-task
recovery is a separate concern.
