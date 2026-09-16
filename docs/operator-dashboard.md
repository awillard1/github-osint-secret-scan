# Operator dashboard

## Operator console presentation

The console adds a shared autoescaped Jinja shell for the live dashboard, assessment
index, queue drill-downs, operator queue cards and finding detail. Existing services remain the
source of queue membership, risk, lifecycle and authorization decisions. Shared
design tokens support light and dark preferences, compact tables, visible state and
severity chips, keyboard focus and responsive navigation. Queue cards lead the
dashboard; the assessment index highlights failed jobs and links to each workbench.
Finding detail groups priority, workflow, context, redacted evidence and history.
Its decision form returns to the same finding after a successful update; optional
JavaScript refreshes detail in place when no protected reveal controls are present.
Findings with protected evidence retain full-page navigation so reveal cleanup and
initialization continue to work. Reader
sessions do not see this form; decisions still use the protected POST endpoint and
CSRF check. Protected values remain behind audited reveal.

Static CSS and JavaScript are served under `/static`. JavaScript is optional and
does not determine queue state, permissions or risk. An unenhanced POST still uses
the normal redirect. Exported HTML remains
self-contained and omits browser session controls. Jinja2 is a runtime dependency;
installed wheels must include the templates and static assets.

This is an incremental migration. Assessment detail tabs, scan-job detail, graph,
settings, login and the standalone HTML report still assemble escaped HTML in
Python. Their routes and forms remain supported. Deployment-specific visual and
accessibility review remains needed.

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
