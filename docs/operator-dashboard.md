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

Live browser pages for assessment tabs, discovery results, recon settings, scan-job
detail, login and user administration now use autoescaped Jinja templates and the
shared console shell. Standalone exported HTML remains self-contained. Some
compatibility rendering helpers remain for non-browser consumers. Deployment-specific
visual and accessibility review remains needed.

Assessment overview and Discovery now use the shared Jinja shell. The overview
summarizes latest discovery state, linked assets, failures, queue backend
reachability and next actions. Discovery places persisted target/stage progress
before configuration, with a separate review and explicit durable-job confirmation.
An authenticated fragment refreshes active status without navigation; hidden pages
pause requests, failures back off, and terminal states stop polling. Service code
owns state aggregation and safe diagnostic classifications. The browser never
interprets raw queue errors or secret evidence. The Scans tab now uses the same
shell, with selected scope, scanner readiness, profile review, saved scan-run state,
safe failure codes and browser publication/execution controls for the DB queue.
The remaining assessment tabs use the same shell and semantic tables/forms.

The Targets page now explains the GitHub repository workflow in place. An admin
can create the tenant's public GitHub.com connection there; a disabled connection
links to Settings for repair. Imports show per-line results and a direct next step
to Discovery. Adding a target to an active assessment is allowed because existing
jobs retain their saved scope. Repository scanners and readiness are visible on
the Scans page before any repository is selected, with links back to Targets and
Discovery. The assessment list and primary navigation expose those entry points.
Target import results use fixed, safe reason labels for missing or disabled
connections; raw parser diagnostics stay behind the existing sanitizer.

Discovery Results now leads from scoped domain names to an optional HTTPX follow-up.
An analyst authorizes active contact, then durable jobs run through the existing
queue and recon pipeline. The UI shows queued/running/completed/failed status,
links to job details and provides retry/cancel controls. Only names beneath a
saved valid domain target are eligible, and the worker rechecks target scope.

Large discovery populations are read through bounded source batches that share
credential knowledge. Report and projection context row defaults are 10,000 each;
the complete authorized context must still fit the aggregate structural and text
budgets. This keeps the dashboard and discovery results usable after ordinary
multi-tool discovery while retaining fail-closed redaction.

Global and assessment Relationships now share the console shell. Assessment links
retain filters and connected entity navigation, with source and confidence beside
each edge. Discovery can select ready passive or all ready providers; active tools
still require explicit scope authorization. Browser launch attempts queue publication
for that assessment. Database queue deployments expose a bounded **Execute queued
jobs** action; Redis/RQ deployments use their supervised worker. Readers cannot
publish or execute jobs. Providers still run through durable worker claims.

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
Newly discovered asset links now open shared, autoescaped HTML detail pages for
domains, organizations, repositories and accounts. These pages reuse the same
authorized, redacted projections as the JSON asset endpoints and show identity,
risk, relationships and high signal findings. Domain pages also show exposure
observations and identity correlations. Missing or out-of-tenant IDs return 404.
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
recovery is a separate concern. The assessment Discovery view adds an analyst-scoped
**Stop this run** action for pending, queued and running target operations. It shows
**Cancelling** until a worker confirms a running stop, then **Cancelled**; already
completed observations remain available for review.
