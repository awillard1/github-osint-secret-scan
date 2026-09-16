# Assessment operator control plane

## Current scope

The server-rendered entry point is `/dashboard/assessments`. The existing
`/dashboard` and standalone API/CLI remain available. Navigation includes an
Assessments link and a New Assessment shortcut. The root URL now opens Assessments. The disposable browser acceptance test covers
the complete operator workflow; external deployment certification is separate.

An assessment has tenant ownership, lifecycle timestamps, reusable configuration,
a dedicated organization context, many normalized targets, explicit asset links,
and links to existing scheduled operations. It does not duplicate queue state.
Findings are canonical records selected through assessment asset membership.
Excluding an asset from scanning does not delete its relationships or findings.

## Operator workflow

1. Open Assessments and create an assessment with a tenant, name and description.
2. In Settings / GitHub Connections, configure each GitHub.com or GHES host.
3. Paste target locations one per line, or import UTF-8 text/CSV. Review valid,
   duplicate and invalid rows. Valid rows survive individual parse errors.
4. Choose a discovery profile and optional expansion/provider settings. Launch
   discovery and watch provider/stage status. Deployment administrators provision
   the existing enqueuer and DB/RQ workers; ordinary operation is through the UI.
5. Review repositories, accounts, domains and relationship provenance. Filter
   repository scope by search, visibility, archived/fork, confidence, update dates
   and scanned state. Include/exclude checked rows, a page or all filtered rows,
   or clear scan scope. Discovery data is retained.
6. Review the selected repository/scanner counts and history mode, then confirm
   launch. Review creates no jobs. Both review and launch use ScanPlan. Monitor
   latest repository completion, queue states and severity counts; open job details.
7. Open an assessment finding, review observations and association provenance,
   explicitly reveal if authorized, and record analyst triage.
8. Export JSON, CSV, HTML, PDF or SARIF, or generate optional local AI advice.

Saving an assessment does not start network activity. Classification is offline.
An ambiguous GitHub owner URL is resolved as organization/user during discovery.
Supported typed prefixes are `org:`, `user:`, `repo:`, `domain:` and `path:`.
GitHub URLs require an enabled connection matching their host. CSV columns are
`type,location,connection,notes`; connection accepts an ID or configured name.

There is no small fixed assessment target count. Imports are bounded per batch
(default 1 MB / 5,000 rows); subsequent batches are supported. Pages contain
50 rows by default, with a maximum API page size of 500. Imports/queries also
obey the complete credential-context budgets described in projection-safety.md.
Exceeding a context budget fails closed; pagination does not truncate security
context. Local paths require admin import plus
`ORGSCAN_ASSESSMENT_ALLOW_LOCAL_PATHS=true`, and execution requires an existing
absolute path with no symlink root. Existing scanner path protections still apply.

## Connections and tenant credentials

GitHub.com requires its official HTTPS web/API origins. GHES supports an HTTPS
web origin and API origin, normally ending in `/api/v3`. Connections are scoped
to tenants; discovered GitHub asset identities include the connection ID, so
identical owner/repository names on different instances do not collide.

Tokens are environment-provisioned in API and worker processes. A connection
stores only an environment reference, never a token. The deployment operator
must also assign each reference to exactly one tenant:

```sh
ORGSCAN_GITHUB_CONNECTION_CMS_TOKEN=...
ORGSCAN_GITHUB_CONNECTION_CREDENTIALS_JSON='{"cms":["ORGSCAN_GITHUB_CONNECTION_CMS_TOKEN"]}'
```

Enter `ORGSCAN_GITHUB_CONNECTION_CMS_TOKEN` in the connection form for tenant
`cms`. A tenant administrator cannot select a reference assigned to another
tenant. Workers recheck grants and connection enablement when executing.
Git authentication is operation-local, host-specific and supplied through Git
configuration environment values; it is absent from URLs, arguments and job
payloads. Redirects are disabled. Rate-limit scopes include tenant/connection;
HTTP retry classification preserves server delay information.

Private/internal repositories require both an enabled, credentialed connection
grant and an explicit discovery option. Each target can inherit the profile, stay
public-only, or explicitly include authorized private/internal repositories. Target
choices are snapshotted at launch; a later public-only restriction also narrows a
queued discovery. Public-only organization enumeration requests public repositories
directly. Private user inventory uses the [authenticated repository endpoint](https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user)
and filters to the target owner before persistence. Contributor expansion remains
public; private fork relationships reuse independently authorized assessment assets. Unknown or
contradictory public visibility is excluded. Connection tests expose safe
identity/rate-limit metadata and generic diagnostics, without tokens.

## Discovery and correlation

Profiles: quick-organization, organization-comprehensive, github-only,
domain-only, passive-only and custom. Registered provider readiness drives
selection. Saved profiles can be listed/stored through `/recon-profiles` and
launched with `options.saved_profile`. Unavailable providers/scanners fail
validation. Profiles have explicit registry-backed provider defaults; they never enable tools
merely because a binary is installed. Comprehensive Passive includes members,
contributor-owned public repositories and public search. Active selections require
explicit authorization and browser review before launch. Explicit provider choices
override profile defaults. See [Recon toolchain](recon-toolchain.md) for current profiles. Private scope still requires an explicit checkbox. Profiles can
be saved and selected in the discovery UI. Launch options are snapshotted per job.

GitHub discovery ingests repository metadata, owner accounts, forks/parents,
contributors, optional visible members, commit email domains and optional public
contributor-owned repositories. Explainable association reasons accompany asset
links. Official ownership, membership, contributions and fork evidence have
separate deterministic meanings; contributions never establish employment. Repeated
observations combine sources, confidence reasons and first/last-seen times. Public
search reuses the existing search service with connection-scoped ingestion. Named
organizations have their own connection-scoped entities; an assessment association
is not represented as organizational ownership. Commit emails without a linked
GitHub login use separate fingerprinted, self-reported identities.
Edges retain existing provenance/first-last-observed behavior.

The domain workflow invokes existing providers through ScanPlan. Registered
provider observations are correlated into shared subdomain entities and parent
relationships. Repository metadata can refer to those same domain records.
The legacy globally unique domain key means an existing foreign-tenant domain
cannot be reassigned; that conflicting discovery is refused.

Traversal has explicit page budgets. Reaching a page budget produces a partial
failed operation rather than an exhaustive-discovery claim. Contributors, forks, commits and contributor-owned repositories use the configured
`ORGSCAN_ASSESSMENT_DISCOVERY_MAX_PAGES` budget too. Stages record status/counts;
failed domain providers do not prevent the other selected providers from running.
Retry reruns the failed target idempotently, rather than pretending to resume an
external provider from an unknown cursor.

## Jobs, findings and reports

Launch creates durable manual ScheduledScan rows and AssessmentRun links. The
existing enqueuer/worker executes them; launching does not require Redis to be
available immediately. Pause is cooperative: running work may finish and pending
operations fail safely if picked up while paused. Resume then explicitly retry
failed operations. This is not process suspension.

Repository inclusion and connection/tenant bindings are rechecked by workers.
ScanPlan owns scanner, branch, history and incremental-mode validation. Existing
canonical deduplication, lifecycle, encrypted SecretEvidence and authorized reveal
remain the finding model. Assessment report selection is separate from complete
tenant credential knowledge. All five formats contain target/scope/provenance
sections and canonical finding details. Asset/target sections are read in batches
and include every record within the configured projection budget; exceeding the
budget fails explicitly rather than returning an incomplete report. Finding details
are complete by default within the configured report context budget. PDF uses technical
finding detail; CSV contains typed JSON records so scope and evidence are retained.
An available AI Suggested executive summary is opt-in at export.

## New adapters

UI: assessment index/create; overview, targets, discovery, repositories, accounts,
domains, relationships, scans, findings, reports and AI advice tabs; GitHub and
local AI settings.

JSON: `/assessments` list/create/detail/update; targets list/import/remove;
artifact uploads; assets/filtering/selection; scan preview, launch, jobs, pause and
retry; assessment finding detail, relationships,
reports and AI advice; `/github-connections` list/create/edit/disable/test; `/recon-profiles`
list/save; `/local-ai` read/update/test. Consult generated OpenAPI for methods and
parameters. No new CLI command family is added; existing scan/queue/report/doctor
commands are reused.

## Migration and deployment

Migration `20260915_0014` adds eight tables: assessments, assessment_targets,
assessment_entities, assessment_runs, github_connections, recon_profiles,
local_ai_configurations and ai_advice. It makes no changes to existing records.
Migrations through 0013 remain frozen. Downgrade removes these new control-plane
tables and their data; use normal backup/change procedures.

The configured development/production database is not upgraded by validation.
Upgrade it explicitly with the established deployment migration workflow before
starting the new production application.

## Uploaded artifacts and retention

Use Targets / Uploaded artifacts for files, ZIP or TAR archives, up to 10 MB per
request. Archives share the existing 2,000-file/25 MB extraction protections.
Accepted source bytes are staged encrypted with AES-GCM under the deployment data
directory, bound to tenant/assessment/digest. A private staging key is kept outside
the database. Do not remove that key while staged uploads are needed; include it
in administrator backup procedures. Temporary extraction is cleaned after validation
and after each scan. Workers verify ciphertext integrity before materializing input.

An upload immediately becomes an included artifact repository. Deduplication is
per assessment/content. Removing its target revokes inclusion, marks the target
purged, and removes the encrypted source; canonical findings and provenance remain.
Re-uploading identical content restores the source and scope explicitly. Artifact
source staging does not use or decrypt Protected SecretEvidence.

## Operational limits and external certification

- Connection names, credential references, private authorization and enablement
  are editable. Endpoint identity is immutable to prevent existing targets or jobs
  from being silently rerouted. Add a new connection to use a different host.
- Local paths, token provisioning, worker deployment, migration and resource-budget
  configuration are administrator tasks. Ordinary assessment operation needs no CLI.
- An existing foreign-tenant domain cannot be reassigned under the legacy globally
  unique domain schema. Such conflicting discovery fails closed. Tenant-specific
  duplicate domain identities require a separately reviewed ownership migration.
- No interactive visualization framework or process-killing cancellation was added.
  The supported graph is paginated, filtered relationship traversal with provenance.
- Reports are generated downloads; report artifact/history scheduling remains the
  established reporting subsystem. Detail limits and truncation are explicit.
- Live GHES, Windows/WSL Ollama and PostgreSQL/Redis deployment certification require
  configured test deployments. Normal acceptance uses disposable SQLite and mocks.

Local AI policy and deployment limits are documented in [local AI](local-ai.md).
