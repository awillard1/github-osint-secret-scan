# Assessment control plane validation — 2026-09-15 continuation

## Autonomous continuation classification (2026-09-16)

This review preserves the historical acceptance results below. Initial backlog:

| Remaining item | Classification | Disposition |
|---|---|---|
| Existing assessment creation, bulk targets, connections, scope, scans, progress, findings, Reveal, triage, reports, AI adapters | COMPLETE | Retain existing acceptance/security coverage |
| Nuclei local template Settings editor and binary/template readiness | PARTIAL | Implement shared persisted configuration and browser controls |
| Active launch review and upstream execution provenance | PARTIAL | Implement explicit review and bounded causal input records |
| Domain observation detail and HTTP/DNS presentation | PARTIAL | Enrich canonical results using existing safe projection |
| Hundreds of mixed targets and 1,000-observation performance acceptance | PARTIAL | Extend deterministic integration coverage |
| Combined GitHub mock, real loopback, Reveal/report/AI acceptance | PARTIAL | Extend acceptance evidence without external targets |
| Live GHES instances, authorized external Amass/Subfinder discovery, Windows Ollama endpoint | OPERATOR CONFIGURATION | No network/firewall changes or external recon |
| Optional scanner binaries, local Nuclei templates, workers, credentials and resource budgets | OPERATOR CONFIGURATION | Accurate readiness; no automatic installation |
| Distributed PostgreSQL/Redis deployment certification | OPERATOR CONFIGURATION | Requires deployment environment |
| Cross-tenant duplicate globally unique domains | BLOCKED | Requires separately reviewed ownership/schema migration; retain fail-closed boundary |
| Uncover, tlsx, asnmap; Amass newer than v3 | BLOCKED | Unsupported by current compatibility policy; do not advertise support |
| Standalone IP registration targets, distributed installer jobs, interactive graph | COMPLETE | Existing bounded domain-RDAP, local installer and table graph contracts; outside accepted product scope |

No new tool adapter is NOT STARTED within the supported inventory. Historical
limits are retained rather than represented as new product regressions.

## Outcome

The disposable browser operator acceptance workflow passes. The continuation keeps
and extends the original control-plane implementation; it does not restart the
architecture. Final validation passes: **866 tests passed, 7 skipped**, doctor,
build, clean install and static checks. Live deployments are not certified by
mocked acceptance; the blocked deployment/schema limits below remain explicit.

## Reconstructed baseline

Inspected the full previous checkpoint, architecture/development/testing/scanner/
projection/release documents, working-tree changes, migration, source and tests.
The base commit was `c2804af`; all assessment work remained uncommitted. The initial
assessment test run passed **39 tests**. The previous full run's **842 passed,
7 skipped** was historical evidence, not proof of this continuation's changes.

The actual gaps included missing connection edit/disable controls, artifact lifetime,
public-search connection identity, launch-option snapshots, traversal beyond one
page, combined association provenance, full scan review/progress, scope in exported
reports, filtered relationship exploration, and complete browser acceptance.

## Milestone matrix

“Complete” means the specified operator behavior is implemented and covered by
normal tests. Resource limits and deployment prerequisites are listed separately.

| Milestone | Status | Implemented behavior / exact limitation |
| --- | --- | --- |
| A — Assessment lifecycle | COMPLETE | Create, edit, pause/resume, complete/archive and reopen through web/service/API. |
| B — Many target locations | COMPLETE | Multiple GitHub/GHES orgs/users/repos, domains, permitted local paths and uploaded artifacts in one assessment; no fixed assessment target count. |
| C — Bulk import | COMPLETE | Line/UTF-8 file/CSV batches, normalization, deduplication, valid rows retained beside invalid lines; 151 unique locations tested. |
| D — Connection management | COMPLETE | Add/edit/disable/test; safe identity/rate-limit metadata; environment references with exclusive tenant grants. Endpoint changes require a new connection to prevent rerouting existing jobs. |
| E — Operator workflow/review | COMPLETE | Saved targets, recon configuration, scope review and a separate scan review step that creates no jobs. |
| F — Organization recon | COMPLETE | Organization/user repositories, per-target explicit private/internal scope, archive/fork metadata, fork parents, contributors, members, commits/email domains, contributor-owned public repositories and connection-bound public search. |
| G — External recon | COMPLETE | All existing ready registered external providers can be orchestrated; comprehensive resolves readiness dynamically. Aggregate aliases are not duplicated; GitHub search uses its explicit target connection. |
| H — Discovery control center | COMPLETE | Durable queued/running/completed/failed stage records, provider readiness/selection/status/counts, refresh and failed-target retry. Other domain providers continue after a provider fails. Pause is cooperative, not process cancellation. |
| I — Correlated asset views | COMPLETE | Repository/account/domain tables with source/connection/association metadata, filters and pagination; HTTP status shown only from an observed HTTPX result. |
| J — Scope review | COMPLETE | Search, visibility/archive/fork/confidence/source/date/scanned filters; checked rows, page, filtered include/exclude and clear. Exclusion retains discovery data. |
| K — Scan launcher | COMPLETE | Shared ScanPlan and scanner registry, all requested profiles including Custom, readiness, branch/ref/history/incremental controls, review counts and explicit launch. Readiness is checked once per scanner per review/launch. |
| L — Progress | COMPLETE | Actual queue states, latest scan completion per repository, severity totals, attempts/failure codes, stage status and job drilldown. No invented percentages. |
| M — Canonical findings | COMPLETE | Existing canonical correlation is retained; acceptance observes one finding per repository from eight scanner observations. New finding-to-repository edges retain scanner provenance. |
| N — Deterministic association | COMPLETE | Source/reason accumulation, first/last observations, membership/contribution/fork/email signals. Verified ownership edges do not automatically assert target association. |
| O — Relationship exploration | COMPLETE | Paginated/filterable graph tables and asset traversal, including organization ownership, contributors, owned repositories, forks, email domains, referenced domains and findings. Every edge has provenance/confidence/time. |
| P — Findings workbench | COMPLETE | Severity/confidence/status/scanner/repository/org/account/domain/credential-type/date/lifecycle filters; complete scoped detail, evidence, association provenance, remediation and triage. Reveal remains explicit and audited. |
| Q — Assessment home | COMPLETE | Assessment root landing, counts, owner/activity, job-state and failed-job attention summary. |
| R — Navigation | COMPLETE | Global and assessment tabs, breadcrumbs and contextual finding/relationship links. |
| S — Large-input/resource safety | COMPLETE | Multiple bounded batches/pages; full security context is retained independently of display pagination. Oversized context fails closed. |
| T — Multiple GitHub/GHES instances | COMPLETE | Three-host normalization, discovery/search, asset correlation and scan acceptance; credential and rate-limit isolation tests. Live GHES certification is separate below. |
| U — Discovery observations | COMPLETE | Shared domains across providers/repository metadata; deduplicated sources and timestamps; connection-scoped repositories/accounts/orgs; unlinked commit identities are explicitly self-reported. |
| V — Reusable recon profiles | COMPLETE | Save/select profiles in UI and API; each job retains resolved launch options. |
| W — UI quality | COMPLETE | Server-rendered forms/tables, empty/validation/running/failure states, pagination, selection controls, model selector and consistent navigation. |
| X — Security/release validation | COMPLETE | 866 tests passed, 7 skipped; doctor, wheel/sdist, clean install, compile/diff checks, migration/security/query-count regressions pass. Live certification remains blocked separately. |
| Y — Operator acceptance | COMPLETE | The complete disposable browser workflow passes, including exact credential reveal with one audit and no secret in reports or Ollama input. |
| Z — Optional local AI | COMPLETE | Configured endpoint/model inventory/selection, purpose-specific advisory prompts, explicit repository/finding selection, bounded sanitized input, independent queued failure/cache and optional sanitized report summary. No tools, downloads, automatic decisions or protected plaintext. |

## Security and operational limits

- **BLOCKED — live certification:** no enabled Ollama/model or live-scanner opt-in
  is configured. Dedicated GHES A/B, Windows/WSL Ollama and distributed deployment
  certification require external test deployments. No firewall/network/model changes
  were made. SQLite/mocked acceptance is not live-service certification.
- **BLOCKED — cross-tenant duplicate domain identities:** the legacy Domain name is
  globally unique. A domain already owned by another tenant cannot be reassigned;
  discovery refuses the conflict. Supporting independent duplicate domain rows
  requires an ownership/schema migration and compatible changes to existing domain
  providers. This run preserves the fail-closed boundary instead of weakening it.
- Local path enablement, token provisioning, worker deployment, migrations and
  resource budgets are administrator configuration. Ordinary operator workflow is web.
- GitHub traversal uses configured page budgets; exhaustion fails the operation
  explicitly. Search retains the existing bounded GitHub search policy and public
  visibility checks. Retry repeats the target idempotently, not an unknown cursor.
- Reports include all assets and targets using bounded batches; a **601-target**
  export is tested. Complete finding details and complete security context must fit
  the configured budgets, otherwise export fails explicitly. Downloaded reports are
  not a new report-archive/history product.
- AI uses bounded advisory sampling. Oversized sanitized input reduces whole
  observations deterministically and records omitted counts in its input policy;
  impossible budgets fail closed. Exhaustive hierarchical analysis and source-code
  sharing are not enabled. Canonical analyst triage remains separate from AI output.
- Generation concurrency is enforced per shared data directory. Distributed workers
  require a shared lock-capable directory or deployment concurrency configuration.
- Interactive graph graphics and process-killing cancellation are not required:
  the supported alternatives are explainable table traversal and cooperative pause.

## Operator acceptance evidence

`tests/assessments/test_operator_acceptance.py` logs in an authorized operator,
creates **Comprehensive Organization Assessment**, configures GitHub.com and GHES
A/B through the web, imports org/user/repository/domain targets with duplicates
and an invalid line, runs comprehensive recon, correlates providers/assets, excludes
archived repositories, reviews and confirms Comprehensive Scan, checks ScanPlan
and completion, verifies eight scanner observations per canonical finding, opens
the masked credential, reveals its exact value and checks one audit, triages,
exports all five report formats, and generates sanitized local AI advice.

External transport and scanner execution are mocked; canonical persistence,
queue orchestration, auth/CSRF, service projections, encryption/reveal and report
renderers are real. Separate tests exercise real local/artifact scanning and
151-target ingestion, 601-target export, malformed archives, three-host search replay, context limits,
foreign-tenant relationships and query counts.

## Migration and workspace

Head remains `20260915_0014`. The additive eight-table migration from the previous
run was inspected and not rewritten. Migrations through 0013 remain unchanged.
No configured database was modified. Tests, doctor and install validation use
disposable databases. Work remains uncommitted; no deployment or release was made.

## Validation results

- Baseline assessment suite: **39 passed**.
- Focused assessment/archive/report suite: **115 passed** at that milestone.
- Focused assessment/search/profile suite: **78 passed** at that milestone.
- Browser acceptance plus AI safety suite: **11 passed**.
- Expanded assessment suite: **52 passed** before the final small additions.
- Latest provenance/connection/report/UI regression module: **13 passed** at that milestone.
- Large-report plus operator acceptance: **15 passed**.
- Mixed public/private target and recon regressions: **24 passed**.
- Final focused assessment/search/profile suite: **87 passed**.
- Final credential-context and recon regressions: **28 passed**.
- Initial full run: **857 passed, 7 skipped**, with one stale root-redirect test
  expectation subsequently corrected. An intermediate run interrupted during review
  is not treated as final validation.
- Final full pytest: **866 passed, 7 skipped, 2 warnings**, **580.06 seconds**;
  `/tmp/orgscan-assessment-final-validation.log`. Skips are optional live tests;
  warnings are existing Starlette/httpx/AnyIO deprecations.
- `orgscan doctor --json`: **ok=true**, **21 ok / 17 warnings / 0 errors**, disposable
  database; `/tmp/orgscan-assessment-doctor-apxich8b/doctor-final.json`.
- Distribution build: wheel and sdist passed; log
  `/tmp/orgscan-assessment-final-build.log`.
- Clean install: passed runtime-only dependency checks, migrations, CLI/API, scan,
  JSON/SARIF and encrypted evidence/exact reveal against the rebuilt final wheel;
  `/tmp/orgscan-assessment-final-clean-install.log`.
- Static: `compileall` and `git diff --check` pass; all 32 untracked source/test/doc
  files pass whitespace checks. No Ruff/mypy configuration exists. The final source
  inventory and diff were reviewed; frozen migrations have no changes.
- Performance: repository scope pages retain **5 SELECTs** at **10/100/300** records;
  full-suite query/security regressions pass.

New UI/API families and administrator deployment guidance are listed in
[the operator guide](assessment-control-plane.md). No new CLI command family was
added; existing scan/queue/report/doctor commands are reused.

## Final delivery summary

- **Completed this run / new UI:** lifecycle and connection editing, target-specific
  visibility, encrypted upload retention/purge, reusable recon profiles, durable
  discovery stages, complete scope controls, read-only scan review/confirmation,
  actual progress, assessment finding detail/triage, relationship traversal and
  complete assessment report exports. Navigation and operator validation are coherent.
- **New API:** assessment/connection/profile management, artifact upload/removal,
  target visibility, discovery/retry, correlated asset/scope/graph views, ScanPlan
  preview/launch, progress, finding detail/triage, reports and advisory AI use the
  same tenant-scoped services as the web adapters. See the operator guide for routes.
- **New CLI:** no command family added; existing administrator migration, queue,
  scanning, reporting and doctor commands remain the shared operational foundation.
- **Recon/correlation:** registered ready domain providers and connection-bound
  GitHub search; organizations, repositories, accounts, self-reported commit
  identities, domains and relationships retain deterministic provenance and
  observation times. Canonical scanner observations remain merged into findings.
- **Multi-target / multi-GHES:** no small target-count restriction; bounded batches
  retain valid input beside errors. GitHub.com plus GHES A/B are covered in one
  assessment, including credential/rate-limit isolation and public/private limits.
- **Ollama:** optional and disabled in this environment; endpoint test/model
  selection and all five advisory purposes are tested with transport fakes. No
  automatic model download, firewall change, tool execution or authoritative action.
- **Security validation:** the full suite covers tenant and assessment isolation,
  credential context completeness and budget failures, encrypted protected evidence,
  explicit exact audited Reveal, safe reports/AI requests/cache/metadata/logs,
  private-scope boundaries, CSRF, queue integrity and bounded input/acquisition.
  Repository-derived assets and updates retain candidate context through ingestion.
- **Still partial / blocked / remaining product gaps:** live GHES, Windows/WSL
  Ollama and distributed deployment certification require external deployments.
  Cross-tenant duplicate domain support remains blocked on a separately reviewed
  ownership/schema migration; conflicting discovery fails closed. Bounded advisory
  sampling is not exhaustive source-code analysis. The required disposable operator
  workflow passes; these broader deployment/schema limits are not declared complete.
- **Migrations:** unchanged additive development migration 0014; upgrade preservation
  tests pass. Frozen migrations and configured database remain untouched.

All required local validation gates pass. Changes remain uncommitted and undeployed.

## Recon toolchain follow-up

The subsequent recon integration adds Settings → Recon Tools, explicit installers,
scoped provider stages, canonical recon assets and migration 0015. Its validation
and remaining compatibility limits are recorded separately in
[Recon toolchain validation](recon-toolchain-validation.md); the earlier migration
and CLI statements above describe the preceding assessment release.

## Completion-run acceptance (2026-09-16)

The initial PARTIAL items above are now implemented and covered by tests:

| Area | Final classification | Evidence / boundary |
|---|---|---|
| Operator workflow | COMPLETE | Authenticated browser handlers: assessment, mixed targets, discovery, scope, scan review/launch, progress, finding detail, Reveal, triage, five reports and optional AI |
| Nuclei configuration | COMPLETE | Platform-admin UI saves multiple approved local directories; atomic private configuration shared by workers/doctor; binary/template readiness separate; no downloads |
| Active recon | COMPLETE | Explicit review and confirmation, operator/time snapshot, scoped inputs, resolved-host dependency for HTTPX/Naabu; installed does not mean enabled |
| Correlation / provenance UI | COMPLETE | Per-provider domain attributes, address/status/technology/confidence/timestamps, expandable observations; stage input entity IDs, digest and upstream providers |
| Multi-target / multi-GHES | COMPLETE | 400 unique mixed locations, duplicate imports, GitHub.com + GHES A + GHES B; bounded pages |
| Correlation performance | COMPLETE | 100 targets, 1,000 observations, ten providers, exactly 100 canonical domains; fewer than 1,000 SELECTs; bounded transaction-local identity reuse |
| Combined local acceptance | COMPLETE | Three mocked GitHub instances + real DNSX/HTTPX/Katana/Nuclei on loopback + real local scanner + exact encrypted Reveal + JSON/HTML/CSV/PDF/SARIF + sanitized mocked Ollama |
| Live recon contracts | COMPLETE | Local DNSX, HTTPX, Katana, Naabu, Nuclei; deterministic Subfinder contract; Amass passive command/parser/correlation mocked |
| External deployments and authorized external enumeration | OPERATOR CONFIGURATION | Live GHES, external Subfinder/Amass, optional binaries, Windows-host Ollama endpoint, shared worker paths and deployment resources |
| Legacy foreign-tenant duplicate domains | BLOCKED | Existing global uniqueness still fails closed; separate ownership migration required |
| Unsupported tool/platform extensions | BLOCKED | tlsx/asnmap/Uncover and newer Amass remain explicitly unsupported |

**Partial workflows:** none identified within the supported operator workflow. This
is local/mocked acceptance, not certification of external services or all deployment
platforms. GitHub transport is mocked in the combined live workflow; recon binaries
and local repository scanning are real. Reports and AI are checked independently
for absence of the synthetic protected credential. No configured database was
migrated, no optional tools installed, and no external reconnaissance performed.

Validation results:

- Focused assessment/recon/projection run: **126 passed** (before the final two
  path/Amass regressions); final new-feature suite: **10 passed**.
- Complete live suite: **8 passed, 5 skipped**, 103.74 seconds. Skips: optional
  live Ollama and four unavailable scanner executables.
- Full regression suite: **899 passed, 14 skipped**, two existing dependency deprecation warnings, 703.10 seconds. Established security and migration
  suites are included; projection safety also passed in the focused run.
- Doctor: **required checks passed, 21 warnings**. Nuclei reports **Binary Ready;
  Templates Missing or invalid** on the unchanged workstation configuration.
- Build: passed. Final clean runtime-only install: passed (runtime dependencies, migrations, CLI/API, scanning, reports and encrypted Reveal).
- Compile and whitespace checks: passed. Migration head remains
  **20260915_0015**; no schema change or configured-data migration.

Remaining product boundary: legacy cross-tenant duplicate-domain ownership.
Optional tool availability, Nuclei template choice, live GHES and Windows/WSL
Ollama reachability require operator configuration; they do not prevent the
independently tested workflow. A fresh loopback-only `/api/tags` check remained unreachable. No Windows
networking/firewall changes were made.
