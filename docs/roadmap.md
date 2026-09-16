# orgscan phased roadmap

This is the implementation status, reconciled against source and tests on 2026-09-14. [projectspec.md](../projectspec.md) remains product vision; [development-plan.md](development-plan.md) defines the engineering phase order. The older roadmap's Phase 0–10 labels described historical feature slices, not completion of the new engineering phases. The Phase 0 audit is retained below; the initial Phase 1 finding-management slice is recorded separately and does not mark the full decomposition or later phases complete.

## Current architecture/capability baseline

The package now has `api/` (FastAPI, compatibility `OrgscanApiService`, artifact handling), `cli/` (Typer commands), `services/` (finding workflows, scanner inventory, scan planning/execution and incremental decisions), and shared modules: `runner.py`, `repositories.py` (`Storage`), `models.py`, `schemas.py`, `mirroring.py`, `scheduler.py`, `queueing.py`, `providers.py`, `discovery.py`, `expansion.py`, `auth.py`, and `reporting.py`. Finding routes and commands have been extracted into `api/routes/findings.py` and `cli/commands/findings.py`; the remaining adapters still live in the package `__init__.py` files. Shared scan execution and persistence already exist, but substantial orchestration remains in presentation code. The full layout in [architecture.md](architecture.md) remains a migration target.

“Implemented” below means present in source with the cited test coverage; it does not imply live external-service certification or completion of every product-vision requirement.

| Area | Implemented capability and evidence | Partial or missing scope |
| --- | --- | --- |
| Foundation and storage | Packaging, CLI entry point, environment configuration/redaction, bootstrap/readiness, SQLAlchemy `Storage`, canonical findings, evidence, risk scores, targets, jobs, relationships, suppressions, users/sessions, queue and rate-limit records. `db.py` supports explicit Alembic migration through `20260914_0011`; production startup checks the revision without applying migrations. Tests: `test_config.py`, `test_bootstrap.py`, `test_db.py`, `test_storage.py`, `test_schemas.py`. | SQLite fresh initialization and populated prior evidence-schema upgrades are exercised; PostgreSQL operation remains unverified. Phase 16 adds non-creating doctor and wheel resources; Phase 18 adds runtime-only clean-install CI and frozen historical migration inputs. Bootstrap offers installation guidance, not a complete external-binary installer. |
| Scanners and plugins | Ten registered scanners (Phase 7 adds heuristic-rules): custom-patterns, git-history-patterns, repo-governance, gitleaks, detect-secrets, semgrep, trufflehog, yara, ripgrep-heuristics, heuristic-rules. Registry factory and `orgscan.scanners` entry-point loading already exist, including report ingestion for supporting scanners. `runner.py` normalizes `ScanMatch` into stored `CanonicalFinding` and records ToolRuns. Phase 2 adds uniform metadata/readiness/context/result adapters, duplicate-ID rejection and registry-driven API/CLI inventory. Tests: `test_scanner.py`, `test_external_scanners.py`, `test_runner.py`, `test_cli.py`, `tests/scanners/`, `tests/api/test_scanner_registry.py`. | YARA versions and detect-secrets 1.5.x version/help compatibility are probed with bounds; other external versions remain unknown and runtime configuration is not certified; legacy plugins retain responsibility for execution safety. Mocked tests do not establish live tool compatibility. |
| YARA and heuristics | YARA ships three token/key rules and accepts a configured rules file; its parser redacts matches. Ripgrep scans configurable internal suffixes and organization keywords. Tests: YARA/ripgrep parser cases in `test_scanner.py`; configuration cases in `test_config.py`. | Phase 6 maps local rule metadata and unknown rule IDs, detects versions, and fully redacts matched values/source snippets. Tests: `tests/scanners/test_yara_contract.py`. Phase 18 fingerprints bounded local includes and disables skipping for unresolved configuration. Phase 7 adds the opt-in heuristic-rules scanner with validated JSON, timed regex, stable digests and five starters. Existing ripgrep/custom definitions remain compatible. Tests: `tests/scanners/test_heuristic_rules.py`. |
| Scan planning | Eight deterministic profiles, explicit overrides and versioned plans shared by CLI/API/scheduler/queues; job/schedule JSON preserves intent. Tests: `tests/services/test_scan_plan.py`, `tests/api/test_scan_profiles.py`. | Discovery profiles use existing domain providers; the dashboard scanner dropdown still supplies explicit scanner selection. Batches are sequential, with per-scanner commits. |
| Repository acquisition and history | `mirroring.py` clones/reuses a working checkout, fetches tags/remote refs, persists mirror path/time and tracked/available refs, and checks out requested branches/tags. CLI and scheduled scans support multiple refs and record scope/ref on scan jobs. Built-in history scanning reads Git diffs. Tests: `test_mirroring.py`, mirror/history cases in `test_cli.py`, `test_scheduler.py`, `test_scanner.py`. Phase 4 adds isolated scan worktrees, POSIX locking, default-branch discovery and persisted sync/scan checkpoints in existing JSON. Tests: `tests/services/test_repository_cache.py`. Phase 5 adds opt-in unchanged skipping, verified history ranges, branch/deletion policies and conservative full fallback. Tests: `tests/services/test_incremental.py`. | Crash-orphan cleanup and distributed locking remain incomplete. |
| Discovery and relationships | GitHub repository/organization discovery and bounded contributor/fork/ownership expansion; relationships include source and confidence. Domain providers include local metadata, crt.sh, WHOIS, DNS, ProjectDiscovery subfinder/httpx, security.txt, and GitHub repository/code/issue search. Search stores query/evidence provenance in domain exposures and identity correlations. Tests: `test_discovery.py` and discovery/expansion cases in `test_cli.py`. | Phase 10 integrates validated repository/code/issue search results into canonical findings, evidence and graph entities; malformed resource identities are skipped. Phase 9 adds explainable ownership, forks, contributors, mentioned domains and commit email-domain associations through a shared service. Pagination/recovery and confidence-based expansion remain incomplete. |
| Paid enrichment | Optional HIBP, DeHashed, Intelligence X and enriched aggregate providers are implemented with configuration checks and persisted exposure/correlation records (`providers.py`). Mocked CLI coverage: `test_cli_paid_domain_discovery_and_enriched_aggregate`. | Not live-provider certification. HIBP currently filters breach-catalog entries by breached domain; it is not a comprehensive employee-account exposure search. |
| Findings and risk | Stable normalized hashes, repeated-finding updates, first/last seen, severity/confidence/source-weighted scoring, filters and entity risk summaries; triage, owner/notes/deadline, suppression, accepted risk and unsuppression. Qualifying later-scan reappearances become REGRESSED with legacy `triage_state="reopened"`. Shared `services/finding_service.py` now owns listing/detail and decision transactions. Tests: `test_storage.py`, `test_schemas.py`, `test_runner.py`, finding workflows in `test_cli.py`/`test_api.py`, and `tests/services/test_finding_service.py`. | Phase 8 adds repository-scoped exact-secret-digest correlation and idempotent evidence with scanner provenance; tests: `tests/services/test_correlation.py`. Legacy records are retained without automatic backfill. Phase 12 adds explicit lifecycle transitions, retained audit history and chronological regression detection; tests: `tests/services/test_lifecycle.py`, `tests/api/test_lifecycle_routes.py`. Legacy timestamps are inferred; concurrent transition races remain unverified. |
| API and dashboard | FastAPI JSON health/summary, findings/evidence/workflows, entities/risk, scan jobs, schedules, graph and trends; server-rendered dashboard/detail/graph pages and file/ZIP/TAR artifact scans (TAR extraction is present in source; tests cover files and ZIP). Tests: `test_api.py`. | API/UI do not expose every CLI use case. Extraction has path-containment and size/count checks, TAR special-entry rejection and temporary-workspace cleanup, with Phase 17 adversarial tests for traversal, symlinks, resource bounds and cleanup. Concurrent external filesystem mutation remains a deployment limitation. Phase 13 adds service-backed operator queues and paginated drill-downs; operator queues use authorized SQL counts and pagination; other dashboard queries and production-scale query performance remain follow-up work. |
| Authentication and tenancy | `auth.py` defines `AuthContext`, environment tokens, hashed database session tokens, role/tenant resolution, expiry/revocation checks. CLI creates users, grants tenant roles, creates/revokes sessions. Reporting accepts tenant scope. Tests: CLI user/session management and tenant-scoped scheduled reports. | Phase 11 enforces configured auth across HTTP routes with shared token/browser AuthContext, expiring/revocable cookies, CSRF, global user administration and storage-level tenant read/write checks. Tests: `tests/api/test_browser_auth.py`, `tests/storage/test_authorized_storage.py`, `tests/services/test_auth_service.py`. Password login, MFA/SSO and abuse throttling remain absent. |
| Scheduling, queues and rate limits | Scheduled scans use shared execution; manual cadence disables after execution. Both Redis/RQ and database queue backends exist, with duplicate-enqueue guards, configurable retries and DB task leases. Memory/DB outbound pacing supports per-scope overrides; GitHub rate-limit errors include guidance. Tests: `test_scheduler.py`, `test_queueing.py`, `test_rate_limit.py`, `test_discovery.py`, queue CLI cases. | Phase 14 classifies failures, bounds retries, defers rate limits, guards completed-task replay and conditionally claims DB tasks. Explicit expired-lease quarantine disables schedules; heartbeat-based recovery and distributed exactly-once execution remain absent. |
| Reports | JSON/CSV/HTML and basic ReportLab PDF export, summary/trends, relationship graph, organization comparison and remediation suggestions in `reporting.py`. Scheduled reports support tenant scope, files and webhook delivery. Tests: export/dashboard cases in `test_cli.py` (including PDF signature), `test_api.py`, `test_scheduled_reports.py`. | Phases 15/18 add schema-tested SARIF, executive/technical PDFs, portable local/artifact/repository locations, and authorized SQL filtering/aggregation with batched evidence loading. Unicode font coverage, host-specific SARIF acceptance and large exports remain unverified. Scheduled report delivery is not a general finding-alert system. |

## Remaining gaps and engineering phase mapping

Follow [development-plan.md](development-plan.md) in order, extending existing code rather than recreating these capabilities:

- **Phase 1 (partial; service slices implemented):** finding reads/decisions now share a service and extracted adapters. Continue the remaining families listed below while preserving adapters and imports.
- **Phase 2 (implemented):** common scanner contract and registry, documented below. **Phase 3 (implemented):** shared ScanPlan, eight profiles and persisted resolved intent.
- **Phase 4 (implemented):** cache manager, isolation and checkpoints. **Phase 5 (implemented):** incremental ref/history decisions.
- **Phases 6–7 (implemented):** YARA readiness/metadata/redaction and an opt-in validated rule-driven scanner. Existing ripgrep remains available.
- **Phase 8:** implemented conservative correlation; **Phase 9 (implemented):** bounded GitHub relationship provenance and confidence.
- **Phase 10 (implemented):** bounded public search queries, request provenance and integration into canonical findings/graph.
- **Phase 11 (implemented):** HTTP/browser authentication and tenant boundaries. **Phase 12 (implemented):** lifecycle history and regression detection. **Phase 13 (implemented):** operator queues and drill-downs. **Phase 14 (implemented):** bounded retry policy, rate-limit deferral and conservative recovery.
- **Phase 15 (implemented):** SARIF and PDF variants over shared report queries. **Phase 16 (implemented):** doctor, wheel packaging/installation smoke tests and a release-readiness checklist with explicit deployment gaps.

## Post-Phase-16 release recovery

Recovery on 2026-09-14 found a clean `codex/architecture-foundation` tree at `03cc9fa`.
The interrupted release fixes were committed, including migration 0008. Baseline
security/scanner/authorization checks passed 91 tests and the full suite passed 360.
Inspection and additional adversarial probes found remaining portions of audit items
1, 3, 4, 5 and 8; only those implementations were changed. Items 2, 6, 7, 9 and 10 were
verified and preserved. No MEDIUM/LOW work was included.

Shared redaction now removes copied/nested source values and known secrets in paths,
while ripgrep/governance/YARA omit raw source snippets. Original target spelling reaches no-follow validation;
parent traversal and external filesystem trees containing symlinks are rejected.
Saved/live Gitleaks reports and YARA location reads are bounded; file-output budgets
remain enforced when a child closes stdout/stderr. Historical imports and raw-payload
commit observations cannot falsely reopen remediation, while current-tree regression
still works. Legacy HTTP provider timeout/decoding failures now have safe diagnostics.

The [release recovery audit table](release-readiness.md#post-phase-16-recovery-audit-2026-09-14)
records evidence, compatibility changes and remaining risks for all ten items.
`orgscan doctor` found the configured database still at 0007 (application head 0008),
so deployment needs a backed-up upgrade; the database was not modified by recovery.

Final validation: **192 focused tests passed** and **398 full-suite tests passed**,
with two existing Starlette/AnyIO deprecation warnings, in 129.03 seconds outside
the sandbox. The recovery adds 38 adversarial cases; existing tests were not weakened
or changed. Compilation and `git diff --check` passed; the full diff was inspected.
No static checker is configured. Doctor exits 1 for the pre-existing migration lag
and reports 17 configuration/dependency warnings. Changes remain uncommitted.

## Operator queue pagination follow-up

The operator overview now uses storage-owned SQL filtering, counts and bounded pages
for findings and scan jobs. Recent assets are counted and paginated across all four
entity types in one ordered union. Tenant loader criteria apply to aggregate queries
and every union branch; lifecycle risk policy and the existing API response shape
are preserved. Equal timestamps/scores have deterministic tie breakers. No migration,
CLI or job adapter is needed for this read-only dashboard change.

Regression tests cover bounded ORM loading, stable/disjoint pages, offsets beyond the
last row, high-risk lifecycle parity, and all queue counts and asset union pages across
multiple tenant contexts. Counts/pages are separate reads; concurrent changes can
shift pages. Other dashboard sections and deployment-scale SQL tuning remain outside
this slice. See [operator dashboard](operator-dashboard.md).

Validation: relevant baseline **2 passed**; full baseline **357 passed**. Focused
dashboard/authorization tests **7 passed**; final full suite **360 passed**, with two
existing Starlette/AnyIO deprecation warnings, in 404.36 seconds outside the sandbox.
Compilation, tracked diff and changed untracked-file whitespace checks passed. No
static checker is configured. Existing uncommitted work is preserved.

## Phase 16 — Doctor and release hardening

Added human/JSON doctor with required/optional exit semantics, read-only database/migration checks, directory permissions, queue/token/auth/scanner/provider readiness and safe diagnostics. Fixed installed-wheel migration resources and percent-escaped database URL handling; source checkout behavior remains. Added offline build/install smoke coverage and development build tools. README distinguishes bootstrap side effects from doctor, and [release readiness](release-readiness.md) records installation, backup/upgrade, startup, smoke/security checks and unresolved 1.0 requirements. Version remains 0.1.0; no publication or production certification.

Validation: full baseline **304 passed**; relevant bootstrap/config/database baseline **8 passed**. Initial wheel inspection confirmed no bundled migrations. Focused doctor/packaging/bootstrap/config/database checks passed **13 tests**; the rebuilt installed wheel completed its local smoke path. Final full suite: **309 passed**, two existing Starlette/AnyIO dependency deprecation warnings, in 109.51 seconds outside the sandbox. `pip check`, compilation, tracked diff checks and untracked text whitespace checks passed. No configured static checker, release publication or commit was added.

## Phase 15 — SARIF and PDF reporting

All export formats use canonical report queries with lifecycle and scanner evidence. Added SARIF 2.1.0, paginated executive/technical PDFs and authorized HTTP downloads; existing JSON/CSV/HTML and PDF alias remain. Export redaction omits raw source material, CSV guards formula cells, and static HTML omits browser session controls. Added development-only jsonschema/pypdf for official offline schema validation and PDF content checks. No schema migration. See [reporting](reporting.md) for compatibility and limits.

Validation: full baseline **294 passed**; focused existing CLI/export/scheduled baseline **2 passed**. Focused checks passed **11 report/CLI/scheduler tests** and **23 API/browser/report tests**. Full suite: **304 passed**, two existing warnings, in 115.80 seconds. SARIF validates against the offline OASIS schema; PDF text tests cover zero and 120 findings. Diff/whitespace and compilation checks passed.

## Phase 14 — Job reliability

Both queue backends now share failure classification and bounded retry delays; explicit rate limits defer and terminal failures disable schedules. RQ retry scheduling is enabled with safe failure logging. DB claims use conditional updates, completed tasks/RQ executions have replay guards, and expired DB leases can be inspected/quarantined explicitly. Domain/search service boundaries preserve deferred failures. Existing checkpoints/canonical upserts remain the partial-scan idempotency mechanism. Logical job metadata uses existing JSON; no schema change. See [job reliability](job-reliability.md) for limits and recovery procedure.

Validation: full baseline **282 passed**; focused queue/scheduler/rate-limit/incremental baseline **22 passed**. Focused checks passed **58 queue/policy/provider/plan/scheduler/incremental tests**. Full suite: **294 passed**, two existing warnings, in 101.00 seconds. Existing fakeredis tests now mock the newly enabled scheduler process/Lua boundary; dedicated tests assert scheduler enablement and retry registry state. Diff/whitespace and compilation checks passed.

## Phase 13 — Operator dashboard

The server-rendered dashboard now leads with seven service-backed queues and total counts, with paginated drill-downs and JSON overview. Risk/lifecycle policy is shared, user-controlled labels are escaped and request storage preserves tenant boundaries. Existing uploads and triage actions remain. No schema/framework change. See [operator dashboard](operator-dashboard.md) for queue definitions and scalability limits.

Validation: full baseline **280 passed**; existing dashboard/API baseline passed in Phase 12. Focused checks passed **14 existing API tests**, **8 browser authorization tests**, **1 operator API/HTML test** and **1 queue service test**. Full suite: **282 passed**, two existing warnings, in 105.51 seconds. The JSON overview was moved outside the browser redirect prefix after its authentication test exposed the distinction. Diff/whitespace and compilation checks passed.

## Phase 12 — Finding lifecycle and regression detection

Added an explicit lifecycle alongside compatible legacy statuses/triage labels, before/after audit records, remediation/regression timestamps and counts. Shared storage recognizes only later scan-job re-observations as regressions, preserving analyst notes/owner and first seen; repeat/old observations do not regress. CLI/API expose transitions and state filters; finding detail HTML/JSON shows history and report rows/summaries expose states. Alembic `20260911_0007` maps populated legacy records with marked inferred timestamps. See [finding lifecycle](finding-lifecycle.md) for transition rules, compatibility and limits.

Validation: Phase 11 full baseline **275 passed**; relevant baseline **23 passed**. Focused checks passed **22 storage/service/runner/migration tests**, **8 lifecycle/authorization/migration tests** and **22 API/browser tests**. Full suite: **280 passed**, two existing dependency warnings, in 92.11 seconds. The first full run exposed a stale revision assertion and cached-settings leakage in the new CLI integration test; both were corrected. Diff/whitespace and compilation checks passed; no static checker is configured.

## Phase 11 — Browser authentication and user administration

Existing tokens now authenticate JSON and browser routes through one auth service. Browser login mints a bounded, revocable child session; POST forms and JSON/multipart cookie requests enforce CSRF and origin checks. Current memberships cap DB token roles/scopes, parent revocation invalidates child sessions, and auth storage errors fail closed. Global administrators manage users/memberships and issue tokens through JSON/browser adapters. Request-owned SQLAlchemy sessions enforce tenant visibility and writes beneath the existing services, including lazy relationships and aggregates. No schema migration. See [browser auth](browser-auth.md) for bootstrap, compatibility changes and deployment limits.

The generated environment template no longer contains a known token. Existing unconfigured local mode remains. Scoped users cannot provision unassigned assets, and user administration requires wildcard admin scope. Correlation preservation tests were corrected to assert real persisted triage fields rather than incidental Python attributes.

Validation: Phase 10 baseline **265 passed**; relevant auth/finding/CLI baseline **12 passed**. Final focused checks passed **32 API/auth/finding tests** and **7 storage/token/config tests**. Full suite: **275 passed**, two existing dependency deprecation warnings, in 104.60 seconds outside the sandbox. Diff/whitespace checks passed; no static checker is configured.

## Phase 10 — GitHub public search intelligence

The existing provider now delegates to a bounded query service for domain/organization identifiers and identifier-paired sensitive filenames. Normal jobs retain exact request/pagination/rate-limit metadata, including empty results; repositories/accounts, canonical findings, evidence, relationships and legacy domain exposure views share deduplication. Target string matches remain heuristic. Corrected the provider's literal masked authorization header to send the configured Bearer token, skipped code search without credentials, and stopped on rate-limit exhaustion/failure with recorded safe diagnostics. CLI adds explicit organization search via `--provider github-search`. No schema migration. See [GitHub search](github-search.md) for output and coverage limits.

Validation: Phase 9 full baseline **257 passed**; relevant search/discovery/rate-limit baseline **10 passed**. Final focused checks passed **17 service/CLI/discovery/rate-limit tests** and **1 request-history API/HTML test**. The full suite passed **265 tests**, with two existing dependency deprecation warnings, in 83.23 seconds outside the sandbox. Diff/whitespace checks passed; no static checker is configured.

## Phase 9 — GitHub relationship intelligence

Existing discovery/expansion now shares repository ingestion in `services/relationship_service.py` with compatibility exports. Typed relationship names, deterministic confidence, bounded recent commit/email-domain associations and discovery metadata retain source/endpoint/reason/timestamps. Existing graph/entity JSON exposes provenance; the graph page renders it with HTML escaping. Discovery preserves repository cache state. Fresh fork observations correct matching unannotated legacy inverse edges. No schema change or new graph store. See [GitHub relationships](github-relationships.md) for limits and compatibility.

Validation: Phase 8 full baseline **254 passed**; discovery/expansion baseline **8 passed**. Final focused checks passed **21 discovery/storage/CLI tests** and **1 graph API test**. Full suite: **257 passed**, two existing dependency deprecation warnings, in 88.40 seconds outside the sandbox. Diff/whitespace checks passed; no static checker is configured.

## Phase 8 — Finding correlation and evidence deduplication

The runner now applies conservative organization/repository-scoped value fingerprints, attaches multiple scanner observations to one canonical finding, and upserts repeated evidence. Scanner-specific detector metadata remains visible through evidence; stronger confidence/severity/risk remains visible regardless of scanner order. Operator decisions are retained. Built-in secret parsers provide compatible digests without persisting raw values; source snippets are fully redacted. See [finding correlation](finding-correlation.md) for path/line behavior, primary-source filter semantics, per-scan match counts and limits.

Alembic `20260911_0006` adds evidence identity/provenance with a populated SQLite upgrade test. Historical findings are preserved without speculative backfill; first rescans can leave legacy duplicates. No new lifecycle states or discovery/auth/reporting features are included.

Validation: Phase 7 baseline **247 passed**; initial correlation/storage/parser baseline **20 passed**. Final focused checks passed **115 tests**; the full suite passed **254 tests**, with two existing dependency deprecation warnings, in 92.70 seconds outside the sandbox. The first full run exposed an outdated CLI migration-revision assertion, which was corrected. Diff/whitespace checks passed; no static checker is configured.

## Phase 7 — Rule-driven heuristics

Added `heuristic-rules` through the existing registry, reusing custom scanner file handling. Bounded JSON schema/regex loading, include/exclude patterns, timed matching, redacted values and stable digests support operator-authored rules. Five packaged starter rules are opt-in through this scanner; existing scanners and profile defaults remain. Added the regex dependency for bounded matching. No schema or adapter dispatch change. See [heuristic rules](heuristic-rules.md). Baseline **238 passed**; focused checks **93 passed**; full suite **247 passed**, two existing warnings, in 77.90 seconds. Diff/whitespace checks passed.

## Phase 6 — YARA scanner

Extended the existing adapter with bounded version readiness, local rule metadata mapping, conservative unknown-rule defaults, no-follow-symlink execution, output-path containment and fully redacted snippets/indicators. Generic registry paths and canonical persistence are reused; detected versions reach ToolRuns. No new schema, tool-name adapter dispatch or rule downloads. See [YARA](yara.md) for configuration and limits. Baseline scanner checks: **76 passed**; focused tests: **82 passed**; full suite: **238 passed**, two existing warnings, in 76.57 seconds. Diff/whitespace checks passed. Phase 5 changes remain preserved and uncommitted.

## Phase 5 — Incremental branch/history orchestration

Shared plan execution now selects default, explicit, all-remote-branch or legacy tracked refs and makes per-scanner checkpoint decisions. Incremental mode skips unchanged commits/ref objects without materializing worktrees, uses verified fast-forward ranges for the history adapter, and falls back to full coverage after divergence or for content scanners without range semantics. Explicit full/history modes remain available. Deleted known refs produce skip records; unknown refs fail early. Jobs record actual OIDs/ranges, coverage/limits, decisions, configuration keys and resolved intent. Successful checkpoints advance after execution and cleanup, never on skip/failure.

CLI mirror scan/schedule commands expose mode and branch policy; serialized plans, scheduler and both queue backends share execution. `skipped` status and result fields are additive, using existing string/JSON columns without a migration. Settings/version, declared rules-file hashes and binary identity conservatively invalidate checkpoints; remote/undeclared inputs still require an explicit full scan. Full history retains its configured cap; incremental ranges are not truncated by that cap. Skips do not update finding last-seen or resolve findings. No recency heuristic, distributed locking, crash sweeper or lifecycle redesign is included. See [incremental scans](incremental-scans.md).

Validation: Phase 4 baseline **218 passed**; final focused checks passed **63 service/cache/plan/scheduler/queue/scanner/runner tests**; CLI/API compatibility checks passed **41 tests**. Full suite: **233 passed**, two existing dependency warnings, in 78.62 seconds outside the sandbox. Diff and new-file whitespace checks passed; AST comparison confirms the history parser and canonical normalization/hash functions are unchanged. No static checker is configured.

## Phase 4 — Repository cache and checkpoints

The existing mirror module now exposes a manager around sync, inventory, ref resolution and disposable worktrees. Cache mutation and scanning serialize under a bounded POSIX lock. Git subprocesses use safe arguments, timeout/error handling and disabled hooks/global config. Remote symbolic HEAD supplies the default branch; repeat sync preserves configured clone URLs. Storage records previous/current ref observations separately from per-scanner successful checkpoints in versioned existing JSON, preserving legacy metadata without a migration. Scan paths map back to stable cache paths before unchanged canonical normalization.

Compatibility entry points and ordinary cache paths remain. Sync now commits state before releasing its lock. Names containing underscores get collision-resistant paths; unsupported hosts and unmanaged/symlink paths fail explicitly. Output buffering, crash-orphan cleanup and cross-host independent-cache locking remain limitations. [Repository cache documentation](repository-cache.md) details these tradeoffs. Incremental skipping is not part of this phase.

Validation: baseline **206 passed**; focused checks passed **26 tests**, with the final cache-specific run passing **12 tests** after the collision regression was added. Final full suite: **218 passed**, two existing warnings, in 81.74 seconds outside the sandbox. Diff and new-file whitespace checks passed. No static checker is configured.

## Phase 3 — ScanPlan and profiles

`services/scan_plan.py` resolves eight explicit profiles, validates target/scanner/scope combinations, and serializes versioned intent. `services/scan_service.py` shares execution across CLI/API, scheduler and both existing queue backends. Existing explicit single-scanner selection remains available; omitted profiles keep previous defaults. Schedules retain resolved plans in metadata; legacy schedules resolve their existing scanner/scope. Jobs persist the plan alongside existing parameters. No schema migration or canonical normalization change is required.

CLI scan/schedule/mirror commands and artifact API/dashboard POST accept profiles. `scan-plan` validates or executes resolved JSON, including domain-only and osint-only plans through existing providers. Batch responses add individual results and aggregate findings, retaining first-run identifiers. Invalid combinations now fail before job creation. Profiles never silently skip unavailable tools. Phase 5 subsequently adds incremental/all-branch execution, while preserving legacy tracked-ref selection for no-profile commands. See [scan-plans.md](scan-plans.md) for all defaults, override precedence, partial-batch behavior and discovery/UI limitations.

Validation: Phase 2 baseline **185 passed**; Phase 3 focused checks passed **27 service/runner/scheduler/queue/mirror tests** and **5 API integration tests**. The full suite passed **206 tests**, with the same two dependency deprecation warnings, in 86.01 seconds outside the sandbox. Diff/whitespace checks passed. No static checker is configured.

## Phase 2 — Scanner contract and registry

At completion of Phase 2, all nine then-existing scanners declared metadata and execute through a compatibility adapter with readiness, target/context and result types. Native and legacy Python entry-point plugins share deterministic discovery; duplicate IDs are rejected. Saved-report ingestion, legacy factories/imports, parser behavior and canonical finding hashes/persistence remain intact. Registry inventory feeds bootstrap, CLI config/verify-deps, API tooling and dashboard selection; artifact-capable plugins appear without presentation dispatch edits. Configured binaries now drive both legacy optional-tool booleans and detailed readiness.

Built-in scanner subprocesses share explicit working directories, captured results and a configurable 300-second per-process timeout. Failures no longer expose raw subprocess diagnostics through the runner. There are no schema, migration, ScanPlan, profile, heuristic-rule or authentication changes. Scheduler/queue execution inherits the contract through the existing shared runner.

Compatibility changes are additive inventory fields and broader metadata-driven artifact choices, predictable duplicate-ID errors, bounded built-in subprocess execution, and sanitized failure text. Existing missing-binary guidance is retained. Current readiness includes bounded YARA version and detect-secrets 1.5.x version/help probes; other external versions remain unknown. Captured output is bounded, timeout is per subprocess, and third-party plugins must implement safe execution. YARA supports custom rule metadata and unknown rule IDs; heuristic-rules supports validated local rules. These later phases supersede the initial Phase 2 limitations. See [scanner-contract.md](scanner-contract.md) for plugin integration details.

Validation: the pre-change full suite passed **115 tests**. `tests/scanners tests/api/test_scanner_registry.py tests/test_bootstrap.py tests/test_docs.py` passed **75 tests**; final scanner/runner checks (`tests/scanners tests/test_external_scanners.py tests/test_runner.py`) passed **73 tests**. The full `.venv/bin/python -m pytest` suite passed **185 tests**, with the same two Starlette/AnyIO deprecation warnings. API/full runs used the established outside-sandbox workaround for TestClient hangs. Diff/whitespace checks passed; an AST comparison confirmed all nine parser and canonical persistence/report-recording functions unchanged. Normal tests fake external tools, including timeout, malformed output and failure cases. No static checker is configured.

## Phase 1 — Initial finding-management decomposition

The first coherent slice extracts finding listing/detail, high-signal selection, triage, suppression, accepted risk and reopening into `services/finding_service.py`. Typed dataclass requests separate these operations from Pydantic HTTP models and Typer arguments. `Storage` still implements persistence; each service mutation owns its transaction, including the suppression record. The existing session factory (`expire_on_commit=False`) supplies scalar ORM results for adapter serialization.

`api/routes/findings.py` owns the existing `/findings` routes and dashboard workflow POST; `api/schemas.py` owns their unchanged HTTP models. `OrgscanApiService` remains an import-compatible presentation facade that maps requests/results and delegates finding workflows to the service. Browser action/default mapping stays in that facade. `cli/commands/findings.py` owns the existing `findings`, `triage`, `suppress`, `accept-risk`, and `unsuppress` commands; `cli/dependencies.py` holds shared settings/logging setup. Package-root re-exports preserve `orgscan.api.create_app`, `OrgscanApiService`, request models, `orgscan.cli.app`, `main`, and moved command functions. Root command registration retains the previous ordering.

No scanner, canonical hash, schema/migration, lifecycle policy or authentication behavior changes. Existing HTTP/CLI validation and distinct serializers are retained. The finding service remains local/unscoped, matching the existing adapters; filters are not authorization. Jobs do not perform these operator decisions, so scheduler/queue integrations are not applicable to this slice. Their scan execution already shares `runner.execute_scan` through scheduler/mirroring and was left intact.

Exact remaining Phase 1 decomposition items:

- Extract target/asset-context resolution shared by CLI scans/intake and API uploads, and artifact preparation/execution from `OrgscanApiService`; reuse `runner.py` and `mirroring.py` rather than create a second scan engine.
- Extract discovery/provider persistence and expansion orchestration from CLI commands into discovery/target services.
- Extract entity/detail/risk/report/dashboard query assembly and presentation helpers from the API facade; finish separating finding serialization and browser mapping from the package root.
- Extract remaining configuration, target, discovery, scan/mirror, report, user/session, and worker/job CLI families; separate the corresponding remaining API route families and app/dependency assembly as their service boundaries become clear.
- Preserve existing shared scheduling, queue, mirroring and runner functions with compatibility exports when migrating them. Their retry/scanner/checkpoint behavior belongs to later phases, not this decomposition.

Validation: the pre-change full suite passed **89 tests** with two dependency deprecation warnings. `.venv/bin/python -m pytest tests/services tests/api/test_finding_routes.py tests/cli/test_finding_commands.py tests/test_api.py tests/test_cli.py` passed **66 tests** with the same warnings. An exact generated OpenAPI comparison and CLI command/option metadata comparison against pre-change snapshots passed (ignoring Python object memory addresses); the installed `orgscan --help` entry point also passed. The full `.venv/bin/python -m pytest` run passed **115 tests**, with the same two warnings, in 64.10 seconds outside the sandbox. Diff/whitespace checks passed, and an AST comparison confirmed unmigrated API/CLI functions and facade methods were unchanged. Existing adapter tests remain, supplemented by direct service tests for filtering/detail, partial updates, suppression/reopen history, transaction rollback and missing findings, plus adapter validation/error/compatibility tests. No static checker is configured.

## Phase 0 baseline validation and pre-existing limitations

Before Phase 0 edits, the supplied full-suite result was **86 passed, 2 failed**. A local rerun of `.venv/bin/python -m pytest tests/test_bootstrap.py tests/test_cli.py -q` reproduced both failures (26 passed, 2 failed):

- `tests/test_bootstrap.py::test_bootstrap_verify_only_reports_mode` expected `venv_exists=False`, but bootstrap correctly observed the development checkout's `.venv`. The test now redirects bootstrap's module-derived checkout root to a temporary directory and covers both absent and existing venvs, asserting verify-only performs no installation.
- `tests/test_cli.py::test_cli_scan_reports_missing_semgrep` invoked installed Semgrep rather than the missing-binary path. Its output included `Cannot create auto config when metrics are off`. Missing-scanner CLI tests now fake executable lookup, including the analogous Gitleaks and detect-secrets cases. Production scanner behavior, installed tools and the checkout `.venv` are unchanged.

Phase 0 also removes one duplicate `python-multipart` dependency. No feature, schema, command or endpoint changes are included. Post-change validation:

- `.venv/bin/python -m pytest tests/test_bootstrap.py tests/test_cli.py tests/test_docs.py`: **31 passed**.
- `.venv/bin/python -m pytest`: **89 passed, 2 warnings** in 42.51 seconds outside the sandbox. The extra test is the existing-venv parameter case. Warnings concern Starlette's httpx TestClient integration and AnyIO's deprecated BlockingPortal alias; no dependency upgrade was attempted.
- The sandboxed full run stalled at `test_api_findings_supports_extended_filters` and was interrupted. A separate 25-second bounded run with `-o faulthandler_timeout=10` showed TestClient waiting in AnyIO's thread portal. Running the unchanged suite outside the sandbox resolved the hang; this is an execution-environment limitation, not a failing assertion.
- `git diff --check` passed; TOML parsing confirmed unique runtime requirements and the unchanged CLI entry point. No configured static checker was available to run.

Stale documentation corrected here: the prior roadmap said YARA/ripgrep, paid providers, PDF and mirror management were absent, and described ad hoc SQLite evolution despite existing Alembic migrations. The tooling-gap document repeated some of these claims. Architecture/contract/plan documents describe future requirements; a baseline link now distinguishes those requirements from current implementation.

At the end of Phase 0, remaining risks were: external scanner and mirror subprocess calls lack uniform timeouts; scanner stderr can propagate into persisted errors without uniform redaction; untrusted-path/archive safety and HTTP authorization need dedicated hardening and tests. Normal tests use synthetic repositories and mocked external outputs, and do not prove production-scale safety or compatibility. No Ruff/mypy or other static-check configuration is currently present in `pyproject.toml` or CI.

## Phase 18 — medium/low release hardening

The eight scoped items are implemented: domain context/stable job asset IDs; safe
checkpoint invalidation; production schema checks with explicit migration execution;
portable report locations and SQL filtering/aggregation; separate runtime-only
clean-install CI; shared asset/domain services; dead internal helper and duplicate
inventory cleanup; documentation reconciliation. Phase 17 security fixes remain
covered by their adversarial regression suite. Exact final validation and limitations
are recorded in [release readiness](release-readiness.md#phase-18-release-hardening).

Architecture remains partial: moving target/domain use cases does not complete the
API/CLI decomposition. No HTTP domain execution endpoint, schema revision, new
scanner, or unrelated feature was added. Current registry count is ten. Historical
phase entries below/above are implementation-time records, not current limitations:
Phase 17 supersedes old unbounded-output/symlink/redaction claims; Phase 18 supersedes
old include-fingerprint and automatic-production-migration behavior.

Phase 18 final validation: **420 tests passed** (22 added cases), two existing
deprecation warnings; doctor required checks passed with 17 environment warnings.
The distribution build and separate runtime-only Python 3.13 clean-install validation
passed. Phase 1 remains partial; see release readiness for migration and deployment limits.


## Phase 19 — adversarial security boundaries

Implemented shared persistence/presentation sanitization and forward legacy repair,
tenant-scoped domain source reads, authoritative report/request visibility, verified
public GitHub ingestion, credential-safe URL diagnostics, bounded HTTP/Git acquisition,
and the detect-secrets 1.5.x command/readiness contract. See the seven-item coverage
and exact validation status in [release readiness](release-readiness.md#phase-19-adversarial-boundary-remediation).

Production rollout requires explicit migration from 0008 to 0009 after backup.
Portable cache checks require deployment disk quotas; PostgreSQL and live external
tools remain uncertified. Phase 1 remains **partial**. Dashboard scaling, queue batch
summaries, compatibility-helper cleanup and broader decomposition are deferred.


## Phase 20 — final non-blocking correctness and performance cleanup

Both queues now persist/replay the same full batch aggregation as synchronous scans,
including every scanner/ref result while retaining first-job compatibility fields.
Dashboard summaries reuse storage SQL aggregates, selected graph endpoint labels,
bounded previews and SQL trends. Dashboard high-signal filtering runs before the SQL
limit. Report evidence remains batched. Public `resolve_requested_tenants` is retained
and its unauthorized request correctly raises HTTP 403.

Scanner readiness documentation is reconciled, with opt-in generated-fixture smoke
coverage for five external tools. No migration or broad decomposition is required;
head remains 0009. Phase 1 remains **partial**: upload/expansion orchestration and
remaining API/CLI command-family extraction still need incremental work. See
[release readiness](release-readiness.md#phase-20-correctness-and-performance-cleanup)
for exact validation, preview limits, legacy replay limitations and deployment risks.


## Phase 21 — secret-safety and sanitizer hardening

A shared credential-label policy now covers structured fields and copied assignments,
including AWS credentials and access/client tokens. Browser finding rows, details,
triage queues and report previews retain the same metadata-derived secret knowledge
as API presentation. Bounded tokenization replaces repeated URL-prefix matching;
central work limits fail closed without echoing input.

Forward migration `20260914_0010` repairs legacy fields missed by 0009 using a frozen,
parity-tested sanitizer. Released migration 0009 is unchanged. Deployments must run
explicit migration before production startup. Phase 1 remains **partial**; this phase
adds no general architectural decomposition. See release readiness for validation
and operational limits.


## Phase 22 — escaped credential assignment hardening

The final gate reproduced escaped JSON credential values surviving provider output,
persistence, presentation and migration 0010. The shared parser now recognizes
bounded escaped quote delimiters with the existing label vocabulary and carries
encoded/decoded secret knowledge into sibling fields. No adapter-specific sanitizer
or unrelated architecture, tenant, queue or scanner changes were introduced.

Forward data repair `20260914_0011` follows 0010 using a new frozen parity-tested
snapshot. Earlier migrations remain unchanged. See release readiness for validation
and rollout status; architectural Phase 1 remains partial.

## Phase 23 — controlled secret preservation and analyst reveal

Adds opt-in encrypted SecretEvidence, explicit tenant-scoped reveal capability,
authenticated POST reveal with committed audit events, and masked finding detail
controls with Hide/automatic hiding. Ordinary APIs, reports, diagnostics and initial
HTML remain redacted. Migration 0012 adds dedicated storage; older redacted secrets
cannot be recovered. Remaining Phase 1 decomposition is still partial and unchanged.
See release readiness for key provisioning, operational limits and validation results.

## Phase 24 — secret capture/redaction pipeline correction

Candidate knowledge now remains available through ordinary normalization and storage,
closing the Phase 23 copied-plaintext leak without losing encrypted credentials.
The original gate probe, SQL-column invariant, reader/analyst/report/audit matrix,
imported results and both queue backends have regression coverage. Migration 0013
performs keyless, conservative repair of affected ordinary records while retaining
protected ciphertext and references. See release readiness for repair data loss and
validation results. No reveal endpoint or permission expansion is introduced.

## Phase 25 — report projection secret context

Complete report/summary projections now retain ordinary finding and evidence secret
knowledge through final shared sanitization, including legacy copied remediation,
query and provenance values. All five formats, API exports, scheduled/webhook delivery
and an RQ service invocation have regressions. Encrypted evidence and explicit reveal
are unchanged. This is a presentation-only correction: no migration, head remains
0013, and frozen migrations remain intact. Summary context adds one bounded joined
query; existing query-count and detail-limit checks remain required.

## Phase 26 — complete credential context propagation

Report context now covers all authorized contributing source populations rather than
the page, top ranking, graph endpoints or remediation selection. Finding/API/browser
presentation receives batched associated evidence context through one shared boundary.
Both paths fail closed when context completeness exceeds their documented budgets.
The two gate reproductions and query measurements have permanent regression coverage.
No migration or authorized reveal change is required; head remains 0013. Phase 1
decomposition remains partial. See release readiness for final validation results.

## Phase 27 — derived projection credential context

Operator job/asset labels and standalone graph/trend output now retain credential
knowledge through a shared derived-projection boundary. Asset/job detail, CLI job
inventory and compatibility aggregates use the same contract. Source families are
tenant-scoped, batched and bounded; incomplete context fails closed. Graph endpoints
are loaded by ID without unrelated ORM collections. No schema migration or reveal
change is introduced. See [projection safety](projection-safety.md) and release
readiness for the source inventory, validation and remaining operational limits.

## Assessment operator control plane — initial integration (2026-09-15)

Historical checkpoint; the continuation section and linked milestone matrix below
supersede its counts and remaining-work list.

Added first-class assessments with normalized multi-target import, tenant-scoped
GitHub/GHES connection configuration, durable reconnaissance/scanning, scope review,
canonical findings/reports and server-rendered operator pages. Optional Ollama advice
is disabled by default, uses bounded safe metadata and cannot change evidence or
reveal credentials. Migration 0014 is additive; earlier migrations stay frozen.

See [implementation and remaining epic gaps](assessment-control-plane.md) and
[local AI scope](local-ai.md). The full A–Z epic remains partial: public search needs
connection-aware ingestion, artifact assessment ownership is pending, and richer
home/progress/filter/profile/AI workflows remain. Existing standalone interfaces
continue to be supported.

Validation: 39 assessment tests; final full suite **842 passed, 7 skipped**, two
existing dependency warnings. Doctor on a disposable 0014 database returned
**ok=true** with 16 optional warnings. Build, clean runtime installation, compile
and whitespace checks passed. See [checkpoint validation](assessment-control-plane-validation.md).


## Assessment continuation validation (2026-09-15)

The assessment continuation adds encrypted artifact staging/lifetime, editable
connection state, snapshotted discovery options and durable stages, connection-bound
public-search ingestion, correlated organization/commit identities and source
observations, scope controls, ScanPlan review, progress, traversable relationships,
assessment finding detail, complete scope exports and bounded optional AI advice.
The browser acceptance test in `tests/assessments/test_operator_acceptance.py`
uses disposable databases and external service fakes to exercise login through
report generation and exact audited reveal. See
[the current milestone matrix](assessment-control-plane-validation.md) for final
validation counts and explicit operational/deployment limits. Migration 0014 remains
additive; migrations through 0013 and the configured database are unchanged.

## Recon toolchain integration (2026-09-15)

Settings → Recon Tools, explicit verified Go installation, passive/active readiness,
canonical recon assets, ordered assessment stages, scope controls, discovery result
tabs and bounded optional AI recon context are implemented. See
[recon toolchain](recon-toolchain.md) for operator instructions, configuration,
upstream contracts and exact limitations (notably Amass v3-only, restricted local
HTTP Nuclei templates, domain-only RDAP and POSIX/shared-directory locking).
Migration head is 0015; configured deployment databases are not upgraded by this run.

## Live recon certification (2026-09-16)

Real DNSX, HTTPX, Katana, Nuclei and Naabu passed loopback execution, parser,
correlation and browser/queue/report acceptance on WSL2. Subfinder passed isolated
empty-source/timeout contracts; Amass v3 installed and its passive CLI was verified.
No external reconnaissance or live Ollama/GHES certification is claimed. Readiness
now checks required CLI flags; setup describes Minimal/Recon/Full requirements.
See [the exact versions, evidence and limits](recon-toolchain-validation.md#live-workstation-certification--2026-09-16).
