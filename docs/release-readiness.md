# Doctor and release readiness

The recon toolchain follow-up has a separate
[validation record](recon-toolchain-validation.md), covering migration 0015,
explicit installation, scoped provider execution and remaining compatibility
limits. Earlier phase records below retain their historical scope.

`orgscan doctor` performs diagnostic reads. `orgscan doctor --json` returns
`ok`, individual checks and warnings; exit 1 indicates a required failure.
`--require-queue` makes unavailable Redis a required failure for RQ deployments.
Without that flag Redis connectivity is checked when RQ is selected, but an outage
is a warning for operators using local scans. DB queue mode does not contact Redis.

Checks cover Python/application version, read-only database connectivity/current
Alembic heads, data/mirror/report directory permissions, Git, queue configuration,
Redis when applicable, token configured state, HTTP authentication/cookie settings,
scanner registry readiness and known versions, and provider configuration.
Unknown scanner versions are explicit. Provider readiness checks do not send requests.
Doctor does not create missing directories/databases, migrate, install, scan, fetch
repositories, or print configured credentials/URLs. Registry readiness can run its
bounded compatibility probes (YARA and detect-secrets). Third-party plugins remain trusted code.
Directory permission checks cannot certify capacity, quotas or later filesystem changes.
PostgreSQL connectivity/schema reads have a code path but no integration certification.

The existing setup/verify-deps/bootstrap commands retain their behavior, including
creating the configured data directory. Use doctor for non-creating diagnosis.
A missing database is a required failure with explicit initialization guidance.
Missing optional scanners/providers, missing creatable directories, unconfigured
GitHub code search and local HTTP cookie settings are warnings.

## Installation and upgrade

For source development:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
orgscan init-db
orgscan doctor
```

For a built release (Python 3.12+):

```bash
python -m build --wheel
python -m pip install dist/orgscan-0.1.0-py3-none-any.whl
```

Wheels now contain Alembic configuration/migrations and starter heuristic rules.
The previous wheel omitted migrations and could not initialize outside a checkout.
Editable source paths remain compatible. No release version bump or publication is
performed by this phase; the package still identifies itself as 0.1.0.

Before upgrading an existing installation:

1. Stop API writers, schedulers and workers; record the installed version/configuration.
2. Back up SQLite with its backup API/tool (including committed WAL data), or use a
   database-native PostgreSQL backup. Back up configuration, rules and artifacts
   separately, with restricted access. Test restoring to a separate location.
3. Install the reviewed wheel in the intended virtual environment.
4. Run `orgscan doctor --json`; an old schema should report an upgrade requirement.
5. Run `orgscan init-db` explicitly, then doctor again. Head is `20260914_0013`.
   Migration 0006 adds evidence identity; 0007 maps lifecycle and records inferred
   legacy timestamps. Migration 0008 adds durable queue execution identities,
   quarantines duplicate legacy executions, and sanitizes legacy evidence/diagnostics.
   Migration 0009 repairs additional credential-bearing evidence and diagnostic fields,
   including domain summaries, nested plugin metadata and job targets.
   Migration 0010 repairs credential assignments and copied values missed by 0009.
   Migration 0011 repairs escaped/copied assignments missed by 0010.
   Migration 0012 adds encrypted secret evidence and reveal audit tables.
   Migration 0013 conservatively removes copied secrets from affected ordinary fields;
   review the Phase 24 repair implications below before upgrading.
   Redaction is irreversible; these migrations do not reconstruct unavailable history.
6. Validate authorized reads, a local test scan and reporting before restarting workers.

Rollback should restore a tested matching backup and application version. Downgrading
0011/0010/0009/0008 cannot restore redacted data, and downgrading 0007 removes lifecycle/history fields; it is not a lossless rollback strategy.

## Local smoke and validation

```bash
python -m pytest tests/services/test_doctor_service.py tests/packaging/test_installed_wheel.py
python -m pytest
python -m pip check
git diff --check
```

The installed-wheel test builds without network isolation, installs with
`--no-index --no-deps` into a temporary directory and runs outside the checkout.
It checks migration resources, initialization, bundled rules, local scanning,
remediation/regression, SARIF, doctor and API schema construction. Normal tests mock
external scanner/network behavior. Installing declared development dependencies is
required first. No static checker is currently configured; compile checks are also
run during this phase.

## Deployment checklist

Phase 16 validation: **309 tests passed**, with two existing dependency deprecation warnings. Focused doctor/build/install checks and `pip check` passed. Checked below means implementation/test evidence exists, not production certification.

- [x] Fresh and populated SQLite migration tests; installed-wheel migration resources.
- [x] Shared scanner contract, canonical correlation and retained lifecycle history.
- [x] Token/browser auth, tenant/role checks, expiry/revocation and browser CSRF tests.
- [x] Queue retry classification, safe failure diagnostics and explicit DB lease quarantine.
- [x] SARIF structural validation and executive/technical PDF content tests.
- [x] Non-creating doctor and an offline installed-package smoke path.
- [ ] Restore an actual deployment backup and validate its data/authorization after upgrade.
- [ ] Bootstrap administrators per [browser auth](browser-auth.md); require authentication
  before binding outside loopback, configure HTTPS/Secure cookies and trusted proxy handling.
- [ ] Start API with `orgscan serve-api`; start the selected worker with `orgscan run-worker`.
  For RQ, run doctor with `--require-queue`, restrict Redis access and protect its serialized
  worker configuration. Validate scheduled retries against the actual Redis deployment.
- [ ] Validate live scanner/provider versions, token permissions, quota behavior and
  custom rule updates. Semgrep requires `ORGSCAN_SEMGREP_RULES_PATH` pointing to a
  local rules file and no longer uses `--config auto`; telemetry stays off unless
  `ORGSCAN_SEMGREP_METRICS` is explicitly enabled. Runtime rule compatibility still
  needs validation against the installed binary.
- [x] Legacy WHOIS/subfinder/httpx processes use finite time/output limits and safe
  diagnostic messages. JSON/crt.sh/security.txt transport and decoding failures are
  normalized without raw exception messages; timeout failures retain retryability.
- [x] Adversarial upload/archive, no-follow file reads, output-flood, evidence,
  rediscovery ownership, historical regression and queue publication/replay tests.
- [ ] Validate production-scale resource use and deployment concurrency. External scanner
  preflight assumes targets are not concurrently modified by another local process.
  POSIX cache locks are local, not distributed leases.
- [ ] Validate PostgreSQL, full Unicode PDF fonts and target code-scanning-host SARIF ingestion.
- [ ] Add password/MFA/SSO or login-abuse controls if required by the deployment threat model.
- [ ] Review dependencies/security advisories and run deployment-specific security testing
  before declaring 1.0 readiness. The unit suite and this checklist are not a security audit.

Review legacy findings/free-form operator text before sharing reports. Raw source
material is excluded from new reports, but arbitrary secrets in third-party metadata
cannot be recognized reliably. See phase-specific documents for additional limits.


## Post-Phase-16 recovery audit (2026-09-14)

Recovery started on `codex/architecture-foundation` at `03cc9fa` (`fix`), with no
modified or untracked files and empty staged/unstaged diffs. The interrupted fixes
were already committed in that commit; their presence did not establish completion.
The recovery report was presented before implementation. Baseline: 91 focused tests
and 360 full-suite tests passed; `git diff --check` passed. Synthetic probes then
reproduced gaps in items 1, 3, 4, 5 and 8, which are the only implementations changed
by this recovery. Completed ownership, artifact identity, queue, Semgrep and server
bind work was retained. No MEDIUM/LOW findings were addressed.

The following statuses describe implementation of the ten scoped audit fixes, not
production certification. `recovery` below means
`tests/security/test_release_recovery.py`; other test names are under
`tests/security/` unless noted.

| Item | Recovery status | Final implementation | Changed files in this recovery | Coverage | Remaining risk |
| --- | --- | --- | --- | --- | --- |
| 1. Raw scanner evidence | PARTIALLY IMPLEMENTED | COMPLETE | `redaction.py`, `runner.py`; scanners `ripgrep_heuristics.py`, `repo_governance.py`, `yara_scanner.py` | `recovery`: copied/nested source values, credential-bearing paths and neighboring credentials; `test_evidence_and_tenancy.py`; `test_failures_and_upgrade.py`; report tests | Arbitrary unlabelled operator/plugin text cannot be reliably classified as secret. Review legacy exports/backups; masking does not rotate exposed credentials. |
| 2. Rediscovery tenant reassignment | COMPLETE | COMPLETE, preserved | None | `test_evidence_and_tenancy.py`: conflicting org/repository rediscovery and tenant reads; `tests/storage/test_authorized_storage.py` | PostgreSQL and deployment-scale race behavior remain unverified. Trusted raw SQL is outside ORM guards. |
| 3. Direct-path containment | IMPLEMENTED BUT INCORRECT | COMPLETE | `scanners/files.py`, external/history/YARA/ripgrep adapters; `runner.py`; `cli/__init__.py` | `recovery`: parent traversal, root/nested symlinks, YARA and saved-report reads; `test_execution_and_paths.py` | Descriptor-relative Python reads reject symlinks. External preflight cannot prevent another local process changing a target after validation; use private/quiescent scan roots. |
| 4. Resource limits | PARTIALLY IMPLEMENTED | COMPLETE | `processes.py`; scanners `files.py`, `external.py`, `yara_scanner.py` | `recovery`: saved/live report caps, cleanup, YARA bounds, file floods with open/closed pipes; `test_execution_and_paths.py`: upload/archive/output/timeouts | File-output polling can transiently overshoot the threshold. These limits are not an OS disk quota or CPU/memory sandbox for external binaries. |
| 5. Historical false regression | IMPLEMENTED BUT INCORRECT | COMPLETE | `repositories.py` | `recovery`: imports, raw-payload commits, unknown history; `test_lifecycle_artifacts.py`: removed/old/novel/current-tree observations | Imports cannot independently establish regression; a fresh scan is required. Git commit timestamps are source-provided, not trusted wall-clock attestations. |
| 6. Temporary artifact identity | COMPLETE | COMPLETE, preserved | None | `test_lifecycle_artifacts.py`: repeated custom/governance uploads retain finding/evidence IDs | Legacy temporary-path identities are not automatically merged; third-party path conventions need contract validation. |
| 7. Queue atomicity and replay | COMPLETE | COMPLETE, preserved | None | `test_queue_atomicity.py`: producer races, fast worker, replay, publication failure, crash after claim | Crashed claimed tasks require review. Durable IDs prevent blind replay, but Redis/DB are not a distributed transaction and partial scan work may have committed. |
| 8. Legacy provider failures | PARTIALLY IMPLEMENTED | COMPLETE | `providers.py` | `recovery`: JSON/crt.sh/security.txt timeout/decoding errors; `test_execution_and_paths.py`: WHOIS/subfinder/httpx errors | Live upstream behavior and deployment network policy remain unverified. |
| 9. Semgrep auto configuration | COMPLETE | COMPLETE, preserved | None | `test_execution_and_paths.py`: local rules/readiness/metrics arguments; scanner contract tests | Local rule compatibility requires an installed-version smoke test. |
| 10. Unauthenticated non-loopback serving | COMPLETE | COMPLETE, preserved | None | `test_execution_and_paths.py`: loopback/authenticated/refused/unsafe override bind policy; browser-auth API tests | The explicit unsafe development override remains dangerous; deployments must use the guarded entry point and configure HTTPS/authentication. |

### Resource and compatibility details

Saved reports are capped at 8,000,000 bytes and read through no-follow file
descriptors. Gitleaks' temporary report contributes to the subprocess's combined
8,000,000-byte output budget, monitored while running and checked after exit; its
existing `finally` cleanup is retained. YARA location reads share the 1,000,000-byte
content cap. External filesystem scanners reject trees containing symlinks or special
files before launch and cap preflight traversal at 100,000 entries. CLI scan/schedule
paths retain original components until runner validation; `..` and symlink target
components are rejected rather than silently resolved. No new schema is needed.

### Local deployment diagnostic

The recovery `orgscan doctor` run found read-only DB connectivity working but exited
1: the configured database remains at `20260911_0007`, while the application expects
`20260911_0008`. The existing database was not upgraded during code recovery.
Follow the backup/upgrade procedure above before serving or starting workers.
Other diagnostics reported 17 warnings, including unavailable Redis, optional
scanners/provider credentials, absent GitHub token, unconfigured local authentication
and non-Secure browser cookies. This checkout is not certified deployment-ready.


### Final recovery validation

- Focused security/scanner/lifecycle/correlation suite: **192 passed**.
- Full `.venv/bin/python -m pytest`: **398 passed**, two existing Starlette/AnyIO
  deprecation warnings, in 129.03 seconds outside the sandbox.
- Added **38 adversarial cases**; existing tests were not weakened or changed.
- `orgscan doctor`: **exit 1**, schema 0007 versus expected 0008; 17 warnings,
  detailed above. This is an existing deployment-state issue, not a passing check.
- Compilation, tracked/new-file whitespace checks and `git diff --check` passed;
  the full diff was inspected. No static checker is configured.
- No new migration, commit, deployment or production database modification was made.

## Phase 18 release hardening

Scope: eight MEDIUM/LOW audit items, preserving Phase 17. Recovery began on clean
`codex/architecture-foundation` at `f15aa75` (`codex-phase-17`). The 68 relevant
baseline tests passed before edits; current migrations and source were inspected.

### Migration execution and upgrade implications

Production deployments must set `ORGSCAN_APP_ENV=production` and run
`orgscan migrate-db` once as a deployment step before starting API, workers or
schedulers. Production startup verifies the current head and fails with migration
guidance; it never runs Alembic even if `ORGSCAN_AUTO_MIGRATE=true`.
Development mode (the existing default) retains automatic bootstrap; set
`ORGSCAN_AUTO_MIGRATE=false` to exercise explicit initialization locally. `init-db`,
`migrate-db` and `setup --init-db` remain explicit initialization commands.

No new schema revision is required; head remains `20260911_0008`. The baseline
revision previously imported current application metadata. Its input is now frozen
to exactly the schema Phase 17 produced, including its existing forward-created
tables; the revision operations/identity remain intact. Migration 0008's redaction
input is frozen too. Neither frozen module should be updated for future models.
This narrowly changes replay inputs without rerunning or rewriting applied data.
Already-upgraded databases need no extra migration. Fresh replay and populated
legacy evidence/security upgrades are tested. PostgreSQL upgrades still require
integration validation. Backups and irreversible Phase 17 redaction implications
above remain unchanged.

### Scoped audit status

| Item | Status | Principal files | New/focused tests | Remaining risk |
| --- | --- | --- | --- | --- |
| 1. Domain ScanPlan context | Complete | `services/target_service.py`, `scan_plan.py`, `scan_service.py`, `github_search.py`, `providers.py`, `scheduler.py`, CLI | `test_phase18_targets.py`, scan-plan/GitHub search/queue tests | Old name-based job rows retained; API supports domain reads, not execution. Tenant-only discovery requires an existing owning organization. |
| 2. Effective scanner configuration | Complete | `repository_state.py`, `mirroring.py` | `test_incremental.py`: unchanged JSON rules, transitive YARA includes, unsafe-config reruns | Unmodelled external/plugin configuration disables skipping; extra scan cost. Rules must remain quiescent during execution. |
| 3. Migration execution | Complete | `db.py`, `config.py`, startup callers, migrations 0001/0008, `migration_snapshots/` | `test_startup_migrations.py`, `test_db.py`, security upgrade tests | Production mode must be configured; PostgreSQL/deployment races not certified. |
| 4. Report locations/queries | Complete | `services/report_service.py`, `repositories.py`, `storage/report_queries.py`, `runner.py`, `reporting.py`, `reports/pdf.py` | `test_phase18_report_queries.py`: path/file/artifact/mirror formats, 300 findings, limits, tenant scope, evidence provenance | Unmapped historical paths stay locationless; ancillary arrays/encoding remain in memory; Unicode/font/host acceptance limits remain. |
| 5. Clean runtime install | Complete | `scripts/validate_clean_install.py`, `.github/workflows/clean-install.yml`, `.gitignore` | Separate fresh-venv runtime install and CLI/API/scan/report smoke; ordinary wheel test retained | Local execution validates Python 3.13; Python 3.12 awaits CI. External services/binaries not certified. |
| 6. Architectural decomposition | Complete for this slice; Phase 1 partial | `services/target_service.py`, `scan_service.py`, API/CLI roots | Service-level target/domain tests plus existing CLI/API compatibility tests | Upload/expansion and other presentation orchestration remain for future slices. |
| 7. Compatibility/inventory cleanup | Complete | `runner.py`, `auth.py`, `scheduler.py`, `bootstrap.py`, `scanner_service.py`, API/CLI | Registry single-probe test, bootstrap and adapter tests | Public legacy scanner/provider interfaces retained; trusted third-party plugins still own safe behavior. |
| 8. Documentation reconciliation | Complete | roadmap, architecture/plan, scanner/YARA, scans, reporting, testing, this checklist | Documentation tests and final source/diff review | Historical phase results are historical records, not deployment certification. |

### Final validation

Final validation on 2026-09-14:

- Pre-edit relevant baseline: **68 passed**.
- Focused Phase 18/security regression run: **123 passed**; final target, startup
  and shared-inventory checks: **16 passed**; report/checkpoint checks: **34 passed**.
- Complete final suite: **420 passed, 2 warnings in 111.00 seconds**, including
  **22 added test cases**. Warnings are the existing Starlette httpx TestClient and
  AnyIO BlockingPortal deprecations. API/full runs used the established outside-sandbox
  workaround; no test was weakened to conceal a failure.
- `orgscan doctor` and `orgscan doctor --json`: required checks passed, **17 warnings**.
  Local database head is **20260911_0008**. Warnings concern optional tools/providers,
  unavailable Redis, unconfigured authentication/secure cookies and creatable report/
  mirror directories. This environment is not a production deployment.
- `python -m build --no-isolation`: sdist and wheel built successfully at **0.1.0**.
- Clean-install validation passed on **Python 3.13**: fresh `/tmp` venv outside the
  checkout, declared runtime dependencies only, `pip check`, explicit production
  initialization, CLI startup, API lifespan/health, local scan, JSON/SARIF reports.
  pytest/httpx were absent. Python 3.12 validation is configured in CI but was not
  executed locally. The ordinary installed-wheel test also passed in the full suite.
- Frozen migration metadata independently matched all **21 tables**, columns,
  foreign keys, indexes and unique constraints in the Phase 17 schema.
- Compile checks, `git diff --check`, final source/test/documentation diff review
  and wheel-resource inspection passed. No static checker is configured.

All eight scoped hardening items are complete; **architectural Phase 1 remains
partial**. PostgreSQL/live external-tool/provider compatibility, deployment-scale
concurrency and large ancillary report arrays remain release risks. Production must
explicitly select production mode and execute migration once before services start.
Public CLI/API commands and supported legacy scanner/provider entry points remain;
resolved domain IDs, conservative rescanning and portable report labels are intentional
behavior changes. No release publication or commit was performed; changes remain in
the working tree for review.


## Phase 19 adversarial boundary remediation

The preceding final adversarial audit reported four release blockers: domain and
plugin evidence disclosure, cross-tenant local metadata discovery, inconsistent
report ownership, and private results entering public GitHub search. It also
identified credential-bearing URL diagnostics, unbounded HTTP/Git acquisition and
an unsupported detect-secrets argument. This section records that audit's scope
and the current corrections; earlier phase test counts are historical.

| Item | Implemented boundary | Adversarial coverage |
| --- | --- | --- |
| 1. Evidence disclosure | Shared recursive redaction before ORM persistence and at API/report/provider/inventory serialization; secret fingerprints retained; forward repair 0009 | `test_phase19_redaction.py`: tokens, AWS keys, bearer credentials, URL credentials, copied/nested/plugin values, readiness, domain summaries, legacy API rows, repeatable upgrade |
| 2. Domain tenant isolation | Local metadata reads through a fresh, read-only tenant-scoped source session, including nested providers | `test_phase19_tenancy.py`: private repositories/accounts across synchronous, scheduled and queued local/aggregate discovery |
| 3. Report ownership | Request authorization, report queries and discovery consume `storage/visibility.py`; explicit finding owner takes precedence; both relationship endpoints required; related assets also scoped | Mixed ownership across JSON/CSV/HTML/PDF/SARIF, API scopes, summaries, scheduled reports and webhook payloads |
| 4. Public GitHub ingestion | Public repository/issue queries; legacy code queries restricted to verified public repositories; independent affirmative, consistent visibility validation and provenance | Public, private, internal, missing, contradictory and authenticated private responses for each result kind |
| 5. Safe diagnostics | Shared URL rendering masks userinfo and credential query/fragment fields; safe settings/bootstrap/CLI output; controlled legacy transport errors | Configuration URL copies and CLI diagnostics; URLError, TimeoutError and decoding failures |
| 6. Acquisition bounds | Shared bounded HTTP reader/deadline; bounded Git stdout/stderr; conservative cache size pre/post checks | Exact byte limit, limit+1, Content-Length, unknown length, deadline, excessive Git output and cache budget |
| 7. detect-secrets | Baseline JSON scan contract without `--json`; readiness accepts verified 1.5.x version/help contract | Argument/output fixtures, incompatible versions and optional live smoke |

### Migration and deployment implications

`20260914_0009` follows `20260911_0008`; no released migration is changed.
It uses a frozen sanitizer and keyset batches of 250 rows. It changes data only,
retains primary/foreign keys and valid correlation digests, logs no evidence values,
and is repeatable. Downgrade cannot recover removed credentials. Back up and stop
writers before explicitly running `orgscan migrate-db`; production startup still
checks the head without applying migrations. Test a deployment backup separately.
Existing backups and previously exported reports are not repaired automatically.

Authentication records, live connection settings and scheduled webhook URLs retain
operational credentials required to execute their functions. Diagnostic and report
rendering masks those credentials; restrict access to the database/configuration.
Recognized credential formats, labelled secrets and their copies are removed, but
no heuristic identifies every arbitrary unlabelled secret. Plugins execute trusted
Python code and must not log or send raw evidence outside the supported boundaries.

Public search coverage is deliberately conservative: ambiguous visibility is
excluded, including issue payloads without repository visibility. Authenticated
legacy code search is restricted to at most five verified public repository results.
See [GitHub search](github-search.md) for the command semantics and provenance.
CLI/API command names and response structure remain compatible; unsafe evidence,
mixed-tenant associations and ambiguous public results are intentionally omitted.

HTTP defaults to 2,000,000 response bytes and a 15-second request deadline. Git
stdout/stderr defaults to 8,000,000 bytes; repository cache budget defaults to
1,000,000,000 bytes. See [repository cache](repository-cache.md). Pre/post checks
are not hard disk quotas: use deployment-level quotas for mirrors, temporary
worktrees and process output, plus process/container resource limits. DNS resolution
and underlying platform transport behavior still require deployment-level egress
and time limits. PostgreSQL integration and real external scanner/provider
certification remain deployment validation requirements. General architecture,
dashboard scaling and queue batch summaries are outside this phase.

### Phase 19 validation

- Focused Phase 19 adversarial suite: **84 passed, 1 skipped**, two dependency
  deprecation warnings, 25.17 seconds.
- Complete suite: **504 passed, 1 skipped**, two dependency deprecation warnings,
  146.10 seconds. The optional live detect-secrets test skipped because the
  executable is absent; argument/parser/readiness fixture tests passed.
- Compile checks (`src`, `migrations`, `scripts`, `tests`) and `git diff --check` passed.
- Source and wheel distributions built successfully with isolated build dependencies.
- Clean-install validation passed in a new external virtual environment with only
  declared runtime dependencies: `pip check`, explicit database initialization,
  CLI startup, API lifespan/health, local scan and JSON/SARIF reports. Development
  pytest/httpx packages were absent.
- Populated legacy repair tests and a separate explicit SQLite **0008 → 0009**
  upgrade passed. A repeated repair preserved relationships and correlation hashes.
  Alembic source head: **20260914_0009**. Released migrations 0001–0008 are unchanged.
- Configured-database doctor: **exit 1**, expected migration-head failure (database
  remains at 0008), **17 warnings**. The existing database was not modified.
- Temporary upgraded database doctor using the DB queue: **exit 0**, no required
  failures, **16 warnings** for optional tools/configuration and deployment settings.
- Final source/test diff reviewed. Synthetic credentials are constructed only in
  tests; no full GitHub/AWS credential-shaped literals were introduced into changed
  files or documentation. No real provider credentials were used for validation.

These checks certify the tested SQLite/runtime paths, not a production PostgreSQL
rollout or live external-tool availability. Before deployment, back up and explicitly
apply 0009, rerun doctor with the intended queue/auth configuration, and enforce the
resource quotas described above.


## Phase 20 correctness and performance cleanup

Started from clean `9be0fe0` (`codex-phase-19`), with 29 relevant baseline tests passing.
Phase 19 is preserved. No schema/data migration is added; the configured database
was explicitly upgraded to **20260914_0009** before this phase.

| Item | Status | Implementation and coverage |
| --- | --- | --- |
| 1. Queued batch results | Complete | Both RQ and DB use the synchronous aggregation helper, store all scanner/ref results and replay the stored payload. Four backend/ref combinations test totals, compatibility IDs and replay without rescanning. |
| 2. Summary efficiency | Complete | Storage SQL counts/trends/top lists replace full finding/evidence materialization; graph label reads select only visible endpoints. Tests cover 10/100/300 findings, full aggregate semantics, batched report evidence, ancillary limits and bounded untrusted previews. |
| 3. Authorization helper | Complete | Retained public unprefixed auth helper under the documented compatibility policy; repaired HTTP 403 and tested allowed, denied and wildcard scopes. |
| 4. Readiness documentation | Complete | Scanner contract/roadmap distinguish YARA probes, detect-secrets 1.5.x compatibility, local Semgrep rules and unknown versions for other tools. |
| 5. Live-tool structure | Complete | Five explicitly opted-in smokes use generated inert targets/local rules; normal suite skips them. |
| 6. Release readiness | Complete | This section records current validation and deployment limitations; Phase 1 remains partial. |

### Compatibility and performance boundaries

Queue responses retain existing first-job/scanner/target fields. Batch totals and
finding IDs cover all runs, with per-run `results`. DB responses include the queue
task ID on both initial completion and replay. Historical completed tasks that stored
only their first result are replayed unchanged; missing historical aggregation is
not guessed or regenerated by rerunning scanners. Queue crash/retry policy is unchanged.

Summary counts remain exact for all authorized rows. Ancillary collections and
high-cardinality breakdowns show at most 200 entries, graph previews contain at most
200 edges/400 endpoints, top lists remain ten and recent job/tool lists remain 25.
Summary strings show at most 2,048 characters; each relationship provenance preview
has an 8,192-character/128-node budget and bounded nesting. `summary_limits` describes
these preview limits. Persisted records are unchanged. Graph endpoint references and
historical dashboard degree strings are preserved. Dashboard high-signal SQL filters
now apply before pagination, so sparse matches beyond the old candidate window can
appear. Detailed reports retain one batched evidence query for the selected page.

### Deployment validation and remaining risks

- SQLite/runtime behavior is tested; PostgreSQL integration, migration behavior and
  deployment-scale query plans remain **unverified**. SQL uses portable SQLAlchemy
  expressions; no PostgreSQL-only optimization was introduced.
- RQ tests use fakeredis, not a live Redis deployment. Live Redis connectivity,
  durability, failover and distributed crash recovery remain **unverified**.
- External tools are optional. Opted-in smoke results below apply only to generated
  inert inputs; broad scanner/provider compatibility and production egress policy
  remain deployment responsibilities.
- Phase 1 decomposition is **partial**. Upload/expansion orchestration and remaining
  API/CLI command families still need extraction. This phase does not rewrite them.
- HTTP/Git/output/archive application limits still require production filesystem
  quotas, private/quiescent roots, process/container CPU/memory limits and controlled
  egress. Portable Git pre/post disk checks are not a hard quota.
- Bounded previews are not full exports. Counts cover all rows; large detail exports,
  arbitrary third-party metadata and production concurrency need operational sizing.

### Phase 20 final validation

- Focused Phase 20/dashboard/report/tenant/queue run: **73 passed, 5 skipped**,
  49.94 seconds. Added ten ordinary regression cases and five opt-in live cases.
- Complete suite: **514 passed, 6 skipped**, two existing Starlette/AnyIO dependency
  deprecation warnings, 184.14 seconds. Skips are the five opt-in smokes plus the
  existing detect-secrets live check, now also gated by explicit opt-in.
- Query-count regression at **10, 100 and 300 findings**: summary **36 SELECTs**;
  rendered dashboard **52 SELECTs**, unchanged with dataset size. No per-finding
  evidence reads; report details use **one batched evidence SELECT**. The audit's
  approximately 161-SELECT summary behavior is removed. Counts remain complete
  while ancillary previews and detail pages are bounded.
- Opted-in live tools: **1 passed (Semgrep), 4 skipped (missing detect-secrets,
  YARA, Gitleaks and TruffleHog)**. Semgrep used generated local rules, disabled
  metrics/version checks and inert temporary input. This is a narrow compatibility
  smoke, not broad external-tool certification.
- `orgscan doctor`: **exit 0**, all required checks passed, **17 warnings** for
  optional tools/providers and deployment configuration, including unavailable
  Redis and local authentication/cookie settings. Database and source head are
  **20260914_0009**; no migration was added or applied by Phase 20.
- Compile checks and `git diff --check` passed; final code/test/documentation diff
  reviewed. No general architecture rewrite or unrelated feature was introduced.
- Source distribution and wheel built successfully at **0.1.0**. Clean-install
  validation passed on Python 3.13 in a new external virtual environment using only
  declared runtime dependencies: `pip check`, database initialization, CLI startup,
  API lifespan/health, inert local scan and JSON/SARIF reports. Python 3.12 remains
  configured for CI, not locally certified.

All six scoped corrections are implemented. Production PostgreSQL/Redis behavior,
full live-tool compatibility, hard resource enforcement and remaining Phase 1
extraction remain documented deployment or follow-up work. Changes are uncommitted;
no release publication was performed.


## Phase 21 — final secret-safety and sanitizer hardening

All three reported defects were reproduced before changes: credential assignments
survived domain persistence/presentation and the frozen 0009 sanitizer; a legacy
finding leaked through dashboard HTML despite API protection; unbroken input took
approximately 0.94 seconds at 16 KB and exceeded three seconds at 64 KB.

| Item | Correction | Coverage / remaining risk |
| --- | --- | --- |
| Credential assignments | One case-insensitive label policy handles structured fields, free text, copied JSON, URL/query credentials and nested copies while retaining labels. | Adversarial label/grammar and provider persistence tests; opaque unlabelled values still require known-secret context. |
| Dashboard presentation | API, report rows, summary previews and operation queues share finding context; browser renderers sanitize DTOs before HTML escaping. | Legacy rows remain unsafe in the database while API, dashboard, details and JSON/CSV/HTML/PDF/SARIF output redact them. |
| Sanitizer CPU | Monotonic tokenization replaces repeatedly attempted URL-prefix matching; explicit input, depth, node, URL-field, secret-count and replacement-work budgets fail closed. | Five input shapes at 16/32/64 KB; 64 KB took 0.003–0.052 seconds in the focused run. Oversized legitimate payloads can now be rejected with controlled diagnostics. |

Migration head is **20260914_0010**. After backup, run `orgscan migrate-db` once
before production services start. The new forward data repair uses a frozen,
parity-tested implementation and keyset batches; released 0009 and earlier files
are unchanged. Tests begin with unsafe legacy rows at 0009, verify repair and
preserved relationships/fingerprints, then repeat the upgrade. Redaction cannot be
undone by downgrade. Historical backups are not repaired. A legacy row exceeding
sanitizer limits stops migration for operator review rather than retaining unsafe
values silently. The configured database was not upgraded during this phase.

Validation: focused adversarial/presentation tests **63 passed**. Compile checks,
`git diff --check`, distribution build and external clean-install validation passed.
The clean environment installs only declared runtime dependencies and exercises
migration, CLI, API lifespan/health, scan and JSON/SARIF report workflows. Doctor on
a temporary database explicitly upgraded through 0009 to 0010 returned **exit 0,
ok=true, 17 warnings** for optional tools/providers, absent data directories and
unconfigured authentication/credentials. Production configuration must resolve
applicable warnings. The final complete suite passed: **577 passed, 6 skipped**,
with two existing Starlette/TestClient deprecation warnings.

CLI/API response shapes remain compatible; sensitive values are more aggressively
redacted and excessive sanitizer work raises a controlled error. PostgreSQL, live
Redis and absent external binaries retain their previously documented unverified
status. Deployment disk/process quotas remain necessary. Phase 1 architectural
decomposition remains partial; no unrelated cleanup was undertaken.


## Phase 22 — escaped credential assignment hardening

The post-Phase-21 gate reproduced one release blocker: escaped copied JSON keys
bypassed assignment recognition. Synthetic credentials survived provider summaries,
finding fields, nested copies, readiness diagnostics, HTTP/browser/report output and
0010 repair. Standard unescaped assignments were already protected.

The shared parser now recognizes literal/escaped quote delimiters using the existing
credential vocabulary. Encoded and decoded values enter the same cross-field secret
context. Value scanning advances monotonically; quote escaping is capped at eight
copied JSON layers (255 backslashes), with bounded value decoding. Existing sanitizer
budgets remain unchanged. Excessive escaping raises a controlled, input-free error.
Ordinary escaped keys such as `token_count` and `password_policy` remain unchanged.
No surface-specific redaction or unrelated tenant/queue/architecture changes were added.

Forward data repair **20260914_0011** follows 0010. The new frozen sanitizer has parity
tests against runtime behavior. Released migrations 0009 and 0010 and their snapshots
are unchanged. Migration tests insert unsafe legacy rows at 0010, then verify removal,
unchanged IDs/relationships, useful evidence locations, valid fingerprints and repeat
upgrade behavior. Presentation tests separately retain unsafe legacy rows to prove
that API/browser/report rendering itself protects them. Repair logs contain no values.

Back up and explicitly run `orgscan migrate-db` before production startup. The
configured database was not modified in this phase. Repair is irreversible and does
not change historical backups. Oversized/deeply escaped legacy payloads stop repair
for operator review rather than passing through unsafe values. Unlabelled opaque
secrets still require known-secret context. Public response fields remain compatible;
sensitive copied text is now redacted. Previously documented deployment limitations
remain unchanged.


### Phase 22 validation

- Baseline: 63 existing sanitizer/presentation tests passed; escaped assignments
  at one, three and seven backslashes reproduced the disclosure before editing.
- Final complete suite: **642 passed, 6 skipped**, two existing dependency
  deprecation warnings, **288.19 seconds**.
- Final focused suite: **143 passed**, including **65 added cases**, with two
  existing dependency deprecation warnings. Exact reported reproduction passed.
- Five new adversarial performance shapes at 16/32/64/256 KB: **64 KB took
  0.0055–0.0160 seconds; 256 KB took 0.0230–0.0643 seconds**. Growth stayed near
  linear within conservative two-second test bounds. Existing performance tests
  also passed. Quote/work-limit failures contain no input values.
- Doctor on a disposable database explicitly upgraded from 0010 to **0011**:
  **exit 0, ok=true, 17 warnings** for optional tools/providers and configuration.
- Final wheel/sdist build and clean-install validation passed: fresh external
  virtual environment, runtime dependencies only, `pip check`, migration, CLI,
  API lifespan/health, inert local scan and JSON/SARIF reports.
- Compile checks and `git diff --check` passed. Final review confirmed frozen
  migration history is unchanged and no fixture credentials entered documentation.

## Phase 23 — controlled secret preservation and analyst reveal

Preservation is disabled by default, including when a key is present. To enable it,
set `ORGSCAN_PRESERVE_SECRETS=true`, `ORGSCAN_SECRET_ENCRYPTION_KEY` to a securely
generated URL-safe base64 encoding of 32 random bytes, and optionally
`ORGSCAN_SECRET_ENCRYPTION_KEY_ID` (default `v1`). Provision these through your secret
manager to the API and every scanner/scheduler/worker process. Never commit the key.
Serialized settings deliberately omit it even with `include_secrets=True`; queued
workers must receive it independently through their environment. Missing/invalid keys
fail preservation closed. Doctor reports only enabled/disabled and configured/missing.

AES-256-GCM uses the declared cryptography runtime library. Ciphertexts are bound to
the tenant and finding. HMAC fingerprints support equality/correlation within a tenant
and key version without publishing a raw password hash. The schema records key IDs,
but automated rotation and a multi-key keyring are not implemented: retain the matching
key/version to read existing rows. Losing a key makes those values unrecoverable.
Database backups include ciphertext; protect keys separately and test restoration.
Python cannot guarantee immediate memory zeroization. Operators, trusted plugins and
process debuggers remain within the application trust boundary.

`GET /findings/{finding_id}/secrets` returns masked metadata to authenticated users in
the finding's tenant. `POST /findings/{finding_id}/secrets/{secret_id}/reveal` requires
an explicit action, tenant authorization and either scoped admin or analyst with
`secrets:reveal`. Readers and unauthenticated local users cannot reveal. Environment
token entries accept `capabilities: ["secrets:reveal"]`; the existing administrator
membership API accepts the same field for database users. Membership updates without
capabilities revoke the grant. Multi-tenant analyst sessions require the grant in
every effective tenant scope. Reveal commits a security audit event before returning
plaintext, with no-store/anti-caching headers. Operate behind HTTPS and ensure reverse
proxies/APM do not capture reveal response bodies.

The finding detail view initially contains masks only. Authorized users can Reveal,
Hide, or let a value hide after 30 seconds or when leaving the page. Plaintext is not
put in URLs, browser storage, logs or clipboard automatically. Screenshots, manual
copying and authorized analyst actions cannot be prevented by the application.
JSON/CSV/HTML/PDF/SARIF, scheduled reports, webhooks and generic finding APIs remain
redacted; there is no privileged bulk secret export.

Migration **20260914_0012** adds `secret_evidence` and `secret_reveal_audit` without
rewriting 0009–0011 or recovering irreversibly redacted values. Stop writers and run
`orgscan migrate-db` explicitly before startup. The configured database was not changed
by this implementation. New scans can preserve recognized values supplied by scanners;
digests, already-redacted scanner output and unrecognized opaque values are not
recoverable. Preservation requires a tenant-owned canonical finding. Downgrading 0012
drops protected evidence and reveal audits; restore matching backups for rollback.
PostgreSQL/live Redis/external-tool certification and deployment resource quota
assumptions remain as previously documented.

### Phase 23 validation

- Final complete suite: **691 passed, 6 skipped**, two existing dependency
  deprecation warnings, **357.92 seconds**.
- Added 49 tests for protected capture, encryption/reveal, authorization and current
  grants, browser CSRF/initial HTML, reports/webhooks, audit failure, configuration,
  provider projection, literal JSON escape fidelity, checkpoints and migration.
- Final focused security/legacy-presentation/performance run: **172 passed**, two
  existing dependency deprecation warnings.
- Adversarial runtime probes: **64 KB 0.0097–0.0672 seconds; 256 KB
  0.0383–0.2647 seconds** across unbroken, backslash, copied-assignment and URL shapes.
  Existing boundedness regression tests passed.
- Doctor on an explicitly migrated disposable database: **exit 0, ok=true,
  17 warnings** for optional tools/providers and deployment configuration; preservation
  enabled, encryption key configured, schema **20260914_0012**. No key was printed.
- Protected schema/model comparison: **zero differences**. Forward upgrade from 0011
  and repeat upgrade preserve existing evidence; frozen migration history is unchanged.
- Wheel/sdist build and clean install passed. The latter used a fresh external venv,
  runtime dependencies only, `pip check`, migrations, CLI/API startup, local scan,
  JSON/SARIF reports and encrypted storage with exact authorized reveal.
- Compile checks and `git diff --check` passed. Documentation contains no synthetic
  test credentials. The configured database was not migrated or otherwise changed.

Changing preservation mode or key ID invalidates reusable scanner checkpoints;
missing encryption configuration cannot silently reuse a checkpoint when preservation
is enabled. Change the key ID when provisioning a different key. Copied JSON extraction
retains literal backslashes, quotes, Unicode and actual newlines without repeatedly
decoding the original credential. Provider records containing recognized password
fields are captured before adapters reduce them to redacted summaries.

## Phase 24 — candidate-aware sanitization and keyless repair

The Phase 23 gate reproduced encrypted evidence accompanied by plaintext copies in
ordinary title/description/metadata and reader-facing APIs, browser HTML and reports.
The fix retains bounded private candidate knowledge through batch normalization and
all affected storage writes. Ordinary data is sanitized before flush; exact values
remain available for encryption and the existing authorized reveal workflow. Generic
serializers still never decrypt. Reader, tenant and audit policies are unchanged.

### Upgrade implications

Migration **20260914_0013**, after frozen 0012, repairs ordinary records associated
with existing protected evidence. It does not read an encryption key, decrypt, create
new protected evidence, or change any existing protected ciphertext, nonce, key ID,
fingerprint or tenant binding. It uses a frozen deterministic repair helper, keyset
batches of 100 rows, and emits no record values. Migrations 0009–0012 are unchanged.

**This repair deliberately loses ordinary evidence text on affected records.**
An unlabeled opaque copy cannot be distinguished reliably from useful prose without
its original candidate context/key. The keyless migration therefore masks ambiguous
free-text fields and clears JSON on affected findings, evidence, history, risk scores,
suppressions, matching domain exposures and finding relationships. This includes
otherwise useful titles, descriptions, scanner names, paths and metadata. Numeric
IDs/references, timestamps, line numbers, valid identity digests and recognized
severity/confidence/lifecycle states remain. Relationship labels receive deterministic
masked hashes so distinct edges cannot collide. Unassociated records are untouched.
Authorized reveal continues to recover the original protected credential afterward;
re-scans can repopulate scanner evidence and metadata, while historical masked
titles/descriptions remain masked.

Stop writers, back up, and explicitly run `orgscan migrate-db` before deploying.
The configured database was not changed during this implementation. Repeat repair is
stable; downgrade cannot recover removed ordinary text. Existing restrictions on
key provisioning, one active key version, trusted process memory, reverse-proxy
response logging and deployment resource quotas remain applicable.

Phase 24 validation: 204 focused tests passed; the complete suite passed with
729 passed, 6 skipped and 2 dependency deprecation warnings. The 38 new tests cover
candidate-copy persistence, exact authorized reveal, reader/tenant denial, ordinary
database columns, all five report formats, API/dashboard, audit counts, queued/plugin
ingestion, failure safety and keyless 0012-to-0013 repair. Doctor returned `ok: true`
on an upgraded disposable database with preservation enabled. Distribution build,
clean-install validation (including candidate-copy storage and exact reveal), compile
checks and whitespace checks passed. Optional live tools and PostgreSQL/live Redis
certification remain subject to the previously documented limitations.

## Phase 25 — report projection secret-context hardening

The Phase 24 gate reproduced ordinary plaintext in JSON/CSV/PDF/SARIF after report
construction appended fields without their credential-bearing source metadata.
The final shared report boundary now sanitizes complete projections using ordinary
finding/evidence context, including omitted metadata/snippets and source fields.
Summary provenance, priorities and custom remediation hints retain bounded context
before clipping, even when the detailed report page excludes the source finding.
All five formats and manual/API/scheduled/webhook paths consume the sanitized model.

This is **case A: presentation/projection only**. The reproduction requires unsafe
legacy/direct-SQL rows; normal Phase 24 storage already sanitizes these copies.
No new migration is needed. Head remains **20260914_0013**; migrations 0009–0013 are
unchanged. Reports neither repair legacy rows nor decrypt protected evidence.
Existing 0013 repair semantics remain unchanged, including its documented ordinary
text loss. Ciphertext remains intact and authorized reveal returns the exact value.

One bounded joined context query supports summaries, preserving batched detail
loading and exact aggregate counts. The 1,000-row context cap and existing sanitizer
work budgets fail closed; unusually large custom remediation groups/evidence history
may need operator review or legacy repair. No evidence context is silently truncated.
There is no built-in queued-report job type; validation exercises the existing service
from an RQ caller without adding new production queue functionality. PostgreSQL/live
Redis certification and previously documented deployment limitations remain unchanged.

### Phase 25 validation

- Added **19 regression cases**. Focused reports/API/background plus Phase 23/24
  protected-secret run: **129 passed**, two dependency deprecation warnings.
- Complete suite: **748 passed, 6 skipped**, two dependency deprecation warnings,
  423.21 seconds. Existing tests/assertions were not weakened.
- Original legacy-copy reproduction passes all five formats. Ciphertext stays
  byte-for-byte unchanged; generic reads/exports create zero reveal audits, then
  authorized analyst reveal returns the exact original value and creates one audit.
- At 10/100/300 findings: summaries **37 SELECTs**, dashboards **53 SELECTs**,
  constant with dataset size (previously 36/52). Detail evidence remains batched;
  the extra joined context query does not materialize Evidence ORM rows.
- Doctor: **ok=true, 17 warnings**, configured schema/head **0013**. Preservation
  is disabled locally because no key is configured; encrypted tests use disposable
  keys/databases. The configured database was not migrated or modified by this phase.
- Distribution build, runtime-only clean-install validation, compile checks and
  whitespace checks passed. Clean install exercises CLI/API startup, migrations,
  scan/report output, encrypted storage and exact authorized reveal.
- Field inventory and final projection boundary reviewed; no frozen migration or
  secret-evidence/reveal implementation changed. No release commit/tag was created.

## Phase 26 — complete credential context propagation

The Phase 25 gate reproduced two context-selection defects: omitted low-ranked
sources could identify credentials copied into aggregate labels or displayed titles,
and generic finding presentation missed credential labels found only in evidence.
The new storage-owned context builder fixes both without changing authorized reveal.

Report context covers complete tenant-authorized populations contributing details,
aggregates, groups, provenance and source labels, independently of display selection.
One bounded UNION ALL reads ordinary string/JSON columns; requested and inherited
tenant scopes are intersected using the shared visibility policy. The context is
reused through final summary/report sanitization, including compatibility exports.
Finding presentation batches associated evidence/history/risk text for emitted IDs.
API, browser, detail and operation queues consume the shared finding boundary.
Neither context path queries protected evidence or calls decryption.

This remains **case A: presentation/context selection only**. Normal persistence is
covered by the retained Phase 24 tests; unsafe SQL fixtures deliberately bypass it.
No migration is needed; current/head stays **20260914_0013**, and migrations 0009–0013,
ciphertext, key handling, reveal authorization and audit implementation are unchanged.

Report context defaults to 1,000 source rows across all contributing populations;
finding context defaults to 2,000 rows per batch and 500 distinct finding IDs. These
are source-completeness limits, not display limits. Environment settings and exact
source populations are documented in [reporting](reporting.md) and
[architecture](architecture.md#complete-credential-context-phase-26). Existing
character/node/depth/replacement limits remain active. Large scopes can fail closed
even with safe data; operators must size the configured budget accordingly. No
truncated credential context is used to emit output. Detached finding objects without
context now fail safely instead of permitting incomplete compatibility serialization.

PostgreSQL/live Redis/live scanner certification and production resource assumptions
remain as previously documented; this phase does not certify those environments or
complete Phase 1 decomposition. No commit/tag is created by this implementation.

### Phase 26 validation

- Added **21 adversarial cases**; both exact gate reproductions pass. Final focused
  Phase 23–26 security/report/API/service run: **159 passed** in 215.45 seconds.
- Final complete suite: **769 passed, 6 skipped** in 478.22 seconds, with two existing
  dependency deprecation warnings. Existing assertions were not weakened.
- JSON/CSV/HTML/PDF/SARIF and compatibility exports contain no fixture plaintext.
  Retained Phase 25 scheduled/webhook/RQ service tests pass. API/list/detail/browser,
  summary and operator queues redact evidence-identified copies. Generic reads are
  tested with decryption forbidden, unchanged ciphertext and zero reveal audits;
  authorized analyst reveal returns the exact original secret and records one audit.
  Reader/ungranted-analyst/other-tenant denial and the existing admin matrix pass.
- At **10/100/300 findings**: page plus credential context **2 SELECTs**; report
  context **1 SELECT**; complete summary **37 SELECTs**; dashboard **55 SELECTs**.
  Summary counts remain unchanged; dashboard adds two batch queries over Phase 25.
  Existing ORM-materialization, evidence-batching and query-count checks pass.
- Doctor: **ok=true, 17 warnings**. Configured schema and migration head are both
  **20260914_0013**. Local preservation is disabled/key missing; protected tests use
  disposable keys/databases. The configured database was not migrated or modified.
- Final wheel and sdist build passed. Fresh external runtime-only installation
  passed dependency checks, migrations, CLI/API startup, scan/JSON/SARIF and encrypted
  evidence/exact reveal smoke validation. Compile and `git diff --check` passed.
- Final projection/context diff and documentation reviewed; no synthetic credential
  values were introduced into documentation. No frozen migrations were changed.

## Phase 27 — derived projection credential context

The three Phase 26 gate reproductions are covered by a shared derived-projection
boundary: failed-job labels identified in parameters, repository/graph labels
identified in asset metadata, and trend keys identified in finding metadata. Context
is retained until the complete DTO is sanitized. Operator, graph, trend, asset/job
detail, schedule, CLI job and compatibility aggregate output consume the same policy.
No endpoint-specific credential regex or decryption path is added.

Storage defines explicit contributor families and loads bounded ordinary text/JSON
columns in one query per context. Graph edge selection is bounded, and endpoint
labels are loaded in batches by ID. Queue diagnostic context inherits scheduled-scan
tenant visibility through the authoritative policy. Dashboard trends reuse report
context; operator context remains scoped to its own session. The full source inventory
and A/B/C classification are in [projection safety](projection-safety.md).

`ORGSCAN_PROJECTION_CONTEXT_MAX_ROWS` defaults to 10,000 rows per family (configurable
up to 100,000). Existing report/page and sanitizer work limits remain active. Oversized
or incomplete context fails closed before derived output is emitted; no first-N
partial context is accepted. Large scopes may therefore require budget configuration.

These are presentation/projection defects. Direct SQL is required to seed the unsafe
legacy reproduction rows; current job/repository persistence already sanitizes their
copies, and Phase 24 persistence regressions remain required. **No migration is
needed**, head remains **20260914_0013**, and frozen migrations are unchanged. Protected
ciphertext, encryption/key handling, authorized exact reveal and reveal audits are
unchanged. No configured database upgrade, release commit or tag is performed.

Existing PostgreSQL/live Redis certification gaps, optional scanner availability and
deployment resource requirements remain documented limitations. Phase 1 decomposition
remains partial; this phase does not perform unrelated architectural cleanup.

### Phase 27 validation

- Added **34 regression cases**, including all three original SQL-bypass probes,
  adjacent source families, CLI job/queue diagnostics, tenant context isolation,
  family overflow, aggregate keys and current job/asset persistence.
- Final focused Phase 23–27 security/report/API/service run: **193 passed** in
  293.31 seconds. Final full suite: **803 passed, 6 skipped** in 562.37 seconds,
  with two existing dependency deprecation warnings. Existing tests were not weakened.
- Reader operator/dashboard/graph/trend and asset/job surfaces contain no fixture
  plaintext. Generic operations run with decryption forbidden, leave legacy values
  and ciphertext unchanged and create **zero** reveal audits. Reader/ungranted analyst/
  wrong-tenant reveal is denied; authorized analyst/admin reveal returns the exact
  original value and creates **one** audit. Phase 23–26 report/persistence regressions
  continue to pass, including all five report formats and scheduled/webhook delivery.
- At 10/100/300 items: operator **15 SELECTs**, dashboard **55**, graph **4**, trends
  **2**, with context reads **1 / 3 / 1 / 1** respectively. Existing Phase 20/26 query
  assertions remain unchanged. The combined 300-item fixture explicitly uses a
  2,000-row report budget because findings/assets/jobs contribute multiple source rows.
- Doctor: **ok=true, 17 warnings**, configured current/head **20260914_0013**. Local
  preservation is disabled/key missing; encrypted tests use disposable databases/keys.
- Final wheel/sdist build and runtime-only clean install passed. Clean install covers
  dependency checks, migrations, CLI/API startup, scan/report workflow and encrypted
  evidence/exact reveal. Compile and whitespace checks passed.
- Final diff/source inventory reviewed. No frozen migration or secret-evidence/reveal
  implementation changed, and synthetic fixture credentials were not added to docs.

## Assessment control-plane checkpoint (2026-09-15)

Historical checkpoint; the continuation section and linked milestone matrix below
supersede its counts and remaining-work list.

Migration head is now **20260915_0014**, an additive eight-table control-plane
schema. Prior migrations and protected-evidence/reveal implementation are unchanged.
The configured application database was not upgraded; production deployment requires
the established explicit migration step.

The final full suite passed **842 tests**, with **7 optional live tests skipped**
and two existing dependency deprecation warnings. The assessment suite contributes
39 tests, including exact authorized reveal after all AI purposes, tenant/assessment
isolation, browser CSRF, connection grants, query counts and migration preservation.
Doctor on a disposable 0014 database returned **ok=true**, 16 optional warnings.
Wheel/sdist build, clean runtime-only installation, compile and whitespace checks
passed. Scope pages retain five SELECTs at 10/100/300 repositories.

This is an implementation checkpoint, not completion of the full A–Z product epic
or live GHES/Windows/WSL/Ollama/PostgreSQL certification. See the
[validation report](assessment-control-plane-validation.md) and its remaining
product/integration dependencies.


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

## Cross-tenant domain identity migration (0016)

The [domain identity migration](domain-identity.md) is a forward ownership-model
change from frozen `20260915_0015` to `20260916_0016`. Back up, stop writers and test
an upgraded copy before deployment. Normalized duplicate associations within one
tenant/legacy scope and invalid names stop preflight; no arbitrary merge is allowed.
Downgrade is deliberately refused; rollback uses a verified pre-upgrade backup.

The configured database remains at 0015 and is not changed by this development run.
Consequently configured doctor reports a required schema upgrade; doctor on the
upgraded disposable database passes. Do not start development auto-migration against
the configured database as a validation shortcut. SQLite upgrade and foreign-key
integrity are tested; PostgreSQL live upgrade remains deployment validation.
