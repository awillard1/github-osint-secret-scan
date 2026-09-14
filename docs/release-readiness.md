# Doctor and release readiness

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
5. Run `orgscan init-db` explicitly, then doctor again. Head is `20260914_0009`.
   Migration 0006 adds evidence identity; 0007 maps lifecycle and records inferred
   legacy timestamps. Migration 0008 adds durable queue execution identities,
   quarantines duplicate legacy executions, and sanitizes legacy evidence/diagnostics.
   Migration 0009 repairs additional credential-bearing evidence and diagnostic fields,
   including domain summaries, nested plugin metadata and job targets.
   Redaction is irreversible; these migrations do not reconstruct unavailable history.
6. Validate authorized reads, a local test scan and reporting before restarting workers.

Rollback should restore a tested matching backup and application version. Downgrading
0009/0008 cannot restore redacted data, and downgrading 0007 removes lifecycle/history fields; it is not a lossless rollback strategy.

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
