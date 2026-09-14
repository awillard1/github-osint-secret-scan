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
bounded version probe (currently YARA). Third-party plugins remain trusted code.
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
5. Run `orgscan init-db` explicitly, then doctor again. Head is `20260911_0008`.
   Migration 0006 adds evidence identity; 0007 maps lifecycle and records inferred
   legacy timestamps. Migration 0008 adds durable queue execution identities,
   quarantines duplicate legacy executions, and sanitizes legacy evidence/diagnostics.
   Redaction is irreversible; these migrations do not reconstruct unavailable history.
6. Validate authorized reads, a local test scan and reporting before restarting workers.

Rollback should restore a tested matching backup and application version. Downgrading
0008 cannot restore redacted data, and downgrading 0007 removes lifecycle/history fields; it is not a lossless rollback strategy.

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
