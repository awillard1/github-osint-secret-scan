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
5. Run `orgscan init-db` explicitly, then doctor again. Head is `20260911_0007`.
   Migration 0006 adds evidence identity; 0007 maps lifecycle and records inferred
   legacy timestamps. Neither reconstructs unavailable historical evidence.
6. Validate authorized reads, a local test scan and reporting before restarting workers.

Rollback should restore a tested matching backup and application version. Downgrading
0007 removes lifecycle/history fields; it is not a lossless rollback strategy.

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
  custom rule updates. Semgrep auto configuration with metrics disabled is a known
  runtime compatibility risk; doctor warns without silently enabling telemetry.
- [ ] Review existing provider subprocess timeout coverage and raw upstream diagnostics.
  Built-in scanner execution is bounded, but older enrichment adapters still need hardening.
- [ ] Complete adversarial archive/symlink/upload coverage, large-data limits and concurrent
  tenant/lifecycle/queue race testing. POSIX cache locks are local, not distributed leases.
- [ ] Validate PostgreSQL, full Unicode PDF fonts and target code-scanning-host SARIF ingestion.
- [ ] Add password/MFA/SSO or login-abuse controls if required by the deployment threat model.
- [ ] Review dependencies/security advisories and run deployment-specific security testing
  before declaring 1.0 readiness. The unit suite and this checklist are not a security audit.

Review legacy findings/free-form operator text before sharing reports. Raw source
material is excluded from new reports, but arbitrary secrets in third-party metadata
cannot be recognized reliably. See phase-specific documents for additional limits.
