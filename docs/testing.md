# Testing and Validation

## Baseline

Before a phase:

```bash
pytest
```

If the project has baseline failures, record them before changing code.

## Required test levels

### Unit

Use for:

- scanner parsers;
- fingerprints;
- scan-plan resolution;
- lifecycle transitions;
- retry classification;
- auth/authorization decisions.

### Service tests

Use a temporary SQLite database and fakes for external dependencies.

Test use cases independently of FastAPI/Typer.

### API tests

Verify:

- status codes;
- validation;
- authorization;
- compatibility of documented endpoints;
- no secret leakage in response errors.

### CLI tests

Verify documented command compatibility and exit codes.

Do not duplicate all service business-rule tests at the CLI layer.

### Migration tests

For schema changes:

- upgrade a representative previous schema;
- verify newly required fields/indexes;
- verify SQLite compatibility.

### External process tests

Mock/fake subprocess behavior.

Cover:

- executable missing;
- success;
- scanner findings;
- no findings;
- timeout;
- malformed output;
- non-zero exit.

## Security regression tests

Maintain tests for:

- path traversal in archive extraction;
- unsafe symlink handling;
- secret redaction;
- authorization/tenant boundaries;
- command injection avoidance;
- scanner timeout;
- artifact cleanup;
- unsafe filename handling.

## Test organization

Prefer test files aligned to architectural modules after decomposition:

```text
tests/
    api/
    cli/
    services/
    scanners/
    storage/
```

Do not reorganize the entire suite only for cosmetics. Move tests alongside corresponding refactors.

## Completion command

Minimum:

```bash
pytest
```

If Ruff/mypy are introduced/configured later:

```bash
ruff check .
mypy src/orgscan
pytest
```

Do not make `AGENTS.md` require a static tool until it exists in project configuration.

## Performance-sensitive tests

Repository history tests must use small synthetic git repositories.

Never clone large public repositories in the normal test suite.

## Determinism

Tests must not depend on:

- GitHub being reachable;
- crt.sh being reachable;
- current public DNS;
- local installation of Gitleaks/TruffleHog/Semgrep/YARA;
- Redis being externally available.

Use recorded fixtures or fakes.

## Clean runtime installation (CI/release validation)

The ordinary `tests/packaging/test_installed_wheel.py` verifies wheel contents and
installed imports using development dependencies; it is not a clean-install claim.
Run the separate validation after building:

```bash
python -m build
python scripts/validate_clean_install.py dist/orgscan-0.1.0-py3-none-any.whl
```

The script creates a fresh venv under `/tmp`, outside the checkout, with no system
site packages, PYTHONPATH or development extras. It installs the wheel with declared
runtime dependencies, runs `pip check`, explicit production database initialization,
CLI startup, local scan, JSON/SARIF reports and API lifespan/health without httpx.
It asserts pytest/httpx are absent and cleans the temporary environment afterward.
Index access (or pip wheelhouse configuration) is required. The GitHub Actions
`clean-install.yml` runs this independently on Python 3.12 and 3.13; normal unit tests
remain offline and do not perform this dependency install.


## Optional live tools

Normal tests never require external scanner executables. Explicitly opt in with:

```bash
ORGSCAN_LIVE_TOOLS=1 python -m pytest tests/live -rs
```

The five scanner smokes skip missing executables/unmet readiness, generate their own
inert inputs and local rules, and disable Semgrep metrics and TruffleHog update/verification
requests. No target repository code is executed. See the scanner contract for limits.
The existing detect-secrets live test also requires this opt-in variable.


Phase 21 regressions live in `tests/security/test_phase21_sanitizer.py` and
`tests/security/test_phase21_presentation.py`. They cover shared label grammar,
URL/copy context, fail-closed budgets, 16/32/64 KB adversarial growth, unsafe legacy
API/browser/report presentation, provider persistence and repeatable 0009-to-0010
repair. Performance assertions use a conservative two-second ceiling and growth
allowance, rather than exact machine-dependent timings. Legacy presentation tests
verify the database remains unsafe, proving serialization itself supplies safety.


Phase 22 adds `tests/security/test_phase22_escaped_assignments.py` and
`tests/security/test_phase22_boundaries.py`: escaped quote levels, decoded sibling
copies, negative labels, bounded failure, five 16/32/64/256 KB adversarial shapes,
provider/plugin persistence, readiness, real HTTP handlers, legacy browser/report
presentation and repeatable 0010-to-0011 repair. Migration parity tests compare the
new frozen snapshot with runtime behavior; released snapshots are not edited.

## Phase 23 protected evidence

Run `pytest tests/security/test_phase23_secret_evidence.py` for encrypted ingestion,
quoted/copied assignment capture, actual scanner/provider ingestion, exact authorized
reveal, tamper rejection, tenant/role/capability checks, current membership revocation,
browser CSRF, no-store headers, audit commit failure, masked initial HTML, all five
report formats, webhook summaries, key diagnostics and the 0011-to-0012 schema upgrade.
These tests use disposable databases and generated encryption keys. Existing Phase
21/22 sanitizer performance and legacy presentation tests remain required regressions.

Test raw values only in fixtures and explicit authorized reveal assertions. Check
ordinary ORM columns and audit events independently of masked serializers. Do not
log keys or revealed credentials during validation. Clean-install validation continues
to install only declared runtime dependencies in an external virtual environment;
cryptography is a runtime requirement, not a development-only dependency.

## Phase 24 candidate-copy regression

Run `pytest tests/security/test_phase23_secret_evidence.py tests/security/test_phase24_candidate_context.py`.
The original release-gate reproduction is permanent coverage: a masked indicator and
snippet with a protected candidate and plaintext copies in title/description/nested
metadata. Tests inspect SQL columns directly, then separately verify ciphertext,
exact analyst reveal, reader denial, all five report formats, browser initial HTML,
webhook payloads and zero audit events from ordinary reads. Explicit reveal creates
one audit event with no secret value. Credential cases include spaces, apostrophes,
quotes, backslashes, punctuation, Unicode, equals/colons, newlines and JSON escaping.

Additional cases cover canonical/evidence/domain create and update, imported artifact
results, DB/RQ execution, candidate lifetime/bounds, batch ownership, disabled
preservation and encryption failure. The migration test seeds unsafe Phase 23-style
SQL rows at 0012, upgrades without a key, repeats repair, compares protected columns
byte-for-byte, verifies relationship IDs/lifecycle history, and successfully reveals
the original value afterward. Existing sanitizer/presentation defenses remain tested.

## Phase 25 report projection regression

`tests/reports/test_phase25_projection.py` inserts unsafe legacy copies through SQL,
including the release-gate metadata/remediation/query reproduction. It checks all five
formats, reader/analyst/admin HTTP exports, evidence-only and cross-field knowledge,
summary-only and out-of-page remediation groups, relationship provenance, compatibility
rows, scheduled/webhook output and an RQ service invocation. Protected columns remain
byte-for-byte unchanged, legacy SQL values remain unsafe during reads, decryption is
forbidden during export, report audits stay at zero, and explicit authorized reveal
returns the exact original value and creates one audit. A separate normal-ingestion
case verifies that this is a presentation defect, not a new persistence regression.
Existing report/query-count assertions are retained unchanged.

## Phase 26 complete-context regression

`tests/security/test_phase26_context.py` adds 21 cases. Direct SQL fixtures reproduce
both reported leaks: an older credential source excluded from page/top/graph/group
selection, and finding text whose only credential label is in associated evidence.
Coverage includes finding/evidence-only knowledge, copied source-tool/category labels,
titles, evidence queries and relationship provenance; JSON/CSV/HTML/PDF/SARIF; reader,
analyst and admin API/browser/summary/operator surfaces; inherited tenant-scope
intersection; detached-object and context-overflow safe failures.

Protected columns must remain identical. Generic reads run with decryption forbidden,
create zero reveal audits and leave deliberately unsafe SQL fixtures unchanged.
Authorized reveal subsequently returns the exact original value and creates one audit;
readers, ungranted analysts and other tenants remain denied. At 10/100/300 findings,
page loading is two SELECTs and report-context loading is one, with SQL limits and
no protected-evidence query. Existing Phase 20 aggregate/query-count and Phase 25
scheduled/webhook/RQ service regression assertions remain unchanged.

## Phase 27 derived projections

`tests/security/test_phase27_projections.py` covers the three exact gate failures
and additional job errors, tool diagnostics, repository/provider, account, domain,
organization, relationship, schedule and finding aggregate labels. Fixtures insert
unsafe values with SQL so tests prove presentation safety independently of persistence.
Authenticated reader API/browser/graph/trend requests must redact every copy, leave
the unsafe source and ciphertext unchanged, and create zero reveal audits. Generic
decryption is forbidden. Reader/ungranted analyst/foreign tenant reveal is denied;
authorized analyst/admin reveal remains exact and creates one audit.

The suite also covers CLI job/queue output, compatibility aggregate keys, family
overflow, context isolation between tenants, current job/repository persistence,
and 10/100/300 query-count measurements. See [projection safety](projection-safety.md)
for the A/B/C source inventory, family limits and query counts. Existing Phase 23–26
tests and query assertions remain required and unchanged.

## Assessment control plane and local AI

`pytest tests/assessments` covers target batches, connection identities/credential
grants, visibility, API/browser permissions and CSRF, durable discovery/local scan
execution, scope selection and ScanPlan options, reports, migration preservation,
query counts, provider domain correlation, local AI protocol/cache/failure/limits,
and no-decryption/exact-reveal security. Normal tests use disposable databases and
mock transports. `tests/live/test_ollama.py` requires the explicit environment opt-in
documented in local-ai.md; no normal test requires Windows or a live Ollama model.
Migration-head assertions advance to 0014; historical repair assertions are retained.


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

## Recon toolchain

`pytest tests/recon` covers detection, identity/version rejection, explicit install
and failed-update preservation, platform-administrator permissions, active consent,
missing tools, scope rejection before subprocess execution, canonical correlation,
empty upstream blocking, limits, Nuclei findings/evidence, template policy,
repository metadata, legacy projection safety, browser routes and additive migration
preservation. No normal test installs recon executables or calls their live APIs.
PyYAML is a declared runtime dependency for the restricted local template policy.
See [Recon toolchain validation](recon-toolchain-validation.md) for the integration
validation record and deployment limits.

## Live local recon certification

`ORGSCAN_LIVE_RECON=1 pytest tests/live/test_recon_compatibility.py` explicitly
requires the certified recon binaries. It starts disposable loopback DNS/HTTP/TLS
services and uses an orgscan-owned inert Nuclei template; it never installs binaries
or queries external targets. Missing required recon binaries fail this opt-in run.
Normal pytest skips it. See [the workstation certification record](recon-toolchain-validation.md#live-workstation-certification--2026-09-16).
