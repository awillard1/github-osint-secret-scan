# orgscan

`orgscan` is the Phase 0/1 foundation plus practical slices through later phases of the OSINT Security Platform described in [`projectspec.md`](./projectspec.md). The repository roadmap is tracked in [`docs/roadmap.md`](./docs/roadmap.md), and OSS/tooling gaps are documented in [`docs/open-source-tooling-gaps.md`](./docs/open-source-tooling-gaps.md). It currently provides:

- a Python package and CLI
- environment-based configuration loading with `.env` support
- structured logging
- normalized core storage models for organizations, domains, repositories, accounts, scan jobs, findings, evidence, relationships, and risk scores
- a SQLite-first persistence layer built on SQLAlchemy for future PostgreSQL support
- target intake commands for organizations, domains, repositories, and accounts
- finding inspection, GitHub metadata discovery, local scanning, reporting, export, dashboard generation, and dependency verification commands
- repository expansion, scheduled scanning, execution telemetry, and a lightweight JSON API
- tests for config, validation, storage, and CLI flows

## Requirements

- Python 3.12+

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

Or use the bootstrap helper from a fresh clone:

```bash
python scripts/bootstrap.py
python scripts/bootstrap.py --verify-only
python scripts/bootstrap.py --install-only
```

The bootstrap helper creates `.venv`, installs the editable package with development dependencies, initializes the default SQLite database, and reports dependency status. Use `--verify-only` to print dependency status and next steps without modifying the environment, or `--install-only` to prepare the Python environment without initializing the database.

## Configuration

Configuration is loaded from environment variables prefixed with `ORGSCAN_` and optionally from a local `.env` file.

Example:

```env
ORGSCAN_DATABASE_URL=sqlite:///./data/orgscan.db
ORGSCAN_LOG_LEVEL=INFO
```

## Usage

Initialize local directories and inspect dependency status:

```bash
orgscan setup --create-venv --install-dev --init-db
```

Initialize the database explicitly:

```bash
orgscan init-db
```

Print application status and entity counts:

```bash
orgscan status
```

Add a target:

```bash
orgscan add-target organization example-org
orgscan add-target domain example.com --organization example-org
```

List stored findings:

```bash
orgscan findings --limit 20
```

Update finding triage fields:

```bash
orgscan triage 1 --status triaged --triage-state reviewing --owner alice --note "validated and assigned" --due-date 2026-09-30
orgscan suppress 1 --reason "false positive"
orgscan accept-risk 1 --reason "compensating controls in place" --owner alice
orgscan unsuppress 1 --note "reopened after new evidence"
```

Run the built-in custom pattern scanner against a file or directory:

```bash
orgscan scan path ./path/to/scan --organization example-org --repository example-org/app
```

If `gitleaks`, `semgrep`, or `trufflehog` are installed locally, you can run them through the same workflow:

```bash
orgscan scan path ./path/to/scan --scanner gitleaks
orgscan scan path ./path/to/scan --scanner semgrep
orgscan scan path ./path/to/scan --scanner trufflehog
```

Discover public GitHub repository metadata and persist it locally:

```bash
orgscan discover repository psf/requests
orgscan discover domain example.com
```

Expand related repositories and contributors:

```bash
orgscan expand repository psf/requests
orgscan expand organization psf
```

Print a stored summary report:

```bash
orgscan report
```

Export findings and generate a static HTML dashboard:

```bash
orgscan export ./data/findings.json --format json
orgscan dashboard ./data/dashboard.html
```

Schedule recurring scans and inspect execution history:

```bash
orgscan schedule-scan ./path/to/scan --repository example-org/app --cadence daily
orgscan run-scheduled --limit 5
orgscan jobs --json
```

Serve the local JSON API:

```bash
orgscan serve-api --host 127.0.0.1 --port 8000
```

Verify required local dependencies:

```bash
orgscan verify-deps
```

Run tests:

```bash
pytest
```

## Development notes

- SQLite is the default backend for local development.
- Storage code uses SQLAlchemy abstractions so PostgreSQL support can be added in later phases with minimal API churn.
- Canonical scanner output should be normalized through `orgscan.schemas.CanonicalFinding` before persistence.
- The bootstrap helper recommends package-manager installation only for base OS dependencies; use official upstream install methods for tools such as Gitleaks and TruffleHog.
- The initial `scan` command uses the built-in `custom-patterns` scanner and stores scan jobs, findings, and evidence in SQLite for later reporting.
- The `discover` command uses the public GitHub REST API and can use `ORGSCAN_GITHUB_TOKEN` when configured for higher rate limits.
- The current roadmap status and remaining gaps relative to the full project spec are documented in `docs/roadmap.md`.
- Additional open-source tools that can close current capability gaps are documented in `docs/open-source-tooling-gaps.md`; Semgrep is now available as an optional external scanner integration.
