# orgscan

`orgscan` is the Phase 0/1 foundation plus practical slices through later phases of the OSINT Security Platform described in [`projectspec.md`](./projectspec.md). The repository roadmap is tracked in [`docs/roadmap.md`](./docs/roadmap.md), and OSS/tooling gaps are documented in [`docs/open-source-tooling-gaps.md`](./docs/open-source-tooling-gaps.md). It currently provides:

- a Python package and CLI
- environment-based configuration loading with `.env` support
- structured logging
- normalized core storage models for organizations, domains, repositories, accounts, scan jobs, findings, evidence, relationships, and risk scores
- a SQLite-first persistence layer built on SQLAlchemy for future PostgreSQL support
- target intake commands for organizations, domains, repositories, and accounts
- finding inspection, GitHub metadata discovery, local scanning, git-history scanning, governance scanning, reporting, export, dashboard generation, and dependency verification commands
- repository expansion, scheduled scanning, execution telemetry, intuitive configuration helpers, and a live FastAPI dashboard/API
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
ORGSCAN_CRTSH_BASE_URL=https://crt.sh
ORGSCAN_REDIS_URL=redis://127.0.0.1:6379/0
ORGSCAN_SCAN_QUEUE_NAME=orgscan:scans
ORGSCAN_DETECT_SECRETS_BINARY=detect-secrets
ORGSCAN_SUBFINDER_BINARY=subfinder
ORGSCAN_HTTPX_BINARY=httpx
ORGSCAN_WHOIS_BINARY=whois
```

Generate a starter `.env` template and inspect the effective configuration:

```bash
orgscan init-config
orgscan config
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

The built-in custom pattern heuristics redact matched values and skip obvious placeholder assignments such as example, sample, dummy, fake, or change-me style values to reduce false positives.

If `git-history-patterns`, `repo-governance`, `gitleaks`, `detect-secrets`, `semgrep`, or `trufflehog` are available, you can run them through the same workflow:

```bash
orgscan scan path ./path/to/repository --scanner git-history-patterns
orgscan scan path ./path/to/repository --scanner repo-governance
orgscan scan path ./path/to/scan --scanner gitleaks
orgscan scan path ./path/to/scan --scanner detect-secrets
orgscan scan path ./path/to/scan --scanner semgrep
orgscan scan path ./path/to/scan --scanner trufflehog
```

The built-in `git-history-patterns` scanner uses `git log --patch` to look for secrets in added and removed historical diffs, and the built-in `repo-governance` scanner checks for missing `CODEOWNERS`, missing `SECURITY.md`, and unpinned GitHub Actions references in workflow files.

External scanner wrappers honor the configured `ORGSCAN_*_BINARY` settings, and additional scanners can be registered through Python entry points in the `orgscan.scanners` group.

You can also ingest previously saved scanner output and normalize it into the same canonical data model:

```bash
orgscan ingest-results --scanner gitleaks --target example-org/app --repository example-org/app ./reports/gitleaks.json
orgscan ingest-results --scanner detect-secrets --target example-org/app --repository example-org/app ./reports/detect-secrets.json
orgscan ingest-results --scanner semgrep --target example-org/app --repository example-org/app ./reports/semgrep.json
```

Discover public GitHub repository metadata and persist it locally:

```bash
orgscan discover repository psf/requests
orgscan discover domain example.com
orgscan discover domain example.com --provider all
orgscan discover domain example.com --provider crtsh
orgscan discover domain example.com --provider projectdiscovery
orgscan discover domain example.com --provider whois
orgscan discover domain example.com --provider dns
```

The `all` domain provider aggregates local metadata, crt.sh, ProjectDiscovery, WHOIS, and DNS enrichment in one pass and returns warnings for providers that are unavailable. The `crtsh` domain provider uses the public crt.sh certificate-transparency feed to discover additional domain-linked hosts. The `projectdiscovery` domain provider uses `subfinder` and `httpx` when installed to enrich domain exposure data with discovered subdomains and reachable HTTP services. The `whois` domain provider extracts registrar and nameserver context from WHOIS output. The `dns` provider uses `dnspython` to collect NS, MX, TXT, A, AAAA, and CNAME records for the tracked domain and discovered hosts.

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
orgscan enqueue-scheduled --limit 5
orgscan queue-status
orgscan run-worker --burst --max-jobs 5
orgscan jobs --json
```

Use `run-scheduled` for local in-process execution, or `enqueue-scheduled` plus `run-worker` to process scheduled scans through Redis/RQ workers.

Serve the live dashboard and API:

```bash
orgscan serve-api --host 127.0.0.1 --port 8000
```

Key routes:

- `/dashboard` live HTML dashboard with filter controls
- `/summary` summary JSON
- `/findings` filtered findings JSON
- `/findings/{id}` detailed finding JSON with evidence and risk scores
- `/findings/{id}/evidence` evidence-only JSON for a finding
- `/organizations`, `/repositories`, `/domains`, `/accounts` entity inventory JSON with high-signal risk summaries
- `/organizations/{id}`, `/repositories/{id}`, `/domains/{id}`, `/accounts/{id}` entity detail JSON with related findings and relationships
- `/risk-summary` aggregated entity risk profiles filtered by minimum confidence
- `/relationships/graph` relationship graph JSON
- `/trends/findings` findings trend JSON

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
- The optional ProjectDiscovery integration uses `subfinder` for passive subdomain discovery and `httpx` for HTTP service enrichment.
- The optional crt.sh integration adds certificate-transparency-based host discovery for tracked domains.
- The optional WHOIS integration adds registrar and nameserver enrichment for tracked domains.
- The optional DNS integration adds record-level enrichment for tracked domains and previously discovered subdomains.
- The built-in git-history-patterns scanner searches git diff history for added or removed content that matches the same core secret patterns used by the local file scanner.
- The built-in repo-governance scanner checks for missing ownership/security policy files and unpinned GitHub Actions references.
- The initial `scan` command uses the built-in `custom-patterns` scanner and stores scan jobs, findings, and evidence in SQLite for later reporting.
- The `discover` command uses the public GitHub REST API and can use `ORGSCAN_GITHUB_TOKEN` when configured for higher rate limits.
- External scanner output from `gitleaks`, `detect-secrets`, `semgrep`, and `trufflehog` can be normalized through `orgscan ingest-results` without rerunning the original tool.
- The local web surface now runs on FastAPI and serves both live HTML dashboard views and JSON endpoints from the same application.
- Scheduled scans can also be enqueued onto Redis/RQ workers for queue-based execution in addition to the local synchronous scheduler flow.
- The current roadmap status and remaining gaps relative to the full project spec are documented in `docs/roadmap.md`.
- Additional open-source tools that can close current capability gaps are documented in `docs/open-source-tooling-gaps.md`; Semgrep is now available as an optional external scanner integration.
