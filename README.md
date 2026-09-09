# orgscan

`orgscan` is the Phase 0/1 foundation plus practical slices through later phases of the OSINT Security Platform described in [`projectspec.md`](./projectspec.md). The repository roadmap is tracked in [`docs/roadmap.md`](./docs/roadmap.md), and OSS/tooling gaps are documented in [`docs/open-source-tooling-gaps.md`](./docs/open-source-tooling-gaps.md). It currently provides:

- a Python package and CLI
- environment-based configuration loading with `.env` support
- structured logging
- normalized core storage models for organizations, domains, repositories, accounts, scan jobs, findings, evidence, relationships, and risk scores
- a SQLite-first persistence layer built on SQLAlchemy for future PostgreSQL support
- target intake commands for organizations, domains, repositories, and accounts
- finding inspection, GitHub metadata discovery, local scanning, governance scanning, reporting, export, dashboard generation, and dependency verification commands
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
ORGSCAN_SCAN_QUEUE_BACKEND=rq
ORGSCAN_SCAN_QUEUE_NAME=orgscan:scans
ORGSCAN_SCAN_QUEUE_RETRY_MAX=2
ORGSCAN_SCAN_QUEUE_RETRY_INTERVALS=30,120
ORGSCAN_SCAN_QUEUE_LEASE_SECONDS=300
ORGSCAN_SCAN_QUEUE_POLL_INTERVAL_SECONDS=5
ORGSCAN_OUTBOUND_REQUESTS_PER_MINUTE=0
ORGSCAN_OUTBOUND_MIN_INTERVAL_SECONDS=0
ORGSCAN_RATE_LIMIT_BACKEND=db
ORGSCAN_RATE_LIMIT_SCOPE_OVERRIDES_JSON={"github-api":{"requests_per_minute":120},"hibp":{"min_interval_seconds":2}}
ORGSCAN_RATE_LIMIT_POLL_INTERVAL_SECONDS=1
ORGSCAN_API_TOKENS_JSON=[{"name":"viewer","token":"change-me","role":"reader","tenants":["*"]}]
ORGSCAN_HIBP_API_KEY=
ORGSCAN_DEHASHED_EMAIL=
ORGSCAN_DEHASHED_API_KEY=
ORGSCAN_INTELLIGENCEX_API_KEY=
ORGSCAN_DETECT_SECRETS_BINARY=detect-secrets
ORGSCAN_YARA_BINARY=yara
ORGSCAN_YARA_RULES_PATH=
ORGSCAN_RG_BINARY=rg
ORGSCAN_HEURISTIC_TERMS=corpname,internal-project
ORGSCAN_INTERNAL_HOSTNAME_SUFFIXES=corp,internal,local,lan
ORGSCAN_GIT_HISTORY_MAX_COMMITS=250
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
orgscan migrate-db
```

Print application status and entity counts:

```bash
orgscan status
```

Add a target:

```bash
orgscan add-target organization example-org
orgscan add-target organization tenant-org --tenant-key tenant-a
orgscan add-target domain example.com --organization example-org --tenant-key tenant-a
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
orgscan scan path ./path/to/scan --organization example-org --repository example-org/app --tenant-key tenant-a
```

If `repo-governance`, `gitleaks`, `detect-secrets`, `semgrep`, `trufflehog`, `yara`, `ripgrep-heuristics`, or `git-history-patterns` are available, you can run them through the same workflow:

```bash
orgscan scan path ./path/to/repository --scanner repo-governance
orgscan scan path ./path/to/scan --scanner gitleaks
orgscan scan path ./path/to/scan --scanner detect-secrets
orgscan scan path ./path/to/scan --scanner semgrep
orgscan scan path ./path/to/scan --scanner trufflehog
orgscan scan path ./path/to/scan --scanner yara
orgscan scan path ./path/to/scan --scanner ripgrep-heuristics
orgscan scan path ./path/to/repository --scanner git-history-patterns
```

The built-in `repo-governance` scanner checks for missing `CODEOWNERS`, missing `SECURITY.md`, missing Dependabot coverage, missing contributor/issue/PR workflow templates, unpinned GitHub Actions references, `pull_request_target` workflow triggers, self-hosted runner usage, missing explicit workflow permissions, and broad workflow write permissions.

The built-in `yara` scanner uses bundled default rules for GitHub tokens, AWS access keys, and private key material unless `ORGSCAN_YARA_RULES_PATH` points at a custom ruleset. The built-in `ripgrep-heuristics` scanner uses ripgrep to look for internal hostnames, internal URLs, and configured `ORGSCAN_HEURISTIC_TERMS` strings. The built-in `git-history-patterns` scanner scans repository history with the core secret regex patterns, can target individual refs during mirror scans, and persists commit-linked evidence.

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
orgscan discover domain example.com --provider securitytxt
orgscan discover domain example.com --provider github-search
orgscan discover domain example.com --provider hibp
orgscan discover domain example.com --provider dehashed
orgscan discover domain example.com --provider intelligencex
orgscan discover domain example.com --provider all-enriched
```

The `all` domain provider aggregates local metadata, crt.sh, ProjectDiscovery, WHOIS, and DNS enrichment in one pass and returns warnings for providers that are unavailable. The `all-enriched` provider extends that flow with `securitytxt`, `github-search`, and configured paid providers. The `crtsh` domain provider uses the public crt.sh certificate-transparency feed to discover additional domain-linked hosts. The `projectdiscovery` domain provider uses `subfinder` and `httpx` when installed to enrich domain exposure data with discovered subdomains and reachable HTTP services. The `whois` domain provider extracts registrar and nameserver context from WHOIS output. The `dns` provider uses `dnspython` to collect NS, MX, TXT, A, AAAA, and CNAME records for the tracked domain and discovered hosts. The `securitytxt` provider reads published `security.txt` contacts and policy metadata, while `github-search` uses the public GitHub search APIs to correlate repositories, code hits, and issue discussions that mention tracked domains. Paid integrations for **Have I Been Pwned**, **DeHashed**, and **Intelligence X** can add breach and exposure records when their credentials are configured.

Expand related repositories and contributors:

```bash
orgscan expand repository psf/requests
orgscan expand organization psf
```

Print a stored summary report:

```bash
orgscan report
```

Schedule recurring reports and optional webhook alerts:

```bash
orgscan schedule-report --format json --cadence daily
orgscan schedule-report --format pdf --tenant-key tenant-a --webhook-url https://alerts.example.test/orgscan
orgscan run-scheduled-reports --limit 5
```

Export findings and generate a static HTML dashboard:

```bash
orgscan export ./data/findings.json --format json
orgscan export ./data/findings.pdf --format pdf
orgscan dashboard ./data/dashboard.html
```

Schedule recurring scans and inspect execution history:

```bash
orgscan schedule-scan ./path/to/scan --repository example-org/app --cadence daily
orgscan schedule-mirror-scan example-org/app --scanner git-history-patterns --ref main --ref release/2026 --cadence daily
orgscan run-scheduled --limit 5
orgscan enqueue-scheduled --limit 5
orgscan queue-status
orgscan rate-limit-status --json
orgscan run-worker --burst --max-jobs 5
orgscan jobs --json
```

Use `run-scheduled` for local in-process execution, or `enqueue-scheduled` plus `run-worker` to process scheduled scans through either Redis/RQ (`ORGSCAN_SCAN_QUEUE_BACKEND=rq`) or the built-in database-backed queue backend (`ORGSCAN_SCAN_QUEUE_BACKEND=db`). Queue retries and backoff are controlled with `ORGSCAN_SCAN_QUEUE_RETRY_MAX` and `ORGSCAN_SCAN_QUEUE_RETRY_INTERVALS`; DB workers also use `ORGSCAN_SCAN_QUEUE_LEASE_SECONDS`, `ORGSCAN_SCAN_QUEUE_POLL_INTERVAL_SECONDS`, and optional `ORGSCAN_SCAN_QUEUE_WORKER_ID` for distributed worker coordination. Outbound provider/GitHub requests can be coordinated across workers with `ORGSCAN_RATE_LIMIT_BACKEND=db`, global defaults via `ORGSCAN_OUTBOUND_REQUESTS_PER_MINUTE` / `ORGSCAN_OUTBOUND_MIN_INTERVAL_SECONDS`, and per-scope overrides in `ORGSCAN_RATE_LIMIT_SCOPE_OVERRIDES_JSON`.

Mirror repositories for larger-history or repeat scanning workflows:

```bash
orgscan sync-mirror example-org/app --ref main --ref release/2026
orgscan sync-mirrors --organization example-org --ref main
orgscan scan-mirror example-org/app --ref main --ref release/2026 --scanner git-history-patterns
```

Create DB-backed users, tenant roles, and session tokens for API access:

```bash
orgscan create-user alice --email alice@example.com
orgscan grant-tenant-role alice tenant-a --role analyst
orgscan create-session alice --tenant tenant-a --json
orgscan revoke-session 1
```

Serve the live dashboard and API:

```bash
orgscan serve-api --host 127.0.0.1 --port 8000
```

When `ORGSCAN_API_TOKENS_JSON` is configured, API requests must include `X-Orgscan-Token`. Tokens map to `reader`, `analyst`, or `admin` roles and can be restricted to specific `tenant_key` values. API consumers can also pass `tenant_key` as a query parameter to further narrow results within their allowed scope. If environment tokens are not configured, the API can also authenticate DB-backed session tokens created with `create-user`, `grant-tenant-role`, and `create-session`.

Key routes:

- `/dashboard` live HTML dashboard with filter controls
- `/auth/context` resolved API auth and tenant scope JSON
- `/summary` summary JSON
- `/findings` filtered findings JSON
- `/scheduled-scans` list/create scheduled scans
- `/scheduled-scans/run` trigger due scheduled scans (admin)
- `/scheduled-reports` list/create scheduled reports
- `/scheduled-reports/run` trigger due scheduled reports (admin)
- `/queue-status` queue backend status JSON (admin)
- `/rate-limits` distributed rate-limit state JSON (admin)
- `/domain-exposures` filtered domain exposure JSON
- `/relationships/graph` relationship graph JSON
- `/trends/findings` findings trend JSON
- `/comparisons/organizations` multi-org comparison JSON
- `/remediation/suggestions` remediation suggestion JSON

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
- Storage code uses SQLAlchemy abstractions and Alembic-backed schema migrations so PostgreSQL support can be added in later phases with minimal API churn.
- Canonical scanner output should be normalized through `orgscan.schemas.CanonicalFinding` before persistence.
- Database initialization and upgrades run through formal Alembic migrations instead of ad hoc SQLite-only column evolution.
- The bootstrap helper recommends package-manager installation only for base OS dependencies; use official upstream install methods for tools such as Gitleaks and TruffleHog.
- The optional ProjectDiscovery integration uses `subfinder` for passive subdomain discovery and `httpx` for HTTP service enrichment.
- The optional crt.sh integration adds certificate-transparency-based host discovery for tracked domains.
- The optional WHOIS integration adds registrar and nameserver enrichment for tracked domains.
- The optional DNS integration adds record-level enrichment for tracked domains and previously discovered subdomains.
- Optional paid domain intelligence integrations are available for Have I Been Pwned, DeHashed, and Intelligence X.
- The built-in repo-governance scanner checks for missing ownership/security policy files, contributor and review templates, risky workflow triggers, self-hosted runners, broad or implicit workflow permissions, and unpinned GitHub Actions references.
- The initial `scan` command uses the built-in `custom-patterns` scanner and stores scan jobs, findings, and evidence in SQLite for later reporting.
- Additional built-in scanners cover YARA rule matching, ripgrep-based heuristics, and git history scanning for regex-based secret exposures.
- The `discover` command uses the public GitHub REST API and can use `ORGSCAN_GITHUB_TOKEN` when configured for higher rate limits.
- External scanner output from `gitleaks`, `detect-secrets`, `semgrep`, and `trufflehog` can be normalized through `orgscan ingest-results` without rerunning the original tool.
- The local web surface now runs on FastAPI and serves both live HTML dashboard views and JSON endpoints from the same application, including token-based tenant scoping, multi-org comparison, remediation, and filtered domain exposure views.
- Reporting exports now include PDF alongside JSON, CSV, and HTML outputs.
- Scheduled scans can also be enqueued onto either Redis/RQ or the built-in database-backed worker backend for queue-based execution, with configurable retry/backoff and worker lease metadata.
- Scheduled reports can generate JSON/CSV/HTML/PDF artifacts on a cadence and optionally POST summary payloads to webhook-based alert integrations.
- Repository mirrors can be synchronized into the local data directory and re-scanned for repeatable branch/history analysis workflows.
- The current roadmap status and remaining gaps relative to the full project spec are documented in `docs/roadmap.md`.
- Additional open-source tools that can close current capability gaps are documented in `docs/open-source-tooling-gaps.md`; Semgrep is now available as an optional external scanner integration.
