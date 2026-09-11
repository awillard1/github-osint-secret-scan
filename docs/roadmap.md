# orgscan phased roadmap

This roadmap maps the current repository implementation to the phased goals from `projectspec.md`.

## Completed or partially completed phases

### Phase 0 — Foundation
- Python package scaffold under `src/orgscan`
- `pyproject.toml` packaging and CLI entrypoint
- environment and `.env`-based configuration
- structured logging setup
- pytest-based test suite
- bootstrap script for local development
- README installation and usage guidance

### Phase 1 — Core data model and storage
- normalized SQLAlchemy models for Organization, Domain, Repository, Account, ScanJob, Finding, Evidence, Relationship, RiskScore, DomainExposure, IdentityCorrelation, Suppression, ToolRun, and ScheduledScan
- canonical finding normalization via `orgscan.schemas.CanonicalFinding`
- SQLite-first persistence and repository helpers designed around SQLAlchemy abstractions for future PostgreSQL support
- lightweight schema evolution for new finding columns on existing SQLite databases
- CLI database initialization and status commands

### Phase 2 — Operator workflows
- target intake via `orgscan add-target`
- stored finding inspection via `orgscan findings`
- dependency verification via `orgscan verify-deps`
- generated configuration template via `orgscan init-config`
- optional tool readiness reporting with configured binary paths and install guidance in CLI/API/dashboard
- finding triage, suppress, accept-risk, and unsuppress workflows

### Phase 3 — Initial scanning pipeline
- built-in custom pattern scanner
- built-in repository governance scanner for CODEOWNERS, SECURITY.md, and unpinned workflow checks
- persisted scan jobs, tool runs, findings, risk scores, and evidence
- redacted evidence handling for scanner output
- external scanner wrappers for `gitleaks`, `detect-secrets`, `semgrep`, and `trufflehog` with graceful failure when binaries are unavailable

### Phase 4 — Discovery and reporting
- public GitHub repository and organization discovery using the GitHub REST API
- optional `ORGSCAN_GITHUB_TOKEN` support for authenticated discovery
- ProjectDiscovery-backed domain enrichment through `subfinder` and `httpx`
- summary reporting, JSON/CSV/HTML export, and richer static dashboard generation

### Phase 5 — Domain intelligence providers
- provider abstraction for domain intelligence
- local metadata provider for repository-domain and account-email correlation
- crt.sh certificate transparency provider for public host discovery
- WHOIS provider for registrar and nameserver enrichment
- DNS provider for NS, MX, TXT, A, AAAA, and CNAME enrichment across domains and discovered hosts
- aggregate domain discovery mode that combines installed providers and surfaces provider warnings
- persisted DomainExposure and IdentityCorrelation records

### Phase 6 — Expansion and relationship mapping
- GitHub expansion engine for repository forks and contributors
- relationship persistence for contributor and fork edges
- `orgscan expand` CLI for repository and organization expansion

### Phase 7 — Scheduling and re-scan workflow
- scheduled scan model and CLI commands for scheduling and running due scans
- queue-like scan job execution using persisted scheduled scans and tool runs
- optional Redis/RQ queue backend with worker and enqueue commands for scheduled scans
- manual cadence disables itself after execution to avoid runaway reprocessing

### Phase 8 — API surface
- FastAPI service with health, summary, filtered findings, scheduled-scan, relationship graph, and trend endpoints
- live HTML dashboard served from the same app with interactive filter controls
- finding and scan-job drill-down HTML pages plus a graph-focused HTML view
- artifact upload and analysis via API and dashboard, including optional installed external scanners
- scanner/tooling readiness JSON for easier OSS integration setup
- `orgscan serve-api` for local web/API serving

### Phase 9 — Execution telemetry
- ToolRun persistence for auditability of scanner invocations
- `orgscan jobs` for scan job, tool run, and scheduled scan inspection
- execution state is visible in reports and API summary output

### Phase 10 — Open-source tooling gap analysis
- documented OSS capability matrix and remaining gaps in `docs/open-source-tooling-gaps.md`
- current implementation keeps a free-first approach while identifying where additional OSS systems are needed
- saved output from supported external scanners can be ingested and normalized through the common finding model

## Remaining gaps versus the full project spec
- no YARA or ripgrep-heuristic coverage yet; repo history coverage now includes built-in git-history pattern scanning alongside current detect-secrets, repo-governance, DNS, WHOIS, crt.sh, ProjectDiscovery, and local metadata support
- no advanced distributed orchestration beyond the initial Redis/RQ worker backend, and no tenant-aware HTML auth/session layer or PDF reporting
- no paid provider implementations; only the abstraction and free/local correlation path exist
- no large-scale branch/history orchestration or incremental repo mirror management

## Beta-readiness priorities
- add YARA and ripgrep-style heuristics to close the most obvious OSS integration gaps
- harden dashboard auth and tenant-aware filtering before any shared deployment
- add richer interactive graph exploration and scan-log navigation polish on top of the current HTML views
- package repeatable local/container setup so external scanners are easier to enable in beta environments

## Current implementation stance
The repository now covers the requested Phase 0/1 foundation and extends into practical slices for phases 2-10. The remaining gaps are primarily integrations, web UX, distributed execution, and enrichment breadth rather than missing core application structure.
