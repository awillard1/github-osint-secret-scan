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
- finding triage, suppress, accept-risk, and unsuppress workflows

### Phase 3 — Initial scanning pipeline
- built-in custom pattern scanner
- persisted scan jobs, tool runs, findings, risk scores, and evidence
- redacted evidence handling for scanner output
- external scanner wrappers for `gitleaks`, `semgrep`, and `trufflehog` with graceful failure when binaries are unavailable

### Phase 4 — Discovery and reporting
- public GitHub repository and organization discovery using the GitHub REST API
- optional `ORGSCAN_GITHUB_TOKEN` support for authenticated discovery
- summary reporting, JSON/CSV/HTML export, and static dashboard generation

### Phase 5 — Domain intelligence providers
- provider abstraction for domain intelligence
- local metadata provider for repository-domain and account-email correlation
- persisted DomainExposure and IdentityCorrelation records

### Phase 6 — Expansion and relationship mapping
- GitHub expansion engine for repository forks and contributors
- relationship persistence for contributor and fork edges
- `orgscan expand` CLI for repository and organization expansion

### Phase 7 — Scheduling and re-scan workflow
- scheduled scan model and CLI commands for scheduling and running due scans
- queue-like scan job execution using persisted scheduled scans and tool runs
- manual cadence disables itself after execution to avoid runaway reprocessing

### Phase 8 — API surface
- lightweight JSON API service with health, summary, findings, and scheduled-scan endpoints
- `orgscan serve-api` for local API serving without introducing a full web stack yet

### Phase 9 — Execution telemetry
- ToolRun persistence for auditability of scanner invocations
- `orgscan jobs` for scan job, tool run, and scheduled scan inspection
- execution state is visible in reports and API summary output

### Phase 10 — Open-source tooling gap analysis
- documented OSS capability matrix and remaining gaps in `docs/open-source-tooling-gaps.md`
- current implementation keeps a free-first approach while identifying where additional OSS systems are needed

## Remaining gaps versus the full project spec
- no FastAPI/Jinja2 or React live dashboard yet; current API is lightweight stdlib HTTP and dashboard output is static HTML
- no distributed worker backend such as Celery/RQ/Dramatiq or Redis-backed queue
- no CT log, WHOIS, DNS, YARA, or broader enrichment integrations yet
- no graph visualization UI, multi-tenant auth, or PDF reporting
- no paid provider implementations; only the abstraction and free/local correlation path exist
- no large-scale branch/history orchestration or incremental repo mirror management

## Current implementation stance
The repository now covers the requested Phase 0/1 foundation and extends into practical slices for phases 2-10. The remaining gaps are primarily integrations, web UX, distributed execution, and enrichment breadth rather than missing core application structure.
