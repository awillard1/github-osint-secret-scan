# orgscan phased roadmap

This roadmap maps the current repository implementation to the phased goals from `projectspec.md`.

## Completed

### Phase 0 — Foundation
- Python package scaffold under `src/orgscan`
- `pyproject.toml` packaging and CLI entrypoint
- environment and `.env`-based configuration
- structured logging setup
- pytest-based test suite
- bootstrap script for local development
- README installation and usage guidance

### Phase 1 — Core data model and storage
- normalized SQLAlchemy models for Organization, Domain, Repository, Account, ScanJob, Finding, Evidence, Relationship, and RiskScore
- canonical finding normalization via `orgscan.schemas.CanonicalFinding`
- SQLite-first persistence and repository helpers designed around SQLAlchemy abstractions for future PostgreSQL support
- CLI database initialization and status commands

### Phase 2 — Operator workflows
- target intake via `orgscan add-target`
- stored finding inspection via `orgscan findings`
- dependency verification via `orgscan verify-deps`
- finding triage updates via `orgscan triage`

### Phase 3 — Initial scanning pipeline
- built-in custom pattern scanner
- persisted scan jobs, findings, and evidence
- redacted evidence handling for scanner output
- external scanner wrappers for `gitleaks` and `trufflehog` with graceful failure when binaries are unavailable

### Phase 4 — Discovery and reporting
- public GitHub repository and organization discovery using the GitHub REST API
- optional `ORGSCAN_GITHUB_TOKEN` support for authenticated discovery
- summary reporting, JSON/CSV/HTML export, and static dashboard generation

## Not yet implemented
- FastAPI web API
- live dashboard application
- queued/background worker system
- continuous scheduling and re-scan orchestration
- domain intelligence provider plugins beyond GitHub metadata discovery
- richer suppression workflows, asset inventory, tool runs, and historical trend analysis
- HTML/PDF report styling beyond the current static export view

## Current implementation stance
The repository now satisfies the requested foundation and core storage phases and includes a thin but working slice of the later roadmap so contributors can add discovery, scanners, scoring, and presentation layers incrementally.
