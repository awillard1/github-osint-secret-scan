# orgscan

`orgscan` is the Phase 0/1 foundation for the OSINT Security Platform described in [`projectspec.md`](./projectspec.md). It currently provides:

- a Python package and CLI
- environment-based configuration loading with `.env` support
- structured logging
- normalized core storage models for organizations, domains, repositories, accounts, scan jobs, findings, evidence, relationships, and risk scores
- a SQLite-first persistence layer built on SQLAlchemy for future PostgreSQL support
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
```

The bootstrap helper creates `.venv`, installs the editable package with development dependencies, initializes the default SQLite database, and reports dependency status.

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
orgscan setup --init-db
```

Initialize the database explicitly:

```bash
orgscan init-db
```

Print application status and entity counts:

```bash
orgscan status
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
