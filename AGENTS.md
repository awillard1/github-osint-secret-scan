# AGENTS.md — orgscan engineering contract

This file is the primary instruction set for AI coding agents and human contributors.

Read it fully before changing code.

## Product

`orgscan` is an OSINT/security exposure platform that discovers public assets and relationships, scans repositories/artifacts for security findings, normalizes evidence, tracks finding lifecycle/risk, and exposes the same capabilities through CLI, API, jobs, and an operator UI.

The repository already contains working functionality. Prefer migration and decomposition over rewrites.

## Mandatory workflow

Before editing:

1. Read this file.
2. Read `docs/architecture.md`.
3. Read the relevant section of `docs/development-plan.md`.
4. Inspect analogous existing code and tests.
5. Run the most relevant existing tests before modification.
6. Check `git status` and do not overwrite unrelated user changes.

After editing:

1. Run focused tests for changed behavior.
2. Run the complete test suite.
3. Run any configured static checks.
4. Inspect the diff for accidental unrelated changes.
5. Update documentation when behavior or architecture changed.
6. State any remaining limitation explicitly.

Never declare a task complete while required tests are failing unless the failure demonstrably predates the task and is documented.

## Architectural rules

### Presentation layers are thin

CLI, FastAPI routes, HTML handlers, scheduler entry points, and workers are adapters.

They may:

- parse input;
- perform transport-specific validation;
- construct service requests;
- map service results to output;
- enforce transport-specific authentication/authorization.

They must not become the primary home of business logic.

### Services own use cases

Cross-cutting application behavior belongs in service modules.

Examples:

- starting a scan;
- creating a scan plan;
- synchronizing a repository;
- discovering an organization;
- triaging a finding;
- generating a report;
- authenticating a user.

CLI and API implementations should call the same service for the same operation.

### Scanner contract is uniform

All scanners must use the contract documented in `docs/scanner-contract.md`.

A scanner must expose:

- stable scanner ID;
- display name/version when available;
- target capabilities;
- readiness;
- configuration requirements;
- execution behavior;
- normalization to canonical findings.

Do not add tool-name `if/elif` dispatch in API/CLI code when registry dispatch can be used.

### Canonical findings

Scanner output must normalize through the canonical schema before persistence.

Raw secret material must not be emitted in logs or user-facing diagnostics.

Prefer fingerprints, redacted indicators, metadata, and evidence references.

### Persistence

Use repository/storage abstractions for persistence.

Do not spread SQLAlchemy queries through CLI/API/web code.

Any schema change requires an Alembic migration and migration tests or upgrade validation.

SQLite remains a supported local backend. Do not introduce PostgreSQL-only behavior without an abstraction or compatibility path.

### Git repository handling

Treat scanned repositories as untrusted data.

Do not:

- run repo-provided scripts;
- source repo-provided shell files;
- install dependencies from a scanned repository merely to scan it;
- execute build hooks;
- follow unsafe symlinks outside scan roots.

Use explicit subprocess argument arrays, never shell-concatenated commands for untrusted input.

All external processes require timeouts and captured exit status.

### Archives/uploads

Prevent path traversal and unsafe symlink extraction.

Temporary artifacts must have explicit cleanup behavior.

### Authentication/tenancy

Never weaken an existing authorization boundary to simplify a feature.

Service methods that operate on tenant-scoped data must receive or derive an authorization context where appropriate.

### Jobs

Queued and scheduled execution should call the same application services used by synchronous execution.

Jobs must be idempotent where practical and classify transient versus permanent failure.

## Code organization target

The target architecture is:

```text
src/orgscan/
    api/
        app.py
        dependencies.py
        routes/
    cli/
        app.py
        commands/
    services/
    scanners/
    providers/
    storage/
    web/
```

Do not perform a flag-day rewrite. Migrate modules incrementally with compatibility imports when necessary.

## Compatibility

Preserve documented CLI commands and API behavior during structural phases unless the phase explicitly changes a contract.

When moving functions/classes, prefer compatibility wrappers or re-exports until callers and tests have migrated.

## Testing

Follow `docs/testing.md`.

Every new feature must include tests.

External scanner tests must not require the real external binary in the normal unit test suite.

Use fakes/mocks/fixtures for network services and subprocess execution.

## Definition of done

A feature is done only when applicable portions are complete:

- domain/service implementation;
- persistence and migration;
- API adapter;
- CLI adapter;
- web adapter;
- job/scheduler integration;
- tests;
- readiness/configuration;
- documentation;
- no raw-secret logging;
- backward compatibility evaluated.

Not every feature needs every adapter. If one is not applicable, say why.

## Change discipline

Prefer a focused vertical slice over broad unrelated cleanup.

Do not opportunistically rewrite unrelated modules.

If architectural debt blocks a feature, perform the smallest enabling refactor and test it separately.

## Documentation discipline

`projectspec.md` describes long-term product intent.

`docs/architecture.md` describes intended engineering architecture.

`docs/development-plan.md` describes implementation order.

`docs/roadmap.md` should describe actual current status.

Update `docs/roadmap.md` when functionality materially changes.

## Commit-sized work

A normal agent task should be mergeable as one commit or one small PR.

If the requested task expands unexpectedly, stop at a coherent boundary, describe the newly discovered work, and avoid silently broadening scope.
