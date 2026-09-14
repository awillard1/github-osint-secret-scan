# orgscan Architecture

## Goals

The architecture should make it inexpensive to add scanners, discovery providers, workflows, and UI features without duplicating orchestration across CLI/API/jobs.

The most important design objective is not maximum abstraction. It is stable boundaries that reduce change amplification.

This document describes the target architecture. See [Current architecture/capability baseline](roadmap.md#current-architecturecapability-baseline) for implemented scope and evidence. API/CLI are now packages with extracted finding adapters; their roots retain the remaining code and compatibility exports. The scanner registry, mirror/ref scanning, AuthContext helpers, both RQ and DB queues, and PDF export already exist in partial form. The types and flows below are migration targets, not declarations that those foundations are missing.

## Current-state principle

The repository already implements substantial functionality: FastAPI, CLI commands, SQLAlchemy persistence, Alembic migrations, scanner integrations, mirroring, reporting, scheduling/RQ, discovery, enrichment, and tests.

Refactor incrementally. Preserve behavior while moving responsibilities to clearer boundaries.

The initial Phase 1 slice routes finding reads and decisions through `services/finding_service.py`, using `Storage` and the existing session factory. HTTP serialization/request models and browser form mapping remain presentation concerns; CLI formatting and argument parsing remain in `cli/commands/findings.py`. `api/routes/findings.py` registers the JSON finding routes and dashboard workflow action. The service has no FastAPI/Typer imports and owns decision transactions. `api/__init__.py` and `cli/__init__.py` retain compatibility imports and unmigrated adapters; splitting these roots into the full target structure below is incremental follow-up work. See the [remaining Phase 1 items](roadmap.md#phase-1--initial-finding-management-decomposition).

## Layers

### 1. Presentation/adapters

Examples:

- Typer CLI
- FastAPI JSON routes
- HTML dashboard routes
- scheduler entry points
- RQ workers

Responsibilities:

- input parsing;
- auth/authorization adapter;
- output formatting;
- HTTP/CLI status mapping.

Not responsible for core workflow decisions.

The live [operator dashboard](operator-dashboard.md) consumes `DashboardService` queues over authorized storage; templates do not classify risk or lifecycle states.

### 2. Application services

Services model use cases.

Target services:

```text
services/
    auth_service.py
    discovery_service.py
    finding_service.py
    report_service.py
    repository_service.py
    scan_service.py
    target_service.py
```

Services may coordinate:

- repositories/storage;
- scanner registry;
- repository mirrors;
- providers;
- queues;
- scoring;
- reporting.

Services should be usable from CLI, API, scheduler, and tests.

### 3. Domain/contracts

Stable data types:

- ScanPlan
- ScanProfile
- ScanTarget
- ScanContext
- ScanResult
- ScannerMetadata
- ScannerReadiness
- CanonicalFinding
- Evidence
- AuthContext
- RepositoryCheckpoint

Use Pydantic/dataclass types where appropriate. Do not pass large transport-specific dictionaries through the entire application.

### 4. Infrastructure

Includes:

- SQLAlchemy/Alembic;
- Git repository mirrors/worktrees;
- subprocess execution;
- HTTP clients;
- Redis/RQ;
- filesystem artifact storage.

Infrastructure should implement interfaces consumed by services.

## API target structure

```text
src/orgscan/api/
    __init__.py
    app.py
    dependencies.py
    routes/
        accounts.py
        auth.py
        domains.py
        findings.py
        graph.py
        organizations.py
        repositories.py
        reports.py
        scans.py
        settings.py
```

`app.py` builds the FastAPI app and registers routers.

Do not place scan execution logic in route functions.

## CLI target structure

```text
src/orgscan/cli/
    __init__.py
    app.py
    commands/
        config.py
        discovery.py
        findings.py
        reports.py
        scans.py
        targets.py
        users.py
        workers.py
```

Commands call services.

Preserve the `orgscan` console entry point.

## Scanner architecture

See [scanner-contract.md](scanner-contract.md). Phase 2 implements the common metadata/readiness/context/result types and a registry adapter for native and legacy scanners. The shared runner uses this contract; scanner inventory and artifact choices are registry-driven. Phase 3 adds shared [ScanPlan/profile resolution](scan-plans.md), execution and serialized job intent.

High-level flow:

```text
ScanPlan
   |
   v
ScanService
   |
   +--> repository/artifact preparation
   |
   +--> ScannerRegistry
           |
           +--> scanner readiness
           +--> scanner execution
           +--> normalization
   |
   +--> correlation/deduplication
   |
   +--> persistence/evidence/risk
```

## Repository acquisition architecture

Phase 4 implements [RepositoryMirrorManager](repository-cache.md), using the existing checkout cache with isolated detached scan worktrees, POSIX locking, remote HEAD discovery and persisted sync/checkpoint state. No SQL schema change is needed because Storage extends existing JSON metadata.

Target abstraction:

```text
RepositoryService
   |
   +--> RepositoryMirrorManager
           |
           +--> ensure_mirror()
           +--> fetch()
           +--> remote_head/ref inventory
           +--> worktree/materialization
           +--> checkpoint comparison
           +--> cleanup()
```

Phase 5 uses that state for [incremental decisions](incremental-scans.md), pinned history ranges, and explicit skip/deletion records. Content scanners without incremental semantics conservatively scan the full changed tree.

Persist enough state to distinguish:

- never scanned;
- remote unchanged;
- changed default branch;
- changed selected branches;
- full history scan required;
- incremental scan possible.

Do not assume the default branch is named `main`.

## ScanPlan

`ScanPlan` is the single description of what a scan should do.

It should encode:

- target;
- profile;
- selected scanners;
- branch policy;
- history policy;
- incremental/full mode;
- discovery/enrichment switches;
- execution limits;
- optional tenant/organization context.

The CLI, API, scheduler, and UI should all construct or reference a ScanPlan.

## Profiles

Initial profiles:

- `quick`
- `standard`
- `comprehensive`
- `history`
- `secrets-only`
- `osint-only`
- `domain-only`
- `governance-only`

Profiles are configuration, not duplicated code paths.

## Finding correlation

Multiple scanners may report the same underlying issue. Phase 8 implements conservative [finding correlation](finding-correlation.md) in the shared runner, with storage-owned evidence upserts and scanner provenance.

Target model:

```text
Canonical Finding
    |
    +-- Evidence: Gitleaks
    +-- Evidence: TruffleHog
    +-- Evidence: custom-patterns
```

Do not merge unrelated issues merely because their titles match.

Fingerprinting should use stable attributes such as repository identity, path, location, category, normalized detector identity, and a non-secret indicator fingerprint.

## Finding lifecycle

Target lifecycle:

```text
NEW
 -> REVIEWING
 -> CONFIRMED
 -> REMEDIATED
 -> REGRESSED

Alternative terminal/managed states:
FALSE_POSITIVE
ACCEPTED_RISK
SUPPRESSED
```

Phase 12 implements [lifecycle policy and retained history](finding-lifecycle.md) through shared storage/service operations; only later scan-job observations trigger regression. Legacy statuses remain compatible.

## OSINT relationship graph

Relationships should carry provenance and confidence. Phase 9 shares GitHub ingestion/expansion in `services/relationship_service.py`, retaining the old expansion imports and exposing stored provenance through existing graph/reporting adapters. See [GitHub relationships](github-relationships.md).

Examples:

- organization OWNS repository;
- account CONTRIBUTED_TO repository;
- account USED_EMAIL_DOMAIN domain;
- repository FORK_OF repository;
- domain RESOLVES_TO service;
- repository MENTIONS domain.

A relationship is more valuable when orgscan can explain why it exists.

## Authentication

Use a common `AuthContext` for authorization decisions. Phase 11 implements [token-backed browser authentication](browser-auth.md), shared auth services and request-owned storage authorization for all HTTP adapters. Local CLI/worker storage remains trusted.

Browser authentication and API token authentication should both produce the same authorization context.

Target browser flow:

```text
/login -> secure session cookie -> AuthContext -> services/routes
```

API:

```text
Bearer/API token -> AuthContext -> services/routes
```

Do not put authorization solely in templates/UI.

## Queue model

Retain the existing RQ and database queue backends; do not replace them solely for architectural preference.

Classify jobs by logical type:

- DISCOVERY
- REPO_SYNC
- SCAN
- NORMALIZE/CORRELATE
- DOMAIN_ENRICH
- REPORT

Phase 14 applies the shared [job reliability policy](job-reliability.md), preserving both backends. Retry only transient failures.

Rate-limit responses should defer rather than hammer an upstream service.

## Reporting

Reporting adapters consume canonical stored data through the shared [report query service](reporting.md); CLI, HTTP and scheduled exports use the same query and redaction boundary.

Outputs:

- JSON
- CSV
- HTML
- PDF
- SARIF

Do not implement a separate finding model per report format.

## Dependency direction

Preferred:

```text
presentation -> services -> domain/contracts
                         -> repositories/interfaces
                         -> scanner/provider interfaces

infrastructure -> implements interfaces
```

Avoid services importing FastAPI or Typer.

Release diagnostics and installed migration resources are documented in [release readiness](release-readiness.md). Doctor performs reads; initialization/upgrades remain explicit operations.

## Migration strategy

1. Add service abstraction around existing behavior.
2. Move one route/command family at a time.
3. Keep compatibility imports where needed.
4. Run full tests.
5. Remove old code only after callers migrate.

No flag-day rewrite.

## Phase 18 boundary refinement

Phase 1 remains **partial**. `services/target_service.py` owns shared asset ownership
resolution and domain context; `services/scan_service.py` owns durable domain
execution for CLI and jobs. API/CLI retain thin compatibility entry points.
Report detail queries and aggregation live behind `Storage` in
`storage/report_queries.py`; services map records into portable report DTOs.
API upload orchestration, organization expansion and other command families still
need incremental extraction. No wholesale API/CLI rewrite or public command removal
was performed. Unused private runner/auth helpers and scheduler imports were removed;
public scanner factories, parsers, auth helpers and documented exports remain.

## Controlled secret evidence (Phase 23)

Raw credentials may be retained solely in dedicated encrypted secret evidence and
exposed only through an explicit authorized reveal operation. Ordinary canonical
findings, evidence, summaries, diagnostics, browser HTML and reports remain redacted.
The shared bounded redaction parser supplies short-lived opaque ingestion candidates
before sanitization, including copied JSON and complete quoted assignments. Candidates
are not JSON serializable and conceal their value in repr; they are consumed after
persistence. Scanner adapters establish the preservation context; scan services carry
settings into storage, and providers create a canonical finding for protected evidence.

`services/secret_evidence.py` owns AES-256-GCM encryption, tenant-bound HMAC-SHA256
fingerprints (a separate HKDF-derived key), metadata authorization and audited reveal.
Fresh 96-bit nonces accompany each ciphertext. Authenticated associated data binds the
ciphertext to its finding, tenant, type, fingerprint, source and key ID. The new
`secret_evidence` table contains only ciphertext, nonce, masked display and provenance;
`secret_reveal_audit` records actor, tenant, finding/evidence IDs, source and timestamp.
The audit transaction must commit before plaintext can leave the service. No model
property, generic serializer or report invokes decryption.

Reveal requires authentication even in local mode. Readers cannot reveal. Analysts
need `secrets:reveal`; administrators can reveal within their authorized tenants.
Database session capabilities are derived from current memberships across all active
session scopes; use a single-tenant session for a grant limited to one tenant.
Browser sessions inherit current parent permissions and existing CSRF protection.
The dedicated API router and small browser adapter call this service. This does not
claim completion of the remaining Phase 1 presentation decomposition.

## Candidate-aware ingestion (Phase 24)

`SecretCandidateContext` is a bounded, non-serializable ingestion scope. It retains
exact candidate knowledge while ordinary fields are sanitized, including copied
values in titles, descriptions, nested metadata, paths and encoded JSON strings.
Batch normalization shares redaction knowledge across matches without assigning
one match's protected candidates to another. Candidate objects remain private and
available for subsequent encryption; generic presentation never decrypts them.

Storage creation/update boundaries activate the same context for findings, evidence
and domain exposures. The ORM safety guard also consumes its knowledge while those
operations flush. Encryption may consume individual candidates, but the enclosing
scope retains its private redaction knowledge until all ordinary writes are safe;
exit discards that knowledge on success or failure. Source extraction precedes
redaction, and encrypted evidence retains the exact original value. The dedicated
reveal service, authorization checks, audit commit and response headers are unchanged.

## Report projection context (Phase 25)

Report DTO construction now ends at `reports/projection.py::safe_report_projection`.
The complete projection is sanitized against combined ordinary finding/evidence,
job and ancillary summary source context before any source knowledge is discarded.
Summary clipping follows sanitization. Storage owns the bounded joined context query;
there are no per-finding evidence reads or protected-evidence/decryption dependencies.
All format adapters and manual/API/scheduled delivery consume that logical model.
See the field inventory and resource bounds in [reporting](reporting.md).
