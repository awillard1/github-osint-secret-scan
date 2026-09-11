# Cohesive Development Plan

These phases define implementation order, not a list of absent features. Consult the [current baseline](roadmap.md#current-architecturecapability-baseline) before each phase. Registry/plugins, mirror/ref/history scanning, YARA, ripgrep heuristics, GitHub search, auth helpers, queue retries/rate limiting, and PDF/scheduled reports already exist; their phases should extend and integrate that code, not replace it.

## Guiding principles

1. Stabilize architecture before adding many features.
2. One use case should have one service implementation.
3. One scan description should drive CLI/API/UI/jobs.
4. Scanners should plug into a registry, not force edits everywhere.
5. Repository acquisition and incremental state are core platform infrastructure.
6. Findings should correlate evidence rather than multiply duplicates.
7. OSINT relationships require provenance and confidence.
8. Existing behavior remains available during refactors.

## Phase 0 — Baseline and truth reconciliation

Goal: make documentation match the actual implementation and establish architectural guardrails.

Deliverables:

- repository capability inventory;
- reconcile `docs/roadmap.md` with current code;
- fix trivial project metadata/dependency duplication if safe;
- adopt `AGENTS.md` and architecture docs;
- document current baseline tests;
- no new OSINT feature work.

Exit:

- tests pass or pre-existing failures documented;
- roadmap distinguishes implemented/partial/not implemented.

## Phase 1 — API/CLI/service decomposition

Goal: reduce change amplification in large presentation modules.

Status: the initial finding-management service/router/command slice is implemented. The [roadmap](roadmap.md#phase-1--initial-finding-management-decomposition) records compatibility, validation and the exact remaining decomposition items; this does not mark the entire phase complete.

Deliverables:

- introduce service modules around existing use cases;
- split FastAPI routes incrementally;
- split CLI command groups incrementally;
- preserve public commands/endpoints;
- compatibility exports where necessary.

Exit:

- business behavior for migrated workflows is tested at service layer;
- presentation functions are primarily adapters.

## Phase 2 — Scanner contract and registry

Status: implemented; see [roadmap](roadmap.md#phase-2--scanner-contract-and-registry) for compatibility, validation and remaining execution limits.

Goal: make scanner integrations uniform.

Deliverables:

- formal metadata/readiness/context/result contract;
- registry handles built-ins + existing entry-point plugins;
- migrate existing scanner dispatch;
- scanner listing/readiness consumes registry;
- no duplicated tool-specific routing in API/CLI.

Exit:

- adding a scanner does not require scanner-name branches in multiple presentation layers.

## Phase 3 — ScanPlan and profiles

Status: implemented; see [scan plans](scan-plans.md) for defaults, precedence and execution limits.

Goal: one representation of scan intent.

Deliverables:

- ScanPlan model;
- profiles: quick, standard, comprehensive, history, secrets-only, osint-only, domain-only, governance-only;
- CLI/API/scheduler accept plan/profile;
- explicit override behavior documented.

Exit:

- the same plan can be executed synchronously or queued.

## Phase 4 — Repository mirror/cache/checkpoint engine

Status: implemented; see [repository cache](repository-cache.md) for state, locking and compatibility limits.

Goal: stop treating every scan as a fresh repository operation.

Deliverables:

- ensure/fetch mirror;
- ref inventory;
- repository fingerprint/checkpoint;
- worktree/materialization lifecycle;
- persisted sync/scan state;
- cleanup and locking strategy.

Exit:

- unchanged repositories can be recognized without redoing expensive work.

## Phase 5 — Incremental branch/history orchestration

Goal: efficiently select what needs scanning.

Deliverables:

- branch policies;
- full/history/incremental decisions;
- commit/ref checkpoint comparison;
- recoverable state when scans fail;
- deterministic scan scope recorded on the scan job.

Exit:

- a scan can explain exactly what refs/range it covered.

## Phase 6 — YARA scanner

Goal: add signature-based content detection through the common scanner contract.

Deliverables:

- readiness/version detection;
- configured local rulesets;
- canonical normalization;
- timeout/error behavior;
- tests without requiring YARA installed;
- configuration and docs.

Exit:

- works through existing scan service/API/CLI without custom presentation dispatch.

## Phase 7 — Rule-driven heuristic scanner

Goal: move organization-specific detection logic into validated data-driven rules.

Deliverables:

- rule schema;
- rule loader/validator;
- regex/file inclusion/exclusion;
- redaction/fingerprinting;
- test fixtures;
- starter rules.

Exit:

- new heuristic rules generally require YAML/data changes, not Python.

## Phase 8 — Finding correlation and evidence deduplication

Goal: one issue with multiple evidence sources instead of duplicate issues.

Deliverables:

- stable non-secret fingerprints;
- correlation service;
- evidence attachment;
- scanner agreement metadata;
- safe treatment of path/line changes.

Exit:

- repeated scans and multiple tools do not inflate finding counts incorrectly.

## Phase 9 — GitHub relationship intelligence

Goal: make discovered users/repos/forks/commits explainable relationships.

Deliverables:

- relationship types;
- provenance;
- confidence scoring;
- organization/repository/account correlation;
- graph API/UI improvements.

Exit:

- an operator can see why an asset/account is associated with a target.

## Phase 10 — GitHub public search intelligence

Goal: discover organization-linked public exposure outside owned repositories.

Deliverables:

- query builder;
- domain/org/identifier search strategies;
- provenance stores exact query/source/time;
- rate-limit aware pagination;
- dedup into existing entities/findings.

Exit:

- search results feed the same graph/finding model, not a side database.

## Phase 11 — Interactive authentication and user administration

Goal: complete browser authentication using existing authorization concepts.

Deliverables:

- login/logout;
- secure session cookie;
- session expiry/revocation;
- user administration;
- role assignment;
- tenant scope;
- CSRF strategy for state-changing browser actions.

Exit:

- HTML dashboard routes enforce appropriate auth just like JSON operations.

## Phase 12 — Finding lifecycle and regression detection

Goal: preserve remediation history.

Deliverables:

- explicit transitions;
- transition audit trail;
- remediation timestamp;
- regression detection when a previously remediated fingerprint returns;
- filtering/reporting.

Exit:

- first seen / last seen / remediated / regressed are explainable.

## Phase 13 — Operator dashboard redesign

Goal: optimize for decisions, not database browsing.

Dashboard should answer:

- what is new;
- what is high risk;
- what regressed;
- what is scanning;
- what failed;
- what assets were newly discovered;
- what needs triage.

Avoid a frontend framework rewrite unless the server-rendered approach demonstrably blocks required UX.

## Phase 14 — Job reliability

Goal: reliable long-running scheduled/queued execution.

Deliverables:

- logical job types;
- transient/permanent failure classification;
- exponential backoff;
- GitHub/upstream rate-limit handling;
- idempotency where practical;
- stale-job recovery;
- job diagnostics.

Retain the existing RQ and database queue backends until requirements justify a change.

## Phase 15 — Reporting

Deliverables:

- SARIF;
- executive PDF;
- technical PDF;
- maintain JSON/CSV/HTML;
- report adapters consume canonical findings/evidence.

## Phase 16 — Doctor and release hardening

Add:

```bash
orgscan doctor
```

Check:

- Python/app version;
- DB connectivity/migration state;
- writable directories;
- Redis;
- GitHub token configuration;
- scanner readiness/version;
- provider readiness;
- API configuration;
- warnings.

Then:

- dependency cleanup;
- packaging;
- installation documentation;
- upgrade documentation;
- end-to-end smoke test;
- security review;
- 1.0 readiness checklist.

## Parallelization

Do not parallelize phases 0-5.

After phase 5, these can often proceed separately:

- YARA;
- heuristic rules;
- auth;
- report adapters.

Correlation should land before extensive detector expansion if duplicate volume is becoming problematic.

## Out of scope until justified

- replacing RQ solely for architectural preference;
- React/Vue rewrite solely for aesthetics;
- Kubernetes deployment;
- microservices;
- PostgreSQL-only features;
- AI classification of raw secrets;
- executing target repository code to improve analysis.
