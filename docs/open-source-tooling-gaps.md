# Open-source tooling gaps and recommendations

For implementation status and test evidence, see the [current architecture/capability baseline](roadmap.md#current-architecturecapability-baseline). This document identifies integration limitations rather than assigning engineering phase order; use [development-plan.md](development-plan.md) for that order.

## Already integrated or supported

- Built-in custom patterns, Git history diff patterns, and repository governance checks.
- Optional Gitleaks, TruffleHog, Semgrep, detect-secrets, YARA and ripgrep heuristic adapters, plus entry-point scanner plugins and supported saved-report ingestion.
- YARA default token/private-key rules and a configurable rules path; ripgrep internal-hostname and organization-keyword heuristics.
- ProjectDiscovery subfinder/httpx, crt.sh, whois, dnspython DNS, security.txt, and local repository/account/domain correlation.
- GitHub REST discovery, contributor/fork/ownership relationships, and domain-based repository/code/issue search.
- Optional Have I Been Pwned, DeHashed and Intelligence X provider implementations and aggregate enrichment.
- Reusable repository checkouts, fetch/ref selection and scheduled mirror scans.
- SQLAlchemy/SQLite persistence with Alembic, JSON/CSV/HTML/basic PDF reports, scheduled reports and webhook delivery.
- FastAPI JSON API and server-rendered dashboard, detail/graph views and artifact uploads.
- Redis/RQ and database queue workers, configurable retries and memory/database outbound request pacing.
- CLI/API/dashboard binary-presence inventory with configured paths and install guidance.

## Remaining integration and hardening gaps

- Phase 2 supplies uniform scanner metadata/readiness and built-in subprocess timeout/error handling with safe diagnostics. External version/runtime configuration validation, output size limits, third-party execution safety remain incomplete; Phase 4 adds mirror subprocess timeouts and isolated materialization. Phase 6 maps custom YARA metadata and unknown rule IDs; ripgrep retains its original definitions; Phase 7 adds a separate validated heuristic-rules adapter. Existing parser tests are not live-binary compatibility certification.
- Phase 8 implements conservative cross-scanner correlation and evidence deduplication; legacy records are retained without speculative backfill.
- Phase 4 adds checkpoints, isolated materialization and local POSIX locking. Phase 5 adds incremental decisions and history ranges; crash recovery remains pending.
- Other CT sources, dnsrecon and amass could broaden enrichment; subfinder and httpx are already integrated.
- Phase 14 extends both queues with retry classification, upstream deferral and explicit stale-lease quarantine. Heartbeat-driven recovery and distributed exactly-once execution remain unverified.
- Phase 11 enforces browser/API authentication and tenant boundaries. Password login, MFA/SSO, abuse throttling and deployment certification remain outside that implementation.
- Phase 15 adds executive/technical PDFs and SARIF; Phase 13 adds operator queues. Host-specific ingestion, Unicode font coverage and large-data performance still require validation.
- Paid integrations require configured credentials and external service access. Mocked coverage does not certify current provider contracts; HIBP currently matches breached domains in its breach catalog rather than searching all employee accounts.

Production safety, release packaging and scale require validation beyond the existing unit suite. These are follow-on work, not new integrations undertaken in Phase 0.
