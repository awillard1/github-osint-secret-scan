# Open-source tooling gaps and recommendations

This document summarizes what the current repository can accomplish directly and where additional open-source tools or larger systems would materially improve coverage.

## Already integrated or supported
- Built-in custom pattern scanning for local files and directories
- Built-in repository governance scanning for missing CODEOWNERS, missing SECURITY.md, missing Dependabot configuration, risky workflow triggers/permissions, and unpinned GitHub Actions references
- Built-in YARA scanning for rule-based secret and artifact matching
- Built-in ripgrep heuristic scanning for internal hostnames, internal URLs, and org-specific strings
- Built-in git history scanning for regex-based secret detection across repository refs
- Optional `gitleaks` integration for generic secret scanning
- Optional `detect-secrets` integration for complementary baseline-style secret detection
- Optional `semgrep` integration for policy and code/config scanning
- Optional `trufflehog` integration for verified secret detection
- Optional ProjectDiscovery integration via `subfinder` and `httpx` for domain and HTTP exposure enrichment
- Optional `crt.sh` integration for certificate-transparency host discovery
- Optional `whois` integration for registrar and nameserver enrichment
- Optional `dnspython` integration for DNS record enrichment
- Optional paid-provider integrations for Have I Been Pwned, DeHashed, and Intelligence X
- GitHub REST API discovery for public repository and organization metadata
- Local correlation of domains against stored repository metadata and account emails
- SQLite-backed persistence, exports, reports, and local API responses
- FastAPI-served live dashboard and JSON API for local interactive use, including client-side graph and trend visualization
- Optional Redis/RQ-backed scheduled scan queue workers

## High-value OSS tools to add next

### Code and config analysis
- **YARA**: now integrated for rule-based secret and artifact matching; expand with richer rulesets over time
- **ripgrep**-based heuristics: now integrated for internal hostnames, internal URLs, and org-specific strings; expand heuristics and governance coverage over time

### Domain and infrastructure enrichment
- other CT log APIs can complement the existing `crt.sh` integration with broader or redundant certificate-transparency coverage
- **dnsrecon**: broader DNS enumeration beyond the current `dnspython` resolver-based enrichment
- **httpx** / **subfinder** / **amass**: broader asset discovery, only where scope permits

### Execution and scale
- **Dramatiq** or **Celery** with **Redis**: richer worker orchestration, retries, and scaling beyond the current initial RQ queue backend
- **Alembic**: now integrated for formal schema migrations; future revisions should carry new entities and shared-deployment data model changes
- richer client-side visualization stack for graph exploration and advanced dashboard UX beyond the current server-rendered FastAPI dashboard
- deeper PDF reporting and notification/alert delivery workflows beyond the current initial PDF export support

## Gaps that cannot be fully solved by simple library swaps alone
- distributed, rate-aware scanning at scale requires queue infrastructure and operational deployment choices
- graph visualization needs a UI layer and likely client-side visualization libraries, not just backend storage
- multi-user auth/RBAC requires deployment architecture and identity integration, not only an OSS scanner
- PDF reporting requires dedicated rendering tooling and styling, not just data export
- paid breach/exposure providers require external accounts and ToS review; OSS can only cover the free-first subset

## Current recommendation
Use the current repository as the local-first control plane, then layer in:
1. Semgrep + crt.sh enrichment
2. DNS/WHOIS tooling
3. deeper retries/rate-aware scaling on top of the initial Redis/RQ queue workers
4. richer graph/trend visualization on top of the current FastAPI dashboard
5. Optional paid providers and deeper reporting/alerting after the free-first path is solid
