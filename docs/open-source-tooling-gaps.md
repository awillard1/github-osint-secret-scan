# Open-source tooling gaps and recommendations

This document summarizes what the current repository can accomplish directly and where additional open-source tools or larger systems would materially improve coverage.

## Already integrated or supported
- Built-in custom pattern scanning for local files and directories
- Optional `gitleaks` integration for generic secret scanning
- Optional `trufflehog` integration for verified secret detection
- GitHub REST API discovery for public repository and organization metadata
- Local correlation of domains against stored repository metadata and account emails
- SQLite-backed persistence, exports, reports, and local API responses

## High-value OSS tools to add next

### Code and config analysis
- **Semgrep**: supply-chain, CI/CD, and IaC policy checks beyond raw secret detection
- **detect-secrets**: complementary detector set and baseline workflow
- **YARA**: matching for known document or artifact patterns
- **ripgrep**-based heuristics: lightweight scanning for internal hostnames, org-specific strings, and governance files

### Domain and infrastructure enrichment
- **crt.sh** or other CT log APIs: certificate transparency signals for domain expansion
- **dnspython** / `dnsrecon`: DNS and subdomain enrichment
- **whois**: ownership and registrar context
- **httpx** / **subfinder** / **amass**: broader asset discovery, only where scope permits

### Execution and scale
- **RQ**, **Dramatiq**, or **Celery** with **Redis**: true worker pools and queueing beyond the current local scheduler
- **Alembic**: formal schema migrations instead of lightweight SQLite evolution
- **FastAPI** + **Uvicorn** + templates/UI stack: richer interactive API and dashboard experience

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
3. Redis-backed queue workers
4. FastAPI-based interactive API/dashboard
5. Optional paid providers after the free-first path is solid
