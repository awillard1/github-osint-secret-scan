# Project Spec: OSINT Security Platform for Organization Risk Discovery

## 1. Overview

Build a best-in-class, easy-to-use OSINT security platform that helps organizations discover exposed data, leaked secrets, risky public artifacts, insecure repo practices, and external indicators of compromise or weak security posture.

The platform should ingest organization names, domains, GitHub orgs/users/repos, and other approved targets, then continuously discover and score:
- exposed credentials and secrets
- leaked internal information
- governance and ownership risk
- supply-chain risk
- infrastructure exposure
- public org identity graph relationships
- domain-linked exposure and breach signals
- evidence of compromise or prior exposure

The system should be designed as a modern Python application with:
- a strong CLI
- a web dashboard
- a database-backed scanning pipeline
- concurrent workers
- plugin-based integrations for OSINT and secret-scanning tools
- a robust bootstrap/setup process that installs dependencies and third-party binaries

This is a defensive security and exposure-management tool for authorized use only.

---

## 2. Goals

### Primary goals
- Discover organization-linked public assets and risk signals at scale.
- Integrate best open-source OSINT and secret-scanning tools.
- Support organization domain intelligence as a first-class capability.
- Normalize findings into a common schema.
- Provide a clear dashboard of org security posture.
- Support continuous re-scanning and historical comparison.
- Make installation and setup easy and reproducible.

### Secondary goals
- Allow multiple orgs/targets to be managed from one instance.
- Provide evidence and provenance for every finding.
- Support free-first enrichment with optional paid provider plugins.
- Support local-first deployment and optional team/server deployment.
- Allow custom rules and scanners to be added without changing core code.

---

## 3. Non-goals

- Offensive exploitation
- Credential use or login attempts
- Private data access without authorization
- Social engineering
- Vulnerability scanning of live infrastructure unless explicitly added as a scoped module later
- Mass crawling outside approved scope

---

## 4. Target Users

### Security teams
Need to monitor org exposure, leaked credentials, and public attack surface signals.

### AppSec / DevSecOps
Need repo and CI/CD posture visibility, secret leak monitoring, and remediation workflows.

### OSINT analysts
Need a unified place to collect and correlate public signals across GitHub and related sources.

### Consultants / auditors
Need repeatable assessments and historical evidence.

---

## 5. Core Use Cases

1. An organization is added by name, domain, or GitHub org.
2. The platform discovers related GitHub users, repos, contributors, forks, maintainers, and public org affiliations.
3. It scans public repos and histories for leaked secrets.
4. It expands into related repositories and likely owned accounts based on OSINT signals.
5. It discovers domain-linked exposure signals from public and free sources.
6. It optionally enriches domain intelligence using paid breach/exposure providers if configured.
7. It scores findings by severity and confidence.
8. A dashboard shows current risk, trends, and remediation priorities.
9. Re-scans detect new issues and changed risk posture over time.

---

## 6. Key Capabilities

### 6.1 Discovery
The system should discover:
- GitHub organizations
- GitHub users associated with the organization
- repositories owned by those orgs/users
- forks of target repos
- contributors and maintainers
- governance files and ownership hints
- public metadata tied to the org
- organization domains and subdomains
- domain-linked email identities
- links between repos, people, domains, and external identities

### 6.2 Risk detection
The system should detect:
- secrets and credentials
- exposed private keys and certificates
- tokens in repo history
- CI/CD secrets
- cloud credentials
- container and registry credentials
- exposed config files and backups
- internal endpoints and hostnames
- IaC files exposing infrastructure details
- sensitive docs and operational files
- supply-chain and repo hygiene issues
- domain-linked breach and exposure signals
- public identity correlation and reuse patterns

### 6.3 Visualization
The dashboard should show:
- org overview
- repos and accounts discovered
- domain inventory and exposure signals
- findings by severity and category
- scan history
- trends over time
- evidence and source references
- top risky assets
- remediation status

### 6.4 Automation
The platform should:
- run scans on a schedule
- re-scan changed targets automatically
- queue jobs and process in parallel
- export reports and machine-readable findings
- allow suppression and triage workflows

---

## 7. Scope of Discoverable Risk

This section defines what the platform should look for.

### 7.1 Secrets and credentials
- API keys
- PATs
- OAuth tokens
- cloud credentials
- service account keys
- SSH keys
- PGP keys
- webhook secrets
- Slack/Discord/Teams tokens
- database connection strings
- JWTs and signing material
- password files and exports
- `.env`, `.npmrc`, `.pypirc`, `.netrc`, kubeconfigs
- private certs and TLS keys

### 7.2 Org identity and relationship risk
- public emails tied to org members
- usernames reused across orgs/services
- contributor overlap
- fork relationships suggesting hidden ownership
- maintainer/admin patterns
- abandoned or orphaned repos
- third-party contractors with persistent access hints
- CODEOWNERS and maintainer files
- personal accounts with company-linked roles

### 7.3 Infrastructure exposure
- DNS/subdomain references
- internal hostnames
- cloud account IDs and tenant IDs
- S3/bucket names
- deployment env names
- API gateway URLs
- webhook and callback endpoints
- Terraform and Kubernetes configs
- registry URLs
- VPN/SSO references
- staging/preprod identifiers

### 7.4 Supply-chain risk
- exposed package publishing tokens
- workflow changes that touch release automation
- unpinned or drifting GitHub Actions
- suspicious dependency additions
- package manifests with risky provenance
- release artifact and tag integrity issues
- signing key references
- source map leaks
- build artifact leaks

### 7.5 Repo governance risk
- missing CODEOWNERS
- missing branch protection evidence
- stale repos with secrets
- repos with broad write access signals
- lack of security policy
- lack of commit hygiene
- archived or abandoned repos with sensitive history
- forks or mirrors preserving old secrets
- weak workflow controls
- uncontrolled public release history

### 7.6 External intelligence
- paste/site references
- public breach references
- public issue threads with sensitive material
- support docs with leaked details
- job posts exposing stack and vendors
- conference slides / PDFs / manuals
- exposed source maps and bundles
- old docs and archived pages

### 7.7 Domain intelligence and exposure
- domain-linked emails
- email/domain reuse across public repos
- certificate transparency entries
- public references to subdomains and hosts
- public documents and code containing org domains
- domain mentions in issue threads, docs, and support content
- exposure references tied to org domains
- optional paid breach-provider results
- public breach/disclosure references
- public indicators of account compromise associated with org email addresses

---

## 8. System Architecture

### 8.1 Recommended tech stack
- **Language:** Python 3.12+
- **CLI:** Typer or Click
- **Web API:** FastAPI
- **Dashboard:** Streamlit or FastAPI + React; start with Streamlit or server-rendered pages for speed
- **Storage:** SQLite for local use, PostgreSQL for shared/team use
- **Queue/Workers:** Celery, RQ, Dramatiq, or a lightweight internal task queue; choose one based on deployment complexity
- **ORM:** SQLAlchemy or SQLModel
- **Concurrency:** asyncio + worker pools where appropriate
- **Packaging:** pyproject.toml + uv or pip-tools
- **Containerization:** Docker optional but recommended

### 8.2 Architectural layers
1. **Input layer**
   - org names
   - domains
   - repo lists
   - GitHub queries
   - explicit targets
   - file-based manifests

2. **Discovery layer**
   - GitHub API
   - relationship mining
   - OSINT enrichment
   - domain intelligence enrichment
   - expansion logic

3. **Scanning layer**
   - Gitleaks wrapper
   - TruffleHog wrapper
   - custom pattern scanner
   - future scanner plugins

4. **Normalization layer**
   - converts tool-specific output into common findings

5. **Storage layer**
   - persists targets, scans, results, evidence, status, history

6. **Dashboard/reporting layer**
   - visualizes posture and findings

7. **Setup/installer layer**
   - installs app dependencies
   - installs external binaries
   - verifies versions and compatibility

---

## 9. Data Model

### 9.1 Core entities
- **Organization**
- **Target**
- **Repository**
- **Account/User**
- **Domain**
- **Email Identity**
- **Scan Job**
- **Finding**
- **Evidence Item**
- **Relation**
- **Asset**
- **Suppression**
- **Risk Score**
- **Tool Run**
- **Domain Exposure Record**
- **Provider Result**

### 9.2 Recommended finding fields
- id
- target_id
- repository
- source_tool
- category
- severity
- confidence
- title
- description
- detected_at
- first_seen_at
- last_seen_at
- status
- fingerprint
- evidence references
- remediation hints
- raw tool payload
- hash of normalized result
- source_class (`free`, `paid`, `internal`)
- source_name

### 9.3 Evidence fields
- source
- source_url or repo/path/commit
- snippet reference or line range
- extracted indicator
- confidence
- timestamp
- related entity
- source_class
- query used

### 9.4 Domain entity
- domain name
- organization mapping
- ownership confidence
- verification status
- discovered emails
- discovered subdomains
- discovery sources
- risk score

### 9.5 DomainExposure entity
- domain_id
- source
- source_class (`free`, `paid`)
- source_name
- query used
- result summary
- confidence
- severity
- first_seen
- last_seen
- evidence_url
- normalized_hash

### 9.6 IdentityCorrelation entity
- domain_id
- email
- username
- person/profile reference
- source
- confidence
- relation type
- evidence reference

---

## 10. Scanner Plugins

### 10.1 Required first-party integrations
- **Gitleaks**
- **TruffleHog**
- **Custom regex/pattern scanner**
- **GitHub metadata discovery**

### 10.2 Strongly recommended optional integrations
- **Semgrep** for security rules on code/config
- **YARA** for matching known file patterns or artifacts
- **Ripgrep-based custom heuristics**
- **Detect-secrets** if it adds value in the environment
- **gitsign / commit signature checks**
- **git-secrets** style checks where appropriate
- **subfinder/amass/httpx** style tooling only if later expanding to controlled external surface discovery and if in scope
- **whois/dnsrecon-style enrichment** only if explicitly approved

### 10.3 Domain intelligence providers
Implement a provider abstraction for free and paid sources.

#### Free/public providers
- public GitHub/email/domain correlation
- CT log sources
- public search-based enrichment
- public docs/web references
- public breach disclosure references

#### Optional paid providers
- Have I Been Pwned
- DeHashed
- Intelligence X
- other commercial exposure intelligence providers

### 10.4 Plugin interface
Each scanner/provider plugin should declare:
- name
- version
- supported target types
- required binaries or API keys
- input mode
- output parser
- severity mapping
- confidence mapping
- provenance class (`free`, `paid`, `internal`)
- remediation notes

---

## 11. Discovery and Expansion Logic

### 11.1 Input types
- org name
- user name
- repo name
- domain name
- query string
- file-based target list

### 11.2 Expansion sources
- GitHub org repos
- user repos
- contributors
- forks
- org memberships
- governance files
- release and tags metadata
- search-based repo discovery
- public domain/email correlation
- public CT and asset references

### 11.3 Expansion rules
- Every discovered target gets a confidence score.
- Targets can be expanded only when they meet configurable thresholds.
- Expansion must be bounded by limits to avoid runaway collection.
- All expansion must be logged with provenance.

### 11.4 Risk scoring for expansion
Use source weighting such as:
- official org repo: highest confidence
- contributor affiliation: medium-high
- governance file handle: medium
- fork owner / similar name: medium
- company mention in metadata: lower
- public email domain match: lower to medium depending on evidence
- verified domain ownership evidence: high
- paid provider result: high if source confidence supports it
- unverified public mentions: lower

---

## 12. Domain Intelligence Design

### 12.1 Objectives
The platform shall support organization domain intelligence as a first-class capability.

### 12.2 Free-first design
The platform must provide useful domain intelligence without paid services by default.

Free/public discovery should include:
- emails tied to the domain
- usernames tied to the domain
- public repository and commit references
- public docs/config references
- certificate transparency evidence
- public asset references
- public breach/disclosure references

### 12.3 Optional paid enrichment
Paid providers must be:
- optional
- disabled by default
- easy to configure
- clearly marked in the UI and reports

### 12.4 Domain risk signal categories
- exposed employees or identities
- leaked credential associations
- public breach/disclosure references
- public asset exposure
- identity reuse
- infrastructure indicators
- stale or suspicious domain-linked artifacts

### 12.5 Domain confidence model
Domain signals should be classified by:
- verified
- likely
- heuristic
- unverified

### 12.6 Domain-related correlation
The platform should correlate:
- domain ↔ email
- domain ↔ GitHub user
- domain ↔ repo
- domain ↔ CT entry
- domain ↔ public doc
- domain ↔ breach reference
- domain ↔ exposed credential

### 12.7 Provider provenance
Every domain-related result must indicate:
- free source or paid source
- source name
- query used
- evidence location
- time observed

---

## 13. Domain Intelligence Workflow

### 13.1 Input
Accept one or more organization domains.

### 13.2 Free/public discovery pipeline
1. Discover domain-linked identities.
2. Search public repositories and history for domain references.
3. Search public asset references and CT logs.
4. Search public web/document references.
5. Search public breach/disclosure references.
6. Correlate and score results.

### 13.3 Optional paid enrichment pipeline
If API keys are configured:
1. Query the provider.
2. Normalize results.
3. Merge with free/public evidence.
4. De-duplicate identical exposures.
5. Annotate findings with paid-source provenance.

### 13.4 Output
Produce:
- findings
- relationships
- domain exposure score
- evidence trail
- remediation suggestions

---

## 14. Scanning Workflows

### 14.1 Repository scan
For each repo:
- acquire repo metadata
- determine branches/tags to scan
- fetch or update local mirror
- run selected scanners
- normalize findings
- persist results
- update dashboard state

### 14.2 History scan
- scan commit history where tool supports it
- prioritize recent branches and default branch
- optionally scan all branches/tags
- support incremental scans using fingerprints/checkpoints

### 14.3 Continuous monitoring
- periodic rescan by repo/branch
- new-finding alerts
- changed-risk alerts
- stale finding tracking
- suppression expiry and review

### 14.4 Domain monitoring
- periodic domain re-enrichment
- CT log updates
- new public mentions
- new identity correlations
- optional paid-provider refreshes

---

## 15. Risk Scoring Model

### 15.1 Scoring dimensions
- severity
- confidence
- exposure type
- asset sensitivity
- age / recency
- repeat occurrence
- provenance strength
- blast radius estimate
- source class (`free`, `paid`, `internal`)

### 15.2 Example score categories
- Critical
- High
- Medium
- Low
- Informational

### 15.3 Sample rules
- private key in public repo history = critical
- live cloud credential with verification indicators = critical/high
- generic token pattern without context = medium
- internal hostname in public config = medium
- abandoned repo with historic secret = high depending on recency
- broad org membership signal = medium
- missing CODEOWNERS on critical repos = medium
- verified domain-linked credential exposure = high/critical depending on artifact
- weak public mention of domain with no corroboration = low

---

## 16. Dashboard Requirements

### 16.1 Org overview page
Shows:
- total targets
- discovered repos/accounts
- domains tracked
- high/critical findings
- active vs resolved issues
- trends
- top sources of risk

### 16.2 Repository page
Shows:
- repo metadata
- scan history
- findings by category
- branch coverage
- evidence list
- remediation status

### 16.3 Domain intelligence page
Shows:
- domains tracked
- discovered emails
- likely employee identities
- breach/exposure hits
- CT log references
- public web references
- provider coverage
- source provenance
- paid/free labels
- risk score and trends

### 16.4 Finding detail page
Shows:
- normalized finding
- raw tool output
- evidence
- commit/path/branch
- confidence/severity
- suppress/triage actions

### 16.5 Relationship graph
Shows:
- orgs
- users
- repos
- domains
- emails
- forks
- contributor overlap
- governance links
- discovered evidence connections

### 16.6 Export options
- JSON
- CSV
- HTML report
- PDF later if needed
- API access

---

## 17. Setup and Installation Strategy

This should be first-class, not an afterthought.

### 17.1 Bootstrap script responsibilities
- detect OS and package manager
- install base OS packages
- create Python virtual environment
- install Python dependencies
- install or update external tools
- verify versions
- print next steps
- support non-root mode where possible
- provide explicit sudo instructions when required

### 17.2 Base OS dependencies
Typical packages:
- git
- curl
- jq
- openssl
- ca-certificates
- Python build tools
- optional: build-essential, pkg-config, libssl-dev

### 17.3 External tool installation
Do not assume `apt install` is enough for latest versions.

For tools like Gitleaks and TruffleHog:
- prefer official upstream release binaries or install scripts
- verify checksums or signatures when available
- provide manual fallback instructions
- support `--install-only` and `--verify-only` modes

### 17.4 Installation modes
- local install
- user install
- system install with sudo
- container install
- CI install

### 17.5 Safety and clarity
The setup script should:
- clearly tell the user when sudo is required
- never silently escalate
- print exact commands when manual installation is needed
- handle missing dependencies gracefully

---

## 18. CLI Design

Suggested top-level commands:

- `orgscan setup`
- `orgscan add-target`
- `orgscan discover`
- `orgscan scan`
- `orgscan status`
- `orgscan findings`
- `orgscan report`
- `orgscan dashboard`
- `orgscan export`
- `orgscan verify-deps`

Key options:
- scope selection
- include/exclude filters
- branch coverage modes
- scanner selection
- concurrency limits
- output format
- rescan strategy
- suppressions/triage
- domain inputs
- paid provider enablement flags

---

## 19. Concurrency and Performance

### 19.1 Requirements
- parallel target processing
- parallel scanner execution where safe
- bounded concurrency
- backpressure for large orgs
- resumable jobs

### 19.2 Best practices
- isolate scanner processes
- use queues for long-running jobs
- avoid overloading GitHub API
- cache metadata
- rate-limit-aware GitHub client
- persist intermediate state frequently

---

## 20. Security, Safety, and Compliance

### 20.1 Guardrails
- only operate on approved targets
- log every access and scan
- support scope allowlists
- no credential use or authentication attempts
- no exploitation features
- no destructive actions

### 20.2 Operational security
- protect tokens and secrets in config
- redacted logs
- encrypted secrets at rest if supported
- role-based access for multi-user deployments

### 20.3 Auditability
- full scan provenance
- source URL and timestamps
- tool version tracking
- repeatable output for reports

---

## 21. Reporting and Triage

### 21.1 Output types
- live dashboard
- JSON/CSV exports
- HTML reports
- summary emails/slack later if needed

### 21.2 Triage actions
- suppress false positives
- mark accepted risk
- assign owner
- set remediation deadline
- add notes and references

---

## 22. Testing Strategy

### 22.1 Unit tests
- parsing
- scoring
- normalization
- target expansion rules
- setup detection
- domain intelligence provider interface behavior

### 22.2 Integration tests
- scanner wrappers
- GitHub API access
- database persistence
- dashboard views
- free/paid provider handling

### 22.3 Fixture-based tests
- sample repos with known findings
- mock tool outputs
- regression tests for parser changes
- sample domain intelligence results

---

## 23. Deployment Options

### Option A: Local analyst workstation
- simplest
- SQLite
- local dashboard

### Option B: Team server
- FastAPI + Postgres
- background worker
- shared dashboard

### Option C: Containerized deployment
- Docker Compose
- repeatable environment
- easier onboarding

---

## 24. Suggested MVP

### MVP should include:
- Python CLI
- GitHub org/user/repo discovery
- domain input support
- public/free domain intelligence
- repo acquisition
- Gitleaks integration
- TruffleHog integration
- custom pattern scanner
- normalized findings storage
- basic dashboard
- HTML export
- setup/bootstrap script
- dependency verifier
- concurrency with safe limits

### MVP should not yet include:
- overly complex external OSINT sources
- large-scale graph database
- enterprise SSO
- multi-tenant RBAC unless needed immediately

---

## 25. Future Enhancements

- graph database for relationships
- automatic remediation suggestions
- alerting integrations
- package registry scanning
- artifact repository scanning
- DNS/subdomain enrichment
- breach feed correlation
- CI workflow policy checks
- source map extraction
- mobile-friendly dashboard
- scheduled reporting
- multi-org comparisons
- expanded paid-provider marketplace
- enrichment orchestration rules by provider cost/coverage

---

## 26. Success Criteria

The platform is successful if it can:
- reliably discover org-linked public assets,
- detect meaningful security exposures,
- provide strong free-first domain intelligence,
- accept paid enrichment easily when available,
- produce low-noise high-confidence findings,
- scale to multiple orgs,
- show a clear dashboard of risk,
- and install cleanly with minimal friction.

---

## 27. Recommended implementation stance

My recommendation is:

1. **Build the core in Python**
2. **Use a plugin architecture**
3. **Store findings in a database**
4. **Ship a dashboard from day one**
5. **Write a real bootstrap installer**
6. **Keep OSINT expansion bounded and auditable**
7. **Normalize all tool outputs into a single finding model**
8. **Make domain intelligence free-first with paid plugins as optional add-ons**

If you want, I can next turn this into:
- a technical architecture document,
- a phased implementation plan,
- or a repository scaffold with the initial Python project structure.