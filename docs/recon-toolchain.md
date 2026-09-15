# Recon toolchain

## Operator workflow

Open **Settings → Recon Tools** for detected status, version, mode, configuration
requirements and upstream documentation. **Test** runs a bounded local version
probe; it does not contact assessment targets. API providers show configuration
readiness, not a claim that their upstream service is reachable.

A platform administrator (admin with `*` tenant scope) can explicitly install or
update the shared executables. Tenant administrators can inspect readiness, but
cannot replace executables used by other tenants. Browser installs run after the
response in the API process, show the current tool and result, and retain a small
status record. Interrupted API-process installations require an explicit retry;
installation is not a distributed queue job. Existing managed binaries survive a
failed install or failed identity/version verification.

Passive and active installation buttons are separate. Installation never enables
execution. No startup or normal test installs recon binaries.

In **Assessment → Discovery**, select a profile and individual providers. Missing
selected tools prevent launch. **Run available tools only** is an explicit choice;
unavailable selections remain recorded in the profile. Crawling and Nuclei require
HTTPX in the selection. Active providers require the authorization checkbox, even
when already installed. Passive profiles reject active selections.

- **Passive Organization**: GitHub metadata/relationships, repository metadata,
  stored references, crt.sh, RDAP, Subfinder and Wayback.
- **Standard Organization**: adds DNSX and HTTPX, with active authorization.
- **Comprehensive Organization**: adds GitHub member/contributor/search expansion;
  operators select Katana, Naabu and Nuclei explicitly.
- **Custom**: explicit individual providers; the same readiness/scope rules apply.
- Earlier profile IDs remain accepted. Legacy combined provider aliases remain
  available to legacy CLI users, but assessment profiles require individual tools.

Only saved domain targets authorize domain/subdomain network recon. A domain found
in repository metadata or a third-party URL is an association, not automatic
permission to probe it. Katana uses domain/host scope and disables redirects;
HTTPX does not enable redirect following. Naabu uses unprivileged TCP connect
scanning on ports 80, 443, 8080 and 8443 at a bounded rate. Arbitrary extra command
options are not accepted.

**Discovery Results** provides Overview, Domains, Hosts, Services and Web tabs,
with links to Repositories, Accounts and Relationships. Canonical endpoints omit
query strings and fragments; different providers contribute observations to one
endpoint identity. Provider timestamps, confidence and source badges are retained.
The relationship table remains the supported graph interface.

## Registry and execution

`recon/registry.py` owns tool definitions, mode, executable/configuration discovery,
version parsing, installation methods, capabilities and stage order. Setup,
verify-deps, doctor, API and UI consume it. Versions that cannot be verified are
reported as unverified, not Ready. A missing optional tool is a doctor warning.

`recon/adapters.py` parses output to `Observation` records. `recon/pipeline.py`
executes ordered durable stages in the existing assessment queue operation.
Discovery precedes DNSX; HTTPX uses DNSX-resolved hosts when DNSX is selected;
Katana and Nuclei consume observed HTTP targets. Empty downstream inputs produce a
blocked stage, not an empty successful scan. Each stage records tool/version,
mode, timestamps, input/output count and a safe failure classification.

`recon/observations.py` correlates Domain and ReconAsset records and links them to
the assessment. ReconAsset kinds are IP address, network service, HTTP service,
endpoint and certificate. Nuclei creates canonical Finding and Evidence records
and finding-to-endpoint relationships. Repository metadata reads GitHub branches,
languages and the bounded Git tree filename inventory; it does not execute code.

ReconAsset is included in tenant visibility, write authorization and the complete
credential-context families. New graph labels and exports retain Phase 27's
sanitize-before-render boundary, including SQL-inserted legacy values. Ordinary
reads never decrypt protected evidence. Optional Ollama summary/correlation/triage
advice receives bounded sanitized recon metadata through the existing AI service.

Migration **20260915_0015** adds `recon_assets`; earlier migrations remain frozen.
Deployments must back up and run the existing explicit migration procedure. This
implementation run does not upgrade the configured application database.

## Installation and configuration

The default managed directory is `<ORGSCAN_DATA_DIR>/tools/bin`. Override its parent
with `ORGSCAN_RECON_TOOLS_DIR`. An explicit tool binary setting takes precedence
(`ORGSCAN_HTTPX_BINARY`, `ORGSCAN_DNSX_BINARY`, etc.); otherwise the managed binary
precedes PATH. Installing a managed tool does not override an explicit binary path.

```sh
orgscan recon-tools list
orgscan recon-tools install subfinder
orgscan recon-tools verify subfinder
orgscan doctor
orgscan verify-deps
```

Install invokes the configured `ORGSCAN_RECON_GO_BINARY` with an argument array,
fixed official module path, HTTPS Go proxy and checksum database, isolated Go
configuration/cache, finite timeout and bounded output. It requires an existing
compatible Go toolchain; it never downloads Go or runs sudo. The current upstream
minimum Go versions can change. Naabu needs platform C/libpcap prerequisites;
Katana uses CGO. Install failures preserve the previous executable. Update uses the
same verified atomic installation path. No third-party mirrors or shell installers
are used.

Subfinder optionally reads an administrator-provided
`ORGSCAN_SUBFINDER_PROVIDER_CONFIG`. Process environments do not inherit arbitrary
application credentials, proxy variables or user tool configuration.

Nuclei requires `ORGSCAN_NUCLEI_TEMPLATES_PATH`. The supported policy is an explicit
local directory containing 1–100 YAML HTTP templates (at most 64 KiB each): GET/HEAD,
`{{BaseURL}}/…` paths, matchers/extractors and no raw requests, redirects, payloads,
code, headless, workflow, OAST or other protocols. Validated templates are copied
into the private working directory. Automatic template downloads and updates are
disabled. This is intentionally a limited local template policy, not support for
every official template. Template acquisition/review remains explicit.

WHOIS has platform package-manager guidance. Amass is detected conservatively:
this adapter supports the documented v3 `enum -passive` contract. Newer major
versions are **unsupported**, not silently treated as compatible; install a
reviewed compatible official binary manually. Amass v5 automation is not certified.

## Resource controls

`ORGSCAN_RECON_` settings include:

| Setting suffix | Default |
| --- | ---: |
| MAX_CONCURRENT_JOBS | 2 |
| MAX_DOMAINS | 1000 |
| MAX_HOSTS | 1000 |
| MAX_URLS | 2000 |
| MAX_ENDPOINTS | 2000 |
| MAX_OUTPUT_BYTES | 2000000 |
| TOOL_TIMEOUT_SECONDS | 180 |
| PIPELINE_TIMEOUT_SECONDS | 900 |
| INSTALL_TIMEOUT_SECONDS | 900 |

The pipeline checks its deadline between stages and passes the remaining duration
to external adapters. Legacy providers also check the remaining budget before
each request/process/DNS lookup. HTTP response reads remain bounded by their
request deadlines; upstream rate-limit waits can defer progress beyond the budget,
after which the next stage/request fails safely. Concurrency locks coordinate workers
sharing the same lock-capable tools directory. Separate distributed hosts need a
shared lock directory or deployment-level concurrency limits. This is not an OS
CPU/memory/disk sandbox. Oversized normalized observations fail visibly as
**LIMIT REACHED**. Raw stdout/stderr are not retained in the database or exposed in
browser diagnostics; bounded safe normalized attributes supply evidence.

## Upstream investigation and compatibility limits

Official references used for installation and CLI contracts:

- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [HTTPX](https://github.com/projectdiscovery/httpx)
- [DNSX](https://github.com/projectdiscovery/dnsx)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [Katana](https://github.com/projectdiscovery/katana)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Amass passive user guide](https://github.com/owasp-amass/amass/wiki/User-Guide)
  and [current Amass documentation](https://owasp-amass.github.io/docs/)
- [gau](https://github.com/lc/gau)
- [Wayback CDX](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [IANA RDAP bootstrap](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml)

[Uncover](https://github.com/projectdiscovery/uncover) aggregates passive search
engines but requires provider-specific API credentials and query semantics. It is
not included in this integration: a maintainable connection/key/query policy for
those engines is not present, and adding a binary alone would not supply that
policy. RDAP currently supports domain registration, not standalone IP-network
registration targets. Historical URL identity is scheme/host/port/path based;
queries are deliberately omitted. Existing globally unique Domain ownership still
fails closed on cross-tenant conflicts.

Live upstream compatibility, GHES deployments, Windows and distributed locking
are not certified by mocked tests. The recon runner supports Linux/macOS POSIX
execution; WSL should use the Linux toolchain. Browser acceptance uses real service,
auth, migration and persistence with fake external process/network responses.
