# Recon toolchain validation — 2026-09-15

## Autonomous continuation classification (2026-09-16)

This review preserves the historical acceptance results below. Initial backlog:

| Remaining item | Classification | Disposition |
|---|---|---|
| Existing assessment creation, bulk targets, connections, scope, scans, progress, findings, Reveal, triage, reports, AI adapters | COMPLETE | Retain existing acceptance/security coverage |
| Nuclei local template Settings editor and binary/template readiness | PARTIAL | Implement shared persisted configuration and browser controls |
| Active launch review and upstream execution provenance | PARTIAL | Implement explicit review and bounded causal input records |
| Domain observation detail and HTTP/DNS presentation | PARTIAL | Enrich canonical results using existing safe projection |
| Hundreds of mixed targets and 1,000-observation performance acceptance | PARTIAL | Extend deterministic integration coverage |
| Combined GitHub mock, real loopback, Reveal/report/AI acceptance | PARTIAL | Extend acceptance evidence without external targets |
| Live GHES instances, authorized external Amass/Subfinder discovery, Windows Ollama endpoint | OPERATOR CONFIGURATION | No network/firewall changes or external recon |
| Optional scanner binaries, local Nuclei templates, workers, credentials and resource budgets | OPERATOR CONFIGURATION | Accurate readiness; no automatic installation |
| Distributed PostgreSQL/Redis deployment certification | OPERATOR CONFIGURATION | Requires deployment environment |
| Cross-tenant duplicate globally unique domains | BLOCKED | Requires separately reviewed ownership/schema migration; retain fail-closed boundary |
| Uncover, tlsx, asnmap; Amass newer than v3 | BLOCKED | Unsupported by current compatibility policy; do not advertise support |
| Standalone IP registration targets, distributed installer jobs, interactive graph | COMPLETE | Existing bounded domain-RDAP, local installer and table graph contracts; outside accepted product scope |

No new tool adapter is NOT STARTED within the supported inventory. Historical
limits are retained rather than represented as new product regressions.

This record supplements the earlier assessment control-plane validation. The
operator contract and compatibility limits are in [Recon toolchain](recon-toolchain.md).

## Delivered behavior

- One registry supplies tool inventory, modes, configuration, actual executable
  detection, parsed versions, installation definitions and pipeline ordering.
- Settings → Recon Tools exposes explicit, separate passive/active installation,
  updates, verification, configuration guidance and installation status.
- Assessment profiles require active authorization and resolve selected missing
  tools before execution. Domain scope and normalized upstream observations gate
  downstream DNS, HTTP, crawl, port and template stages.
- Subfinder, DNSX, HTTPX, Naabu, Katana, Nuclei, compatible Amass and gau adapters
  feed canonical observations alongside crt.sh, Wayback, RDAP and WHOIS.
- Canonical domains/assets, provenance, relationships and Nuclei findings/evidence
  feed Discovery Results, assessment relationships, exports and optional AI advice.
- GitHub discovery retains connection isolation and adds bounded repository
  branch/language/tree metadata without executing repository code.
- Migration 20260915_0015 adds recon assets. Upgrade preservation and tenant-scoped
  projection protections cover the added data family.

## Validation method

Final full-suite result: **885 passed, 7 skipped, 2 warnings in 682.28 seconds**.
The warnings are upstream Starlette/AnyIO deprecations. Command:

```sh
.venv/bin/python -m pytest -o 'pythonpath=src /tmp/orgscan-recon-test-deps'
```

The temporary path supplies the newly declared PyYAML dependency for source tests;
the clean wheel installation resolves its own runtime dependencies normally.

Focused tests exercise real services and disposable database/browser workflows
with fake external processes and network responses. They cover executable identity,
failed-update preservation, installation permissions, explicit active consent,
missing tools, input/scope validation before execution, template restrictions,
correlation, canonical findings/evidence, deadlines, redirect restrictions,
resource limits and credential-safe projection.

The wheel was built with `python -m build --no-isolation`. The clean-install script
passed in a disposable environment: dependency checks, migrations, CLI, API
lifespan/health, scan, JSON/SARIF reports and encrypted evidence/reveal. Doctor
against a disposable database returned success with zero errors; optional
dependency warnings remain expected. Compile checks and `git diff --check` passed.

PyYAML is declared as a runtime dependency. Source tests used a temporary dependency
directory; the developer virtual environment was not modified to add it. No recon
binary was installed and no live reconnaissance was performed. The configured
application database was not migrated. Changes are uncommitted and undeployed.

### Operator-requested follow-up

After the implementation validation, the operator explicitly requested migration,
doctor, a commit and the `codex-recon-toolchain` tag. PyYAML 6.0.3 was then installed
in the project virtual environment. `orgscan migrate-db` successfully upgraded the
configured SQLite database from 0014 to **20260915_0015**. `orgscan doctor` exited
successfully: all required checks passed, with 35 warnings. No recon executable
was installed. The earlier statements above describe the implementation run before
this explicit operational follow-up.

## Operational limits

Amass supports its v3 passive contract; newer majors need a separately validated
adapter. Nuclei accepts a restricted local GET/HEAD HTTP template policy, with no
automatic acquisition. Uncover is deliberately deferred pending connection/key
and query policy. RDAP currently enriches domain registrations, not standalone IP
network registrations. Live upstream/GHES/Windows compatibility is not certified.

Installation runs in the API process with persisted status and explicit retry
after interruption. Pipeline concurrency coordinates workers sharing a POSIX lock
directory; it is not distributed scheduling or an OS resource sandbox. Existing
cross-tenant duplicate-domain conflicts continue to fail closed. Configuration
guidance uses administrator environment settings; it does not edit arbitrary
executable paths through the browser. The relationship table is the graph view.

## Live workstation certification — 2026-09-16

This section supersedes the earlier statement that no recon binaries were installed.
The operator explicitly authorized user-level installation and local certification.
Baseline: clean commit `57579e0`, tag `codex-recon-toolchain`. Baseline focused tests:
**26 passed**. The configured database was only inspected in this phase, not migrated
or populated with test data. Its existing head is **20260915_0015**.

### Machine inventory and certification

Environment: Linux x86-64 on WSL2. In this table `managed` means
`/home/willard/src/github-osint-secret-scan/data/tools/bin`, `local` means
`/home/willard/.local/bin`, and `go-bin` means `/home/willard/go/bin`.
“UI ready” is configuration readiness on this workstation, not certification of
external Internet services. Version/help probes now reject executables missing
required adapter flags. Live execution remains an explicit opt-in test.

| Tool | Installed | Version | Path | Contract test | Live test | orgscan parser | UI ready | Limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Go | New | 1.27.1 | `local/go` → `.local/share/orgscan/go1.27.1/go/bin/go` | Version; real builds | Official Go module installs | N/A | Installer prerequisite | User-level installation; uploads never enabled; telemetry now explicitly off |
| Git | Existing | 2.53.0 | `/usr/bin/git` | Existing scanner suite | Local/inert repository tests | Existing integration | Yes | No external repository acquisition in this phase |
| Subfinder | Existing | 2.14.0 | `/usr/bin/subfinder` | Exact adapter command; isolated GitHub source without keys; timeout; empty/malformed handling | Empty source run only | Mock valid rows; actual empty output | Yes | Contract certified; external discovery unverified without an authorized test domain |
| DNSX | Existing | 1.2.3 | `/usr/bin/dnsx` | Exact adapter invocation | Loopback DNS: A, AAAA, CNAME, NXDOMAIN | Real JSON normalized | Yes | No external DNS targets tested |
| HTTPX | New | 1.12.0 | `managed/httpx` | Exact adapter invocation | Loopback HTTP/TLS, title, status, redirect, technology | Real JSON normalized | Yes | Managed binary overrides unrelated Python HTTPX on PATH |
| Nuclei | New | 3.11.1 | `managed/nuclei` | Exact invocation with local resolver file and owned template | Loopback harmless finding | Real JSONL → canonical finding/evidence | Configure templates; Ready in lab | No template ecosystem downloaded; Go 1.27 emits a harmless Sonic JSON fallback warning |
| Katana | New | 1.7.0 | `managed/katana` | Exact invocation, scoped crawl, redirects disabled | Loopback endpoint discovery | Real JSONL normalized | Yes | External links stayed outside scope; no headless browser |
| Naabu | New | 2.6.1 | `managed/naabu` | TCP CONNECT, host discovery disabled, bounded ports/rate | Loopback listener on 8080 | Real JSON → IP/network service | Yes | libpcap headers/compiler already available; no sudo or raw-packet scanning |
| Amass | New | 3.23.3 | `go-bin/amass`, linked from `local/amass` | Version; `enum -passive -d orgscan.test -h` accepts supported flags | External discovery not run | Existing mock-tested line parser | Yes | v3 only; newer major versions unsupported; passive network behavior unverified |
| WHOIS | Existing | 5.6.6 | `/usr/bin/whois` | Version detection | Not queried | Mock tested | Yes | External registration lookup unverified |
| gau | No | — | — | Mock tested | Not run | Mock tested | Missing | Optional; not part of core installation requested here |
| tlsx | No | — | — | Not integrated | Not run | None | Not listed | No supported orgscan adapter; intentionally not installed |
| asnmap | No | — | — | Not integrated | Not run | None | Not listed | No supported orgscan adapter; intentionally not installed |
| Uncover | No | — | — | Deferred | Not run | None | Not listed | Provider-key/query policy remains absent |
| Gitleaks | No | — | — | Mock tested | Skipped | Existing adapter | Missing | Optional scanner |
| TruffleHog | No | — | — | Mock tested | Skipped | Existing adapter | Missing | Optional scanner |
| Semgrep | Existing | 1.172.0 | `/home/willard/miniconda3/bin/semgrep` | Real adapter with explicit local rules | Inert generated file; metrics/version checks off | Real no-finding output | Binary present; configure rules | No community rules fetched |
| YARA | No | — | — | Mock tested | Skipped | Existing adapter | Missing | Optional system package: `sudo apt install yara` (operator action; not executed) |
| detect-secrets | No | — | — | Mock tested | Skipped | Existing adapter | Missing | Optional project-venv dependency; no installation required for recon |
| Ollama | Not reachable | — | `http://127.0.0.1:11434` | Mock tested | Connection refused | Existing advisory schema | Disabled | Implemented; live Windows/WSL connectivity not configured |

Built-in/provider inventory:

| Provider | Availability/configuration | Certification |
| --- | --- | --- |
| crt.sh | Built-in API; no binary/key needed | Mock tested; no external query |
| RDAP | Built-in IANA-bootstrap domain provider | Mock tested; no external query |
| security.txt | Built-in active HTTP provider; local fixture exposes the endpoint | Provider safety mock tested; endpoint crawled by real Katana; no live Internet fetch |
| GitHub API/search | Built-in connection-scoped integration; workstation token absent | Multi-connection/public-private isolation mock tested; no external search |

No external reconnaissance was performed. Network downloads were restricted to
trusted upstream installation sources; those downloads are not external-network
recon certification.

### Installation evidence and reproducibility

The official Go archive was downloaded over HTTPS from
[go.dev](https://go.dev/dl/) and checked against its published SHA-256:
`63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`.
It was safely extracted under the user's home directory. No shell installer ran.

The existing orgscan installation manager successfully installed these pinned
[official ProjectDiscovery](https://github.com/projectdiscovery) Go packages,
verified version/identity, and atomically published their executables:

- `github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0`
- `github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1`
- `github.com/projectdiscovery/katana/cmd/katana@v1.7.0`
- `github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1`

Compatible Amass was installed with the official
`github.com/owasp-amass/amass/v3/cmd/amass@v3.23.3` module. Go builds used HTTPS
module proxy/checksum verification, bounded runtime/output, two build workers,
`GOTOOLCHAIN=local`. Initial builds used Go's default local-only counters; no
telemetry uploads were enabled. Live inspection showed that the environment variable
`GOTELEMETRY=off` is not a writable Go setting. The installer now explicitly runs
`go telemetry off` in its private environment before building; a real `go env
GOTELEMETRY` check returned `off`, and eight installer/registry tests passed. The
user-local Go telemetry mode was also explicitly set to off. No sudo/root execution,
firewall, Windows networking or shell-startup configuration changes were made.

`~/.local/bin` was already on PATH. It now contains Go and Amass links, so no PATH
edit was necessary. Managed binaries are automatically found for this checkout.
For running orgscan with another working directory, explicitly set
`ORGSCAN_RECON_TOOLS_DIR=/home/willard/src/github-osint-secret-scan/data/tools`.
Nuclei correctly remains **Configuration Required** outside the lab until an
operator selects a reviewed local template directory. Installation never enables
active profiles.

### Corrections found by live execution

- DNSX returns `status_code: NXDOMAIN` records, not necessarily empty output.
  The adapter now preserves this as DNS `rcode`; the UI does not label a failed
  lookup as resolved. HTTPX `host_ip`, AAAA, server and content-type fields are kept.
- Nuclei's resolver option takes a file, unlike DNSX/HTTPX/Katana/Naabu's inline
  resolver option. The adapter writes a private, bounded resolver file.
- Administrator resolver/HTTP-port/source settings accept bounded structured values,
  not arbitrary command-line fragments. Defaults retain ordinary behavior.
- Version detection now verifies required help flags. Missing argument contracts
  produce `unsupported_contract`, and installation verification rejects them.
- Legacy ProjectDiscovery entry points now resolve the same managed binaries as
  the registry, avoiding the unrelated Python HTTPX on PATH. Their update checks
  are explicitly disabled. The focused final registry/execution-safety run passed
  **35 tests**.
- Platform administrators can see detected executable paths in Settings; tenant
  operators cannot read shared installation paths. All paths use safe rendering.
- Setup describes **Minimal**, **Recon**, and **Full** requirements. Doctor labels
  **CORE**, **AI**, **SCANNERS**, and **RECON** sections. **Active Extended** is a
  selectable profile requiring explicit active authorization and complete readiness.

### Live local acceptance

Opt-in command (never invoked automatically by normal pytest):

```sh
ORGSCAN_LIVE_RECON=1 ORGSCAN_LIVE_TOOLS=1 .venv/bin/python -m pytest tests/live -rs
```

Result: **8 passed, 5 skipped, 2 warnings in 73.75 seconds**. The seven recon
checks cover real DNSX/HTTPX, Subfinder empty/timeout behavior, canonical pipeline
correlation, capacity limits, Naabu, browser acceptance and concurrent HTTPX jobs.
The eighth passing check is Semgrep. Four missing scanners and the disabled Ollama
smoke account for the skips. No optional missing executable was treated as a pass.

The lab owns temporary UDP DNS, HTTP and self-signed TLS servers bound to loopback.
DNS answers point exclusively to loopback. Each service and generated certificate
is cleaned up. The Nuclei template under `tests/fixtures/recon/nuclei` only matches
an inert marker in `/health`. It contains no secret and is never enabled by startup.

Twice executing DNSX → HTTPX → Katana → Nuclei yields one canonical domain,
one HTTP service, one finding, and shared endpoint provenance from Katana/Nuclei.
Real browser-route acceptance logs in with CSRF, creates an assessment with domain
and local-repository targets, launches/repeats discovery through the real DB queue,
checks stage counts and correlated results, selects the repository, reviews and
launches a real built-in scanner, opens findings, and exports JSON/HTML/PDF/SARIF.
A synthetic scanner credential is absent from ordinary browser/report/log output.
No provider subprocess response is mocked in these local recon tests.

Twelve concurrent local attempts with a limit of two produce at most two running
HTTPX subprocesses; excess attempts receive a capacity error. The queue browser
workflow and normal job suites cover scheduling and durable stage handling. This
is bounded local evidence, not a distributed-load benchmark.

### Ollama and remaining operator configuration

WSL loopback `http://127.0.0.1:11434/api/tags` returned connection refused outside
the test sandbox. The configured endpoint is the same address; no alternate Windows
interfaces were probed. No model was listed, selected, downloaded or invoked.
Existing sanitized advisory and protected-data exclusion tests remain applicable.

To enable live AI later, make the operator-chosen Ollama endpoint reachable from
WSL, set `ORGSCAN_OLLAMA_BASE_URL` and `ORGSCAN_OLLAMA_MODEL`, then use Settings →
Local AI to test it. This phase does not prescribe or perform firewall/bind changes.

External domain discovery, Amass network enumeration, WHOIS/RDAP/crt.sh/GitHub
live services, GHES, distributed deployment and Windows-native binaries remain
uncertified. Optional absent scanners and unsupported tlsx/asnmap/Uncover do not
block the certified local recon stack. Nuclei's restricted local template policy,
tenant isolation and the existing cross-tenant-domain limitation are preserved.

Actual workstation profile checks (readiness only, no target execution) passed for
Passive, Standard and Comprehensive. Passive selected only passive providers.
Active Extended failed without consent, then failed for the unconfigured Nuclei
template directory, and became ready only with the explicit lab template setting.
This verifies that installation alone does not silently enable execution.

### Final validation results

| Gate | Result |
| --- | --- |
| Full pytest on final implementation | **889 passed, 14 skipped, 2 warnings; 839.83 seconds** |
| Explicit local live suite | **8 passed, 5 skipped** |
| Focused final registry/provider execution safety | **35 passed** |
| Separate Phase 27 projection-safety rerun | **34 passed** |
| Doctor on configured workstation (read-only) | **Required checks passed; 21 warnings; exit 0** |
| Setup `--verify-only --json` and verify-deps | Passed; Minimal/Recon/Full requirements exposed |
| Wheel and sdist build | Passed |
| Clean installation of final code | Passed: runtime dependencies, migrations, CLI/API, scan, JSON/SARIF and encrypted evidence/reveal |
| Dependency consistency | `pip check`: no broken requirements |
| Compile and diff checks | Passed, including new-file whitespace review |
| Migration head | **20260915_0015**, unchanged; disposable upgrade tests passed |
| Security | Full security suite passed, including tenancy, protected evidence/reveal, AI redaction, projection, subprocess bounds/timeouts, paths and GitHub visibility |

The normal-suite skips include the seven new explicit-live recon tests; their
separate enabled run passed. The live-suite skips are four unavailable scanners
and Ollama. The two warnings are upstream Starlette/AnyIO deprecations. An earlier
interrupted full run produced RQ signal-handler errors and is not certification
evidence; the uninterrupted final suite and dedicated projection rerun passed.

Local run logs: `/tmp/orgscan-live-verified-full.log`,
`/tmp/orgscan-live-certification.log`, `/tmp/orgscan-live-projection-final.log`,
`/tmp/orgscan-live-final-doctor.log`, `/tmp/orgscan-live-build.log` and
`/tmp/orgscan-recon-clean-install.log`. These temporary logs are not packaged.
The Naabu live test requires loopback port 8080 to be available for its owned listener.

This phase leaves source/test/documentation changes uncommitted. The previous
`codex-recon-toolchain` tag is unchanged. No configured database migration, external
reconnaissance, firewall modification, model download or release publication occurred.

## Completion-run acceptance (2026-09-16)

The initial PARTIAL items above are now implemented and covered by tests:

| Area | Final classification | Evidence / boundary |
|---|---|---|
| Operator workflow | COMPLETE | Authenticated browser handlers: assessment, mixed targets, discovery, scope, scan review/launch, progress, finding detail, Reveal, triage, five reports and optional AI |
| Nuclei configuration | COMPLETE | Platform-admin UI saves multiple approved local directories; atomic private configuration shared by workers/doctor; binary/template readiness separate; no downloads |
| Active recon | COMPLETE | Explicit review and confirmation, operator/time snapshot, scoped inputs, resolved-host dependency for HTTPX/Naabu; installed does not mean enabled |
| Correlation / provenance UI | COMPLETE | Per-provider domain attributes, address/status/technology/confidence/timestamps, expandable observations; stage input entity IDs, digest and upstream providers |
| Multi-target / multi-GHES | COMPLETE | 400 unique mixed locations, duplicate imports, GitHub.com + GHES A + GHES B; bounded pages |
| Correlation performance | COMPLETE | 100 targets, 1,000 observations, ten providers, exactly 100 canonical domains; fewer than 1,000 SELECTs; bounded transaction-local identity reuse |
| Combined local acceptance | COMPLETE | Three mocked GitHub instances + real DNSX/HTTPX/Katana/Nuclei on loopback + real local scanner + exact encrypted Reveal + JSON/HTML/CSV/PDF/SARIF + sanitized mocked Ollama |
| Live recon contracts | COMPLETE | Local DNSX, HTTPX, Katana, Naabu, Nuclei; deterministic Subfinder contract; Amass passive command/parser/correlation mocked |
| External deployments and authorized external enumeration | OPERATOR CONFIGURATION | Live GHES, external Subfinder/Amass, optional binaries, Windows-host Ollama endpoint, shared worker paths and deployment resources |
| Legacy foreign-tenant duplicate domains | BLOCKED | Existing global uniqueness still fails closed; separate ownership migration required |
| Unsupported tool/platform extensions | BLOCKED | tlsx/asnmap/Uncover and newer Amass remain explicitly unsupported |

**Partial workflows:** none identified within the supported operator workflow. This
is local/mocked acceptance, not certification of external services or all deployment
platforms. GitHub transport is mocked in the combined live workflow; recon binaries
and local repository scanning are real. Reports and AI are checked independently
for absence of the synthetic protected credential. No configured database was
migrated, no optional tools installed, and no external reconnaissance performed.

Validation results:

- Focused assessment/recon/projection run: **126 passed** (before the final two
  path/Amass regressions); final new-feature suite: **10 passed**.
- Complete live suite: **8 passed, 5 skipped**, 103.74 seconds. Skips: optional
  live Ollama and four unavailable scanner executables.
- Full regression suite: **899 passed, 14 skipped**, two existing dependency deprecation warnings, 703.10 seconds. Established security and migration
  suites are included; projection safety also passed in the focused run.
- Doctor: **required checks passed, 21 warnings**. Nuclei reports **Binary Ready;
  Templates Missing or invalid** on the unchanged workstation configuration.
- Build: passed. Final clean runtime-only install: passed (runtime dependencies, migrations, CLI/API, scanning, reports and encrypted Reveal).
- Compile and whitespace checks: passed. Migration head remains
  **20260915_0015**; no schema change or configured-data migration.

Remaining product boundary: legacy cross-tenant duplicate-domain ownership.
Optional tool availability, Nuclei template choice, live GHES and Windows/WSL
Ollama reachability require operator configuration; they do not prevent the
independently tested workflow. A fresh loopback-only `/api/tags` check remained unreachable. No Windows
networking/firewall changes were made.
