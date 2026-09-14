# Scanner Contract

## Purpose

Every scanner must behave predictably enough that the same scan orchestration can execute built-in detectors and external tools.

Phase 2 implements this contract in `src/orgscan/scanners/base.py` and `registry.py`. Existing scanner parsers and `ScanMatch` remain the normalization input; the adapter preserves legacy plugins. See the [current baseline](roadmap.md#current-architecturecapability-baseline).

## Implemented types

All contract records are frozen dataclasses:

- `ScannerMetadata`: stable `scanner_id`, `display_name`, `kind`, `supported_targets`, history/incremental flags, optional `version`, description, binary/settings/environment-key declarations, configuration requirements and optional file settings.
- `ScannerReadiness`: `ready`, `status`, optional binary path/version, missing requirements and warnings. Checks must not execute scans. Built-in Python detectors declare the package version. YARA performs a bounded five-second version probe; failure leaves an unknown version and warning. detect-secrets requires successful five-second version/help probes for the supported 1.5.x scan contract. Semgrep requires readable local rules and leaves runtime compatibility unverified. Other external adapters check executable presence and declared configuration; their versions remain unknown. None of these checks certifies a live scan.
- `ScanTarget`: prepared `path`, `kind` (`path`, `mirror`, or `artifact`) and `ref`.
- `ScanContext`: target, optional job/organization/repository IDs, positive finite `timeout_seconds`, optional environment overrides, and options carrying existing scope settings. Environment is excluded from repr; do not serialize/log contexts containing credentials. It is not an authorization context.
- `ScanResult`: scanner ID, start/completion timestamps, `findings: list[ScanMatch]`, logical `exit_status` and warnings. Zero means the scanner accepted the tool's exit status, including tool-specific findings exits. Result warnings/timings are available to callers; the runner retains its existing persisted job/ToolRun timing model.

## Interface and compatibility

```python
class ScannerPlugin(Protocol):
    metadata: ScannerMetadata
    source_class: str

    def readiness(self) -> ScannerReadiness: ...
    def supports(self, target: ScanTarget) -> bool: ...
    def scan(self, context: ScanContext) -> ScanResult: ...
```

Use `get_registry().get(scanner_id, settings=settings)` for a contract adapter. Native plugins implement the interface above and may accept `settings` in their constructor. Legacy classes declaring `name`, `source_class` and `scan_path(path)` remain supported; optional `scan_path_with_context(path, target_ref=..., scope_json=...)` receives the existing scope. Legacy metadata is synthesized and readiness explicitly warns about its limited checks. `get_scanner()` still returns the underlying instance for compatibility, and existing `get_scanner_class()`, `available_scanner_names()` and `load_report()` imports remain available.

The runner dispatches through the adapter, validates result identity/type/status, and preserves existing canonical persistence. Phase 5 uses history/incremental capability flags for range dispatch. The built-in git-history adapter accepts generated `commit_oid`/`commit_range` context options; native plugins declaring both flags must honor those scope limits. Content scanners otherwise fall back to full-tree execution on change. A plugin can optionally expose `load_report(path)` returning `list[ScanMatch]`; saved-report ingestion does not require an installed executable.

## Registry and discovery

Register Python classes through the `orgscan.scanners` entry-point group. For example, a package may declare:

```toml
[project.entry-points."orgscan.scanners"]
example = "example_package.scanner:ExampleScanner"
```

The registry includes ten bundled scanners (including heuristic-rules), loads entry points in deterministic name/value order, and lists IDs in sorted order. Metadata IDs take precedence over legacy names. Duplicate IDs, including collisions with built-ins, raise `DuplicateScannerError`; an explicit registration ID must match the declared ID. Unloadable entry points are skipped with safe registry warnings. Entry-point discovery is cached for the process lifetime, as before.

Registry inventory supplies `config`, `verify-deps`, bootstrap, `/scanners`, and dashboard scanner choices. Existing inventory fields remain, with metadata/readiness added. Artifact options use declared target capabilities instead of a scanner-name allowlist; new plugins need no API/CLI dispatch branches. Target support describes the prepared input kind, not guaranteed applicability to every file: history scanning still requires Git contents. Failed initialization/readiness is reported as unavailable without exposing arbitrary exception text. Duplicate registration remains a configuration error.

## External scanner execution

Built-in adapters use `execution.run_scanner_process()` with argument arrays, captured stdout/stderr and exit status, the caller’s working directory explicitly preserved (including relative binary/config paths), and a per-process timeout. `ORGSCAN_SCANNER_TIMEOUT_SECONDS` defaults to 300 seconds. The shared runner supplies context; direct legacy built-in calls use the same default timeout. Context environment overrides merge with the inherited process environment and reset after the scan. Accepted exit codes remain compatible. Semgrep requires configured local rules instead of `--config auto`, with telemetry off by default. External filesystem targets reject symlinks and special entries before execution; original root spelling is checked before path resolution. Python content reads use descriptor-relative no-follow opens. External preflight assumes a quiescent target; it is not filesystem sandboxing against concurrent local changes.

Timeouts, process failures and malformed live results produce safe operator errors without raw tool stderr/stdout. `ScannerExecutionError` is reserved for safe diagnostic messages; plugin readiness messages and result metadata must also exclude secrets. Missing binaries remain optional readiness conditions. Temporary Gitleaks/YARA reports retain explicit cleanup.

Limits: combined captured output is capped at 8,000,000 bytes; Gitleaks report-file output also counts toward this budget and is polled while the process runs. Saved reports have an 8,000,000-byte bounded no-follow read; YARA location reads use the 1,000,000-byte content cap. File polling may transiently overshoot the threshold. The timeout applies to each subprocess, not the entire scan. The registry does not sandbox third-party plugins: they must use the helper or implement equivalent timeouts, safe diagnostics and cleanup. Readiness is not live compatibility certification. Legacy provider subprocesses now share bounded execution; see [release recovery](release-readiness.md#post-phase-16-recovery-audit-2026-09-14).

## Normalization

All persisted detections must become `CanonicalFinding` objects.

Preserve useful tool-specific details under evidence metadata, but do not make consumers parse scanner-specific JSON.

## Secret handling

Do not persist or log raw secret values by default.

Use:

- redacted indicator;
- stable one-way fingerprint if correlation requires it;
- path/line;
- detector/rule ID;
- evidence source.

If a scanner output contains raw secrets, parsing code must avoid placing those values into normal logs or exception strings.

## Testing a scanner

Every scanner integration needs tests for:

1. readiness when tool is missing;
2. readiness when tool is available;
3. successful parsing;
4. no-findings result;
5. malformed output;
6. non-zero exit;
7. timeout;
8. normalization;
9. redaction;
10. registry discovery.

Normal unit tests must not require the real scanner binary.

Use fixture output representative of supported scanner versions.

## YARA integration guidance

YARA should be treated as a scanner adapter with configurable rulesets.

Initial use cases:

- private key/certificate structures;
- credential/config exports;
- sensitive filename/content signatures;
- organization-specific artifacts.

Rules should carry stable identifiers and metadata that can map into canonical category/severity/confidence.

Do not download arbitrary YARA rules at scan time.

## Rule-driven heuristic scanner guidance

Keep custom organization heuristics in data files rather than Python conditionals.

Suggested schema:

```yaml
id: internal-hostname
category: exposure
severity: medium
confidence: medium
regex: '...'
file_patterns:
  - '*'
exclude_patterns:
  - '*.min.js'
description: ...
remediation: ...
```

Validate rules at startup/load time.

A bad rule should identify the file/rule and fail predictably rather than corrupting the scan.

## Phase 18 effective configuration and readiness

An inventory snapshot is shared by API tooling, bootstrap and CLI output; one
request does not repeat each scanner's readiness probe for every representation.
YARA checks the configured source file and probes `--version` with a five-second
bound. A failed probe leaves an unknown version and warning; it does not certify or
reject runtime rule compatibility. Rule syntax is checked during execution.

Checkpoint reuse is limited to reviewed built-ins, JSON heuristic rules and bounded
local YARA includes. Other external tools and plugins execute again because their
full effective configuration is not declared. See [incremental scans](incremental-scans.md).
Phase 17 redaction remains in force: source bodies/credential-labelled fields and
recognized copied values are removed before persistence, and exports omit raw
payloads/snippets/indicators. This does not identify every arbitrary unlabelled secret
or make existing backups safe; operator/plugin metadata must remain redacted.


## Phase 19 secret and executable boundaries

All discovered evidence strings and nested metadata cross the shared redactor before
persistence and again at supported presentation boundaries. Raw secret indicators
are replaced with redaction markers; a SHA-256 secret digest supports correlation.
Valid existing digests remain unchanged. Diagnostic targets, provider summaries and
inventory/readiness warnings receive the same policy. Keep non-secret detector and
location information; never rely on a UI alone to hide stored credentials.
Migration 0009 repairs legacy evidence with a frozen copy of this policy.

The supported detect-secrets contract is **1.5.x**. Invoke
`detect-secrets scan --all-files --force-use-all-plugins TARGET`, which emits baseline
JSON. Do not pass `--json`: it is not a scan option in the
[1.5.0 scan parser](https://github.com/Yelp/detect-secrets/blob/v1.5.0/detect_secrets/core/usage/scan.py).
Readiness requires successful, bounded `--version` and `scan --help` probes with
the supported flags. Unknown versions/contracts are unavailable, rather than
advertised ready. An optional live smoke test skips absent/unsupported executables.
YARA retains its bounded version probe and execution-time rule syntax validation.
External binaries and plugins still require deployment-specific validation.


## Opt-in live compatibility checks (Phase 20)

`ORGSCAN_LIVE_TOOLS=1 python -m pytest tests/live -rs` exercises detect-secrets,
Semgrep, YARA, Gitleaks and TruffleHog only when explicitly enabled. Missing binaries
or unmet readiness skip cleanly. Tests create inert temporary target files and local
Semgrep/YARA rules; they do not scan checkout content, execute target code or download
rules. Semgrep metrics/version checks are disabled. The TruffleHog smoke adds
`--no-update --no-verification`, supported by its
[CLI definitions](https://github.com/trufflesecurity/trufflehog/blob/main/main.go),
to prevent update and credential verification requests. Use deployment egress controls
for external binaries; readiness is not a network sandbox.

A live smoke passing certifies only that executable and these tiny inputs. A parser
or command incompatibility fails the opted-in test; do not weaken assertions to hide it.
The ordinary unit suite uses mocks and skips all live executable tests.


## Shared secret presentation policy (Phase 21)

Persistence, diagnostics and presentation share `orgscan.redaction`. Credential
labels are case-insensitive, normalize hyphens, and use the same recognition for
nested fields and value-bearing `key=value` / `key: value` text. Quoted values,
query credentials and copied values are protected; labels and non-secret prose
remain useful. Finding presentation includes hidden metadata as redaction context.
Browser renderers sanitize their inputs before HTML escaping, as API and report
serializers do. Plugin code remains trusted; arbitrary unlabelled opaque strings
cannot be identified as secrets without evidence or known-secret context.

Sanitization fails closed at centrally defined limits: 1,000,000 characters per
string, 8,000,000 total input characters, 100,000 nodes, depth 30, 2,048 known secrets,
32,000,000 replacement-work characters and 4,096 URL fields. Output expansion is
also bounded. Limit errors contain no input. These are independent of acquisition
limits and may reject unusually large legitimate payloads; callers must not retry
by returning unsanitized data. Migration 0010 freezes this policy with parity tests.


### Escaped copied assignments (Phase 22)

The same credential-label vocabulary also recognizes quotes escaped by copied JSON,
including repeated serialization, single-quoted copied text and escaped `=` / `:`
assignment values. Labels and delimiters are preserved; sensitive value spans and
known encoded/decoded copies in sibling fields are removed. Ordinary names such as
`token_count`, `secret_name`, `password_policy` and `access_tokenization` remain intact.

Quote delimiters support up to eight copied JSON layers (255 backslashes). Decoding
secret values allows the base JSON string layer plus eight copied layers, with one
additional attempt solely to detect an exceeded bound. Excessive escaping fails
closed with a controlled error. Existing string, node, depth and replacement-work
limits remain in force. The parser advances through backslash runs without nested
backtracking expressions and does not decode entire documents repeatedly.

Migration 0011 freezes the corrected policy and repairs escaped legacy assignments;
released 0009/0010 migrations and snapshots remain unchanged. Runtime adapters use
the shared policy directly, with no browser/provider-specific escaped-secret rules.
