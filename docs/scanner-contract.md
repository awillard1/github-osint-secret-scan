# Scanner Contract

## Purpose

Every scanner must behave predictably enough that the same scan orchestration can execute built-in detectors and external tools.

Phase 2 implements this contract in `src/orgscan/scanners/base.py` and `registry.py`. Existing scanner parsers and `ScanMatch` remain the normalization input; the adapter preserves legacy plugins. See the [current baseline](roadmap.md#current-architecturecapability-baseline).

## Implemented types

All contract records are frozen dataclasses:

- `ScannerMetadata`: stable `scanner_id`, `display_name`, `kind`, `supported_targets`, history/incremental flags, optional `version`, description, binary/settings/environment-key declarations, configuration requirements and optional file settings.
- `ScannerReadiness`: `ready`, `status`, optional binary path/version, missing requirements and warnings. Checks must not execute scans. Built-in readiness checks executable presence and configured file readability; it does not probe external versions or validate runtime configuration. Built-in Python detectors declare the package version; external versions remain unknown.
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

The runner dispatches through the adapter, validates result identity/type/status, and preserves existing canonical persistence. A plugin can optionally expose `load_report(path)` returning `list[ScanMatch]`; saved-report ingestion does not require an installed executable.

## Registry and discovery

Register Python classes through the `orgscan.scanners` entry-point group. For example, a package may declare:

```toml
[project.entry-points."orgscan.scanners"]
example = "example_package.scanner:ExampleScanner"
```

The registry includes all nine existing scanners, loads entry points in deterministic name/value order, and lists IDs in sorted order. Metadata IDs take precedence over legacy names. Duplicate IDs, including collisions with built-ins, raise `DuplicateScannerError`; an explicit registration ID must match the declared ID. Unloadable entry points are skipped with safe registry warnings. Entry-point discovery is cached for the process lifetime, as before.

Registry inventory supplies `config`, `verify-deps`, bootstrap, `/scanners`, and dashboard scanner choices. Existing inventory fields remain, with metadata/readiness added. Artifact options use declared target capabilities instead of a scanner-name allowlist; new plugins need no API/CLI dispatch branches. Target support describes the prepared input kind, not guaranteed applicability to every file: history scanning still requires Git contents. Failed initialization/readiness is reported as unavailable without exposing arbitrary exception text. Duplicate registration remains a configuration error.

## External scanner execution

Built-in adapters use `execution.run_scanner_process()` with argument arrays, captured stdout/stderr and exit status, the caller’s working directory explicitly preserved (including relative binary/config paths), and a per-process timeout. `ORGSCAN_SCANNER_TIMEOUT_SECONDS` defaults to 300 seconds. The shared runner supplies context; direct legacy built-in calls use the same default timeout. Context environment overrides merge with the inherited process environment and reset after the scan. Existing tool arguments, accepted exit codes and parsers are preserved.

Timeouts, process failures and malformed live results produce safe operator errors without raw tool stderr/stdout. `ScannerExecutionError` is reserved for safe diagnostic messages; plugin readiness messages and result metadata must also exclude secrets. Missing binaries remain optional readiness conditions. Temporary Gitleaks/YARA reports retain explicit cleanup.

Limits: output is currently buffered without a size cap; the timeout applies to each subprocess, not the entire scan. The registry does not sandbox third-party plugins: they must use the helper or implement equivalent timeouts, safe diagnostics and cleanup. Readiness is not live compatibility certification. Mirror/provider subprocess hardening is outside this scanner phase.

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
