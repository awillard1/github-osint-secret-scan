# Scanner Contract

## Purpose

Every scanner must behave predictably enough that the same scan orchestration can execute built-in detectors and external tools.

This is the target contract. The current registry in `src/orgscan/scanners/__init__.py` already handles built-ins and entry-point plugins; adapters currently expose `name`, `source_class`, and `scan_path()` returning `ScanMatch` records, with optional report loaders. Uniform metadata/readiness/context/result types and duplicate-ID rejection remain future work. See the [baseline](roadmap.md#current-architecturecapability-baseline) before migrating existing adapters.

## Required concepts

### ScannerMetadata

Recommended fields:

```python
scanner_id: str
display_name: str
kind: str  # builtin/external
supported_targets: frozenset[str]
supports_history: bool
supports_incremental: bool
homepage: str | None
```

`scanner_id` is stable and is used in configuration, jobs, evidence, and APIs.

### ScannerReadiness

Recommended fields:

```python
ready: bool
status: str
binary_path: str | None
version: str | None
missing_requirements: tuple[str, ...]
warnings: tuple[str, ...]
```

Readiness checks must not execute a scan.

### ScanTarget

Represents a prepared target rather than a raw CLI string.

Examples:

- local path;
- repository worktree;
- repository mirror/history target;
- uploaded artifact extraction root.

### ScanContext

Recommended fields:

```python
target
repository_identity
organization_identity
scan_job_id
timeout_seconds
environment
temp_dir
options
```

Do not store raw authentication tokens in serializable/logged context fields.

### ScanResult

Recommended fields:

```python
scanner_id
started_at
completed_at
exit_status
findings
warnings
tool_logs
metadata
```

## Interface

The exact Python mechanism may be a Protocol, ABC, or compatible existing interface, but the behavior should be equivalent to:

```python
class ScannerPlugin(Protocol):
    @property
    def metadata(self) -> ScannerMetadata: ...

    def readiness(self) -> ScannerReadiness: ...

    def supports(self, target: ScanTarget) -> bool: ...

    def scan(self, context: ScanContext) -> ScanResult: ...
```

## Registry

Scanner selection must use a registry.

The registry should:

- include built-ins;
- load configured/entry-point plugins;
- reject duplicate scanner IDs;
- list metadata/readiness;
- fetch a scanner by stable ID;
- provide deterministic ordering.

Do not require edits to API and CLI dispatch code for every new scanner.

## External scanner execution

Use `subprocess` with an argument array.

Never construct a shell string from untrusted values.

Requirements:

- timeout;
- working directory explicitly selected;
- stdout/stderr captured;
- exit code captured;
- maximum output behavior considered;
- secrets redacted before logging;
- environment explicitly controlled where practical.

A scanner binary being absent is a readiness condition, not an application crash.

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
