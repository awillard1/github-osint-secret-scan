# YARA adapter

The existing `yara` scanner uses `ORGSCAN_YARA_BINARY` and optional `ORGSCAN_YARA_RULES_PATH`. The latter selects a local source ruleset; source-level includes can organize multiple local rule files. When omitted, the three bundled GitHub/AWS/private-key rules remain available. Rules are never downloaded and compiled third-party rules are not enabled.

Readiness reports binary presence, configured rules-file availability and a bounded five-second `--version` probe. Failed version probes return an unknown version and a safe warning; rule syntax is validated during execution. Generic registry/CLI/API/bootstrap inventory shows readiness/version, and ToolRuns record a detected version. Missing YARA remains optional.

Execution reuses the shared timeout/context helper, preserves caller-relative configuration, captures output and uses `-r -N -m -s` (recursive, no symlink following, metadata, matched strings). See the [official CLI options](https://yara.readthedocs.io/en/stable/commandline.html). Generated temporary bundled rules are cleaned up; operator-supplied rules remain untouched.

Rules may supply string metadata `title`, `category`, `description`, `severity`, `confidence`, and `remediation`. Severity/confidence must match orgscan enums. Unknown rule IDs now become findings with medium/heuristic defaults instead of disappearing. Known bundled IDs keep their established defaults. Invalid severity/confidence and malformed metadata fail with safe diagnostics.

Matched values become fully redacted indicators/snippets. Eligible complete-value and non-secret observations also receive SHA-256 digests for correlation. Raw matched values and source lines are not persisted by this adapter, including when multiple values occur on one line. Live output paths must remain inside the prepared target. Parsers remain fixture-testable without an installed binary.

Limits: Phase 18 hashes bounded literal local include dependencies; ambiguous/missing includes or module imports disable unchanged-scan skipping. Captured subprocess output is bounded. Metadata describes trusted operator-authored rules rather than certifying detector quality. Live tool compatibility is not established by mocked unit tests.

For cross-scanner correlation, custom rules must declare `secret_value = true` only when every emitted string is a complete credential value. Structural markers remain same-tool observations by default. Bundled GitHub/AWS token values are recognized directly; private-key headers never receive credential identity.
