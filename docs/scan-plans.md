# Scan plans and profiles

`services/scan_plan.py` defines a versioned, JSON-serializable resolved `ScanPlan`. `resolve_scan_plan()` expands profiles and `services/scan_service.execute_plan()` dispatches through the existing runner, mirror functions or domain providers. CLI/API and scheduled execution share this service; both queue backends already invoke the scheduler. Each scanner still creates its own job and ToolRun, with the complete resolved plan under `parameters_json.scan_plan`. Schedules store the plan in metadata, preserving defaults across later profile changes. Old schedules resolve their explicit scanner and scope when run.

| Profile | Default scanners/provider |
| --- | --- |
| quick | custom-patterns |
| standard | custom-patterns, repo-governance |
| comprehensive | custom-patterns, repo-governance, gitleaks, detect-secrets, semgrep, trufflehog, yara, ripgrep-heuristics |
| history | git-history-patterns; history mode |
| secrets-only | custom-patterns, gitleaks, detect-secrets, trufflehog |
| governance-only | repo-governance |
| osint-only | domain target, github-search provider |
| domain-only | domain target, local-metadata provider |

These are explicit product defaults, not automatic availability selection. Missing optional binaries fail with readiness guidance; they are never silently omitted. Discovery profiles use existing domain provider behavior and store exposure/correlation records, not canonical scanner findings. They do not imply organization-wide repository discovery or paid enrichment. Provider configuration/network limits remain those of the existing providers.

Precedence: explicit non-`None` overrides replace profile defaults. An explicit scanner list replaces the entire list; an empty list is invalid for file/repository plans. Ref lists are deduplicated in supplied order and imply selected branch policy. Otherwise order is stable; resolution does not inspect installed binary availability. Without a profile or scanner, path/artifact defaults remain custom-patterns, and mirror defaults remain git-history-patterns. Scanner/history capability and target incompatibilities are rejected before execution. History defaults to the existing all-history behavior; current-ref can be selected explicitly. Settings supply the process timeout unless overridden in the plan. Tenant/organization context records associations; it does not add authorization.

Examples:

```bash
orgscan scan path ./checkout --profile standard --json
orgscan scan path ./checkout --profile standard --scanner repo-governance
orgscan schedule-scan ./checkout --profile standard
orgscan scan-mirror owner/repo --profile history --ref release
orgscan scan-plan resolved-plan.json --dry-run
orgscan scan-plan resolved-plan.json
```

Artifact API and dashboard POST accept optional `profile` alongside `scanner`; an explicitly supplied scanner wins. The dashboard's existing scanner dropdown still supplies an explicit scanner. Multiple-scanner responses retain first-run identifiers and add `results` for each run, with aggregate findings/IDs. A failed batch can leave earlier completed scanner jobs; execution is sequential and is not an atomic transaction across tools.

To serialize a discovery plan, use `resolve_scan_plan(target="example.com", target_type="domain", profile="domain-only").model_dump_json()`. The same JSON is accepted by the `scan-plan` command or by a scheduled record's `metadata_json.scan_plan`.

Phase 3 records full/incremental/history and branch intent, but incremental and all-branch mirror execution are rejected until Phase 5. Legacy tracked-ref behavior is preserved in the meantime. No repository checkpoint or schema migration is part of Phase 3.
