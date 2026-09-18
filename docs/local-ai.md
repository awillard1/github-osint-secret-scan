# Optional local AI

Local AI is disabled by default. It is independent of startup, authentication,
discovery, scanning, correlation and reporting. The initial provider is Ollama;
there are no cloud providers or model-download actions.

Settings / Local AI stores a tenant's enablement, explicit endpoint and selected
installed model. Save and test queries the model inventory, then sends inert synthetic
input through generation and validates the advisory response. The page reports
disabled, unreachable, model-missing, generation-failed and passed outcomes without
showing raw provider responses. A saved configuration is not presented as a passed
test. The model selector shows inventory returned by the test. From an assessment's
Local AI tab, analysts launch summary, correlations, triage, repository or finding
advice; that tab shows recent durable AI job states and saved advice. Repository/finding
advisory forms accept an explicit entity ID; selection
is applied before pagination, so later pages remain addressable. Only administrators
can configure/test; analysts can request advisory jobs; readers can view advice.
The existing browser CSRF and tenant authorization apply.

Environment defaults:

```sh
ORGSCAN_AI_ENABLED=false
ORGSCAN_AI_PROVIDER=ollama
ORGSCAN_OLLAMA_BASE_URL=http://127.0.0.1:11434
ORGSCAN_OLLAMA_MODEL=
ORGSCAN_AI_TIMEOUT_SECONDS=30
ORGSCAN_AI_MAX_INPUT_CHARS=24000
ORGSCAN_AI_MAX_OUTPUT_TOKENS=1000
ORGSCAN_AI_MAX_OUTPUT_CHARS=16000
ORGSCAN_AI_MAX_ENTITIES=50
ORGSCAN_AI_ALLOW_SOURCE_CODE=false
ORGSCAN_AI_ALLOW_FINDING_CONTEXT=true
ORGSCAN_AI_ALLOW_PROTECTED_SECRETS=false
```

When Ollama runs on Windows and orgscan runs in WSL, configure the endpoint to an
address reachable from that WSL environment. Loopback is not assumed to work.
Orgscan does not discover or alter Windows firewall/network configuration. Doctor
checks environment defaults when AI is enabled and reports optional warnings;
doctor also counts enabled/disabled tenant overrides without remote requests.
Per-tenant endpoints are tested in Settings. Endpoint URLs permit only HTTP(S)
origins without credentials, queries or paths; redirects are disabled.

The adapter uses Ollama's documented [model inventory](https://docs.ollama.com/api/tags)
and [non-streaming generation](https://docs.ollama.com/api/generate) endpoints.
Responses must validate against a small advisory JSON schema. Malformed, oversized,
incomplete or timed-out responses produce safe failures without storing prompts.

## Data and authority

Purposes are summary, correlations, triage, repository, finding and target. The
first three always review the whole selected assessment. Repository and finding
retain their existing batch behavior when no ID is supplied and select one record
when an ID is supplied. Target selects an assessment target, organization,
repository, account, domain, recon asset or finding by type and ID. These are
bounded explanations over authorized assessment metadata, not autonomous agents.
Inputs pass the same complete credential-context projection policy used by the
assessment UI. No SecretEvidence row is loaded or decrypted. No reveal service is
called. Source files, README content, raw scanner matches and arbitrary operator
prompts are not accepted. Source-code sharing remains unsupported even if its
reserved setting is enabled; protected-secret sharing is always prohibited.

Repository/OSINT text is explicitly untrusted data in the system instructions.
The provider receives text and returns validated data; it has no tools. Advice
cannot change severity, scope, finding lifecycle, relationships or authorization.
Output is sanitized again with complete tenant context before persistence and
HTML escaping. Existing limits on identifying completely unlabelled unknown
credentials still apply; see projection-safety.md.

Advice is labelled AI Suggested and stored separately with provider, model,
purpose, generation time, policy version and a SHA-256 safe-input fingerprint.
The fingerprint includes assessment and selected entity, model, endpoint, policy
and system instruction, output schema version, projection version, and the actual
safe selected input. Policy v3 and advisory JSON schema v2 invalidate older cached
prompts without deleting historical advice. The JSON output keeps the schema and
projection version plus input coverage, including omission counts.
Identical selected inputs reuse advice; changed selected inputs invalidate it.
Historical advice remains visible with its generation time. It is not live truth.

The input reuses the assessment workbench's tenant-authorized, fully sanitized
reads. It includes assessment scope/profile, configured targets, the assessment
organization, linked organizations/repositories/accounts/domains/recon assets,
safe provider observations, relationship provenance, canonical finding and
evidence **metadata**, deterministic severity/lifecycle/remediation fields,
assessment-linked scan-job status metadata, and durable run/stage coverage.
Selected entities include directly related assets and
findings where recorded membership or relationship edges support the association.
Assessment targets do not have a direct persisted target-to-asset membership;
their projection includes the target and its runs and explicitly states that
limit. Source bodies, snippets, raw scanner payloads, executable content and
protected secret evidence are excluded. AI receives no decryption capability.
Generated report files are not re-ingested; the advisory uses their canonical
assessment sources and counts instead of duplicating prior narrative text.

`ORGSCAN_AI_MAX_ENTITIES` limits rows per category (default 50, maximum 100).
Finding evidence metadata and durable runs use the same bound. The
per-asset provider observation map also uses this bound; its omitted source
count is recorded. Discovered subdomain lists use the same bound and record
omitted counts. Disabling finding context excludes finding records and
finding relationship nodes before generation and marks the input partial.
The complete tenant credential context retains its independent configured row and
aggregate limits. Category totals record how many rows were omitted. After safe
projection, oversized input is reduced deterministically by removing whole
records and recording category/count and a partial-selection marker. A single
remaining oversized record fails closed. This is bounded sampling rather than
proof that unselected records contain no risk; changes outside the selected
sample do not invalidate its fingerprint. A scope with no meaningful findings
or observations receives a cached, deterministic insufficient-evidence advisory
without invoking Ollama. Analyst decisions remain in canonical triage.

The model is instructed to distinguish facts, inferences and unknowns; respect
omission counts; and never invent vulnerabilities or claim inspection of absent
source/history. It may return optional structured observed facts, exposure,
root-cause, affected-asset, mitigation, severity-commentary and limitation fields.
Strict schema validation rejects extra fields such as authoritative severity or
lifecycle changes. Its discussion of attacker perspective remains high-level and
defensive, without exploit code, payloads, commands or credential-use steps.

A nonblocking file lock limits generation to one process per shared data directory.
Multi-host workers need a shared lock-capable directory or an external deployment
concurrency limit. Busy/unavailable AI jobs fail independently of the assessment
and can be retried. AI work uses the existing queue; there is no model tool executor.

## Validation

Normal tests mock Ollama. They cover enablement, unavailable/model-missing status,
validated output, caching/invalidation, tenant permissions, queue failure, limits,
prompt-injection data, ciphertext preservation and exact authorized reveal.
No live model is required. Explicit opt-in smoke:

```sh
ORGSCAN_RUN_LIVE_OLLAMA_TESTS=1 python -m pytest tests/live/test_ollama.py
```

This uses only inert synthetic text and does not install models.
