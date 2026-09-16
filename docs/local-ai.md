# Optional local AI

Local AI is disabled by default. It is independent of startup, authentication,
discovery, scanning, correlation and reporting. The initial provider is Ollama;
there are no cloud providers or model-download actions.

Settings / Local AI stores a tenant's enablement, explicit endpoint and selected
installed model. Save and test queries the model inventory and populates the model
selector. Repository/finding advisory forms accept an explicit entity ID; selection
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

Purposes are summary, correlations, triage, repository and finding. These are
bounded batch explanations over safe assessment metadata, not autonomous agents.
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
The fingerprint includes model/endpoint/policy and actual safe selected input.
Identical selected inputs reuse advice; changed selected inputs invalidate it.
Historical advice remains visible with its generation time. It is not live truth.

Input samples are explicitly bounded per entity kind, with a partial-selection
marker. After the complete credential projection, oversized advisory input is
reduced deterministically by retaining fewer whole observations; the prompt records
counts omitted for the character budget. Credential context is never truncated.
Input still too large with one observation per kind fails closed. This is bounded
advisory sampling, not an exhaustive hierarchical analysis. Changes outside the
selected sample do not invalidate that sample's cache. Purpose-specific instructions
explain the requested task; all source content remains untrusted data. Policy v2
invalidates the earlier prompt cache. Analyst decisions remain in canonical triage,
separate from AI advice.

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
