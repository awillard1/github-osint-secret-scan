# Derived projection safety (Phase 27)

Stored text must retain its credential-identifying source context until the complete
projection is sanitized. `services/projection_service.py::safe_projection` is the
shared boundary for derived DTOs; `derived_projection` applies the same contract to
storage/report compatibility entry points. Neither performs decryption. The shared
redactor discovers credentials and replaces copies, including dynamic dictionary keys.

The sequence is: read authorized source context, build the complete projection,
sanitize it with that context, then serialize/render it. No raw ORM field may be
appended after the boundary. API adapters call storage/services; HTML escaping remains
separate from credential safety. Context objects are private, ephemeral and excluded
from DTOs. Protected evidence, key configuration and reveal audits are not context
sources.

## Text source inventory

| Population / consumers | Classification | Credential sources and boundary |
|---|---|---|
| Queue titles, route prefixes, default remediation instructions, application-generated action names | A: static application values | No source discovery needed; still included in complete projection sanitization |
| Request-validated options and application-generated enum literals | B: closed values | Validation applies to these new values only, never to arbitrary stored strings |
| Finding labels, severity/category/source-tool/status keys, trend timelines and counts by stored text | C: untrusted | Finding and evidence ordinary columns; trend family. Finding detail additionally retains associated history/risk context through the existing finding boundary |
| Operator finding queues | C | Complete operator context, including finding/evidence/history/risk metadata before labels are projected |
| Active/failed job queues; job/tool detail; CLI job inventory | C | Job parameters/scope/errors, tool diagnostics, queue metadata and target asset context. Queue source visibility inherits its scheduled scan |
| Repository/provider, organization, domain and account names; asset lists/details; risk-summary entity labels | C | Asset metadata, descriptions and discovery fields, exposure/correlation sources, relationship and finding/evidence knowledge; asset family |
| Graph node labels and edge type/source/provenance | C | Graph family: assets, relationships, findings and evidence. Displayed edges are limited; endpoint label reads are batched by entity IDs |
| Scheduled scan/report labels and CLI queued-task fields | C | Schedule/job/queue source metadata and ordinary contributor context; schedules family |
| Complete reports, summary/group labels, remediation and organization comparisons | C | Existing report source boundary; compatibility aggregations now use the shared derived boundary too |
| Numeric counts, IDs, timestamps and booleans | Non-text | No credential discovery required. Stored textual status/severity fields are **C**, even when current ingestion normally validates an enum |

Raw discovery/scanner normalization and mutation results retain their existing
candidate-aware persistence/diagnostic boundaries. Authentication/session credentials
and explicit protected-secret reveal remain separate workflows; this contract does
not turn generic output into an authorized reveal.

## Scope, batching and bounds

`storage/credential_context.py::PROJECTION_SOURCES` explicitly defines the source
families. A single UNION ALL reads only ordinary string/JSON columns, subject to SQL
value-length bounds and the shared sanitizer budgets. Family context conservatively
covers the complete authorized contributor population, not just displayed labels,
ranked rows or graph endpoints. Tenant ID subqueries intersect request and inherited
scope. No per-row metadata query is performed. A tenant's metadata must not influence
another tenant's coincidentally equal label.

`ORGSCAN_PROJECTION_CONTEXT_MAX_ROWS` defaults to **2,000**, configurable from 1 to
100,000. Each family applies this limit independently. The query reads at most limit
plus one; overflow raises a fixed safety error and emits no partial projection.
Character, node, depth, known-secret and replacement-work budgets still apply.
Increasing the row limit does not disable those budgets. Limits are checked before
loading derived populations. No persistent context cache is introduced.

Existing report (default 1,000 rows) and finding-page limits remain in force. Dashboard
requests must satisfy both their report and operator context limits. Dashboard trends
reuse the complete report context, which covers the finding/evidence trend family;
operator context is built independently in its authorized session. Graph edges remain
bounded to the requested limit (maximum 1,000), with endpoint lookups batched by type.

At 10/100/300 findings, repositories and jobs, measured SELECTs are constant:
operator **15**, dashboard **55**, graph **4**, trends **2**. Credential-context reads
within those totals are **1 / 3 / 1 / 1**, respectively. The combined 300-item fixture
uses a 2,000-row report budget because multiple source populations contribute more
than 1,000 rows. Existing default-budget Phase 20/26 assertions remain unchanged.

## Compatibility and migration

Public DTO shapes, CLI commands and authorized reveal semantics are preserved.
Unsafe legacy labels can now be redacted; oversized scopes fail closed. Graph queries
no longer materialize unrelated ORM collections. Frozen migrations remain unchanged,
and no schema/data migration is required for these projection defects. Regression
fixtures deliberately bypass storage guards; current job/repository writes already
sanitize copies. Generic reads leave legacy rows and protected ciphertext unchanged.
