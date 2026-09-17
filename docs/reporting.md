# Canonical reports

CLI exports, static dashboards, HTTP report downloads and scheduled exports use
`ReportService` / `query_report` over the existing canonical finding/evidence storage.
The live browser dashboard uses Jinja templates and packaged static assets; exported
HTML reports remain standalone and do not load the browser console stylesheet.
Formats: `json`, `csv`, `html`, `sarif`, `pdf-executive`, `pdf-technical`.
The existing `pdf` format and `write_pdf` import remain executive-PDF aliases.

```
orgscan export findings.sarif --format sarif
orgscan export executive.pdf --format pdf-executive
orgscan export technical.pdf --format pdf-technical --lifecycle-state REGRESSED
```

`GET /reports/export/FORMAT?limit=500&lifecycle_state=CONFIRMED` downloads the same
report with reader authorization and tenant filtering. Temporary export files are
cleaned before returning the bytes. Responses are attachments with no-store headers.
Scheduled report format options accept the new formats. JSON/CSV retain existing
finding columns and add evidence/provenance; nested CSV cells are JSON. Spreadsheet
formula-leading cells are quoted as text. Static HTML never includes browser session
or CSRF controls, even when exported from an authenticated request.

SARIF 2.1.0 uses scanner/category rule IDs, canonical fingerprint partial identities,
severity levels and lifecycle/confidence/provenance properties. Only evidence paths
that are relative or contained in a recorded scan root map to physical locations;
unmapped paths produce locationless results, not fabricated source locations.
Multiple scanners remain evidence on the same result. Managed findings have external
suppressions. Lifecycle is not mapped to SARIF baselineState because a remediation
decision is not a SARIF baseline comparison. Validation uses the official
[OASIS schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json)
vendored for offline tests. This does not certify acceptance by every code-scanning
host: repository selection, locationless results and platform upload restrictions
still matter.

Executive PDFs contain scoped totals, lifecycle/severity summaries, organization
comparison, ten prioritized included findings and recommended actions. Technical
PDFs paginate every included finding with timestamps, fingerprint, scanner evidence,
query/source provenance and remediation guidance. Zero-result reports are explicit.
Summary counts cover all authorized records; finding detail obeys the requested
limit and lifecycle filter, recorded in report_scope. Default limit is 500.

Raw payloads, source snippets and extracted indicators are omitted. Export defense
also redacts known credential patterns, private-key blocks and URI credentials;
source URLs omit userinfo/query/fragment. This cannot recognize arbitrary secrets
entered into free-form titles/notes or malicious plugin fields: keep operator text
redacted and review legacy data before sharing. Stored canonical hashes are retained.
ReportLab's standard fonts do not guarantee complete Unicode font coverage. PDF
structure and extracted content are tested, including 120 findings; pixel-perfect
layout, external ingestion and production-scale export performance are not certified.

## Phase 18 locations and query bounds

New path/file, artifact and mirror jobs record a logical location root. Reports use
an evidence observation's job provenance (batch-loaded), with legacy job/mirror and
canonical artifact-root fallbacks. Absolute paths outside a known root remain
locationless. No filesystem access is needed at export time. Local-file names,
archive-relative paths and repository-relative paths appear in JSON, static HTML,
executive/technical PDF and SARIF. Summary job/tool labels omit absolute local roots;
raw API job records remain available to authorized operators.

Finding tenant/lifecycle filters and limits run in SQL before ORM materialization.
Evidence and repositories load in batches; finding summaries use SQL counts/grouping,
with bounded priority, trend, graph and comparison queries. Tests cover 300 findings,
tenant separation, zero/negative limits and bounded finding/evidence loading.
Asset-name and ancillary observation arrays retain their existing scope semantics
and can still grow; report encoding is in memory. This is not a streaming exporter
or deployment-scale performance certification. Existing unrelated dashboard analytics
continue to have decomposition/query-efficiency work outstanding.

## Phase 25: complete projection safety

`reports/projection.py::safe_report_projection` sanitizes the complete logical model
with ordinary source context before formats receive it. It uses the shared bounded
redactor; there are no format-specific credential patterns. `query_report`, summary
queries and compatibility `finding_rows` retain source knowledge until this boundary.
No untrusted ORM fields are appended afterward. Format adapters retain their defensive
redaction and output-field exclusions.

The inventory below describes the projection and its non-exported context:

| Surface | Projected fields covered by final sanitization | Additional source context |
| --- | --- | --- |
| Finding | ID; title/description; category/severity/confidence; status and lifecycle timestamps/counts; triage state/owner/notes; remediation due date/hint; scanner/source names; repository/job IDs; risk score; detected time; fingerprint; repository display name | Every ordinary string/JSON column on the finding, including metadata, raw payload and remediation text; loaded repository/job source fields |
| Evidence | Scanner/source; logical path; line range; commit/ref; safe source URL; query; observed time; confidence; observation fingerprint | Every ordinary string/JSON evidence column, including metadata, snippets, extracted indicators, original URLs and provider context; evidence job parameters |
| Relationships | Node IDs/types/labels/degrees; edge endpoints/type/confidence/source/provenance; graph breakdowns | Ordinary relationship columns, including omitted evidence summaries; visible endpoint asset records and finding/evidence context |
| Summary | Counts/breakdowns; organization/repository/account names; domain exposure previews; identity correlations; trends; organization comparisons; remediation suggestions; recent jobs/tool runs; priority findings/assets; schedules | Complete authorized source populations, independently of priority ranking, grouping, graph endpoints or displayed pages; one bounded column query |
| Delivery | JSON/CSV/HTML/PDF/SARIF and manual/API/scheduled report payloads | All consume the sanitized model; scheduler adds operational schedule/output identifiers, never raw finding/evidence columns |

Raw payloads/snippets/indicators are context only and remain excluded from normal
exports. Protected evidence is never queried or decrypted for report construction.
Reports do not require the encryption key, mutate ciphertext, or create reveal audits.
Authorized tenant-scoped reveal remains the only intentional plaintext operation.

Detailed finding filters/limits and select-in evidence loading remain in storage.
Summary counts still cover all authorized rows. Phase 26 context uses one UNION ALL
column query over findings, evidence, organizations, repositories, accounts, domains,
domain exposures, identity correlations, relationships, scan jobs, tool runs, scheduled
scans and scheduled reports, with queued-task diagnostic sources included from
Phase 27. Queue context inherits
the scheduled scan's tenant visibility. Every authorized contributor participates,
including rows outside all displayed pages, rankings and groups. This covers source
tool/category labels, copied previews, remediation groups and provenance. Context
selection intersects requested tenant scope with inherited/request authorization.

Only ordinary string/JSON columns are loaded, excluding identity/fingerprint references;
no source ORM graph or protected evidence is loaded. Descriptions and raw payloads must
participate because credentials can be identified there. SQL bounds each value before
fetching, and shared character/node/depth/replacement budgets still apply. The default
`ORGSCAN_REPORT_CONTEXT_MAX_ROWS=10000` counts source rows across these populations
(a finding and its evidence count separately). Configure this environment setting
before starting the process; its maximum is 100,000. Overflow or uninspectable context
raises an input-free safety error: no partially sanitized report is returned. Increasing
the row limit does not bypass the sanitizer's other work limits. Context sources
are processed in 128-row batches with shared credential knowledge, an aggregate
500,000-node bound and the existing 8-million-character bound.

The same private credential knowledge sanitizes the summary and complete report after
projection. It is never reconstructed from the displayed subset. Large tenant datasets
may require adjusting the context budget; repairing legacy data alone does not remove
the completeness check. Evidence queries remain batched, with no N+1 reads.

There is no built-in queued-report job type. The regression suite exercises an RQ
caller invoking the existing report service with explicit tenant scope; it does not
add queue scheduling, authorization policy or a new production report job API.
