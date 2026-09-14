# Canonical reports

CLI exports, static dashboards, HTTP report downloads and scheduled exports use
`ReportService` / `query_report` over the existing canonical finding/evidence storage.
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
