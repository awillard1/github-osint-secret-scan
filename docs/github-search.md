# GitHub public search

The existing `github-search` domain provider delegates to `services/github_search.py`. Use:

```bash
orgscan discover domain example.org --provider github-search --json
orgscan discover organization Example --provider github-search --tenant-key example --json
```

The query builder accepts one to three literal target identifiers, each 2–100 characters with no query operators, quotes or control characters. It searches repository metadata/readmes, code, issues, and `.env`, `credentials.json` and `id_rsa` filenames paired with the identifier. The service supports a maximum of three pages and 100 items per page; CLI/provider defaults are one page of ten results per query. It constructs pagination URLs itself rather than following arbitrary response links.

Configured GitHub tokens are sent as Bearer credentials. Code search is skipped with a warning when no token is configured. Requests reuse outbound rate limiting under `github-search`, with a default minimum seven-second interval; existing scope overrides still apply. Response rate-limit headers, reset/retry timing, page numbers, page size, exact query, timestamp, endpoint and incomplete-result flags are recorded on a normal `github-search` ScanJob. Even zero-result requests are recorded. Inspect them with `orgscan jobs --json`, the additive `/scan-jobs/{id}` JSON route, or the existing browser job detail page. Reported exhaustion or a request failure stops the search, marks that job failed with safe diagnostics, and returns partial results plus warnings. This phase does not introduce automatic retries. See GitHub's [search documentation](https://docs.github.com/en/rest/search/search) and [rate-limit guidance](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

Results create or reuse normal repositories/accounts, canonical `public-reference` findings, evidence and graph relationships. Domain searches continue to populate domain exposures and identity correlations. Exact target/resource identities deduplicate repeated searches; each distinct query remains evidence on the same finding. Search jobs retain per-request history. Sensitive filenames raise review priority but do not prove a secret is present. Findings and target-reference edges remain heuristic. An API repository owner field supports an owner → repository edge; it never assigns the searched organization's ownership to an outside repository. Explicit organization tenant scope applies to the search target and its findings.

Raw code snippets, issue bodies, repository descriptions and issue titles are not persisted from search responses. Resource URLs/paths, query identifiers and provenance support review at the source. Consequently issue summaries now show repository/issue number instead of arbitrary issue titles. Existing exposure records remain; no historical hash backfill is attempted. Source-only counts and scan-job totals can increase with these additional normal records.

Limits: bounded public indexing is not complete internet or GitHub coverage. Results can be stale, partial or unavailable under token permissions. No ownership or employee inference is made from a string match. Tests mock GitHub transport, authentication, rate-limit responses, pagination and persistence; they do not certify live service availability. HTTP access now uses the shared [browser/API authorization](browser-auth.md) boundary.


## Public visibility enforcement (Phase 19)

Repository and issue queries explicitly use `is:public`. The REST code endpoint uses
[legacy code-search qualifiers](https://docs.github.com/en/search-github/searching-on-github/searching-code),
which document `repo:owner/name`, not `is:public`. Code queries therefore carry at most
five sorted repository qualifiers drawn from affirmative public repository results
in the same bounded search. With no such repository, code search is skipped with a
warning. This narrows coverage; it is not a global public code search.

Every ingested result independently requires `private: false` or
`visibility: public`. Any private/internal, invalid or contradictory visibility field
rejects the result. Missing visibility is rejected, including issue payloads without
repository visibility. Code results must also match the requested repository scope.
Stored repositories already marked private are not reclassified as public. Accepted
finding/evidence metadata retains the visibility observations and `verified_public`.

A configured credential may access private data, but must not expand this public
OSINT ingestion boundary. Both query restrictions and result validation apply with
authentication. No private result metadata is retained as a skipped-result warning.
All HTTP responses use the configured byte limit and request deadline.
