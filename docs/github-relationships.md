# GitHub relationship intelligence

`GitHubExpansionEngine` now lives in `services/relationship_service.py`; `expansion.py` retains compatibility exports. CLI repository/organization discovery uses the same repository ingestion service as expansion. Existing graph JSON, entity detail JSON and server-rendered graph pages expose provenance from stored relationships. No parallel graph store or schema migration is introduced.

| Relationship | Direction | Confidence and evidence |
| --- | --- | --- |
| `owns` | organization/account → repository | Verified GitHub repository owner field. |
| `fork_of` | fork repository → parent repository | Verified listing from the parent repository's forks endpoint. |
| `contributes_to` | account → repository | Likely association from the contributor listing; no employment or ownership inference. |
| `mentions` | repository → domain | Heuristic domain in a homepage/description URL or a commit author's self-reported email domain. |
| `used_email_domain` | account → domain | Heuristic association between GitHub-linked commit author and self-reported author email domain; neither employment nor domain ownership is established. |

Each edge retains source, API endpoint/URL, reason, supporting URL or commit SHA where available, and first/latest observation timestamps. Repeated observations update the same edge. Provenance retains up to 50 distinct supporting records per edge. Existing stronger confidence is retained. Repository discovery metadata is merged without destroying mirror/checkpoint state.

Repository expansion now fetches repository metadata and a bounded recent commit page as well as contributors and forks. Limits are 1–100 records per list endpoint; this is not exhaustive history or pagination. Email local parts are not retained in relationship provenance. Invalid domain-shaped values and GitHub noreply domains are skipped. No DNS ownership validation is implied by syntactic domain extraction.

Compatibility: `fork_of` previously pointed from parent to fork. Fresh expansion corrects only a matching old unannotated `github-api` edge and stores the supported fork → parent edge. Historical edges not observed again, annotated edges and other sources remain untouched. CLI command/output keys remain; relationship counts can increase because more evidence types are recorded. New source/provenance fields in graph/entity responses are additive. Graph output escapes provenance before rendering.

Tests fake GitHub responses, including mismatched ownership, repeated expansion, populated legacy fork correction, provenance, checkpoint preservation, email privacy and HTML escaping. Live GitHub completeness/permissions and distributed ingestion races remain unverified. HTTP access now uses the shared [browser/API authorization](browser-auth.md) boundary.
