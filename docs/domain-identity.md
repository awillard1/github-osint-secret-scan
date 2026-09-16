# Global domain identity and tenant associations

## Model and compatibility

Before revision 0016, `domains.name` was globally unique and its row combined DNS
identity with private organization ownership, observations and lifecycle state.
A second tenant therefore could not assess the same name.

After revision **20260916_0016**:

- `DomainIdentity` / `domain_identities`: only `id` and unique `normalized_name`.
- `Domain` / `domains`: the **tenant-domain association**, retaining its historical
  class/table name and primary key for compatibility. It references `identity_id`
  and stores `tenant_key` and private state. `(tenant_key, identity_id)` is unique.
- Findings, exposures, correlations, jobs, relationship endpoints and assessment
  membership retain their existing association IDs. No private reference is moved
  onto the global identity. Public APIs continue to use association IDs.

Thus two tenants assessing `api.example.com` have one global identity and two
private Domain association rows. Two assessments in one tenant reuse the same
association without moving its original organization anchor. Global identities
have no public inventory endpoint and confer no visibility. The assessment DTO
omits their internal IDs; the UI continues showing the domain name.

## Complete field classification

| Existing Domain field | Classification | Destination / meaning |
|---|---|---|
| `id` | TENANT-SCOPED | Stable association ID; all existing references preserved |
| `name` | GLOBAL IDENTITY, legacy denormalized copy | Normalized identity in the new table; compatibility name retained on the private row |
| `organization_id` | TENANT-SCOPED | Immutable original owner anchor, never moved on same-tenant reuse |
| `ownership_confidence` | TENANT-SCOPED | Tenant's ownership assessment |
| `verification_status` | TENANT-SCOPED | Tenant's verification decision |
| `discovered_emails` | TENANT-SCOPED | Private provider-derived intelligence |
| `discovered_subdomains` | TENANT-SCOPED | Private discovery history |
| `discovery_sources` | TENANT-SCOPED | Private source coverage |
| `risk_score` | TENANT-SCOPED | Tenant's risk assessment |
| `created_at` | TENANT-SCOPED | Association first creation, not global discovery time |
| `updated_at` | TENANT-SCOPED | Association last mutation |
| `organization` relationship | TENANT-SCOPED | Owner anchor |
| `exposures` relationship | TENANT-SCOPED | Provider evidence referencing association ID |
| `identity_correlations` relationship | TENANT-SCOPED | Private identity intelligence |

No existing private field becomes global. Assessment selection, confidence, source
observations, first/last observation times and reasons stay **ASSESSMENT-SCOPED** in
`AssessmentEntity`. New `identity_id` is an internal reference, and new `tenant_key`
is tenant-scoped. The duplicated name is retained for API/query compatibility;
new ORM writes normalize it and prevent changing identity/tenant/owner in place.

## Resolution and providers

`storage/domain_identity.py` is the shared resolution implementation behind Storage.
Callers supply an organization in the intended tenant; existing associations can
also be looked up using explicit tenant context. DNS identities normalize case,
a terminal dot and IDNA encoding. Global identity insertion uses a unique key and
atomic conflict handling on SQLite/PostgreSQL. Association uniqueness is enforced
by the database; concurrent association insertion may require transaction retry.

Assessment ingestion, repository references and discovery resolve through their
owner context. ScanPlans retain association ID, organization and tenant. Legacy
providers execute within a bounded `domain_scope` that is restored even on failure;
nested providers inherit it. A name-only mutating provider call cannot select an
owned association. Ambiguous name-only reads fail rather than choosing a tenant.
Direct legacy provider callers must use `discover_context` for owned domains.

Exposure and domain-finding fingerprints now include the association ID. Existing
legacy hashes remain reusable only on the same association; they are not rewritten.
This prevents identical upstream output from updating another tenant's observations.
Canonical finding references, encrypted SecretEvidence, key handling and exact Reveal
are otherwise unchanged.

## Authorization, projection and legacy data

Visibility continues to derive from the private association's organization, with
an additional tenant-key check. Findings retain authoritative explicit ownership;
exposures/correlations inherit association visibility; relationships require both
endpoints; assessments require membership and tenant visibility. Complete tenant
credential context remains mandatory before graph/report/UI/AI projection.

An unassigned legacy association belongs to the existing **legacy/local scope**,
not every tenant. It retains its ID and private data. A tenant discovering its name
creates a separate association sharing only the global DNS identity. Discovery no
longer implicitly claims legacy observations. Organizations without a tenant also
remain legacy scope; a partial unique index prevents duplicate legacy associations.
An organization anchoring domain associations cannot implicitly change their tenant
by claiming a legacy organization. Both storage claims and ORM mutations reject a
mismatched tenant anchor; explicit reconciliation is required. This is a domain
integrity guard, not an organization identity migration.

## Upgrade policy

Stop writers, back up, and validate a copy before explicit deployment migration.
This phase does **not** run migrations against configured application data.
Revision 0016 follows frozen 0015; previous migration files and snapshots are unchanged.

Preflight validates all names and detects normalization collisions **within the same
tenant/legacy scope before DDL**. Such a collision stops with row-ID-only diagnostics.
Invalid names also stop without echoing their content. Preflight has a one-million
association budget; larger deployments require an explicitly reviewed migration.
Different tenants' overlapping normalized names are safe: only identity is shared.
No tenant is chosen arbitrarily, no association/private row is merged, no evidence is
decrypted, and no private reference is reassigned. All lifecycle/evidence rows remain.
The migration copies the SQLite association table to add its FK and constraints;
normal orgscan migration connections use SQLite's existing foreign-key configuration.
Disposable tests verify post-upgrade foreign-key integrity.

Automatic downgrade is refused because globally unique names cannot represent the
new independent tenant associations. Rollback requires a verified pre-upgrade backup.
PostgreSQL SQL paths exist but require deployment-specific live migration validation.

## Other assets (review only)

| Asset | Classification | Reason |
|---|---|---|
| Organization | NEEDS ASSOCIATION MODEL | Global unique name combines identity and tenant ownership; conflicting ownership currently fails closed |
| Repository | NEEDS ASSOCIATION MODEL | Global full-name identity retains ownership; assessment ingestion uses connection-qualified keys, but independent tenant-global reuse is not general |
| Account | NEEDS ASSOCIATION MODEL | Global username plus owner; assessment connection prefixes isolate instances but are not a general tenant association design |
| Assessment membership | ALREADY ASSOCIATION-BASED | Explicit assessment/entity membership adds assessment-local selection and provenance |
| ReconAsset | SAFE within current supported model | Organization-scoped unique identity, no global private-data reuse |

No organization/repository/account ownership migration is included in this phase.
