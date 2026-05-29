# Operational Audit-Log Sample Plan

> **Status: internal readiness / gap.** No 30-day operational sample has
> been pulled and no assessor is engaged. This records the schema and the
> intended sample-selection method; the samples themselves are an open
> gap.

**Schema:** `spec/audit-log/export-schema.v1.json` (exists in repo)
**Scope:** Chio healthcare design-partner deployment (this assessed release)

## Sample source

A future bounded operational profile would draw 30-day audit-log samples
from a production deployment. The public repository defines the export
schema and the sample classes below. Tenant-private, PHI-bearing records
remain out-of-tree and would be handled only through an approved BAA
evidence channel, never committed to this repository.

## Intended sample classes

| Sample class | Source | Public content | Private handling |
|--------------|--------|----------------|------------------|
| allow decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| deny decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| revoked-capability decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| guard-deny decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| export-integrity checks | audit-log export pipeline | schema hash and export hash | private tenant export receipt |

## Public evidence (in-repo)

- Audit-log schema: `spec/audit-log/export-schema.v1.json`
- Receipt store implementation: `crates/chio-kernel/src/receipt_store.rs`
- Scope boundary: `compliance/hitrust/scope-boundary.md`

## Fail-closed rule

If a sample contains PHI or tenant-private identity data, it is excluded
from any public artifact and represented only by a hash plus a private
evidence reference. As of this writing, no samples have been pulled; this
remains an open gap in the gap self-assessment.
