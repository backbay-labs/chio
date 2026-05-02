# M01 Bounded Operational Profile Sample Pull

**Milestone:** M09.P3.T2
**Source milestone:** M01.P5
**Schema:** `spec/audit-log/export-schema.v1.json`
**Status:** repository sample manifest ready for assessor bundle

## Sample source

M01.P5 closed the audit handoff and made the 30-day bounded operational
profile source available for M09. The public repository records schema,
hash, and sample-selection metadata. Tenant-private PHI-bearing records
remain outside the repository and must be uploaded through the approved
assessor evidence channel.

## Pull manifest

| Sample class | Source | Public bundle content | Private evidence handling |
|--------------|--------|-----------------------|---------------------------|
| allow decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| deny decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| revoked capability decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| guard-deny decisions | receipt export using schema v1 | counts and schema reference | redacted receipt sample hash |
| export-integrity checks | audit-log export pipeline | schema hash and export hash | private tenant export receipt |

## Public evidence

- Audit-log schema: `spec/audit-log/export-schema.v1.json`
- M01 audit doc: `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
- M09 scope boundary: `compliance/hitrust/scope-boundary.md`

## Fail-closed rule

If a sample contains PHI or tenant-private identity data, it is excluded
from this public bundle and represented only by a hash plus private
assessor-upload reference.
