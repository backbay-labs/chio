# Chio HITRUST i1 Readiness Package

> **Status: internal self-assessment / readiness.** This is a HITRUST i1
> readiness package, not an issued certificate. No HITRUST-authorized
> External Assessor (e.g., A-LIGN, Coalfire, Schellman) has performed an
> audit. No assessor is engaged. No MyCSF object exists. Real HITRUST i1
> certification is future work.

**Status:** readiness-draft (no External Assessor engaged)
**Target assessment type:** HITRUST Implemented, 1-year (i1) Validated Assessment
**Framework target:** HITRUST CSF v11.7 i1
**Control population:** the i1 control set (count fixed by HITRUST at MyCSF object creation)
**Subject system:** Chio design-partner deployment (this assessed release)
**Target external assessor:** none engaged
**Issuance date:** none (no assessment performed)
**Expiration date:** none (no assessment performed)
**MyCSF object:** none (no object created)

## Bound scope

This readiness record binds only the assessed Chio deployment used by a
single healthcare design-partner tenant. It excludes mobile patient-app
surfaces, AWS Bedrock and MCP marketplace surfaces, other Chio tenants,
other operator systems, and other Chio releases. The bound scope would
remain the same if a real External Assessor engagement begins.

## Repository evidence

The readiness posture is grounded in artifacts that actually exist in
this repository. There is no frozen evidence bundle and no draft report;
prior versions referenced a fabricated bundle and have been removed.

| Evidence | Path (exists in repo) |
|----------|-----------------------|
| Control mapping | `compliance/hitrust/control-mapping.csv` |
| System security plan | `compliance/hitrust/ssp.md` |
| Scope boundary | `compliance/hitrust/scope-boundary.md` |
| Gap report | `compliance/hitrust/gap-report/gap-report.md` |
| Incident runbook | `compliance/hitrust/ir-runbook.md` |
| Formal evidence | `formal/MAPPING.md`, `formal/proof-manifest.toml` |
| Supply-chain evidence | `supply-chain/audits.toml`, `supply-chain/imports.lock` |
| Threat coverage | `docs/security/threat-coverage.md` |

## Certification status

No external HITRUST certificate exists. No QA receipt, certificate
receipt, or certificate scan exists, because no assessment has been
performed. This file is the public, reviewable readiness record; it does
not assert an issued HITRUST certificate and never represents a future
engagement as having occurred.
