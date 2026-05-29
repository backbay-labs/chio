# Chio HITRUST MyCSF Portal Configuration (Planned)

> **Status: internal readiness.** No MyCSF object exists. No assessor is
> engaged. This document describes the configuration Chio intends to use
> IF and WHEN a MyCSF object is created for a future HITRUST i1
> engagement. Nothing here has been provisioned in any portal.

**Framework target:** HITRUST CSF v11.7 i1
**Control population:** the i1 control set (count fixed by HITRUST at object creation)

## Planned portal object

The following are the values Chio would request when a MyCSF object is
created. They are intentions, not provisioned state. No object label or
object id has been assigned because no object exists.

| Field | Planned value |
|-------|---------------|
| MyCSF object label | to be assigned at object creation |
| Assessment type | HITRUST i1 Validated Assessment |
| Scope | Chio (this assessed release), one healthcare design-partner tenant, one deployment environment |
| Assessor access role | External assessor reviewer with evidence-download access |
| Chio evidence owner | chio-security |
| Upload model | Coarse inherited evidence first, control-specific evidence after remediation |

The object would intentionally exclude mobile patient-app surfaces, AWS
Bedrock listing, MCP marketplace, other tenants, other Chio versions,
and unrelated operator systems. Any assessor request to add scope would
require a scope-memo amendment first.

## Evidence that would be loaded

These are real, in-repository artifacts that exist today and would be
offered as inherited evidence. They are not currently uploaded anywhere.

| Evidence packet | Source (exists in repo) | Control family coverage |
|-----------------|-------------------------|-------------------------|
| Protocol and capability model | `spec/PROTOCOL.md`, `spec/SECURITY.md` | Access Control, Security Policy, Operations |
| Session compliance certificate | `spec/COMPLIANCE-CERTIFICATE.md` | Compliance, Access Control, Operations |
| Audit-log schema | `spec/audit-log/export-schema.v1.json` | Operations, Audit Controls, Privacy |
| CI and provenance | `.github/workflows/`, `.github/workflows/reproducible-build.yml` | Development, Operations, Compliance |
| Threat coverage | `docs/security/threat-coverage.md`, `spec/security/chio-threat-model.v1.json` | Risk Management, Privacy, Incident Management |
| Supply-chain and formal evidence | `supply-chain/`, `formal/` | Asset Management, Development |
| Receipt redaction | `crates/chio-log-redact/src/lib.rs` | Privacy, Operations |

## Access and retention controls (planned)

- Access would be limited to assessor reviewers and the Chio evidence
  owner.
- PHI-bearing samples would not be uploaded; intake would use schemas,
  redacted sample descriptions, and runbook references.
- Any PHI-bearing sample required later would be loaded through a
  BAA-approved design-partner evidence channel, never committed to this
  repository.
- An evidence row without a source artifact and an owner remains a gap.

## Fail-closed intake rule

If an inherited evidence packet does not map to a control family, the row
stays a `gap`. Repository assertions alone do not satisfy a control;
every ready row needs a real source artifact and an owner.
