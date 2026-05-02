# Chio HITRUST MyCSF Portal Provisioning

**Trajectory:** trajectory-3
**Milestone:** M09.P1
**Assessment:** HITRUST i1 readiness and validated assessment
**Framework:** HITRUST CSF v11.7 i1
**Control population:** 182 controls in scope
**Status:** provisioned for assessor gap-assessment intake

## Portal object

| Field | Value |
|-------|-------|
| MyCSF object label | `chio-v3.18-design-partner-i1-2026` |
| Assessment type | HITRUST i1 Validated Assessment |
| Scope | Chio v3.18, one healthcare design-partner tenant, one deployment environment |
| Assessor access role | External assessor reviewer with evidence-download access |
| Chio evidence owner | M09 vendor-coord lane |
| Upload model | Coarse inherited evidence first, control-specific evidence after P2 remediation |

The object intentionally excludes M07 mobile, M10 AWS Bedrock, other
tenants, other Chio versions, and unrelated Backbay systems. If the
assessor requests any additional scope, the row remains out of scope
until the scope memo is amended.

## Inherited evidence preload

The initial portal load uses coarse inherited evidence. These are not
control-final uploads; they are intake artifacts so the assessor can
run the P1 walkthroughs and produce the gap report.

| Evidence packet | Source | Control family coverage | Portal status |
|-----------------|--------|-------------------------|---------------|
| Protocol and capability model | `spec/PROTOCOL.md`, `spec/SECURITY.md` | Access Control, Security Policy, Communications and Operations | preloaded |
| Session compliance certificate | `spec/COMPLIANCE-CERTIFICATE.md` | Compliance, Access Control, Operations | preloaded |
| M01 audit-log schema and pilot audit doc | `spec/audit-log/export-schema.v1.json`, `.planning/trajectory-3/audits/M01-healthcare-pilot.md` | Operations, Audit Controls, Privacy | preloaded as inherited evidence |
| M03 CI and provenance audit doc | `.planning/trajectory-3/audits/M03-ci-restoration.md`, `.github/workflows/**` | Development, Operations, Compliance | preloaded as inherited evidence |
| M05 threat coverage | `docs/security/threat-coverage.md`, `spec/security/chio-threat-model.v1.json` | Risk Management, Privacy, Incident Management | preloaded as inherited evidence |
| M06 supply-chain and formal evidence | `supply-chain/**`, `formal/**`, `.planning/trajectory-3/audits/M06-supply-chain.md` | Asset Management, Development, Business Continuity | queued pending assessor row mapping |
| M08 independent review | `.planning/trajectory-3/audits/M08-vendor-evidence.md`, `releases/audit-reports/` | Complementary security evidence | preloaded as supplemental evidence |

## Access and retention controls

- Access is limited to assessor reviewers and the Chio evidence owner.
- Downloads are logged as evidence-retention events in the audit doc.
- PHI-bearing samples are not uploaded during P1. The P1 gap assessment
  uses schemas, redacted sample descriptions, and runbook references.
- Any PHI-bearing sample required later must be loaded through the
  BAA-approved design-partner evidence channel.
- Evidence rows without a signed source, frozen audit doc, or explicit
  out-of-tree owner remain `gap`.

## Fail-closed intake rule

If an inherited evidence packet does not map to a control family, the
portal row stays in `gap` status. The assessor cannot rely on repository
assertions alone; every ready row needs a source artifact and an owner.
