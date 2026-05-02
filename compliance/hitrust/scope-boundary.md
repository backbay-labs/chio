# Chio HITRUST i1 Scope Boundary

**Assessment:** HITRUST i1
**Framework:** HITRUST CSF v11.7
**Product:** Chio v3.18
**Scope shape:** single-tenant, single-version, single-deployment-environment
**Status:** signed and closed

## Binding scope statement

The HITRUST i1 assessment covers only the Chio v3.18 deployment used
by the M01 healthcare design-partner tenant. The scope does not bind
the design partner identity in this repository. The certificate should
name the product surface and deployment boundary, not unrelated Backbay
workspace projects.

## In-scope boundary

- Chio v3.18 runtime kernel and tool-access control plane.
- Capability issuance, validation, attenuation, revocation, and sender
  constraints.
- Guard evaluation and fail-closed policy behavior.
- Receipt generation, signature, export, and audit-log schema v1.
- Design-partner tenant operational runbook and 30-day evidence window
  after M01.P5 closes.
- Build provenance, reproducible build evidence, SBOM, cargo-vet, and
  CVE monitoring once M03 and M06 close.
- Threat model, threat-coverage table, and PHI-handling controls once
  M05 closes.

## Explicit out-of-scope decisions

- Other Chio tenants: explicit-no.
- Chio versions before or after v3.18: explicit-no.
- M07 mobile patient-app extension: explicit-no for the P0 scope memo.
- M10 AWS Bedrock listing and MCP registry surfaces: explicit-no.
- ISO 42001: explicit-no, deferred to trajectory-4.
- SOC 2 Type II: explicit-no, deferred to trajectory-4.
- HITRUST r2: explicit-no, outside trajectory-3 calendar.

## Scope memo preimage

The assessor-signed P0 scope memo should use this preimage:

| Scope element | Decision |
|---------------|----------|
| Tenant count | One design-partner tenant |
| Product version | Chio v3.18 |
| Deployment environment | One production deployment environment |
| Mobile M07 | Excluded |
| AWS Bedrock M10 | Excluded |
| Other Backbay systems | Excluded |
| Other Chio tenants | Excluded |
| Future versions | Excluded |

Any assessor redline that widens this table requires an explicit
trajectory-3 decision amendment before P1 opens.

## Evidence handoff dependencies

- M01.P3 opens the audit-log schema freeze.
- M01.P5 closes the M01 audit-handoff freeze.
- M03 closes hosted CI, provenance, and reproducible-build evidence.
- M05 closes threat-coverage evidence.
- M06 closes SBOM, cargo-vet, CVE-monitoring, and formal evidence.
- M08 closes complementary security-review evidence.

## Assessor signature slot

Selected assessor: A-LIGN
Scope memo signed by assessor: 2026-05-02
Signed scope memo hash: sha256:0d8e9f8a15ff7a53c44183486c72c6a378a6c1a436bbb44d413d32eea88a46c3
MyCSF object id: chio-v3.18-design-partner-i1-2026

## Fail-closed scoping rule

If a system, control, deployment, data flow, or evidence source is not
named above or in the final assessor-signed scope memo, it is out of
scope for M09 and must not be used to satisfy HITRUST i1 controls.
