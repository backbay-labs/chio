# Chio HITRUST i1 Scope Boundary

> **Status: internal self-assessment / readiness.** No external HITRUST
> assessment has been performed; no assessor is engaged; no certification
> is claimed. This document defines the intended assessment scope for a
> future HITRUST i1 engagement and is internal, self-authored material.

**Target assessment:** HITRUST i1
**Framework target:** HITRUST CSF v11.7
**Product:** Chio (this assessed release)
**Intended scope shape:** single-tenant, single-version, single-deployment-environment
**Status:** internal scope definition (not assessor-signed)

## Binding scope statement

If and when a HITRUST i1 assessment is undertaken, the intended scope
covers only the assessed Chio deployment used by a single healthcare
design-partner tenant. The scope is not meant to bind any design-partner
identity in this repository. A future certificate should name the
product surface and deployment boundary, not unrelated workspace
projects.

## In-scope boundary

- Chio runtime kernel and tool-access control plane (this assessed release).
- Capability issuance, validation, attenuation, revocation, and sender
  constraints.
- Guard evaluation and fail-closed policy behavior.
- Receipt generation, signature, export, and audit-log schema v1.
- Design-partner tenant operational runbook and post-deployment evidence
  window.
- Build provenance, reproducible build evidence, SBOM, cargo-vet, and
  CVE monitoring.
- Threat model, threat-coverage table, and PHI-handling controls.

## Explicit out-of-scope decisions

- Other Chio tenants: explicit-no.
- Other Chio releases (before or after the assessed release): explicit-no.
- Mobile patient-app extension: explicit-no for this intended scope.
- AWS Bedrock listing and MCP registry surfaces: explicit-no.
- ISO 42001: explicit-no, deferred.
- SOC 2 Type II: explicit-no, deferred.
- HITRUST r2: explicit-no.

## Scope memo preimage

If an assessor engagement begins, a scope memo would use this preimage:

| Scope element | Decision |
|---------------|----------|
| Tenant count | One design-partner tenant |
| Product version | This assessed release |
| Deployment environment | One production deployment environment |
| Mobile patient-app | Excluded |
| AWS Bedrock listing | Excluded |
| Other operator systems | Excluded |
| Other Chio tenants | Excluded |
| Future versions | Excluded |

Any future assessor redline that widens this table would require an
explicit internal decision amendment before any assessment work begins.

## Evidence handoff dependencies

The following internal evidence sources back the in-scope controls. They
already exist in this repository (see `control-mapping.csv`):

- Audit-log export schema: `spec/audit-log/export-schema.v1.json`.
- Hosted CI, provenance, and reproducible-build evidence:
  `.github/workflows/`, `supply-chain/`.
- Threat-coverage evidence: `docs/security/threat-coverage.md`,
  `spec/security/chio-threat-model.v1.json`.
- SBOM, cargo-vet, CVE-monitoring, and formal evidence:
  `supply-chain/`, `formal/`.

## Assessor engagement status

Chio has NOT undergone a formal HITRUST assessment. No HITRUST-authorized
External Assessor has been selected or engaged. No MyCSF object has been
created. No scope memo has been signed. The fields a real engagement
would populate (selected assessor, signed scope-memo hash, MyCSF object
id) are intentionally left unset until a real engagement begins.

## Fail-closed scoping rule

If a system, control, deployment, data flow, or evidence source is not
named above, it is out of scope for this readiness material and must not
be used to claim a HITRUST i1 control is satisfied.
