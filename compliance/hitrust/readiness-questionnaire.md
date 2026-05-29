# Chio HITRUST i1 Readiness Questionnaire (Internal Self-Assessment)

> **Status: internal self-assessment / readiness.** No external HITRUST
> assessment has been performed and no assessor is engaged. These are
> Chio's own answers to the scope and readiness questions a future i1
> engagement would ask, grounded in repository evidence.

**Framework target:** HITRUST CSF v11.7 i1
**Scope:** Chio (this assessed release), one healthcare design-partner tenant, one deployment environment

## Scope answers

| Question | Answer | Evidence |
|----------|--------|----------|
| Which product is assessed? | This assessed Chio release only. | `compliance/hitrust/scope-boundary.md` |
| Which tenant is in scope? | One healthcare design-partner tenant; identity is not bound in public docs. | scope boundary |
| Which environment is in scope? | One production deployment environment. | `compliance/hitrust/ssp.md` |
| Are mobile surfaces included? | No. Mobile patient-app is explicitly excluded. | scope boundary |
| Are AWS Bedrock and MCP marketplace surfaces included? | No. Explicitly excluded. | scope boundary |
| Are other operator systems included? | No. Non-Chio systems are out of scope. | scope boundary |

## Self-assessed readiness by family

| Family | Self-assessed posture | Evidence state |
|--------|-----------------------|----------------|
| Information Security Management Program | partial | governance documented; review cadence is a gap |
| Access Control | implemented | capability algebra, sender constraints, revocation (kernel crates, formal proofs) |
| Human Resources Security | gap | out-of-tree HR corpus needed |
| Risk Management | implemented | threat model and coverage |
| Security Policy | implemented | `spec/SECURITY.md` and docs security corpus |
| Organization of Information Security | partial | ownership documented for formal evidence only |
| Compliance | partial | self-assessment only |
| Asset Management | implemented | SBOM and cargo-vet evidence |
| Physical and Environmental Security | gap | cloud-provider inheritance not collected |
| Communications and Operations Management | partial | schema, CI, receipt pipeline exist; production samples are a gap |
| Systems Acquisition, Development, and Maintenance | implemented | provenance, supply chain, formal evidence |
| Incident Management | partial | runbook documented; first-cycle execution is a gap |
| Business Continuity Management | gap | DR posture out of tree |
| Privacy Practices | partial | redaction implemented and de-id policy documented; BAA/PHI out of tree |

## BAA and PHI answers

- This package uploads no PHI-bearing samples anywhere.
- BAA chain references are out-of-tree legal artifacts and are not held
  in this repository.
- The minimum-necessary and telemetry de-identification posture is
  documented in `compliance/hitrust/policies/de-identification.md`.
- The breach-notification runbook is `compliance/hitrust/ir-runbook.md`.

## Fail-closed readiness rule

A family is marked `implemented` only when it has a real source artifact
in the repository and an owner. Otherwise it is `partial` or `gap`. No
family is promoted on the basis of an assessor interaction, because none
has occurred.
