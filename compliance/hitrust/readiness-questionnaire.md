# Chio HITRUST i1 Readiness Questionnaire

**Trajectory:** trajectory-3
**Milestone:** M09.P1
**Framework:** HITRUST CSF v11.7 i1
**Scope:** Chio v3.18, one healthcare design-partner tenant, one deployment environment
**Status:** completed for P1 gap-assessment intake

## Scope answers

| Question | Answer | Evidence |
|----------|--------|----------|
| Which product is assessed? | Chio v3.18 only. | `compliance/hitrust/scope-boundary.md` |
| Which tenant is assessed? | One healthcare design-partner tenant; identity is not bound in public docs. | M01 audit lane |
| Which environment is assessed? | One production deployment environment. | SSP boundary |
| Are mobile surfaces included? | No. M07 is explicitly excluded from this i1 scope. | Scope boundary |
| Are AWS Bedrock and MCP marketplace surfaces included? | No. M10 is explicitly excluded from this i1 scope. | Scope boundary |
| Are other Backbay systems included? | No. Non-Chio workspace systems are out of scope. | Scope boundary |

## Readiness summary by family

| Family | P1 posture | Evidence state | P2 action |
|--------|------------|----------------|-----------|
| Information Security Management Program | partially ready | trajectory-3 governance docs exist | bind owner evidence and review cadence |
| Access Control | ready with inherited evidence | capability algebra, sender constraints, revocation | control-row mapping and sample receipts |
| Human Resources Security | gap | out-of-tree HR corpus needed | collect HR policy reference |
| Risk Management | ready with inherited evidence | M05 threat model and coverage | link gap rows to risk register |
| Security Policy | ready with inherited evidence | `spec/SECURITY.md` and docs security corpus | assessor review for wording precision |
| Organization of Information Security | partially ready | trust-boundary freezes and owner review | attach security reviewer evidence |
| Compliance | partially ready | SSP, scope boundary, audit doc | evidence-pack script and portal records |
| Asset Management | partially ready | M06 SBOM and cargo-vet evidence | final MyCSF row mapping |
| Physical and Environmental Security | gap | cloud-provider inheritance needed | provider evidence reference |
| Communications and Operations Management | partially ready | M01 runbook, CI, receipt pipeline | sample-control mapping |
| Systems Acquisition, Development, and Maintenance | partially ready | M03 provenance, M06 supply chain, formal evidence | plain-English formal evidence bridge |
| Incident Management | gap | P2 runbook pending | author HIPAA breach-notification runbook |
| Business Continuity Management | gap | design-partner DR posture out of tree | collect DR reference |
| Privacy Practices | gap | PHI boundary and telemetry posture pending | author minimum-necessary and de-id policies |

## BAA and PHI answers

- P1 does not upload PHI-bearing samples to MyCSF.
- BAA chain references remain out-of-tree legal artifacts.
- If the assessor treats the BAA chain as insufficient for readiness,
  classify the item as halt 14 candidate and stop promotion to P2.
- The minimum-necessary policy, telemetry de-identification policy,
  and breach-notification runbook are P2 deliverables.

## Fail-closed readiness rule

A family can move to `ready` only when it has a source artifact, an
owner, a control-row mapping, and no unresolved BAA or scope exception.
Otherwise it remains a gap for the P1 report.
