# Chio HITRUST i1 Internal Gap Self-Assessment

> **Status: internal self-assessment / readiness.** No external HITRUST
> assessment has been performed and no assessor walkthroughs have
> occurred. This is Chio's own internal gap analysis against the HITRUST
> i1 control families, based on evidence that exists in this repository.

**Framework target:** HITRUST CSF v11.7 i1
**Method:** internal self-review of repository evidence against i1 control families

## Executive summary

Chio has strong, in-repository evidence for protocol access control,
threat management, audit-log schema and receipts, build provenance,
supply-chain inventory, and formal invariants. The honest gaps are
operational policy execution evidence, out-of-tree legal/HR evidence,
cloud-provider inheritance evidence, incident-response first-cycle
records, and production operational samples. None of these has been
reviewed by any external assessor.

## Posture by control family

| Family | Self-assessed posture | Basis |
|--------|-----------------------|-------|
| Access Control | implemented | kernel crates and formal proofs (`formal/MAPPING.md`) |
| Risk Management | implemented | threat model and coverage table |
| Security Policy | implemented | `spec/SECURITY.md`, `docs/security/` |
| Asset Management | implemented | SBOM, cargo-vet, CVE monitoring |
| Systems Acquisition, Development, and Maintenance | implemented | reproducible build, SLSA, formal evidence |
| Information Security Management Program | partial | governance documented; review cadence is a gap |
| Organization of Information Security | partial | ownership documented for formal evidence only |
| Compliance | partial | self-assessment only |
| Communications and Operations Management | partial | schema and receipts exist; production samples are a gap |
| Privacy Practices | partial | redaction implemented; BAA/PHI handling out-of-tree |
| Incident Management | partial | runbook documented; first-cycle evidence is a gap |
| Human Resources Security | gap | no repository evidence; out-of-tree |
| Physical and Environmental Security | gap | cloud-provider inheritance not collected |
| Business Continuity Management | gap | DR evidence not collected |

## Open gaps and closure paths

| Gap | Area | Closure path |
|-----|------|--------------|
| BAA chain references | Privacy and Compliance | attach private BAA reference before any PHI sample use |
| HR workforce evidence | Human Resources Security | collect out-of-tree HR policy and training references |
| Cloud-provider attestation | Physical and Environmental Security | record provider attestation references (encryption-at-rest pointer) |
| DR posture evidence | Business Continuity Management | collect design-partner DR reference |
| Access-review execution | Access Control / Operations | run first quarterly review per `compliance/hitrust/policies/access-review.md` and retain evidence |
| Key-rotation execution | Operations | execute and retain rotation evidence per `compliance/hitrust/policies/key-rotation.md` |
| Incident first-cycle | Incident Management | exercise `compliance/hitrust/ir-runbook.md` and retain a record |
| Operational samples | Operations | pull 30-day audit-log samples per the schema |

## Accepted-scope exclusions (not gaps)

- Mobile patient-app surfaces remain out of HITRUST scope.
- AWS Bedrock and MCP marketplace surfaces remain out of HITRUST scope.

## Honesty rule

Every implemented posture above cites real repository evidence. Every
gap is stated plainly. No control is marked satisfied on the basis of an
assessor interaction, because none has occurred.
