# Chio HITRUST i1 P1 Gap Report

**Trajectory:** trajectory-3
**Milestone:** M09.P1.T9
**Assessment:** HITRUST CSF v11.7 i1
**Controls in scope:** 182
**Assessor stage:** P1 readiness gap assessment
**Result:** remediation feasible in P2, no halt 14 assessor rejection

## Executive summary

The assessor walkthroughs accepted the Chio v3.18 single-tenant scope
and found no scope blocker that prevents P2 remediation. The current
posture has strong inherited evidence for protocol access control,
threat management, audit controls, build provenance, supply-chain
inventory, and independent review. The remaining gaps are operational
policy, private legal evidence references, cloud-provider inheritance,
incident response, and evidence-pack upload mechanics.

## Counts

| Category | Count |
|----------|-------|
| Total i1 controls in scope | 182 |
| Ready through inherited evidence | 46 |
| Partial, needs P2 policy or P3 bundle evidence | 83 |
| Gap, needs net-new P2 remediation | 53 |
| Sev-1 P2 blockers | 6 |
| Sev-2 remediation items | 19 |
| Sev-3 accepted-risk candidates | 4 |

## Sev-1 blockers

| ID | Control area | Gap | P2 owner | Closure path |
|----|--------------|-----|----------|--------------|
| Sev-1-GOV-BAA | Privacy and Compliance | BAA chain references not attached to assessor evidence channel. | legal / M09 | attach private BAA reference receipt before PHI sample upload |
| Sev-1-IR-001 | Incident Management | HIPAA breach-notification runbook missing. | M09 | author `compliance/hitrust/ir-runbook.md` |
| Sev-1-PRIV-001 | Privacy Practices | Minimum-necessary policy missing. | M09 | author `compliance/hitrust/policies/minimum-necessary.md` |
| Sev-1-PRIV-002 | Privacy Practices | Telemetry de-identification posture missing. | M09 | author `compliance/hitrust/policies/telemetry-deid.md` |
| Sev-1-ACCESS-001 | Access Control | Quarterly human access-review cadence not documented. | M09 | author access-review policy and first-cycle evidence |
| Sev-1-KEY-001 | Development and Operations | Key-rotation schedule not documented for capability signing, TLS, and audit export keys. | M09 | author key-rotation policy |

## Sev-2 remediation items

| Area | Gap | Closure path |
|------|-----|--------------|
| Formal evidence | Assessor needs plain-English bridge for M06 invariants. | P2 formal evidence bridge |
| Cloud inheritance | Provider attestation references missing. | P2 encryption-at-rest evidence record |
| Asset inventory | Production SBOM and CVE monitor hashes not bundled. | P3 evidence bundle |
| Operations | 30-day bounded operational profile samples not bundled. | P3 sample pull |
| Compliance | Evidence-pack automation not present. | P2 script seed and P3 bundle run |
| Governance | Security review cadence not attached to control rows. | P2 policy evidence |

## Sev-3 accepted-risk candidates

- Mobile M07 remains out of HITRUST scope and is not a certificate gap.
- AWS Bedrock M10 remains out of HITRUST scope and is not a certificate gap.
- HR training evidence is out of tree and accepted only as private
  evidence channel input.
- Cloud physical security is provider-inherited and accepted only with
  provider attestation references.

## Halt-trigger review

Halt 14 does not fire in P1. The assessor did not reject the readiness
package or classify the assessment as infeasible. If the BAA evidence
channel is rejected during P2 or P3, halt 14 must be surfaced before
PHI-bearing samples are used.

## P2 remediation backlog

P2 must land access-review policy, key-rotation policy, incident
response runbook, minimum-necessary policy, telemetry de-identification
policy, encryption-at-rest evidence references, formal evidence bridge,
and the evidence-pack script seed.
