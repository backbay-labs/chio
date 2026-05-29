# HITRUST Control Remediation Summary

> **Status: internal self-assessment / readiness.** This maps each
> self-identified gap to the in-repository artifact that addresses it.
> "documented" means a policy or narrative exists in the repository;
> "gap" means evidence is still missing. No external remediation has been
> validated by any assessor.

**Scope:** Chio healthcare design-partner deployment (this assessed release)

## Gap-to-artifact map

| Gap | Closure artifact | Status |
|-----|------------------|--------|
| BAA private evidence | out-of-tree legal artifact | gap (not in repository) |
| HIPAA breach-notification runbook | `compliance/hitrust/ir-runbook.md` | documented |
| Minimum-necessary posture | `compliance/hitrust/policies/de-identification.md` | documented |
| Telemetry de-identification posture | `compliance/hitrust/policies/de-identification.md` | documented |
| Quarterly access review | `compliance/hitrust/policies/access-review.md` | documented (first-cycle execution is a gap) |
| Key rotation | `compliance/hitrust/policies/key-rotation.md` | documented (execution evidence is a gap) |
| Formal evidence bridge | `compliance/hitrust/narratives/formal-evidence-bridge.md` | documented |
| Cloud-provider inheritance | `compliance/hitrust/encryption-at-rest.md` | gap (provider evidence not collected) |
| Operational samples | `compliance/hitrust/operational-samples.md` | gap (samples not pulled) |

## Narrative rule

Every control narrative cites a real source artifact and an owner. Rows
that depend on out-of-tree legal, HR, design-partner DR, or
cloud-provider attestation evidence remain gaps until that evidence
exists; they are never marked satisfied on the basis of a plan.
