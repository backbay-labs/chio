# HITRUST Walkthrough Week 12: Operations and Incident Response

**Milestone:** M09.P1.T6
**Scope:** Chio v3.18 healthcare design-partner deployment
**Families:** Communications and Operations Management, Incident Management
**Status:** complete, no halt candidate

## Evidence reviewed

| Evidence | Purpose |
|----------|---------|
| `.planning/trajectory-3/audits/M01-healthcare-pilot.md` | operator runbook and bounded operational profile |
| `spec/audit-log/export-schema.v1.json` | audit-log export schema |
| `.planning/trajectory-3/audits/M03-ci-restoration.md` | hosted CI and provenance evidence |
| `docs/security/threat-coverage.md` | threat-coverage closure |
| `spec/WORKFLOW.md` | operational workflow context |

## Assessor observations

- The receipt log and audit-log export schema are strong operational
  audit-control evidence if P3 includes sampled records from the
  bounded operational profile.
- Incident-management rows cannot move to ready until P2 adds the
  incident response runbook and HIPAA breach-notification clock.
- The assessor requested a specific escalation matrix for fail-open
  detections, key compromise, capability revocation bypass, and
  evidence-retention failure.
- Pre-existing CI evidence is useful but must be tied to the assessed
  v3.18 build in the P3 bundle.

## Questions captured

| Question | Owner | Disposition |
|----------|-------|-------------|
| Where is the 60-day HIPAA breach-notification clock documented? | M09 | P2 IR runbook |
| Which events trigger customer notification? | M09 | P2 IR runbook |
| Which receipt samples prove operational audit controls? | M01/M09 | P3 sample pull |

## Gap preview

Operations evidence is partially ready. Incident response is a Sev-1
readiness gap until the P2 runbook and escalation matrix land.
