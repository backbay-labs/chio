# HITRUST Walkthrough Week 13: Privacy Practices and HIPAA Technical Safeguards

**Milestone:** M09.P1.T7
**Scope:** Chio v3.18 healthcare design-partner deployment
**Family:** Privacy Practices and HIPAA technical safeguards
**Status:** complete, no halt candidate

## Evidence reviewed

| Evidence | Purpose |
|----------|---------|
| `spec/SECURITY.md` | PHI and data-exposure threat treatment |
| `spec/security/chio-threat-model.v1.json` | `pii_phi_exposure` and related threats |
| `docs/security/threat-coverage.md` | M05 coverage closure |
| `spec/audit-log/export-schema.v1.json` | audit controls and receipt export boundary |
| `compliance/hitrust/scope-boundary.md` | tenant and system boundary |

## Assessor observations

- Capability scoping, receipt audit controls, signed integrity, and TLS
  posture map to HIPAA 164.312 technical safeguards.
- The assessor did not request PHI-bearing samples during P1.
- Minimum-necessary policy, telemetry de-identification posture, and
  BAA reference chain remain P2 evidence requirements.
- If BAA references are rejected by the assessor, M09 must surface halt
  14 before using PHI samples as certification evidence.

## Questions captured

| Question | Owner | Disposition |
|----------|-------|-------------|
| Does Chio telemetry ever contain PHI? | M09 | P2 telemetry de-id policy |
| How is minimum-necessary access enforced beyond protocol scope? | M09 | P2 minimum-necessary policy |
| Where are BAA evidence references stored? | legal | private evidence channel |

## Gap preview

HIPAA technical safeguards are partially ready through protocol and
audit evidence. Privacy policy and BAA evidence remain remediable P2
gaps, with no P1 assessor rejection.
