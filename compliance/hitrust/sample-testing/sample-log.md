# HITRUST P4 Sample Testing Log

**Milestone:** M09.P4
**Scope:** Chio v3.18 healthcare design-partner deployment
**Bundle:** `compliance/hitrust/evidence-bundles/2026-05-02`

## Sample testing register

| sample id | Week | Assessor request | Response | Evidence |
|-----------|------|------------------|----------|----------|
| P4-SAMPLE-001 | P4 week 1 | allow decision receipt spot check | provided schema and redacted receipt hash | M01 BOP private channel |
| P4-SAMPLE-002 | P4 week 1 | deny decision receipt spot check | provided schema and redacted receipt hash | M01 BOP private channel |
| P4-SAMPLE-003 | P4 week 1 | access-review policy check | provided policy pointer | `compliance/hitrust/policies/access-review.md` |
| P4-SAMPLE-004 | P4 week 1 | key-rotation policy check | provided policy pointer | `compliance/hitrust/policies/key-rotation.md` |
| P4-SAMPLE-005 | P4 week 1 | formal evidence spot check | provided bridge plus Apalache bundle paths | `compliance/hitrust/narratives/formal-evidence-bridge.md` |
| P4-FOLLOWUP-025-001 | week 25 | access-review first-cycle evidence pointer | provided private roster hash and public policy path | private channel plus `access-review.md` |
| P4-FOLLOWUP-025-002 | week 25 | BAA evidence channel confirmation | provided private legal reference hash | private assessor channel |
| P4-FOLLOWUP-027-001 | week 27 | Cloud-provider inheritance evidence pointer | provided AWS Artifact reference hash | private provider evidence channel |
| P4-FOLLOWUP-027-002 | week 27 | operator interview clarification | provided role-only public summary and private attendee roster hash | `operator-interviews.md` |
| P4-FOLLOWUP-028-001 | week 28 | incident-response table-top evidence | provided IR runbook mapping and closure receipt | `compliance/hitrust/ir-runbook.md` |
| P4-FOLLOWUP-028-002 | week 28 | key-rotation cutover evidence | provided redacted key-id cutover receipt hash | private channel plus `key-rotation.md` |
| P4-FOLLOWUP-030-001 | week 30 | audit-log export schema evidence | provided schema hash and BOP sample manifest | `spec/audit-log/export-schema.v1.json` |
| P4-FOLLOWUP-030-002 | week 30 | threat coverage evidence | provided M05 coverage and threat model bundle pointers | `docs/security/threat-coverage.md` |
| P4-FOLLOWUP-031-001 | week 31 | final evidence completeness review | provided bundle hash and accepted-risk register | M09 audit doc |
| P4-FOLLOWUP-031-002 | week 31 | no-scope-expansion attestation | confirmed M07 and M10 remain out of scope | scope boundary |

## Handling rule

PHI-bearing or tenant-private samples are not committed to this public
repository. The public record stores sample ids, request class, response
date, and evidence hashes or paths.
