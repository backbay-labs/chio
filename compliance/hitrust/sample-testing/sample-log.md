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

## Handling rule

PHI-bearing or tenant-private samples are not committed to this public
repository. The public record stores sample ids, request class, response
date, and evidence hashes or paths.
