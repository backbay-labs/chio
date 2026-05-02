# Chio HITRUST i1 Draft Report

**Milestone:** M09.P4.T8
**Assessment:** HITRUST CSF v11.7 i1
**Scope:** Chio v3.18 healthcare design-partner deployment
**Draft status:** received for clarification round
**Draft date:** 2026-05-02

## Draft conclusion

The draft report accepts the signed scope boundary, the MyCSF evidence
package, and the P2 remediation posture. No assessor readiness rejection
was issued. Halt 14 does not fire.

## Draft finding summary

| Severity | Count | Summary |
|----------|-------|---------|
| Critical | 0 | none |
| High | 0 | none |
| Medium | 2 | private BAA reference hash and cloud-provider inheritance receipt require final P5 attachment |
| Low | 3 | wording clarifications for access review, formal evidence limits, and evidence retention |
| Informational | 4 | accepted-risk register wording, renewal trigger, public certificate page, and directory link formatting |

## Open clarifications

- Confirm private BAA evidence reference before certificate package
  submission.
- Confirm AWS Artifact report hash before certificate package
  submission.
- Keep M07 mobile and M10 AWS Bedrock out of HITRUST i1 scope.
- Add final certificate id, issuance date, and expiration date in P5.

## Remediation posture

All repository-owned Sev-1 and Sev-2 readiness gaps are closed. Medium
findings are private-channel evidence attachments, not code defects or
trust-boundary fail-open behavior.
