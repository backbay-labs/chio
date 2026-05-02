# HITRUST Walkthrough Week 10: Access Control and Capability Algebra

**Milestone:** M09.P1.T4
**Scope:** Chio v3.18 healthcare design-partner deployment
**Family:** Access Control
**Status:** complete, no halt candidate

## Evidence reviewed

| Evidence | Purpose |
|----------|---------|
| `spec/PROTOCOL.md` | capability token model, attenuation, delegation |
| `spec/SECURITY.md` | trust boundaries, denial behavior, revocation |
| `spec/COMPLIANCE-CERTIFICATE.md` | per-session evidence and signed compliance claims |
| `crates/chio-kernel-core/` | kernel admission and authorization implementation surface |
| `spec/security/chio-threat-model.v1.json` | access-control threat coverage |

## Assessor observations

- Capability validation, sender constraints, expiration, revocation,
  and attenuation map cleanly to access-control rows.
- Guard failures and policy-evaluation errors deny access by default.
- The assessor requested sample receipts showing allow, deny, revoked,
  expired, and sender-mismatch outcomes for the P3 bundle.
- Human access review remains outside the protocol and must be
  documented by P2 policy.

## Questions captured

| Question | Owner | Disposition |
|----------|-------|-------------|
| Provide receipt samples for denied revoked capabilities. | M09 | P3 evidence bundle |
| Show quarterly human access-review cadence. | M09 | P2 access-review policy |
| Map capability scope strings to MyCSF access-control rows. | M09 | P2 control narratives |

## Gap preview

Protocol access control is ready with inherited evidence. Human access
review and sampled receipt evidence are P2/P3 remediation items.
