# HITRUST Access Review Policy

**Milestone:** M09.P2.T2
**Scope:** Chio v3.18 healthcare design-partner deployment
**Cadence:** quarterly
**Owner:** Chio evidence owner and Backbay access administrator

## Purpose

This policy closes the P1 access-review gap by defining a quarterly
human access-review cadence for the HITRUST i1 assessment scope. It
complements Chio protocol access control, which is enforced through
capability validation, sender constraints, revocation, and fail-closed
kernel admission.

## Quarterly review requirements

Each quarter, the evidence owner must review:

- MyCSF assessor portal users and download permissions.
- Production deployment operator access for the assessed tenant.
- Capability authority administrative roles.
- Audit-log export and receipt-log access roles.
- Break-glass access grants and revocation records.

## First-cycle evidence packet

| Item | Evidence source | Status |
|------|-----------------|--------|
| Portal user roster | MyCSF export or screenshot hash | P3 private evidence upload |
| Operator access roster | design-partner tenant access export | P3 private evidence upload |
| Capability authority admins | deployment access-control record | P3 private evidence upload |
| Break-glass grants | incident and access-review log | none active at P2 |
| Exceptions | accepted-risk register | none beyond private HR evidence channel |

## Fail-closed review rule

If a user, service principal, or assessor account cannot be mapped to a
named owner and business need, access is removed or suspended before the
row can be marked ready for HITRUST.
