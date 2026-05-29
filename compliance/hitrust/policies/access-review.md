# HITRUST Access Review Policy

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**Cadence:** quarterly
**Owner:** Chio evidence owner and the deployment access administrator

> **Status:** policy is documented; first-cycle execution evidence has
> not yet been produced and is an open gap.

## Purpose

This policy defines a quarterly human access-review cadence for the
intended HITRUST i1 scope. It complements Chio protocol access control,
which is enforced in code through capability validation, sender
constraints, revocation, and fail-closed kernel admission.

## Quarterly review requirements

Each quarter, the evidence owner reviews:

- Assessor portal users and download permissions (if a MyCSF object
  exists; none does today).
- Production deployment operator access for the assessed tenant.
- Capability authority administrative roles.
- Audit-log export and receipt-log access roles.
- Break-glass access grants and revocation records.

## First-cycle evidence packet

| Item | Evidence source | Status |
|------|-----------------|--------|
| Portal user roster | MyCSF export or screenshot hash | not produced; no portal exists |
| Operator access roster | design-partner tenant access export | out-of-tree; not produced |
| Capability authority admins | deployment access-control record | out-of-tree; not produced |
| Break-glass grants | incident and access-review log | none active |
| Exceptions | accepted-risk register | out-of-tree HR evidence only |

## Fail-closed review rule

If a user, service principal, or assessor account cannot be mapped to a
named owner and a business need, access is removed or suspended before
the row can be considered evidenced for HITRUST.
