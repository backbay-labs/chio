# Trajectory 6 Shadow Tickets

All tickets are draft and non-normative. They are not authorized for runtime
implementation until Trajectory 6 becomes active.

## T6-S-001: 3-vendor golden fixture scope

Acceptance:

- Buyer, Vendor A, Vendor B, and Vendor C roles are fixed.
- Every gap in the current 3-vendor fixture is mapped to a T6 ticket or an
  explicit deferral.
- The fixture remains planning-only.

## T6-S-002: Ladder manifest handshake draft

Acceptance:

- Draft manifest ids, hashes, treaty intersections, consistency classes, and
  destructive action refusal cases are described.
- Missing, stale, or downgraded manifest behavior is specified as fail-closed.

## T6-S-003: WorkflowReceipt / StepRecord v2 draft

Acceptance:

- Draft fields cover parent receipt hash, bilateral receipt hash, governance
  receipt id, consistency anchor, destructive flag, and optional vendor
  cosignature references.
- The draft says these fields are not production schema until T6 is active.

## T6-S-004: Capability lease and governance receipt drafts

Acceptance:

- `chio.capability-lease.v1` and `chio.governance-receipt.v1` are described as
  future interfaces.
- Destructive cross-org action requirements are listed without implementing
  enforcement.

## T6-S-005: Strict bilateral verifier draft

Acceptance:

- Offline verification inputs and outputs are listed.
- Buyer proof package contents are listed.
- The draft explicitly excludes shipped verifier behavior.

## T6-S-006: Selective-disclosure boundary

Acceptance:

- `bbs-stub` cannot satisfy any T6 release claim.
- Real BBS+/zk proof work is a future active-lane dependency.
