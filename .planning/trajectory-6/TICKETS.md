# Trajectory 6 Tickets

Tickets start from the former shadow map. Runtime work is allowed only when it
has a concrete acceptance gate.

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

## T6-006: Real BBS selective disclosure

Acceptance:

- `chio-selective-disclosure` signs receipt, workflow, and step projections
  under the `bbs` feature.
- `chio.selective-disclosure-proof.v1` proof packages verify disclosed fields
  against an issuer-key registry.
- The committed 3-vendor fixture uses the real proof schema and rejects the
  legacy `.stub` schema.
- The gate `bash scripts/check-chio-bbs-acceptance.sh` passes.
- No ticket claims hidden range predicates, VC Data Integrity interop, or zkVM
  support.
