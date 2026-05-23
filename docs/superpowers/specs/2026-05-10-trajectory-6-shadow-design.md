# Trajectory 6 Active Design

## Status

Active implementation slice. It promotes the real BBS selective-disclosure
work from the shadow plan while keeping the rest of T6 draft until gates exist.

## Narrative

Trajectory 6 should be Chio v0.1: cross-vendor attested workflows. The goal
is a buyer-verifiable workflow where Vendor A invokes Vendor B or C across a
trust boundary, both sides co-sign boundary actions, workflow receipts carry
parent links and consistency anchors, and an auditor verifies the bundle
without trusting any vendor unilaterally.

## Draft Workstreams

- Scope-lock the 3-vendor golden fixture and map every fixture gap to a T6
  ticket or explicit deferral.
- Draft ladder manifest handshake behavior for signed manifests, treaty
  intersections, consistency classes, and destructive action refusal.
- Draft WorkflowReceipt and StepRecord v2 fields for parent receipt hashes,
  bilateral receipt hashes, governance receipt ids, consistency anchors, and
  destructive flags.
- Draft `chio.capability-lease.v1` and `chio.governance-receipt.v1` as future
  interfaces, without production enforcement.
- Draft strict bilateral invocation verifier requirements and offline buyer
  proof bundle shape.
- Replace the selective-disclosure boundary with real reveal-set BBS proofs
  over receipt, workflow, and step projections.

## Boundary

The active claim is narrow: real BBS proof generation and verification for
disclosed fields. Hidden range predicates, VC Data Integrity interop, and zkVM
proofs remain future work.
