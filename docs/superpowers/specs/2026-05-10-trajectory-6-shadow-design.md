# Trajectory 6 Shadow Design

## Status

Draft and non-normative. This document is planning only. It does not define
shipped protocol behavior, production schema enforcement, verifier behavior, or
release readiness.

## Narrative

Trajectory 6 should be Chiodos v0.1: cross-vendor attested workflows. The goal
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
- Keep selective disclosure non-release unless a real cryptographic proof path
  replaces the `bbs-stub`.

## Boundary

No runtime code, enforced schema, verifier command, package release, BBS+/zk
claim, or shipped protocol claim may land under this shadow lane. Those belong
to a future active Trajectory 6 implementation lane after 5.2 exits.
