# Tickets

## C7.7-001, Integrator

Create the stacked branch, record the baseline SHA, promote the 7.7 planning
docs, and add the 7.8 dashboard/review shadow note.

## C7.7-002, Buyer Review Contracts

Add receipt-lineage bundle, buyer review package, buyer review report, and
negative corpus schemas and runtime types.

## C7.7-003, Hydrated Buyer Verification

Verify buyer packages only after resolving required artifact roles by hash and
byte count. Reject missing, duplicate, mismatched, or unverified evidence.

## C7.7-004, Lineage Closure

Verify bounded receipt-lineage bundles with root-to-leaf closure, no cycles,
and verified evidence classes only.

## C7.7-005, Buyer CLI

Add `chio attest buyer package`, `verify`, and `explain` over local files.
Keep treaty packet verification as the primitive.

## C7.7-006, Negatives And Gate

Add executable negative coverage for tampered artifacts, asserted lineage,
settlement claims, verifier rejection, and wrong expected codes.

## C7.7-007, Docs And Closeout

Update protocol docs to claim local buyer-verifiable cross-vendor attestation
only, then run focused gates and targeted clippy.
