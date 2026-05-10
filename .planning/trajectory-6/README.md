# Trajectory 6 Active Planning

Status: active implementation slice.

Trajectory 6 is scoped as **Chiodos v0.1: cross-vendor attested workflows**.
Trajectory 5.2 exited with the strict bounded assurance gate green, so T6 may
now carry runtime work that is backed by runnable acceptance gates.

## Guardrails

- Runtime work must be tied to a ticket and a runnable gate.
- Selective disclosure may claim only reveal-set BBS proofs over signed
  receipt, workflow, and step projections.
- Hidden range predicates, VC Data Integrity interop, and zkVM support remain
  out of scope for this slice.
- Legacy `bbs-stub` artifacts cannot satisfy T6 conformance.

## Candidate Interfaces

- `chio.capability-lease.v1`
- `chio.governance-receipt.v1`
- WorkflowReceipt / StepRecord v2 fields
- Chiodos verifier bundle shape

These are draft planning names only.
