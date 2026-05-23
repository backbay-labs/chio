# Trajectory 6 Dependencies

Trajectory 6 became active after Trajectory 5.2 exited.

## Satisfied Before Active T6

- `bash scripts/check-bounded-ship-bar.sh` passes in default mode.
- T5.2 release-truth docs agree on the post-#630 baseline SHA.
- `v0.1.0-bounded-chiodome` is either parked outside release scope or reopened
  by a future release lane with strict gates.
- Selective disclosure is backed by real reveal-set BBS proof fixtures.

## Still Deferred

- Hidden range predicates such as amount caps without revealing the amount.
- VC Data Integrity `bbs-2023` interop.
- zkVM proofs over nested fields and chained receipts.

## Inputs From Existing Specs

- `docs/research/CHIO_3VENDOR_FIXTURE.md`
- `spec/CHIO_LADDER.md`
- `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`
- `spec/CHIO_SELECTIVE_DISCLOSURE.md`
- `spec/CHIO_PHEROMONE.md`

These inputs remain draft sources except where T6 tickets promote a specific
interface with tests.
