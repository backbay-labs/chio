# Public Witness Semantics

`chio.anchor_batch.v1` is additive evidence. It does not replace local receipt
signatures, receipt body hashes, or checkpoint inclusion proofs.

## Guarantees

- Anti-equivocation: once a batch root is published to an allowed witness lane,
  a later batch with the same `checkpointIds` and a different root is detectable
  by querying that lane.
- Claim completeness: every checkpoint named by the batch must have an inclusion
  proof whose leaf verifies against `treeRoot`.
- Local validity stays local: a receipt remains locally verifiable when its
  batch witness is pending or unavailable.

## Failure Modes

- Forged root: reject the batch when recomputed leaves do not produce `treeRoot`.
- Mis-ordered proof: reject the batch when an inclusion entry does not match the
  checkpoint at the same index.
- Witness impersonation: reject the batch when the witness entry resolves to a
  different root or to a lane outside the verifier allow-list.
- Stale witness: when Rekor, OTS, or Solana memo publication is unavailable for
  longer than the verifier freshness window, mark new batches as
  `pending_public_witness`. Verifiers configured with `require_public_witness`
  reject those new batches, but still accept receipts that verify locally and
  already-witnessed batches.

## Operator Defaults

Production verifiers should use an allow-list of witness lanes, enforce a
freshness window per lane, and keep receipt acceptance separate from batch-level
continuity acceptance. This prevents a witness outage from turning into receipt
data loss while preserving fail-closed behavior for public continuity claims.
