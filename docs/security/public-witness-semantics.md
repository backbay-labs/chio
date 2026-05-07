# Public Witness Semantics

`chio.anchor_batch.v1` is additive evidence. It does not replace local receipt
signatures, receipt body hashes, or checkpoint inclusion proofs.

## Guarantees

- Anti-equivocation: the executable verifier detects local batch-root and
  witness body-hash substitution. Full Rekor Merkle anti-equivocation is
  proposed evidence until Rekor inclusion-proof verification lands.
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
- OTS marker-only receipt: an OTS blob that locally decodes and contains a
  Bitcoin attestation marker is advisory only. It does not satisfy
  `require_public_witness` until the receipt contract carries trusted Bitcoin
  block-header evidence or independently verified calendar commitment evidence.
- Stale witness: when Rekor or another trusted public-witness lane is unavailable for
  longer than the verifier freshness window, mark new batches as
  `pending_public_witness`. Verifiers configured with `require_public_witness`
  reject those new batches, reject sync self-asserted `Witnessed` states, and
  accept stale batches only when a verifier-owned cache records a fresh
  `verified_at` timestamp for that batch body hash. Producer-signed
  `last_verified` is telemetry only.

## Operator Defaults

Production verifiers should use an allow-list of witness lanes, enforce a
freshness window per lane, and keep receipt acceptance separate from batch-level
continuity acceptance. This prevents a witness outage from turning into receipt
data loss while preserving fail-closed behavior for public continuity claims.
