# Kani trust-boundary harness deferral

- Date: 2026-05-03
- Owner (carry-forward): trajectory-4.M06-followup
- Status: deferred

## Summary

Trajectory-3.1 Phase 7 inspected the trust-boundary crates listed below for
public-surface Kani harness coverage. Authoring soundness-grade harnesses for
these crates falls outside the trajectory-3.1 stabilization budget and is
deferred to trajectory-4. The current nightly Kani lane (chio-kernel-core) is
green; this deferral does not change the running set of harnesses.

## Crates deferred

- `chio-attest-verify` (crates/chio-attest-verify/)
- `chio-anchor` (crates/chio-anchor/)
- `chio-weights` (crates/chio-weights/)

## Rationale

1. M06 originally proposed adding Kani harnesses for these three crates and
   silently dropped them as "out of scope." Trajectory-3.1 reviewed the
   proposal and confirms the crates each sit on a trust boundary and warrant
   formal coverage; they should not be silently dropped a second time.
2. Trajectory-3.1's stabilization budget targets restoring hosted CI and
   closing trajectory-3 carry-forward without introducing new formal artifacts
   that require domain-expert design review.
3. Each crate's public surface couples to dependency footprints (sigstore,
   webpki, x509-cert, alloy, sha2-backed Merkle constructions) that are not
   tractable for direct symbolic execution under Kani. Useful harnesses for
   these crates require modelling the algebraic property at the same level the
   existing chio-kernel-core harnesses do (see
   `crates/chio-kernel-core/src/kani_public_harnesses.rs`), which is a design
   exercise that needs a formal-methods reviewer in the loop.
4. Local Kani is not currently provisioned on the trajectory-3.1 author's
   workstation, so iterative harness debugging would require hosted-CI round
   trips that are too slow for the stabilization window.

## Carry-forward: best-effort surface candidates

The following public symbols are the best-effort first-cut targets for
trajectory-4 harness authoring. Each is a pure (or near-pure) function with a
clear precondition / postcondition that is amenable to algebraic modelling in
the style of the existing `chio_kernel_core::formal_core::*` harnesses.

### `chio-attest-verify`

Candidate public surface:

- `chio_attest_verify::policy::TenantAttestationPolicy::canonical_signing_bytes`
  - Property: canonical-bytes determinism. Identical policy fields project to
    the same byte sequence; mutating any signed field changes the byte class.
    Algebraic model: the existing `model_delegation_receipt` /
    `canonical_class` pattern in `kani_public_harnesses.rs` ports directly.
- `chio_attest_verify::policy::TenantAttestationPolicy::signed_at_system_time`
  - Property: monotone time projection (no overflow, fail-closed on
    out-of-range `signed_at`). Pure `u64 -> Result<SystemTime, AttestError>`,
    fits the bounded-u8 convention.
- Sigstore `AttestVerifier` impls are NOT good first targets (heavy
  dependency footprint). Defer to a follow-up that introduces an algebraic
  spec analogous to the receipt sign/verify model.

### `chio-anchor`

Candidate public surface:

- `chio_anchor::checkpoint_statement_from_kernel` and
  `chio_anchor::kernel_checkpoint_from_statement`
  - Property: round-trip identity. Converting kernel -> statement -> kernel
    yields the original checkpoint (modulo well-formed inputs). Mirrors the
    receipt-roundtrip algebra in `verify_receipt_roundtrip`.
- `chio_anchor::receipt_inclusion_from_kernel`
  - Property: structural projection preserves the inclusion-proof witness
    (leaf, siblings, root) under a symbolic hash function. Model in the same
    style as `verify_oracle_inclusion_soundness`.
- `chio_anchor::evm::operator_key_hash`
  - Property: hash determinism / collision-freeness modulo a symbolic hash
    abstraction. Pure function over a bounded byte slice; fits the existing
    `model_sign` / `model_verify` algebra pattern.

### `chio-weights`

Candidate public surface:

- `chio_weights::weights_hash_of`
  - Property: hash determinism. `weights_hash_of(b) == weights_hash_of(b)`
    for all `b`; distinct byte classes project to distinct hash strings under
    a symbolic hash. Pure `&[u8] -> String`, simplest first target.
- `chio_weights::lineage::anchor_projection_bytes`
  - Property: canonical-bytes determinism for the lineage anchor (mirrors the
    DelegationReceipt canonical-bytes harness).
- `chio_weights::bundle::verify_model_card_bundle`
  - Property: fail-closed on attestation failure. Defer to after the simpler
    pure-function harnesses land; this surface couples to `AttestVerifier` and
    needs the chio-attest-verify model first.

## Workflow integration plan (trajectory-4)

When trajectory-4 picks this up:

1. Add `kani-public-harnesses-{attest-verify,anchor,weights}.toml` manifests
   in `formal/rust-verification/`, modelled on the existing
   `kani-public-harnesses.toml`. Each manifest names its crate and lists
   harnesses by their `#[kani::proof]` symbol.
2. Add `kani_public_harnesses.rs` modules behind `#[cfg(kani)]` to each
   crate, modelled on `crates/chio-kernel-core/src/kani_public_harnesses.rs`.
3. Generalize `nightly.yml`'s `kani-public-nightly` job to iterate over the
   manifest set instead of hardcoding `cargo kani -p chio-kernel-core`. The
   same lane structure (`lanes.pr` + `lanes.nightly_only`) applies per
   manifest.
4. Mirror the per-crate harness count into `M06-FOLLOWUPS.md` so the
   trust-boundary coverage table stays auditable.

## Verification of current state

- nightly Kani lane (chio-kernel-core only) on `main` HEAD `c456a871`:
  `kani-public-nightly (lanes.pr + lanes.nightly_only)` conclusion `success`
  on the most recent two scheduled runs (run IDs 25272257669, 25245708344).
  No workflow change is required as part of this deferral.
- `formal-tla-liveness` (apalache liveness) lane in `nightly.yml` is failing
  for an unrelated reason (Apalache `SubstRule: Variable a$1 is not assigned
  a value`); that lane is owned by the apalache stream and is out of scope
  for this deferral.

## References

- Model harness file: `crates/chio-kernel-core/src/kani_public_harnesses.rs`
- Existing manifest: `formal/rust-verification/kani-public-harnesses.toml`
- Nightly Kani lane: `.github/workflows/nightly.yml` (job
  `kani-public-nightly`)
- M06 supply-chain audit: `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
