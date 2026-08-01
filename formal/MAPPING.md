# formal/MAPPING.md

Cross-reference table from named formal properties (TLA+ invariants, Kani
harnesses) to the Rust call sites they constrain, the assumption registry
they rely on, and a one-line description of each property.

This file is enforced by `scripts/check-mapping.sh`. The script greps the
source files for the canonical names listed below and fails the build if
any appear in the source but are not represented as a row here.

The columns are:

- **Property** - the named TLA+ invariant or Kani harness exactly as it
  appears in source. The script greps for this literal string.
- **Source** - source file plus a stable anchor (line number is best-effort
  only; the script does not depend on it).
- **Rust path constrained** - the Rust function, type, or module whose
  behavior the property pins down. For TLA+ invariants this is a coarse
  pointer to the surface; for Kani harnesses it is the exact symbol the
  harness targets.
- **Assumption discharge** - link into `formal/assumptions.toml` or
  `formal/proof-manifest.toml` showing which audited assumption(s) the
  property relies on, or `n/a` if the property is purely structural.
- **One-line description** - what the property says, in prose.

When you add a new TLA+ named safety/liveness invariant or a new
`#[kani::proof]` harness to the in-scope source files, add a row here in the
same PR or `scripts/check-mapping.sh` will fail.

## TLA+ named invariants (RevocationPropagation.tla)

Source file: `formal/tla/RevocationPropagation.tla`. The three safety
names below are model-checked by `formal/tla/MCRevocationPropagation.cfg`
via the aggregate SafetyInv. The aggregate itself is intentionally NOT a
row in this table; the script greps for the leaf-named invariants. The
fourth row is the named liveness property RevocationEventuallySeen, which
the nightly Apalache lane checks via `--temporal=` (Apalache reserves
`--inv=` for state invariants, hence the separate flag).

| Property                    | Source                                          | Rust path constrained                                                                                          | Assumption discharge                                                                          | One-line description                                                                                                            |
| --------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `NoAllowAfterRevoke`        | `formal/tla/RevocationPropagation.tla` (~L238) | `crates/kernel/chio-kernel-core/src/evaluate.rs::evaluate`, `crates/kernel/chio-kernel/src/capability_lineage.rs`            | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY (per-row); retired-cross-row tracked separately | Every `allow` receipt was issued at a time when the issuing authority had not yet observed any revocation.                      |
| `MonotoneLog`               | `formal/tla/RevocationPropagation.tla` (~L250) | `crates/kernel/chio-kernel/src/receipt_store.rs`                                                                      | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY; evidence for RETIRED-SQLITE-CROSS-ROW | Per-authority receipt-log timestamps are strictly increasing; the log is append-only.                                           |
| `AttenuationPreserving`     | `formal/tla/RevocationPropagation.tla` (~L262) | `crates/core/chio-core-types/src/capability.rs` (`ChioScope::is_subset_of`), `crates/kernel/chio-kernel-core/src/normalized.rs` | n/a (structural; bounded by `DEPTH_MAX`)                                                      | `depth` stays within `0..DEPTH_MAX`; any cap in the `attenuated` state has been delegated at least once.                        |
| `RevocationEventuallySeen`  | `formal/tla/RevocationPropagation.tla` (~L336) | `crates/kernel/chio-kernel/src/capability_lineage.rs`, `crates/kernel/chio-kernel/src/receipt_store.rs`                      | `formal/assumptions.toml` ASSUME-PROPAGATE-FAIRNESS (weak fairness on `Propagate`)            | Once one authority observes a non-zero revocation epoch for a cap, every other authority eventually catches up to that epoch.   |
| `RevocationFreshness`       | `formal/tla/RevocationPropagation.tla` (~L320) | `crates/trust/chio-revocation-oracle/src/freshness.rs`, `crates/kernel/chio-kernel-core/src/revocation_view.rs`             | `formal/assumptions.toml` ASSUME-OS-CLOCK; jointly anchors RevocationView::install_if_newer    | Every recorded local revocation epoch is strictly less than the global clock; observed-epoch freshness fail-closed gate.        |

Lean cross-references (informational; the script does not enforce these):

- `NoAllowAfterRevoke` corresponds to
  `Chio.Proofs.evalToolCall_revoked_token_never_allows` and
  `Chio.Proofs.evalToolCall_revoked_ancestor_never_allows` in
  `formal/lean4/Chio/Chio/Proofs/Evaluation.lean` (theorem-inventory.json
  ids `proof.evalToolCall_revoked_token_never_allows`,
  `proof.evalToolCall_revoked_ancestor_never_allows`,
  `proof.revocationSnapshot_revoked_token_denies`,
  `proof.revocationSnapshot_revoked_ancestor_denies`).
- `MonotoneLog` corresponds to the bounded receipt-store models in
  `formal/lean4/Chio/Chio/Proofs/Receipt.lean` (theorem ids
  `proof.applyProof_append`, `proof.checkpoint_consistency`) and to
  `proof.receiptFieldsCoupled_preserves_all_fields` in
  `formal/lean4/Chio/Chio/Proofs/Protocol.lean`.
- `AttenuationPreserving` corresponds to the attenuation lemmas in
  `formal/lean4/Chio/Chio/Proofs/Monotonicity.lean` (theorem ids
  `proof.scope_subset_of_grants_subset`,
  `proof.added_constraint_is_subset`,
  `proof.delegation_chain_integrity`) and to
  `Chio.Spec.capability_monotonicity` in
  `formal/lean4/Chio/Chio/Spec/Properties.lean`.

## Apalache named invariants (kernel-state subset)

Source directory: `formal/apalache/`. These rows are the focused kernel-state
invariant set. They are checked by `.github/workflows/apalache-nightly.yml`
against the `MC*.cfg` files in the same directory.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `MonotoneLogApalache` | `formal/apalache/MonotoneLogApalache.tla` | `crates/kernel/chio-kernel/src/receipt_store.rs` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY; single-invariant evidence for `RETIRED-SQLITE-CROSS-ROW` pairing | Per-authority receipt timestamps are strictly increasing in the Apalache-bounded kernel-state subset. |
| `RevocationCutCompleteness` | `formal/apalache/RevocationCutCompleteness.tla` | `crates/kernel/chio-kernel/src/lib.rs::ChioKernel::check_revocation`, `crates/kernel/chio-kernel-core/src/revocation_view.rs` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::revocation_snapshot_denies`; Lean theorem `revocation_is_cut` | A revoked capability removes dispatch eligibility for every transitive descendant in each authority view. |
| `ReceiptBeforeAllow` | `formal/apalache/ReceiptBeforeAllow.tla` | `crates/kernel/chio-kernel/src/receipt_store.rs`, `crates/kernel/chio-kernel-core/src/evaluate.rs::evaluate` | `formal/assumptions.toml` named Apalache evidence for `RETIRED-SQLITE-CROSS-ROW` | An allow decision can be published only after a prior allow receipt for the same authority and capability exists in the log. |
| `KernelTransitionCancelSafe` | `formal/apalache/KernelTransitionCancelSafe.tla` | `crates/kernel/chio-kernel/src/budget_store.rs`, `crates/kernel/chio-kernel-core/src/evaluate.rs::evaluate` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; Kani `verify_budget_checked_add_no_overflow` | A canceled in-flight kernel transition preserves the pre-transition budget and receipt state snapshots. |

## Kani public harnesses (kani_public_harnesses.rs)

Source file: `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`. The
script extracts every function name immediately following a
`#[kani::proof]` attribute in this file and asserts it appears as a row
below. Helper functions (e.g. `one_step_attenuation_predicate`) are not
themselves harnesses and are not enforced.

| Property                                                          | Source line | Rust path constrained                                                                                | Assumption discharge                                                                  | One-line description                                                                                                                  |
| ----------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `public_verify_capability_rejects_untrusted_issuer_before_signature` | ~L102      | `chio_kernel_core::capability_verify::verify_capability`                                              | `formal/proof-manifest.toml` covered_rust_symbols `verify_capability`; ASSUME-ED25519 | `verify_capability` rejects an untrusted issuer fail-closed before any signature work runs.                                            |
| `public_normalized_scope_subset_rejects_widened_child`             | ~L112       | `chio_kernel_core::normalized::NormalizedScope::is_subset_of`                                         | `formal/proof-manifest.toml` covered_rust_symbols `NormalizedScope::is_subset_of`     | A child scope that drops a parent's `dpop_required = true` or `max_invocations` cap is not a subset of the parent.                    |
| `public_normalized_scope_subset_rejects_value_widened_child`       | ~L150       | `chio_kernel_core::normalized::NormalizedScope::is_subset_of`                                         | `formal/proof-manifest.toml` covered_rust_symbols `NormalizedScope::is_subset_of`     | A child that raises `max_invocations` or flips `dpop_required` to false is not a subset of its parent.                                 |
| `public_normalized_scope_subset_rejects_identity_mismatch`         | ~L188       | `chio_kernel_core::normalized::NormalizedScope::is_subset_of`                                         | `formal/proof-manifest.toml` covered_rust_symbols `NormalizedScope::is_subset_of`     | A child grant whose `server_id` differs from its parent's is not a subset (no implicit identity widening).                            |
| `public_resolve_matching_grants_rejects_out_of_scope_request`      | ~L226       | `chio_kernel_core::scope::resolve_matching_grants`                                                    | `formal/proof-manifest.toml` covered_rust_symbols `resolve_matching_grants`           | `resolve_matching_grants` returns no matches for a tool name not in the scope's grants.                                                |
| `public_resolve_matching_grants_preserves_wildcard_matching`       | ~L250       | `chio_kernel_core::scope::resolve_matching_grants`                                                    | `formal/proof-manifest.toml` covered_rust_symbols `resolve_matching_grants`           | A wildcard `*/*` grant continues to match arbitrary `(server, tool)` pairs and is reported with all-zero specificity.                 |
| `public_evaluate_rejects_untrusted_issuer_before_dispatch`         | ~L274       | `chio_kernel_core::evaluate::evaluate`                                                                | `formal/proof-manifest.toml` covered_rust_symbols `evaluate`; ASSUME-ED25519          | `evaluate` denies a tool call whose capability has an untrusted issuer before any guard pipeline runs (fail-closed dispatch gate).    |
| `public_sign_receipt_rejects_kernel_key_mismatch_before_signing`   | ~L339       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` rejects a body whose `kernel_key` does not match the signing backend, before invoking the backend.                     |
| `public_sign_receipt_accepts_matching_kernel_key`                  | ~L353       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` produces a signed receipt with the backend's algorithm when the body's `kernel_key` matches the backend's public key.  |
| `public_sign_receipt_refuses_content_hash_mismatch`                | ~L396       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` recomputes the content hash and refuses a body whose claimed hash does not match the canonical preimage. |
| `public_sign_receipt_accepts_matching_content_hash`                | ~L424       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` accepts a body whose claimed content hash matches the canonical preimage. |
| `verify_scope_intersection_associative`                            | ~L379       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Transitivity of `optional_u32_cap_is_subset` plus reflexivity witnesses an associative meet over the bounded cap lattice. |
| `verify_revocation_predicate_idempotent`                           | ~L406       | `chio_kernel_core::formal_core::revocation_snapshot_denies`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P2                | `revocation_snapshot_denies` is idempotent on the same revocation snapshot and reduces to `token_revoked` on the diagonal.            |
| `verify_delegation_chain_step`                                     | ~L505       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `required_true_is_preserved`, `time_window_valid` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1, P3, P5        | One delegation step preserves attenuation: identity coverage, ops/constraints monotonicity, no cap widening, dpop preserved, and `is_valid_at(now)` propagates child-to-parent under `expiry(c') <= expiry(c)`. |
| `verify_receipt_roundtrip`                                         | ~L676       | `chio_kernel_core::receipts::sign_receipt`, `chio_kernel_core::receipts::ChioReceipt::verify_signature` | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`; P5                  | Receipt sign/verify roundtrip: honest pair verifies, message/key/signature tampering each break verification, and sign is deterministic on equal inputs.                                                       |
| `verify_budget_checked_add_no_overflow`                            | ~L810       | `chio_kernel::budget_store::BudgetUsageRecord` (additive cap update at lines ~1030-1065)              | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Budget overflow never partial-commits: `Overflow` and `CapExceeded` arms both leave post-state == pre-state, dispatch order is checked_add-before-cap-test, and failure is idempotent under retry.            |
| `verify_composite_quota_all_or_nothing`                            | ~L1128      | `chio_kernel_core::formal_core::composite_quota_authorize`                                            | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::composite_quota_authorize` | A three-key authorization increments every applicable quota within its maximum or preserves the complete pre-state. |
| `verify_quota_maximum_immutable`                                   | ~L1153      | `chio_kernel_core::formal_core::quota_maximum_compatible`                                             | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::quota_maximum_compatible` | An initialized quota key accepts only the maximum established on first use. |
| `verify_family_binding_preservation`                               | ~L1167      | `chio_kernel_core::formal_core::family_binding_preserved`                                             | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::family_binding_preserved` | A family descendant preserves every signed root field, binding digest, signature, and immutable maximum. |
| `verify_threshold_distinct_signers`                                | ~L1204      | `chio_kernel_core::formal_core::threshold_distinct_eligible_signers`                                  | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::threshold_distinct_eligible_signers` | Threshold count includes each eligible public-key identity at most once. |
| `verify_delegate_no_widen`                                         | ~L1103      | `chio_core_types::capability::delegate`                                                               | `formal/proof-manifest.toml` covered_rust_symbols `delegate`; P1, P5                  | Two-step delegation chain attenuates iff every step attenuates: runtime form of Lean theorem `delegate_no_widen`.        |
| `verify_delegation_receipt_canonical`                              | ~L1128      | `chio_core_types::delegation_receipt::DelegationReceipt::canonical_bytes`                             | `formal/proof-manifest.toml` covered_rust_symbols `DelegationReceipt::canonical_bytes`; ASSUME-CANONICAL-JSON | Canonical-bytes determinism plus single-axis sensitivity for the DelegationReceipt envelope; pins serialiser injectivity. |
| `verify_revocation_view_freshness`                                 | ~L1173      | `chio_kernel_core::revocation_view::RevocationView::install_if_newer`                                 | `formal/proof-manifest.toml` covered_rust_symbols `RevocationView::install_if_newer`; ASSUME-OS-CLOCK | Monotone-epoch fail-closed gate: strictly-newer candidates accept, equal/stale reject, idempotent on the failure path.   |
| `verify_oracle_inclusion_soundness`                                | ~L1196      | `chio_revocation_oracle::api::InclusionProof::verify`                                                 | `formal/proof-manifest.toml` covered_rust_symbols `InclusionProof::verify`; ASSUME-SHA256 | Sparse-Merkle inclusion proof soundness modulo ASSUME-SHA256: verifier accepts iff (leaf in tree AND chain hashes to root).         |

## Lean recursive-delegation theorems (Capability/Delegation.lean)

Source file: `formal/lean4/Chio/Chio/Capability/Delegation.lean`. Rows
below cross-reference each Lean theorem to the runtime symbol and Kani
harness that witness it.

| Property                       | Source                                                          | Rust path constrained                                                                       | Assumption discharge                                                                  | One-line description                                                                                                            |
| ------------------------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `delegate_no_widen`            | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L92)      | `chio_core_types::capability::delegate`, `chio_core_types::capability::validate_delegation_chain` | `formal/proof-manifest.toml` covered_rust_symbols `delegate`; P1                      | Re-delegating an already-attenuated capability cannot widen scope (recursive case of single-step monotonicity).                          |
| `attenuation_monotone`         | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L106)     | `chio_core_types::capability::ChioScope::is_subset_of`                                       | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Composing two attenuations preserves the subset relation on `ChioScope` (transitivity-under-composition).                        |
| `revocation_is_cut`            | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L120)     | `chio_kernel::ChioKernel::check_revocation`                                                   | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::revocation_snapshot_denies`; P2 | Revoking any ancestor in the delegation chain forces `checkRevocation` to return `Except.error` (revocation is a cut in the DAG). |
| `compose_preserves_algebra`    | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L141)     | `chio_core_types::capability::ChioScope::is_subset_of`                                       | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Composing two attenuated chains preserves the capability-algebra subset relation; closure under composition.                  |

## Adding a new property

1. Add the named TLA+ definition to `formal/tla/RevocationPropagation.tla`
   (top-level `<Name> ==` form), or add the `#[kani::proof]` attribute and
   harness function to `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`.
2. Add a row to the appropriate table above. Use the literal name in a
   backtick code span so `scripts/check-mapping.sh` can find it.
3. Wire the assumption-discharge column into `formal/assumptions.toml`
   and/or `formal/proof-manifest.toml` if the property is not purely
   structural. Use `n/a` if it is.
4. Run `bash scripts/check-mapping.sh`. The script must exit 0.

## Counterexample triage

If a TLA+ invariant or Kani harness named in this file produces a
counterexample, file a tracking issue using
`formal/issue-templates/property-counterexample.md` and follow the
property-failure triage runbook in the formal/ documentation.
