# formal/MAPPING.md

Cross-reference table from named formal properties (TLA+ invariants, Kani
harnesses) to the Rust call sites they constrain, the assumption registry
they rely on, and a one-line description of each property.

This file is the load-bearing artifact cited from
`.planning/trajectory/03-capability-algebra-properties.md` (Phase 3, task 5)
and is enforced by `scripts/check-mapping.sh`. The script greps the source
files for the canonical names listed below and fails the build if any
appear in the source but are not represented as a row here.

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
the nightly Apalache lane checks via `--temporal=` (M03.P3.T4 and the
[cleanup-c9] follow-up that switched the lane off `--inv=`).

| Property                    | Source                                          | Rust path constrained                                                                                          | Assumption discharge                                                                          | One-line description                                                                                                            |
| --------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `NoAllowAfterRevoke`        | `formal/tla/RevocationPropagation.tla` (~L238) | `crates/chio-kernel-core/src/evaluate.rs::evaluate`, `crates/chio-kernel/src/capability_lineage.rs`            | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY (per-row), retired-cross-row tracked at T6 | Every `allow` receipt was issued at a time when the issuing authority had not yet observed any revocation.                      |
| `MonotoneLog`               | `formal/tla/RevocationPropagation.tla` (~L250) | `crates/chio-kernel/src/receipt_store.rs`                                                                      | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY; jointly discharges RETIRED-SQLITE-CROSS-ROW (T6) | Per-authority receipt-log timestamps are strictly increasing; the log is append-only.                                           |
| `AttenuationPreserving`     | `formal/tla/RevocationPropagation.tla` (~L262) | `crates/chio-core-types/src/capability.rs` (`ChioScope::is_subset_of`), `crates/chio-kernel-core/src/normalized.rs` | n/a (structural; bounded by `DEPTH_MAX`)                                                      | `depth` stays within `0..DEPTH_MAX`; any cap in the `attenuated` state has been delegated at least once.                        |
| `RevocationEventuallySeen`  | `formal/tla/RevocationPropagation.tla` (~L336) | `crates/chio-kernel/src/capability_lineage.rs`, `crates/chio-kernel/src/receipt_store.rs`                      | `formal/assumptions.toml` ASSUME-PROPAGATE-FAIRNESS (weak fairness on `Propagate`)            | Once one authority observes a non-zero revocation epoch for a cap, every other authority eventually catches up to that epoch.   |

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

## Kani public harnesses (kani_public_harnesses.rs)

Source file: `crates/chio-kernel-core/src/kani_public_harnesses.rs`. The
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
| `verify_scope_intersection_associative`                            | ~L379       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Transitivity of `optional_u32_cap_is_subset` plus reflexivity witnesses an associative meet over the bounded cap lattice (M03.P2.T1). |
| `verify_revocation_predicate_idempotent`                           | ~L406       | `chio_kernel_core::formal_core::revocation_snapshot_denies`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P2                | `revocation_snapshot_denies` is idempotent on the same revocation snapshot and reduces to `token_revoked` on the diagonal.            |
| `verify_delegation_chain_step`                                     | ~L505       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `required_true_is_preserved`, `time_window_valid` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1, P3, P5        | One delegation step (M03.P2.T2) preserves attenuation: identity coverage, ops/constraints monotonicity, no cap widening, dpop preserved, and `is_valid_at(now)` propagates child-to-parent under `expiry(c') <= expiry(c)`. |
| `verify_receipt_roundtrip`                                         | ~L676       | `chio_kernel_core::receipts::sign_receipt`, `chio_kernel_core::receipts::ChioReceipt::verify_signature` | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`; P5                  | Receipt sign/verify roundtrip (M03.P2.T3): honest pair verifies, message/key/signature tampering each break verification, and sign is deterministic on equal inputs.                                                       |
| `verify_budget_checked_add_no_overflow`                            | ~L810       | `chio_kernel::budget_store::BudgetUsageRecord` (additive cap update at lines ~1030-1065)              | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Budget overflow never partial-commits (M03.P2.T4): `Overflow` and `CapExceeded` arms both leave post-state == pre-state, dispatch order is checked_add-before-cap-test, and failure is idempotent under retry.            |

## Adding a new property

1. Add the named TLA+ definition to `formal/tla/RevocationPropagation.tla`
   (top-level `<Name> ==` form), or add the `#[kani::proof]` attribute and
   harness function to `crates/chio-kernel-core/src/kani_public_harnesses.rs`.
2. Add a row to the appropriate table above. Use the literal name in a
   backtick code span so `scripts/check-mapping.sh` can find it.
3. Wire the assumption-discharge column into `formal/assumptions.toml`
   and/or `formal/proof-manifest.toml` if the property is not purely
   structural. Use `n/a` if it is.
4. Run `bash scripts/check-mapping.sh`. The script must exit 0.

## Counterexample triage

If a TLA+ invariant or Kani harness named in this file produces a
counterexample, file a tracking issue using
`formal/issue-templates/property-counterexample.md` and follow the runbook
in `.planning/trajectory/03-capability-algebra-properties.md` (Property
failure triage runbook).
