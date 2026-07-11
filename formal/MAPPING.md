# formal/MAPPING.md

Cross-reference table from named formal properties (TLA+ invariants, Kani
harnesses) to the Rust call sites they constrain, the assumption registry
they rely on, and a one-line description of each property.

This file is enforced by `scripts/check-mapping.sh`. The script greps the
source files for the canonical names listed below and fails the build if
any appear in the source but are not represented as a row here.
`cargo xtask gen proof-coverage` also parses these tables, so column changes
must preserve the generated coverage contract. It validates each source path
and named property; missing Rust files remain explicit unattributed evidence.

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

Manual Rust-to-model seams are registered separately as `[[mirror]]` entries
in `formal/proof-manifest.toml`. Lean entries are transliterations, while TLA+
entries are abstraction anchors. The required `cargo xtask check
formal-mirrors` gate hashes the named Rust items and fails when their normalized
tokens drift. A hash bless records review; it is not an equivalence proof and
does not establish a modeled property in Rust.

## TLA+ named invariants (RevocationPropagation.tla)

Source file: `formal/tla/RevocationPropagation.tla`. The five safety names
below are model-checked by `formal/tla/MCRevocationPropagation.cfg` via the
aggregate SafetyInv. The aggregate itself is intentionally NOT a row in this
table; the script greps for the leaf-named invariants. The safety rows run in
`.github/workflows/apalache-safety.yml` through the config's `INVARIANT
SafetyInv` selection. The named liveness property RevocationEventuallySeen is
checked by `.github/workflows/apalache-temporal.yml` via `--temporal=`
(Apalache reserves `--inv=` for state invariants).

| Property                    | Source                                          | Rust path constrained                                                                                          | Assumption discharge                                                                          | One-line description                                                                                                            |
| --------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `NoAllowAfterRevoke`        | `formal/tla/RevocationPropagation.tla` (~L302) | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_revocation`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs::ChioKernel::evaluate_tool_call_async_with_session_context`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot::is_revoked`, `RevocationView::is_revoked` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY for single-row commits; cross-row recovery is excluded | Every `allow` receipt was issued at a time when the issuing authority had not yet observed any revocation.                      |
| `MonotoneLog`               | `formal/tla/RevocationPropagation.tla` (~L314) | `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt`, `crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs::SqliteReceiptStore::append_chio_receipt_returning_seq`, `crates/platform/chio-store-sqlite/src/receipt_store.rs::append_chio_receipt_tx` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY and ASSUME-OS-CLOCK; the storage anchors do not enforce strict timestamps | Per-authority receipt-log timestamps are strictly increasing under the model-clock abstraction; the storage path is append-only. |
| `AttenuationPreserving`     | `formal/tla/RevocationPropagation.tla` (~L326) | `crates/core/chio-core-types/src/capability/attenuation.rs::validate_delegation_chain`, `crates/core/chio-core-types/src/capability/scope.rs::ChioScope::is_subset_of`, `crates/kernel/chio-kernel-core/src/normalized.rs::NormalizedScope::is_subset_of`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::validate_delegation_admission` | n/a (structural; bounded by `DEPTH_MAX`) | `depth` stays within `0..DEPTH_MAX`; any cap in the `attenuated` state has been delegated at least once. |
| `RevocationEventuallySeen`  | `formal/tla/RevocationPropagation.tla` (~L407) | `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationGossipPushQueue::enqueue_signed_root`, `RevocationGossipPushQueue::flush_batches_at`, `RevocationCatchupResponse::validate_response`, `respond_to_catchup` | Model-only `WF_vars(PropagateAny)`; `formal/assumptions.toml` ASSUME-NETWORK-TRANSPORT remains audited and does not guarantee delivery | Under the model fairness condition, every authority eventually catches up to an observed non-zero revocation epoch. |
| `RevocationFreshness`       | `formal/tla/RevocationPropagation.tla` (~L344) | `crates/trust/chio-revocation-oracle/src/freshness.rs::FreshnessConfig`, `verify_fresh_epoch_root`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot`, `RevocationView::install_if_newer`, `RevocationView::is_revoked` | `formal/assumptions.toml` ASSUME-OS-CLOCK | Every recorded local revocation epoch is strictly less than the global clock; observed-epoch freshness fails closed. |
| `RevocationStateCoupled`    | `formal/tla/RevocationPropagation.tla` (~L348) | `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot`, `RevocationSnapshot::is_revoked`, `RevocationView::install_if_newer`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_revocation`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view_at` | `formal/assumptions.toml` ASSUME-NETWORK-TRANSPORT; the runtime snapshot has one global epoch and a revoked-subject set rather than a per-subject lifecycle state | In the bounded model, a capability has a non-zero locally observed revocation epoch exactly when its local lifecycle state is revoked. |

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
- `formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean`
  connects every committed Aeneas production function to ordinary-value
  semantics or directly to the bounded reservation-ledger model. Concrete
  runtime store linkage remains outside the ledger equivalence theorem.
- `Chio.Proofs.ReservationLedger.ledger_conservation` and
  `Chio.Proofs.ReservationLedger.ledger_terminal_unique` in
  `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` prove the pure
  reservation transition and child-bound composition. The four-artifact join
  also names `formal/apalache/PostAdmissionDropGuard.tla`,
  `verify_reservation_ledger_conservation`, and the runtime pair
  `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`.
  Scalar admission is linked; production ledger linkage is not established.

## Trace validation

The trace lane consumes callbacks emitted synchronously by the real kernel at
successful revocation commit, completed revocation admission, and receipt
append boundaries. `RuntimeTraceRecorder` joins admission and append events by
the signed request ID, accounts for every callback exactly once, derives the
trace ID from canonical captured events plus caller context, and signs only a
complete stream with a caller-pinned observer key. The authority key inside an
envelope must match every projected receipt's kernel key. The generated full
state ITF is the sole state source for both deterministic Apalache `check`
evaluation and bounded prefix reachability. `ASSUME-TRACE-OBSERVER` remains the explicit
boundary for callbacks omitted, reordered, or rewritten before the recorder
can observe them and for mutation-free recorder deployment.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `TraceNotAccepted` | `formal/tla/trace/TraceCheckRevocationPropagation.tla` | `crates/kernel/chio-kernel/src/runtime_trace.rs`, `crates/kernel/chio-kernel/src/kernel/validation.rs`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`, `crates/tooling/chio-trace-validate/src/capture.rs`, `crates/tooling/chio-trace-validate/src/decode.rs`, `crates/tooling/chio-trace-validate/src/itf.rs`, `crates/tooling/chio-trace-validate/src/map/revocation.rs`, `crates/tooling/chio-conformance/src/native_suite.rs`, `crates/tooling/chio-conformance/tests/runtime_trace_corpus.rs` | `formal/assumptions.toml` ASSUME-TRACE-OBSERVER, ASSUME-ED25519, and ASSUME-SHA256 remain audited boundaries | A complete callback-accounted, canonical, signed runtime trace has every observed prefix bounded-reachable through the production transition relation. |
| `TraceEvaluationIncomplete` | `formal/tla/trace/TraceEvaluateRevocationPropagation.tla` | `crates/tooling/chio-trace-validate/src/apalache.rs`, `crates/tooling/chio-trace-validate/src/itf.rs`, `crates/tooling/chio-trace-validate/src/report.rs`, `formal/tla/trace/negative-registry.toml`, `scripts/check-receipt-trace-negative-registry.py` | `formal/assumptions.toml` ASSUME-TRACE-OBSERVER for callback completeness; no kernel-safety result is assumed | Pinned Apalache `check` deterministically replays the full-state ITF, evaluates all four invariants and witness classes, and rejects one registered real-runtime calibration per invariant. |

## Apalache named invariants (kernel-state subset)

Source directory: `formal/apalache/`. These rows are the focused kernel-state
invariant set. They are checked by `.github/workflows/apalache-safety.yml`
against the `MC*.cfg` files in the same directory; temporal checks use the
separate `.github/workflows/apalache-temporal.yml` workflow.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `MonotoneLogApalache` | `formal/apalache/MonotoneLogApalache.tla` | `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt`, `crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs::SqliteReceiptStore::append_chio_receipt_returning_seq`, `crates/platform/chio-store-sqlite/src/receipt_store.rs::append_chio_receipt_tx` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY and ASSUME-OS-CLOCK; the storage anchors do not enforce strict timestamps | Per-authority receipt timestamps are strictly increasing under the bounded model-clock abstraction. |
| `RevocationCutCompleteness` | `formal/apalache/RevocationCutCompleteness.tla` | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_revocation`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view_at`, `chio_kernel_core::formal_core::revocation_lookup_denies`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot::is_revoked`, `RevocationView::is_revoked` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::revocation_lookup_denies` and `formal_core::revocation_snapshot_denies`; Lean theorem `revocation_is_cut` | A revoked capability removes dispatch eligibility for every transitive descendant in each authority view. Both lazy production lookup paths require the shared projected denial predicate. |
| `DirectParentInClosure` | `formal/apalache/RevocationCutCompleteness.tla` | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::validate_delegation_admission`, `crates/core/chio-core-types/src/capability/attenuation.rs::validate_delegation_chain`, `crates/platform/chio-store-sqlite/src/capability_lineage.rs::SqliteReceiptStore::get_delegation_chain` | n/a (bounded structural closure); production validates a linear parent chain rather than materializing a descendant set | Every non-root parent edge is represented in the parent's descendant closure, so the modeled transitive revocation cut cannot pass over a missing direct edge. |
| `ReceiptBeforeAllow` | `formal/apalache/ReceiptBeforeAllow.tla` | `crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs::ChioKernel::build_allow_response_with_metadata`, `ChioKernel::build_execution_nonce_preflight_allow_response_with_metadata`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_federation`, `ChioKernel::record_chio_receipt`, `chio_formal_diff_tests::counterexample::replay_receipt_before_allow` | Modeled ordering evidence; concrete cross-row crash recovery remains excluded | Returning an allow response is modeled as publication after the corresponding receipt-persistence call, and the committed trace replays that ordering against the kernel. |
| `AllowReceiptsBudgetChecked` | `formal/apalache/ReceiptBeforeAllow.tla` | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_and_increment_budget`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs::ChioKernel::evaluate_tool_call_async_with_session_context`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs::ChioKernel::evaluate_tool_call_with_nested_flow_client_async`, `crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs::ChioKernel::build_allow_response_with_metadata`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_federation` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY; the model abstracts a successful budget admission as monotone set membership and does not establish cross-store atomicity | Every persisted allow receipt is for a capability whose budget check completed before receipt construction on the modeled evaluation path. |
| `KernelTransitionCancelSafe` | `formal/apalache/KernelTransitionCancelSafe.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard`, `PostAdmissionDropGuard::mark_dispatch_started`, `PostAdmissionDropGuard::handle_pre_dispatch_drop`, `PostAdmissionDropGuard::drop`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::reverse_pre_execution_budget_mutation` | Snapshot equality is by construction; the runtime reversal transition is not modeled; post-dispatch and fault cleanup paths are outside this model | The bounded clean pre-dispatch abstraction assumes unchanged budget and receipt snapshots; it does not prove that the Rust reversal restores them. |
| `ReservationConservation` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/budget_store.rs` | n/a (bounded structural model) | Counted reservation partition and shared active-child capacity at every bounded lifecycle state. The four-artifact join also names `verify_reservation_ledger_conservation`, `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `TerminalReceiptExactlyOne` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY | Receipt-bearing terminals append exactly one parent receipt, while a clean pre-dispatch unwind remains receipt-free. |
| `ChildReceiptsFlushed` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` | n/a (structural) | Every buffered child receipt is appended before its parent terminal receipt. |
| `RetainedIffAborted` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs` | n/a (structural) | An admission lease is retained exactly for an ambiguous post-dispatch abort or a failed lease unwind. |

### Negative falsifiability registry

`formal/apalache/_negative_tests/REGISTRY.toml` maps deliberately broken
models to the invariant row they falsify, the production fix commit, and the
runtime regression test for the same defect. `scripts/check-apalache-negative.sh`
fails unless every entry produces Apalache's violation exit, names exactly the
registered invariant and Error outcome, and emits a structurally valid ITF
trace. Registry entries
naming a property absent from this table are rejected before model checking
starts.

### Mutation sensitivity linkage

`formal/mutation/registry.toml` maps the specification and proof mutation
lanes back to the Rust surfaces represented by each model. The generated
coverage map classifies those entries in the existing `mutants` column and
labels them with the mutation lane, report path, activation target, and latest
full-cycle result. A pending or low activation ratio is sensitivity evidence,
not proof that the corresponding Rust surface is correct.

The TLA+ mutator applies the 30 exact curated probes and two mandatory
historical seeds registered in
`formal/apalache/spec-mutants-allowlist.toml`. Its activation evidence is a
clean full campaign with zero unviable results and at least 90 percent killed
globally and for each source; timeouts count as not killed. The Rust mutator
changes only `formal_core.rs` and `formal_aeneas.rs`; Kani harness assertions
and assumptions are outside its discovery set.

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
| `public_sign_receipt_refuses_content_hash_mismatch`                | ~L395       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` recomputes canonical content inside the trust boundary and refuses a mismatched claimed content hash before signing.   |
| `public_sign_receipt_accepts_matching_content_hash`                | ~L423       | `chio_kernel_core::receipts::sign_receipt`                                                            | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`                      | `sign_receipt` accepts a body only when its claimed content hash equals the recomputed canonical-content hash.                         |
| `verify_scope_intersection_associative`                            | ~L379       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Transitivity of `optional_u32_cap_is_subset` plus reflexivity witnesses an associative meet over the bounded cap lattice. |
| `verify_revocation_predicate_idempotent`                           | ~L406       | `chio_kernel_core::formal_core::revocation_snapshot_denies`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P2                | `revocation_snapshot_denies` is idempotent on the same revocation snapshot and reduces to `token_revoked` on the diagonal.            |
| `verify_revocation_admission_projection`                           | ~L505       | `chio_kernel_core::formal_core::revocation_lookup_denies`                                              | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::revocation_lookup_denies`; P2 | The shared lazy token and ancestor projection used by both production revocation callers is exactly the bounded snapshot deny predicate. The harness does not model store or snapshot IO. |
| `verify_delegation_chain_step`                                     | ~L505       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `required_true_is_preserved`, `time_window_valid` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1, P3, P5        | One delegation step preserves attenuation: identity coverage, ops/constraints monotonicity, no cap widening, dpop preserved, and `is_valid_at(now)` propagates child-to-parent under `expiry(c') <= expiry(c)`. |
| `verify_receipt_roundtrip`                                         | ~L676       | `chio_kernel_core::receipts::sign_receipt`, `chio_kernel_core::receipts::ChioReceipt::verify_signature` | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`; P5                  | Receipt sign/verify roundtrip: honest pair verifies, message/key/signature tampering each break verification, and sign is deterministic on equal inputs.                                                       |
| `verify_budget_checked_add_no_overflow`                            | ~L1014      | `chio_kernel_core::kani_public_harnesses::model_budget_apply`                                          | Model-level arithmetic witness; concrete store mutation is covered by runtime budget tests | In the standalone checked-add model, `Overflow` and `CapExceeded` leave post-state equal to pre-state, checked-add precedes cap testing, and failure is retry-idempotent. This harness does not execute either budget store. |
| `verify_budget_admission_projection`                               | ~L1134      | `chio_kernel_core::formal_core::budget_increment_admits`, `chio_kernel_core::formal_core::budget_charge_admits` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::budget_increment_admits` and `formal_core::budget_charge_admits`; P1 | The shared admission projections called by both InMemory and SQLite budget backends match optional invocation, per-invocation, total-cap, overflow, and absent-cap semantics. The harness does not model store mutations or ledger transitions. |
| `verify_reservation_ledger_conservation`                           | `formal_aeneas.rs::ledger_apply` | `chio_kernel_core::formal_aeneas::ledger_apply` | Model-level; production ledger linkage not established | Bounded sequences preserve partition totals, make finalized states absorbing, and reject invalid arithmetic updates as exact no-ops. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`. Scalar admission is linked; production ledger linkage is not established. |
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

## Runtime reservation conservation checks

These debug and stateful-test rows bind the model-level conservation algebra
to the concrete single-node journal without claiming a proved refinement.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `debug_assert_reservation_conservation` | `crates/kernel/chio-kernel/src/kernel/ledger_audit.rs` | `chio_kernel::BudgetStore::list_mutation_events`, drop, unwind, reverse, release, reconcile, and runtime metadata transition groups | `BudgetGuaranteeLevel::SingleNodeAtomic`; model-level audit, production ledger linkage not established | Debug replay checks every monetary journal after-state and the reserve, commit, release, and outstanding partition. Events without hold IDs are conserved as one anonymous pool and do not establish per-hold identity; production reverse and reconcile call sites separately require their named hold to terminate exactly once. The journal has no retain event, so it does not establish retained monetary holds; a separate metadata check validates runtime lease retention. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `verify_reservation_ledger_conservation` plus `Proofs/ReservationLedger.lean`, and `tests/property_reservation_ledger.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `mixed_store_reservation_sequences_preserve_the_journal_law` | `crates/kernel/chio-kernel/tests/property_reservation_ledger.rs` | `chio_kernel::InMemoryBudgetStore` authorization, reverse, release, and reconcile mutations | `BudgetGuaranteeLevel::SingleNodeAtomic`; runtime test evidence, production ledger linkage not established | Stateful store operation sequences compare the concrete monetary journal, usage row, and terminal history after every step. This test does not drive kernel lifecycle, drop, hooks, or receipts. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `verify_reservation_ledger_conservation` plus `Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `drop_guard_disposition_table` | `crates/kernel/chio-kernel/src/kernel/tests/drop_guard_proptest.rs` | `chio_kernel::ChioKernel::run_runtime_admission_hook`, `chio_kernel::kernel::PostAdmissionDropGuard`, receipt log, monetary journal, and usage row | `BudgetGuaranteeLevel::SingleNodeAtomic`; production-path runtime evidence, not a refinement proof | All eight lifecycle cells drive the production runtime-admission hook and real drop guard, then check admission and release counts, receipt retention metadata, exactly one five-unit monetary reversal with no realized spend, journal conservation, and final usage. This complements the store-only randomized lane without claiming retained monetary journal evidence. |

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
