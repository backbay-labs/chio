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
in `formal/proof-manifest.toml`. Lean entries declare either a transliteration
or an abstraction anchor; TLA+ entries are abstraction anchors. The required
`cargo xtask check formal-mirrors` gate hashes the named Rust items and fails
when their normalized tokens drift. A hash bless records review; it is not an
equivalence proof and does not establish a modeled property in Rust.

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
| `NoAllowAfterRevoke`        | `formal/tla/RevocationPropagation.tla` (~L302) | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::revoke_capability`, `ChioKernel::check_revocation`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs::ChioKernel::evaluate_tool_call_async_with_session_context`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs::ChioKernel::evaluate_tool_call_with_nested_flow_client_async`, `crates/kernel/chio-kernel/src/kernel/credential_reservation.rs::ChioKernel::reserve_dispatch_credentials`, `DispatchCredentialReservation::requires_post_reservation_revalidation`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs::ChioKernel::revalidate_immediately_before_dispatch`, `crates/kernel/chio-kernel/src/kernel/construction.rs::ChioKernel::lock_runtime_trace_transition`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_federation`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot::is_revoked`, `RevocationView::is_revoked` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY for single-row commits; cross-row recovery is excluded. The model treats readiness waiting as stuttering and abstracts final non-consuming revalidation plus receipt append as one `Evaluate` transition. After an actual payment authorization, both production evaluation paths force mutable guard and runtime-hook revalidation even when readiness returned immediately. When a single-use dispatch credential is reserved, both paths run the same forced mutable-state boundary again before dispatch; credential-store atomicity, payment blocking, adapter rollback, and callback side effects are outside the model. The Rust append path rechecks revocation while holding the same transition lock used by `ChioKernel::revoke_capability`. Revocation writes covered by this claim are mediated through that kernel method; out-of-band mutation through a retained custom revocation-store handle cannot share the kernel lock and is outside the claim. Runtime trace qualification rejects an observed relevant revocation between recorded admission and append under ASSUME-TRACE-OBSERVER. | Every `allow` receipt was issued at a time when the issuing authority had not yet observed any revocation.                      |
| `MonotoneLog`               | `formal/tla/RevocationPropagation.tla` (~L314) | `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt`, `crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs::SqliteReceiptStore::append_chio_receipt_returning_seq`, `crates/platform/chio-store-sqlite/src/receipt_store.rs::append_chio_receipt_tx` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY and ASSUME-OS-CLOCK; the storage anchors do not enforce strict timestamps | Per-authority receipt-log timestamps are strictly increasing under the model-clock abstraction; the storage path is append-only. |
| `AttenuationPreserving`     | `formal/tla/RevocationPropagation.tla` (~L326) | `crates/core/chio-core-types/src/capability/attenuation.rs::validate_delegation_chain`, `crates/core/chio-core-types/src/capability/scope.rs::ChioScope::is_subset_of`, `crates/kernel/chio-kernel-core/src/normalized.rs::NormalizedScope::is_subset_of`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::validate_delegation_admission` | n/a (structural; bounded by `DEPTH_MAX`) | `depth` stays within `0..DEPTH_MAX`; any cap in the `attenuated` state has been delegated at least once. |
| `RevocationEventuallySeen`  | `formal/tla/RevocationPropagation.tla` (~L407) | `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationGossipPushQueue::enqueue_signed_root`, `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationGossipPushQueue::flush_batches_at`, `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationCatchupResponse::validate_response`, `crates/trust/chio-federation/src/revocation_gossip.rs::respond_to_catchup` | Model-only `WF_vars(PropagateAny)`; `formal/assumptions.toml` ASSUME-NETWORK-TRANSPORT remains audited and does not guarantee delivery | Under the model fairness condition, every authority eventually catches up to an observed non-zero revocation epoch. |
| `RevocationFreshness`       | `formal/tla/RevocationPropagation.tla` (~L344) | `crates/trust/chio-revocation-oracle/src/freshness.rs::FreshnessConfig`, `verify_fresh_epoch_root`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot`, `RevocationView::install_if_newer`, `RevocationView::is_revoked` | `formal/assumptions.toml` ASSUME-OS-CLOCK | Every recorded local revocation epoch is strictly less than the global clock; observed-epoch freshness fails closed. |
| `RevocationStateCoupled`    | `formal/tla/RevocationPropagation.tla` (~L348) | `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot`, `RevocationSnapshot::is_revoked`, `RevocationView::install_if_newer`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_revocation`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view_at` | `formal/assumptions.toml` ASSUME-NETWORK-TRANSPORT; the runtime snapshot has one global epoch and a revoked-subject set rather than a per-subject lifecycle state | In the bounded model, a capability has a non-zero locally observed revocation epoch exactly when its local lifecycle state is revoked. |

## Distributed revocation invariants

Safety source: `formal/tla/DistributedRevocation.tla`. Conditional liveness is
checked in `formal/tla/DistributedRevocationTemporal.tla`, a four-variable
projection that expands weak fairness into primitive temporal logic. A
length-5 bounded check maps one selected full-model authority pair into that
spec, and a deterministic witness reaches an observed state with a fair
stuttering suffix. These checks do not establish unbounded all-pair
refinement. The PR safety lane checks
behavioral invariants over two authorities and three epochs at length 6 and
checks exact function domains plus relational shape in the concrete initial
state. Scheduled safety expands the behavioral check to three authorities and
four epochs at length 6, with initial shape checked at those constants. The temporal property remains
scheduled and non-required. The production projection gate emits and validates
exact scalar ITF schedules from the gossip queue, pinned signer, catch-up
response, and monotone revocation view. It exercises one pinned origin against
the shipped single-snapshot view; per-origin matrix isolation remains
model-only and is not claimed as full-state Rust refinement.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `DistributedDomainsOK` | `formal/tla/DistributedRevocation.tla` | `crates/trust/chio-federation/src/revocation_gossip.rs`, `crates/kernel/chio-kernel-core/src/revocation_view.rs` | n/a (initial state shape) | The concrete initial state has exact function domains for every clock, high-water mark, queue, counting channel, partition clock, and evaluation/allow witness. |
| `ClockSkewBound` | `formal/tla/DistributedRevocation.tla` | `crates/trust/chio-revocation-oracle/src/freshness.rs::verify_fresh_epoch_root`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::verify_snapshot_freshness` | `formal/assumptions.toml` ASSUME-OS-CLOCK and ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND | Independently advancing authority clocks remain within the configured pairwise skew tolerance. |
| `SignerPinnedHighWater` | `formal/tla/DistributedRevocation.tla` | `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationRootGossip::validate_envelope`, `chio_revocation_oracle::SignedEpochRoot::verify`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationView::install_if_newer` | `scripts/check-distributed-revocation-refinement.sh` exercises concrete forged-signer rejection; `formal/assumptions.toml` ASSUME-ED25519 remains the cryptographic primitive boundary; invalid frames are explicit rejected channel input | Every installed view remains authentic and at or below the genuine origin epoch, including against forged frames at already-issued epochs. |
| `NoAllowAfterRevokeDistributed` | `formal/tla/DistributedRevocation.tla` | `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view_at`, `crates/kernel/chio-kernel-core/src/revocation_view.rs::RevocationSnapshot::is_revoked` | ASSUME-OS-CLOCK for the production freshness gate | Every modeled allow records a local view that has not observed the target's revoked epoch. Fresh nonzero snapshots may still allow unrelated subjects. |
| `StaleEvaluationDenied` | `formal/tla/DistributedRevocation.tla` | `crates/trust/chio-revocation-oracle/src/freshness.rs::verify_fresh_epoch_root`, `crates/kernel/chio-kernel/src/kernel/delegation.rs::verify_snapshot_freshness` | ASSUME-OS-CLOCK supplies clock tolerance; the deny predicate itself is production-linked and does not require delivery fairness | An evaluation records an allow only when the installed root timestamp is not in the future and its wall-clock age is within `FreshnessBound`. |
| `RejectedRawEvaluationCountBound` | `formal/tla/DistributedRevocation.tla` | No production rate limiter exists; `crates/kernel/chio-kernel/src/kernel/delegation.rs::verify_snapshot_freshness` is time-based | Explicitly not discharged or claimed; registered claim-witness counterexample | This rejected candidate says observation occurs within a finite number of raw evaluations. Scheduler delay or loss plus repeated same-tick evaluations falsifies it, so it is excluded from `SafetyInv`. |
| `PartitionSuspendResume` | `formal/tla/DistributedRevocation.tla` | `crates/trust/chio-federation/src/revocation_gossip.rs::respond_to_catchup`, `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationCatchupResponse::validate_response`, `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs::request_catchup_over_iroh_with_limits` | Freeze safety is unconditional in the bounded model; eventual resume requires ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND | Repeated cuts freeze the affected peer high-water mark and timestamp. Post-heal catch-up is established separately by scheduled liveness and deterministic projection evidence. |
| `RevocationEventuallyObservedDistributed` | `formal/tla/DistributedRevocationTemporal.tla` | `crates/trust/chio-federation/src/revocation_gossip.rs::RevocationGossipPushQueue::flush_batches_at`, `respond_to_catchup`, `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs::request_catchup_over_iroh_with_limits` | ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND under weak fairness of connected catch-up and partition heal | Every finite origin epoch is eventually observed by the selected authority when the registered fairness and eventual-heal condition holds. The scheduled bounded refinement and non-vacuity witness constrain the scalar abstraction; this is corroborating evidence, not a release claim. |

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
- The DPoP freshness and nonce helpers reach signed runtime boundaries through
  `DpopNonceStore::check_and_insert_through` for the direct verifier and
  `DpopNonceStore::reserve_for_dispatch_through` from
  `ChioKernel::reserve_dispatch_credentials` for kernel dispatch. Both paths
  retain live nonce markers through the proof's inclusive signed horizon and
  deny at capacity. Clock behavior, mutex integrity, and marker storage remain
  runtime qualification boundaries.
- `Chio.Proofs.ReservationLedger.ledger_conservation` and
  `Chio.Proofs.ReservationLedger.ledger_terminal_unique` in
  `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` prove the pure
  reservation transition and child-bound composition. The four-artifact join
  also names `formal/apalache/PostAdmissionDropGuard.tla`,
  `verify_reservation_ledger_terminal_classification`,
  `verify_reservation_ledger_conservation`, and the runtime pair
  `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`.
  Scalar admission is linked; production ledger linkage is not established.
- `Chio.Treaty.PredicateLang.runtime_admission_policy_exact` is the bounded
  fail-closed projection for P3. Its two Lean abstraction anchors bind the
  projected `TreatyScope`, `LadderIntersection`, `BilateralInvocation`, and
  evidence records plus `validate_treaty_scope`,
  `validate_ladder_intersection`, `evaluate_cross_boundary_admission`,
  `validate_bilateral_invocation`, and `ladder_mode_rank`. The hashes detect
  Rust drift; they do not prove the projection refines those Rust functions.

- `Chio.Guards.WasmBoundary.guest_output_confinement`,
  `Chio.Guards.WasmBoundary.no_allow_amplification`, and
  `Chio.Guards.WasmBoundary.resource_exhaustion_fail_closed` model the typed
  core-module verdict boundary. The advisory exception is stated by
  `Chio.Guards.WasmBoundary.advisory_mode_is_nonblocking_by_design`.
  `ASSUME-WASM-ENGINE` remains load-bearing for wasmtime semantics, and these
  theorems do not establish full engine information-flow non-interference.

## Trace validation

The trace lane consumes callbacks emitted synchronously by the real kernel at
successful revocation commit, completed revocation admission, and receipt
append boundaries. `RuntimeTraceRecorder` joins admission and append events by
the signed request ID, accounts for every kernel-assigned source sequence
exactly once, restores causal order despite concurrent callback delivery,
derives the trace ID from canonical captured events plus caller context, and
signs only a complete stream with a caller-pinned observer key. Admission
events preserve the full checked lineage and the exact revoked token or
delegation ancestor. The signed schema checks lineage uniqueness, depth, source
membership, and visible source ordering. It rejects a relevant revocation
strictly between admission and receipt append because the current model combines
those boundaries into one action. For a nonzero observed epoch, the projection
uses that source as the effective TLA capability while the signed receipt
retains the presented child. The authority key inside an envelope must match
every projected receipt's kernel key. The generated full-state ITF is the sole
state source for both deterministic
Apalache `check` evaluation and bounded prefix reachability.
`ASSUME-TRACE-OBSERVER` remains the explicit boundary for callbacks omitted or
rewritten before the recorder can observe them and for mutation-free recorder
deployment; delivery order is no longer assumed.

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
| `ReceiptBeforeAllow` | `formal/apalache/ReceiptBeforeAllow.tla` | `crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs::ChioKernel::build_allow_response_with_metadata_and_payee_binding`, `ChioKernel::build_execution_nonce_preflight_allow_response_with_metadata`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_federation`, `ChioKernel::record_chio_receipt`, `chio_formal_diff_tests::counterexample::replay_receipt_before_allow` | Modeled ordering evidence; concrete cross-row crash recovery remains excluded. Execution-nonce preflight returns API `Verdict::Allow` with terminal `Incomplete` and persists `Decision::Incomplete`; it is an ordering anchor, not a `PublishAllow` transition. | `PublishAllow` models only a completed tool-output allow backed by `Decision::Allow`, after the receipt-persistence call for the same single-use call identity and capability. The committed trace replays that ordering against the kernel. |
| `AllowReceiptsBudgetChecked` | `formal/apalache/ReceiptBeforeAllow.tla` | `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::check_and_increment_budget`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs::ChioKernel::evaluate_tool_call_async_with_session_context`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs::ChioKernel::evaluate_tool_call_with_nested_flow_client_async`, `crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs::ChioKernel::build_allow_response_with_metadata_and_payee_binding`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_federation` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY; the model gives every call a bounded identity and does not establish cross-store atomicity | Every persisted allow receipt carries a call identity and capability whose matching budget check completed before receipt construction on the modeled evaluation path. |
| `KernelTransitionCancelSafe` | `formal/apalache/KernelTransitionCancelSafe.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard`, `PostAdmissionDropGuard::new`, `PostAdmissionDropGuard::mark_dispatch_started`, `PostAdmissionDropGuard::disarm`, `PostAdmissionDropGuard::handle_pre_dispatch_drop`, `PostAdmissionDropGuard::record_pre_dispatch_cleanup_fault_receipt`, `PostAdmissionDropGuard::drop`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::reverse_pre_execution_budget_mutation` | Snapshot equality is by construction; the runtime reversal transition is not modeled; post-dispatch and fault cleanup paths are outside this model | The bounded clean pre-dispatch abstraction assumes unchanged budget and receipt snapshots; it does not prove that the Rust reversal restores them. |
| `ReservationConservation` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard::drop`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::retained_admission_receipt_metadata`, `ChioKernel::ambiguous_dispatch_receipt_metadata`, `crates/kernel/chio-kernel/src/budget_store.rs`, `crates/kernel/chio-runtime-core/src/admission.rs::RuntimeAdmissionReservationTracker`, `evaluate_runtime_admission_tracked`, `crates/kernel/chio-runtime-core/src/admission_hook.rs::ChioRuntimeAdmissionHook::release_reservations`, `ChioRuntimeAdmissionHook::release_reserved` | n/a (bounded structural model) | Counted reservation partition and shared active-child capacity at every bounded lifecycle state. `hold` is the kernel budget hold. A returned output reaches budget reconciliation and commits the modeled hold before its final allow, deny, or incomplete terminal. Payment-adapter authorization is outside `Resources`. For a server `Err` or dropped future, production retained-admission metadata preserves both the hold and that authorization. `lease` conservatively projects destructive, treaty, and swarm reservation identifiers. The named release functions are pre-dispatch drift anchors; the retained-admission metadata path and armed drop branch are the outcome-unknown post-dispatch anchors. A failed pre-dispatch release is retained or possibly stuck. The model's terminal retained hold projects to an outstanding concrete journal reservation because the store has no retain event. Exact per-identifier mutate-then-error ownership, payment-adapter state, and production ledger refinement remain unproved. The evidence join also names `verify_reservation_ledger_terminal_classification`, `verify_reservation_ledger_conservation`, `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`. The classifier and scalar admission are linked; the concrete production ledger is not. |
| `TerminalReceiptExactlyOne` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard::disarm`, `PostAdmissionDropGuard::drop`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::ChioKernel::record_chio_receipt_with_mode`, `ChioKernel::record_chio_receipt`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs::ChioKernel::finalize_tool_output_with_metadata_and_payee_binding` | `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY covers the store transaction, not acknowledgement certainty. An outcome-unknown append is modeled as zero or one durable receipt and is not retried. | A committed parent append has exactly one receipt, an outcome-unknown append has at most one, and a clean pre-dispatch unwind remains receipt-free. The normal path disarms the drop guard before terminal construction; the armed post-dispatch drop path makes one cancellation builder call. |
| `ChildReceiptsFlushed` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard::record_buffered_child_receipts`, `PostAdmissionDropGuard::flush_buffered_child_receipts_from_drop`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs::ChioKernel::record_child_receipt`, `crates/kernel/chio-kernel/src/kernel/mod.rs::SessionNestedFlowBridge::complete_child_request_with_receipt` | Successful child-receipt append availability is assumed. Outcome-unknown durable presence and the failed-suffix branch are outside the invariant. | Under the availability assumption, every buffered child receipt is appended before its parent terminal receipt. The nested-flow bridge signs and buffers each completed child before returning its result. Rust retries only the not-attempted suffix; it removes the outcome-unknown child from the retry buffer and carries that signed receipt in cancellation metadata without claiming whether the append committed. |
| `RetainedIffAborted` | `formal/apalache/PostAdmissionDropGuard.tla` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs::PostAdmissionDropGuard::drop`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs::ChioKernel::mark_runtime_admission_reservations_retained_fail_closed`, `crates/kernel/chio-kernel/src/kernel/validation.rs::ChioKernel::retained_admission_receipt_metadata`, `ChioKernel::ambiguous_dispatch_receipt_metadata`, `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs::ChioKernel::evaluate_tool_call_async_with_session_context`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs::ChioKernel::evaluate_tool_call_with_nested_flow_client_async`, `crates/kernel/chio-kernel/src/kernel/mod.rs::SessionNestedFlowBridge`, `crates/kernel/chio-kernel/src/kernel/credential_reservation.rs::DispatchCredentialReservation`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs`, `crates/kernel/chio-runtime-core/src/admission.rs::evaluate_runtime_admission_tracked`, `crates/kernel/chio-runtime-core/src/admission_hook.rs::ChioRuntimeAdmissionHook::release_reservations`, `ChioRuntimeAdmissionHook::release_reserved` | A pre-dispatch runtime-hook release error or panic is abstracted as a failed lease. Payment authorization is outside the four-resource model. Exact per-identifier disposition, dispatch-credential atomicity, payment-adapter state, and production ledger linkage are not established. | An admission lease remains retained after every non-allow post-dispatch terminal. A returned `Ok` output is known and reaches reconciliation, so its modeled hold commits even if finalization later produces deny or incomplete. A server `Err` or dropped future is outcome-unknown and retains the hold. The model records raw `url` separately from its incomplete receipt projection and quantifies nested bridge activity; both boolean values take the same post-dispatch retention transition, so URL cannot reach pre-dispatch cleanup. Other server errors may produce deny, incomplete, or cancel receipts. Only a kernel error before polling is classified as reversible pre-dispatch cleanup. Production retained-admission metadata leaves budget and payment exposure plus credential and runtime reservations fail closed on the unknown paths. |

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

The TLA+ mutator applies the 31 exact curated probes and two mandatory
historical seeds registered in
`formal/apalache/spec-mutants-allowlist.toml`. Its activation evidence is a
clean full campaign with zero unviable results and at least 90 percent killed
globally and for each source; timeouts count as not killed. The Rust mutator
changes only `formal_core.rs` and `formal_aeneas.rs`; Kani harness assertions
and assumptions are outside its discovery set.

## Loom interleaving harnesses

Source file: `crates/kernel/chio-kernel/tests/loom_concurrency.rs`. These rows
map bounded test-local synchronization models to the production surfaces whose
ordering obligations they approximate. They do not substitute Loom primitives
into the kernel and do not prove the behavior of production std, Tokio,
DashMap, or ArcSwap primitives. `.loom/harnesses.toml` records this boundary as
`scope = "bounded_abstract_model"` for every entry.

| Property | Source | Rust path constrained | Evidence boundary | One-line description |
| -------- | ------ | --------------------- | ----------------- | -------------------- |
| `loom_session_create_lookup_terminal_same_id` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/session.rs`, `crates/kernel/chio-kernel/src/request_matching.rs` | Bounded abstract model; no production-primitive proof | Session creation, lookup, and terminal observation preserve one identity without duplicate allowance. |
| `loom_parent_signs_receipt_while_child_spawns` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/dispatch.rs`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` | Bounded abstract model; no production-primitive proof | A child receipt is observable only after its parent receipt is present in the modeled log. |
| `loom_revocation_race_eval` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `crates/kernel/chio-kernel/src/kernel/delegation.rs` | Bounded abstract model; no production-primitive proof | Serialized evaluation events never allow after the modeled revocation event. |
| `loom_receipt_channel_producer_drain` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/signing_task.rs` | Bounded abstract model; no production-primitive proof | Bounded queue backpressure and draining lose no accepted receipt and sign no receipt twice. |
| `loom_inflight_increment_decrement_storm` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/session.rs` | Bounded abstract model; no production-primitive proof | Concurrent track, complete, and cancel operations return the modeled in-flight count to zero without underflow. |
| `loom_dashmap_session_insert_remove_concurrent` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/request_matching.rs` | Bounded abstract model; no production-primitive proof | A modeled shard under insert, remove, and lookup never exposes a torn duplicate session. |
| `loom_emergency_stop_arcswap` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/construction.rs` | Bounded abstract model; no production-primitive proof | Emergency-stop publication never exposes a partial reason in the modeled state. |
| `protocol_primitives_last_unit_contention` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/budget_store/in_memory.rs`, `crates/platform/chio-store-sqlite/src/budget_store` | Bounded abstract model; no production-primitive proof | Two modeled charges against one unit yield exactly one allowance and one depletion. |
| `protocol_primitives_three_key_all_or_nothing_admission` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite.rs` | Bounded abstract model; no production-primitive proof | Overlapping composite quota reservations admit exactly one complete three-key hold and leave no partial denied hold. |
| `protocol_primitives_immutable_maximum_race` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite.rs` | Bounded abstract model; no production-primitive proof | Concurrent definitions of one quota key accept one immutable maximum. |
| `loom_cumulative_approval_serializes_concurrent_threshold_crossing` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite.rs`, `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/approval.rs` | Bounded abstract model; no production-primitive proof | Concurrent reservations crossing one threshold serialize into one authorization and one approval requirement. |
| `protocol_primitives_capture_versus_reverse` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/capture.rs`, `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs` | Bounded abstract model; no production-primitive proof | Capture and pre-dispatch reversal have one winner and conserve the modeled reservation. |
| `protocol_primitives_idempotent_compensation` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs` | Bounded abstract model; no production-primitive proof | Duplicate compensation attempts apply exactly one modeled reversal. |
| `loom_approval_attachment_and_pending_reverse_have_one_winner` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/approval.rs`, `crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs` | Bounded abstract model; no production-primitive proof | Approval attachment and pending reversal serialize to one terminal transition. |
| `loom_post_admission_drop_guards_race_on_receipt_store_write_lock` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` | Bounded abstract model; no production-primitive proof | Two armed post-dispatch guards serialize deliberately non-atomic receipt appends without loss or duplication. |
| `loom_disarmed_drop_guard_is_noop` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` | Bounded abstract model; no production-primitive proof | A disarmed modeled guard does not release reservations or append a receipt while another writer proceeds. |
| `receipt_writer_liveness_no_lost_wakeup` | `crates/kernel/chio-kernel/tests/loom_concurrency.rs` | `crates/kernel/chio-kernel/src/kernel/receipt_writer_watchdog.rs`, `crates/kernel/chio-kernel/src/kernel/construction.rs` | Bounded abstract model; no production-primitive proof | Receipt-writer liveness publication exposes only modeled published verdicts and retains the terminal verdict. |

## Deterministic simulation harnesses

Source target: `crates/kernel/chio-kernel/tests/dst_drop_injection.rs`, with
support in `tests/dst/support.rs`. These are runtime witnesses over the real
`ChioKernel` and real store traits. The crash rows close and reopen SQLite.
Their scope is single-process and single-store, not distributed refinement.

| Property | Source | Rust path constrained | Evidence boundary | One-line description |
| -------- | ------ | --------------------- | ----------------- | -------------------- |
| `dst_fixed_seed_corpus` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`, `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`, `crates/kernel/chio-kernel/src/budget_store/in_memory.rs` | 64 seeded single-process runtime episodes | Partially polls and drops real evaluation futures on both sides of dispatch-start, injects receipt, budget, and admission faults, and checks ReceiptBeforeAllow, exact disposition, and reservation conservation after every episode. |
| `dst_sqlite_crash_reopen_boundaries` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`, `crates/platform/chio-store-sqlite/src/receipt_store.rs`, `crates/platform/chio-store-sqlite/src/budget_store.rs` | Real SQLite close and reopen; injected process-crash boundary | Crashes immediately before and after synchronous receipt persistence, closes every handle, reopens both databases, and checks recovered ReceiptBeforeAllow and budget conservation. |
| `dst_child_receipt_flush_regression_is_killed` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs` | Deliberate store-boundary mutation over a real nested-flow evaluation | Proves the unmodified child-receipt flush and demonstrates that suppressing the completed child append is rejected by the ChildReceiptsFlushed oracle. |
| `dst_budget_wrapper_preserves_replay_outcome` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/budget_store/in_memory/trait_impl.rs`, `crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs` | Real in-memory and SQLite stores behind the injected DST wrapper in `tests/dst/support.rs` | Proves the wrapper forwards replay outcomes and expired-hold sweeping without duplicating authorization events or leaking retained holds. |
| `dst_wide_sweep` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`, `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` | 10,000 seeded single-process runtime episodes | Runs the same closed episode grammar and three oracles over the nightly wide corpus. |
| `dst_replay_seed` | `crates/kernel/chio-kernel/tests/dst_drop_injection.rs` | `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`, `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` | Exact seed and derived plan replay | Reconstructs one episode from `CHIO_DST_SEED` and prints the seed and full fault plan for one-command reproduction. |

## Executable policy refinement cross-reference

`formal/lean4/Chio/Chio/Treaty/PredicateLang.lean` defines the syntactic
predicate and bounded refinement vocabulary used by the treaty model. The
customer-facing executable counterpart is
`crates/guards/chio-policy/src/analyze/refine.rs`, with rule lowering in
`crates/guards/chio-policy/src/analyze/ir.rs` and exact glob relations in
`crates/guards/chio-policy/src/analyze/glob.rs`. These Rust checks are runtime
qualification evidence and are not included in the Lean proof boundary.

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
| `public_delivery_contract_allow_implies_digest_match`              | ~L1396      | `chio_kernel_core::formal_core::delivery_contract_admits`                                             | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::delivery_contract_admits`; P3 | An Allow from the pure delivery-contract comparison implies exact equality of the bounded expected and observed byte strings. |
| `verify_scope_intersection_associative`                            | ~L379       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1                | Transitivity of `optional_u32_cap_is_subset` plus reflexivity witnesses an associative meet over the bounded cap lattice. |
| `verify_revocation_predicate_idempotent`                           | ~L406       | `chio_kernel_core::formal_core::revocation_snapshot_denies`                                           | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P2                | `revocation_snapshot_denies` is idempotent on the same revocation snapshot and reduces to `token_revoked` on the diagonal.            |
| `verify_revocation_admission_projection`                           | ~L505       | `chio_kernel_core::formal_core::revocation_lookup_denies`                                              | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::revocation_lookup_denies`; P2 | The shared lazy token and ancestor projection used by both production revocation callers is exactly the bounded snapshot deny predicate. The harness does not model store or snapshot IO. |
| `verify_delegation_chain_step`                                     | ~L505       | `chio_kernel_core::formal_core::optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `required_true_is_preserved`, `time_window_valid` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::*`; P1, P3, P5        | One delegation step preserves attenuation: identity coverage, ops/constraints monotonicity, no cap widening, dpop preserved, and `is_valid_at(now)` propagates child-to-parent under `expiry(c') <= expiry(c)`. |
| `verify_receipt_roundtrip`                                         | ~L676       | `chio_kernel_core::receipts::sign_receipt`, `chio_kernel_core::receipts::ChioReceipt::verify_signature` | `formal/proof-manifest.toml` covered_rust_symbols `sign_receipt`; P5                  | Receipt sign/verify roundtrip: honest pair verifies, message/key/signature tampering each break verification, and sign is deterministic on equal inputs.                                                       |
| `verify_budget_checked_add_no_overflow`                            | ~L1014      | `chio_kernel_core::kani_public_harnesses::model_budget_apply`                                          | Model-level arithmetic witness; concrete store mutation is covered by runtime budget tests | In the standalone checked-add model, `Overflow` and `CapExceeded` leave post-state equal to pre-state, checked-add precedes cap testing, and failure is retry-idempotent. This harness does not execute either budget store. |
| `verify_budget_admission_projection`                               | ~L1134      | `chio_kernel_core::formal_core::budget_increment_admits`, `chio_kernel_core::formal_core::budget_charge_admits` | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::budget_increment_admits` and `formal_core::budget_charge_admits`; P1 | The shared admission projections called by both InMemory and SQLite budget backends match optional invocation, per-invocation, total-cap, overflow, and absent-cap semantics. The harness does not model store mutations or ledger transitions. |
| `verify_reservation_ledger_terminal_classification`                | ~L1144      | `chio_kernel_core::formal_aeneas::ledger_is_terminal` | Model-level; Aeneas and Lean link the pure helper, while production ledger linkage is not established | The pure ledger classifier is terminal exactly when no reserved amount remains and at least one committed, released, or retained amount is non-zero. |
| `verify_reservation_ledger_conservation`                           | `formal_aeneas.rs::ledger_apply` | `chio_kernel_core::formal_aeneas::ledger_apply` | Model-level; production ledger linkage not established | Bounded sequences preserve partition totals, make finalized states absorbing, and reject invalid arithmetic updates as exact no-ops. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs` plus `tests/property_reservation_ledger.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `verify_composite_quota_all_or_nothing`                            | ~L1128      | `chio_kernel_core::formal_core::composite_quota_authorize`                                            | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::composite_quota_authorize` | A three-key authorization increments every applicable quota within its maximum or preserves the complete pre-state. |
| `verify_quota_maximum_immutable`                                   | ~L1153      | `chio_kernel_core::formal_core::quota_maximum_compatible`                                             | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::quota_maximum_compatible` | An initialized quota key accepts only the maximum established on first use. |
| `verify_family_binding_preservation`                               | ~L1167      | `chio_kernel_core::formal_core::family_binding_preserved`                                             | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::family_binding_preserved` | A family descendant preserves every signed root field, binding digest, signature, and immutable maximum. |
| `verify_threshold_distinct_signers`                                | ~L1204      | `chio_kernel_core::formal_core::threshold_distinct_eligible_signers`                                  | `formal/proof-manifest.toml` covered_rust_symbols `formal_core::threshold_distinct_eligible_signers` | Threshold count includes each eligible public-key identity at most once. |
| `verify_delegate_no_widen`                                         | ~L1103      | `chio_core_types::capability::delegate`                                                               | `formal/proof-manifest.toml` covered_rust_symbols `delegate`; P1, P5                  | Two-step delegation chain attenuates iff every step attenuates: runtime form of Lean theorem `delegate_no_widen`.        |
| `verify_delegation_receipt_canonical`                              | ~L1128      | `chio_core_types::delegation_receipt::DelegationReceipt::canonical_bytes`                             | `formal/proof-manifest.toml` covered_rust_symbols `DelegationReceipt::canonical_bytes`; ASSUME-CANONICAL-JSON | Canonical-bytes determinism plus single-axis sensitivity for the DelegationReceipt envelope; pins serialiser injectivity. |
| `verify_revocation_view_freshness`                                 | ~L1173      | `chio_kernel_core::revocation_view::RevocationView::install_if_newer`                                 | `formal/proof-manifest.toml` covered_rust_symbols `RevocationView::install_if_newer`; ASSUME-OS-CLOCK | Monotone-epoch fail-closed gate: strictly-newer candidates accept, equal/stale reject, idempotent on the failure path.   |
| `verify_inclusion_step_equivalence`                                | ~L1430      | `chio_core_types::merkle_steps::inclusion_step`, `chio_kernel_core::formal_aeneas::inclusion_step`     | `proof.generated_inclusion_step_eq_model`; `formal/aeneas/production.toml` `merkle_walk` target; paired manual-mirror hashes | The production and extraction-safe scalar steps agree for every symbolic index and size through the eight-leaf bound, including invalid geometry. The authenticated Aeneas snapshot theorem proves the generated machine-integer step refines the Lean model. |
| `verify_oracle_inclusion_walk_parity`                                | ~L1500      | `chio_core_types::merkle::MerkleProof::compute_root_from_hash`, `chio_core_types::merkle_steps::inclusion_step` | `proof.stepFold_eq_applyProof`, `proof.boundedWalkGeometry_decodes`, `proof.bounded_stepFold_sound`; ASSUME-SHA256 | Bounded production/model inclusion-walk parity under an order-sensitive abstract hash, not cryptographic SHA-256 inclusion soundness. Fixed proof fixtures for every index at every tree size from 1 through 8 are runtime-cross-checked against `MerkleTree`; two symbolic hash-relevant bytes per audit node and malformed path shapes compare the production verifier with an independent bounded fold under enabled unwinding assertions. |

## Kani checked-conversion harnesses

Source file: `crates/economy/chio-credit/src/kani_public_harnesses.rs`.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `public_convert_rounding_envelope` | `crates/economy/chio-credit/src/kani_public_harnesses.rs` | `crates/economy/chio-credit/src/formal_economy.rs::convert_ceil_scalar`, `crates/economy/chio-credit/src/formal_economy.rs::convert_floor_scalar` | Production conversion linkage is not established; these are pure checked-integer groundwork helpers. | Successful conversions over the exhaustive four-bit input cube lie inside the exact ceil or floor rounding envelope, including the zero-value ceil case. |
| `public_convert_overflow_fails_closed` | `crates/economy/chio-credit/src/kani_public_harnesses.rs` | `crates/economy/chio-credit/src/formal_economy.rs::convert_ceil_scalar`, `crates/economy/chio-credit/src/formal_economy.rs::convert_floor_scalar` | Production conversion linkage is not established; these are pure checked-integer groundwork helpers. | Full-width products that cannot narrow to `u64` fail closed, while the largest identity conversion and zero units remain exact. |

## Kani settlement-state harnesses

Source file: `crates/economy/chio-web3/src/kani_public_harnesses.rs`.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `public_settlement_state_id_fixed_point` | `crates/economy/chio-web3/src/kani_public_harnesses.rs` | `crates/economy/chio-web3/src/settlement.rs::settlement_state_id` | n/a (finite enum truth table) | Every lifecycle variant maps to its stable public identifier, and repeated evaluation returns the same identifier. |

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

## Lean canonical JSON theorems

Source files: `formal/lean4/Chio/Chio/Json/` and
`formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean`. These rows constrain
the normalized semantic projection. They do not assert injectivity of raw
`serde_json::Value` representations or a proved Rust refinement.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `escape_string_inj` | `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` | `chio_core_types::canonical::canonical_json_bytes` string rendering | Model theorem; production agreement remains `ASSUME-CANONICAL-JSON` | RFC 8785 minimal string escaping is injective over modeled Unicode scalar sequences. |
| `render_int_inj` | `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` | `chio_core_types::canonical::canonical_json_bytes` integer rendering | Model theorem; production agreement remains `ASSUME-CANONICAL-JSON` | Canonical signed-decimal rendering is injective over the modeled i64 and u64 range. |
| `sorted_assoc_ext` | `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` | `chio_core_types::canonical::canonical_json_bytes` object rendering | Model theorem; production agreement remains `ASSUME-CANONICAL-JSON` | UTF-16-sorted unique object entries are determined by their canonical rendering. |
| `canonical_inj` | `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` | `chio_core_types::canonical::canonical_json_bytes` normalized semantic projection | Model theorem; fixture and differential bridge remains `ASSUME-CANONICAL-JSON` | Canonical UTF-8 byte rendering is injective for scalar strings, normalized integers, arrays, and ordered object entries. |
| `receipt_id_input_collision_resistant` | `formal/lean4/Chio/Chio/Proofs/Receipt.lean` | all 20 fields of `chio_core_types::receipt::body::ChioReceiptIdInput` | `ASSUME-SHA256`; production serde projection remains `ASSUME-CANONICAL-JSON` | Equal symbolic receipt identifiers bind the named-object projection with production field order and omission rules when all compound values inhabit bounded `JValue`. |
| `receipt_id_collision_resistant` | `formal/lean4/Chio/Chio/Proofs/Receipt.lean` | `chio_core_types::receipt::chio_receipt_id` content and policy implication | `ASSUME-SHA256`; production serde projection remains `ASSUME-CANONICAL-JSON` | Equal symbolic receipt identifiers imply equal modeled content and policy hashes as a downstream corollary of full projection binding. |

## Runtime reservation conservation checks

These debug and stateful-test rows bind the model-level conservation algebra
to the concrete single-node journal without claiming a proved refinement.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `debug_assert_reservation_conservation` | `crates/kernel/chio-kernel/src/kernel/ledger_audit.rs` | `chio_kernel::BudgetStore::list_mutation_events`, retain, reverse, release, reconcile, and runtime metadata transition groups | `BudgetGuaranteeLevel::SingleNodeAtomic`; model-level audit, production ledger linkage not established | Debug replay checks every monetary journal after-state and the reserve, commit, release, and outstanding partition. Events without hold IDs are conserved as one anonymous pool and do not establish per-hold identity; production reverse and reconcile call sites separately require their named hold to terminate exactly once. The journal has no retain event, so a fail-closed post-dispatch hold remains outstanding rather than gaining a distinct retained journal state. Receipt metadata binds the retained budget hold, payment authorization, and runtime reservation identifiers for operator resolution. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `verify_reservation_ledger_conservation` plus `Proofs/ReservationLedger.lean`, and `tests/property_reservation_ledger.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `mixed_store_reservation_sequences_preserve_the_journal_law` | `crates/kernel/chio-kernel/tests/property_reservation_ledger.rs` | `chio_kernel::InMemoryBudgetStore` authorization, reverse, release, and reconcile mutations | `BudgetGuaranteeLevel::SingleNodeAtomic`; runtime test evidence, production ledger linkage not established | Stateful store operation sequences compare the concrete monetary journal, usage row, and terminal history after every step. This test does not drive kernel lifecycle, drop, hooks, or receipts. The four-artifact join also names `formal/apalache/PostAdmissionDropGuard.tla`, `verify_reservation_ledger_conservation` plus `Proofs/ReservationLedger.lean`, and `kernel/ledger_audit.rs`. Scalar admission is linked; production ledger linkage is not established. |
| `drop_guard_disposition_table` | `crates/kernel/chio-kernel/src/kernel/tests/drop_guard_proptest.rs` | `chio_kernel::ChioKernel::run_runtime_admission_hook`, `chio_kernel::kernel::PostAdmissionDropGuard`, receipt log, monetary journal, and usage row | `BudgetGuaranteeLevel::SingleNodeAtomic`; production-path runtime evidence, not a refinement proof | All eight lifecycle cells drive the production runtime-admission hook and real drop guard. Pre-dispatch cells remain receipt-free and reverse or release admitted state. Post-dispatch cells emit one terminal receipt, release no runtime reservation, and retain an authorized five-unit monetary exposure without a reverse, refund, release, or realized-spend mutation. The test checks receipt retention metadata, journal conservation, and final usage without claiming a formal refinement. |

## Lean delivery-contract theorems (Proofs/DeliveryContract.lean)

These rows describe a deliberately bounded composition model. M3 links the
digest dimension to the pure Rust comparison and the post-delivery terminal.
The finding-purchase Boolean names the M4 composition boundary; it does not
claim that the M3 branch implements purchase verification or that Lean refines
the Rust state machine.

| Property | Source | Rust path constrained | Assumption discharge | One-line description |
| --- | --- | --- | --- | --- |
| `settlement_admission_requires_verified_evidence` | `formal/lean4/Chio/Chio/Proofs/DeliveryContract.lean` | `crates/kernel/chio-kernel-core/src/formal_core.rs::delivery_contract_admits`; `crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs` | `formal/proof-manifest.toml` P3; bounded model with opaque digest identities | A settlement-admitted result is an Allow only when every required purchase is verified and every required digest matches. |
| `allow_requires_verified_evidence` | `formal/lean4/Chio/Chio/Proofs/DeliveryContract.lean` | `crates/kernel/chio-kernel-core/src/formal_core.rs::delivery_contract_admits` | `formal/proof-manifest.toml` P3; bounded model with opaque digest identities | An Allow cannot bypass either enabled evidence requirement. |
| `denied_after_delivery_cannot_settle` | `formal/lean4/Chio/Chio/Proofs/DeliveryContract.lean` | `crates/kernel/chio-kernel/src/admission_operation/state.rs`; `crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs` | `formal/proof-manifest.toml` P3; external rail behavior remains outside the model | Every reachable post-delivery denial keeps the bounded settlement gate closed. |

## Adding a new property

1. Add the named TLA+ definition to `formal/tla/RevocationPropagation.tla`
   (top-level `<Name> ==` form), add the `#[kani::proof]` attribute and harness
   function to `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`, or
   register a new Loom test in `.loom/harnesses.toml`.
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
