//! # Scope
//!
//! This module models the trust-boundary invariants of the public
//! surfaces of `chio-anchor` that are tractable for symbolic
//! execution under Kani's default unwind budget:
//!
//! - `AnchorEmergencyControls::allows`
//!   (`pub fn` at `src/ops.rs:86`).
//! - `ensure_anchor_operation_allowed`
//!   (`pub fn` at `src/ops.rs:383`).
//! - `classify_anchor_lane`
//!   (`pub fn` at `src/ops.rs:346`).
//! - `AnchorIndexerCursor::from_sequences`
//!   (`pub fn` at `src/ops.rs:167`).
//! - Algebraic model of `evaluate_witness_policy`
//!   (`pub fn` at `src/witness.rs:312`) covering the three
//!   `WitnessState` x `require_public_witness` arms.
//!
//! # What these harnesses model and what they do not
//!
//! `AnchorEmergencyControls::allows`, `ensure_anchor_operation_allowed`,
//! `classify_anchor_lane`, and `AnchorIndexerCursor::from_sequences`
//! are pure algebraic predicates over bounded enums and `u64`
//! sequence numbers. Kani enumerates every input combination
//! directly; the harnesses exercise the real `pub fn` rather than an
//! algebraic surrogate.
//!
//! `verify_proof_bundle`, the EVM publication helpers, and the
//! Rekor/OTS clients all transit cryptographic verification (ECDSA
//! P-256, X.509 chain, COSE/CBOR) and async network I/O; both are
//! out of scope for symbolic execution. Their fail-closed properties
//! are pinned by the integration tests under
//! `crates/economy/chio-anchor/tests/` and by the conformance lane.
//!
//! # Bound parameters
//!
//! - Symbolic enum selectors are bounded `u8` values (e.g.
//!   `pick < 5` for the five-variant `AnchorEmergencyMode`).
//! - Symbolic `u64` sequences for `from_sequences` are unconstrained
//!   apart from the trivial relation `canonical >= indexed` (when
//!   the verifier expects a non-negative lag); the saturating
//!   subtraction in the function body absorbs the underflow case
//!   without further bounds.
//! - Per-harness `#[kani::unwind(8)]` matches the workspace default
//!   established by `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`.
//!
//! # Anti-pattern guard
//!
//! Every `#[kani::proof]` function in this module either calls a real
//! `pub fn` of `chio-anchor` or witnesses the algebra of one over a
//! bounded symbolic envelope via a model whose name is prefixed
//! `model_`. No harness body bottoms out in `kani::assume(false)`;
//! no harness targets a non-`pub` internal helper.
//!
//! # Honesty boundary: what "model" harnesses actually prove
//!
//! Model-only scope note:
//!
//! - The first four harnesses
//!   (`public_anchor_emergency_controls_allows_truth_table`,
//!    `public_ensure_anchor_operation_allowed_fail_closed`,
//!    `public_classify_anchor_lane_invariants`,
//!    `public_anchor_indexer_cursor_lag_classification`) call real
//!   production `pub fn`s; a regression in the production function is
//!   caught by Kani.
//! - The fifth harness
//!   (`public_evaluate_witness_policy_advisory_fail_closed_model`)
//!   proves the local `model_evaluate_witness_policy` over
//!   `ModelWitnessState`, NOT the production
//!   `chio_anchor::witness::evaluate_witness_policy` (`src/witness.rs:312`).
//!   A regression in the production function that left the model
//!   unchanged would NOT trip Kani; the runtime regression is caught
//!   instead by:
//!     - the advisory-path fail-closed tests in
//!       `crates/economy/chio-anchor/src/witness.rs`, covering
//!       `WitnessPolicyError::PendingNotAllowed`,
//!       `WitnessPolicyError::SelfAssertedWitnessed`, and
//!       `WitnessPolicyError::StaleNotPreviouslyVerified`.
//!     - the negative conformance regression tests under
//!       `crates/tooling/chio-conformance/tests/`.

extern crate alloc;

use crate::bundle::AnchorLaneKind;
use crate::ops::{
    classify_anchor_lane, ensure_anchor_operation_allowed, AnchorEmergencyControls,
    AnchorEmergencyMode, AnchorIndexerCursor, AnchorIndexerCursorInput, AnchorIndexerStatus,
    AnchorLaneHealthStatus, AnchorOperationKind,
};
use crate::AnchorError;

/// Pick one of the five `AnchorEmergencyMode` variants from a bounded
/// symbolic byte. The `kani::assume(pick < 5)` constraint enumerates
/// every variant; the helper centralises the construction so each
/// harness pulls the same five-variant envelope.
fn pick_emergency_mode(pick: u8) -> AnchorEmergencyMode {
    match pick {
        0 => AnchorEmergencyMode::Normal,
        1 => AnchorEmergencyMode::PublishPaused,
        2 => AnchorEmergencyMode::ProofImportOnly,
        3 => AnchorEmergencyMode::RecoveryOnly,
        _ => AnchorEmergencyMode::Halted,
    }
}

/// Pick one of the three `AnchorOperationKind` variants from a
/// bounded symbolic byte.
fn pick_operation_kind(pick: u8) -> AnchorOperationKind {
    match pick {
        0 => AnchorOperationKind::PublishRoot,
        1 => AnchorOperationKind::ConfirmPublication,
        _ => AnchorOperationKind::ImportSecondaryProof,
    }
}

/// Pick one of the five `AnchorIndexerStatus` variants.
fn pick_indexer_status(pick: u8) -> AnchorIndexerStatus {
    match pick {
        0 => AnchorIndexerStatus::Healthy,
        1 => AnchorIndexerStatus::Lagging,
        2 => AnchorIndexerStatus::Drifted,
        3 => AnchorIndexerStatus::Replaying,
        _ => AnchorIndexerStatus::Failed,
    }
}

/// Pick one of the three `AnchorLaneKind` variants.
fn pick_lane_kind(pick: u8) -> AnchorLaneKind {
    match pick {
        0 => AnchorLaneKind::EvmPrimary,
        1 => AnchorLaneKind::BitcoinOts,
        _ => AnchorLaneKind::SolanaMemo,
    }
}

/// Real public surface exercised symbolically:
/// `AnchorEmergencyControls::allows` MUST pin the documented truth
/// table over the (mode x operation) cross product. The kernel and
/// `ensure_anchor_operation_allowed` paths consume this predicate to
/// gate emergency-state operations; a bug that flipped any cell in
/// the table would silently let a forbidden operation proceed under
/// emergency.
///
/// Production entry: `chio_anchor::ops::AnchorEmergencyControls::allows`
/// (`pub fn` in `crates/economy/chio-anchor/src/ops.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_anchor_emergency_controls_allows_truth_table() {
    let mode_pick: u8 = kani::any();
    kani::assume(mode_pick < 5);
    let op_pick: u8 = kani::any();
    kani::assume(op_pick < 3);
    let changed_at: u64 = kani::any();

    let mode = pick_emergency_mode(mode_pick);
    let operation = pick_operation_kind(op_pick);
    let controls = AnchorEmergencyControls {
        mode,
        changed_at,
        reason: None,
    };

    let observed = controls.allows(operation);

    // Truth table per the documented contract:
    //   - Normal           : every operation allowed.
    //   - PublishPaused    : every operation EXCEPT PublishRoot.
    //   - ProofImportOnly  : ONLY ImportSecondaryProof.
    //   - RecoveryOnly     : ONLY ConfirmPublication.
    //   - Halted           : NO operation allowed.
    let expected = match mode {
        AnchorEmergencyMode::Normal => true,
        AnchorEmergencyMode::PublishPaused => operation != AnchorOperationKind::PublishRoot,
        AnchorEmergencyMode::ProofImportOnly => {
            operation == AnchorOperationKind::ImportSecondaryProof
        }
        AnchorEmergencyMode::RecoveryOnly => operation == AnchorOperationKind::ConfirmPublication,
        AnchorEmergencyMode::Halted => false,
    };
    assert_eq!(observed, expected);

    // Cross-check `AnchorEmergencyControls::normal(...)`: the
    // helper MUST construct a controls value that allows every
    // operation. A regression that inverted the field default would
    // be caught here.
    let normal = AnchorEmergencyControls::normal(changed_at);
    assert!(normal.allows(operation));
}

/// Real public surface exercised symbolically:
/// `ensure_anchor_operation_allowed` MUST mirror the underlying
/// `allows` predicate, returning `Ok(())` exactly when the predicate
/// is true and `Err(AnchorError::InvalidInput(_))` otherwise. The
/// kernel calls this function to enforce emergency-mode policy at
/// every operation entry; a wrong error variant or a missing
/// `Err(_)` would be a fail-open bug.
///
/// Production entry: `chio_anchor::ops::ensure_anchor_operation_allowed`
/// (`pub fn` in `crates/economy/chio-anchor/src/ops.rs`).
///
/// Bounds: the harness exhaustively selects among the five emergency
/// modes and three operation kinds. The production fail-closed arm
/// selects one of three static diagnostic strings with a bounded
/// match, avoiding the dynamic formatting path that exhausted the
/// original 3600s solver budget. The optimized harness runs in the PR
/// lane with the standard non-core timeout while proving the real
/// public `Result` and `AnchorError::InvalidInput` behavior. Additional
/// PR-tier regression coverage for the same property comes from:
///   - `public_anchor_emergency_controls_allows_truth_table` (the
///     truth-table harness above, which calls `controls.allows()`
///     directly and finishes in ~0.1s).
///   - The runtime negative tests under
///     `crates/economy/chio-anchor/tests/` and `ops.rs` unit tests
///     that exercise the bounded static diagnostic path.
#[kani::proof]
#[kani::unwind(4)]
pub fn public_ensure_anchor_operation_allowed_fail_closed() {
    let mode_pick: u8 = kani::any();
    kani::assume(mode_pick < 5);
    let op_pick: u8 = kani::any();
    kani::assume(op_pick < 3);
    let changed_at: u64 = kani::any();

    let mode = pick_emergency_mode(mode_pick);
    let operation = pick_operation_kind(op_pick);
    let controls = AnchorEmergencyControls {
        mode,
        changed_at,
        reason: None,
    };
    let allowed = controls.allows(operation);
    let result = ensure_anchor_operation_allowed(controls, operation);

    if allowed {
        assert!(result.is_ok());
    } else {
        // Fail-closed arm. The error MUST be the `InvalidInput`
        // variant so the kernel can route the refusal to the
        // anchor-error registry. Any other variant would silently
        // change the audit-log code.
        assert!(matches!(result, Err(AnchorError::InvalidInput(_))));
    }
}

/// Real public surface exercised symbolically: `classify_anchor_lane`
/// MUST satisfy a small set of invariants that the runtime-report
/// publication path relies on:
///
/// - A `Failed` indexer status ALWAYS produces `Failed` lane health,
///   regardless of mode or reorg depth (fail-closed: a failed
///   indexer cannot be masked by emergency controls).
/// - A `Halted` mode ALWAYS produces `Paused` lane health (when the
///   indexer is not in the failed state), regardless of indexer
///   status or reorg depth.
/// - A `RecoveryOnly` mode produces `Recovering` lane health (when
///   indexer is not failed), regardless of reorg depth.
/// - In `Normal` mode with `Healthy` indexer and `reorg_depth == 0`,
///   the lane MUST classify as `Healthy`.
///
/// Production entry: `chio_anchor::ops::classify_anchor_lane`
/// (`pub fn` in `crates/economy/chio-anchor/src/ops.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_classify_anchor_lane_invariants() {
    let lane_pick: u8 = kani::any();
    kani::assume(lane_pick < 3);
    let indexer_pick: u8 = kani::any();
    kani::assume(indexer_pick < 5);
    let mode_pick: u8 = kani::any();
    kani::assume(mode_pick < 5);

    let lane = pick_lane_kind(lane_pick);
    let indexer_status = pick_indexer_status(indexer_pick);
    let mode = pick_emergency_mode(mode_pick);
    // Bound `reorg_depth` to a small range so kani can enumerate
    // both the zero and non-zero arms without blowing up the path
    // count. The function's algebra over reorg_depth is
    // monotonic in the predicate `reorg_depth > 0`, so bounding
    // to {0, 1} preserves the property.
    let reorg_depth: u32 = kani::any();
    kani::assume(reorg_depth <= 1);
    let changed_at: u64 = kani::any();
    let controls = AnchorEmergencyControls {
        mode,
        changed_at,
        reason: None,
    };

    let observed = classify_anchor_lane(lane, indexer_status, controls, reorg_depth);

    // (1) Failed indexer is dominant: regardless of mode, regardless
    // of reorg depth, the lane is Failed.
    if indexer_status == AnchorIndexerStatus::Failed {
        assert_eq!(observed, AnchorLaneHealthStatus::Failed);
    }

    // (2) Halted mode (when not Failed-indexer) is Paused.
    if indexer_status != AnchorIndexerStatus::Failed && mode == AnchorEmergencyMode::Halted {
        assert_eq!(observed, AnchorLaneHealthStatus::Paused);
    }

    // (3) RecoveryOnly mode (when not Failed-indexer) is Recovering.
    if indexer_status != AnchorIndexerStatus::Failed && mode == AnchorEmergencyMode::RecoveryOnly {
        assert_eq!(observed, AnchorLaneHealthStatus::Recovering);
    }

    // (4) PublishPaused mode on the EvmPrimary lane (when not
    // Failed-indexer) is Paused.
    if indexer_status != AnchorIndexerStatus::Failed
        && mode == AnchorEmergencyMode::PublishPaused
        && lane == AnchorLaneKind::EvmPrimary
    {
        assert_eq!(observed, AnchorLaneHealthStatus::Paused);
    }

    // (5) ProofImportOnly mode on the EvmPrimary lane (when not
    // Failed-indexer) is Paused.
    if indexer_status != AnchorIndexerStatus::Failed
        && mode == AnchorEmergencyMode::ProofImportOnly
        && lane == AnchorLaneKind::EvmPrimary
    {
        assert_eq!(observed, AnchorLaneHealthStatus::Paused);
    }

    // (6) Normal mode + Healthy indexer + zero reorg => Healthy.
    if mode == AnchorEmergencyMode::Normal
        && indexer_status == AnchorIndexerStatus::Healthy
        && reorg_depth == 0
    {
        assert_eq!(observed, AnchorLaneHealthStatus::Healthy);
    }
}

/// Real public surface exercised symbolically:
/// `AnchorIndexerCursor::from_sequences` MUST classify lag according
/// to the documented thresholds:
///
/// - `failed=true`           => Failed (overrides everything).
/// - `replaying=true`        => Replaying (when not failed).
/// - lag == 0                => Healthy.
/// - lag in 1..=3            => Lagging.
/// - lag > 3                 => Drifted.
///
/// The runtime indexer health surface relies on this for SLO routing;
/// a bug that misclassified lag would silently mask an indexer fall-
/// behind incident.
///
/// Production entry: `chio_anchor::ops::AnchorIndexerCursor::from_sequences`
/// (`pub fn` in `crates/economy/chio-anchor/src/ops.rs`).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_anchor_indexer_cursor_lag_classification() {
    let lane_pick: u8 = kani::any();
    kani::assume(lane_pick < 3);
    let lane = pick_lane_kind(lane_pick);
    let failed: bool = kani::any();
    let replaying: bool = kani::any();
    // Bound the lag by drawing both sequences from a small range.
    // The algebra of `from_sequences` is purely a function of the
    // saturating subtraction of these two `u64` values; we bound
    // them to `0..=8` so kani can enumerate the lag thresholds at
    // 0, 1..=3, and >3 without blowing up the path count.
    let canonical: u64 = kani::any();
    kani::assume(canonical <= 8);
    let indexed: u64 = kani::any();
    kani::assume(indexed <= 8);
    let checked_at: u64 = kani::any();

    let input = AnchorIndexerCursorInput {
        service_id: alloc::string::String::new(),
        lane,
        chain_id: None,
        indexed_checkpoint_seq: indexed,
        canonical_checkpoint_seq: canonical,
        indexed_block_number: None,
        replaying,
        failed,
        checked_at,
        note: None,
    };
    let cursor = AnchorIndexerCursor::from_sequences(input);

    let lag = canonical.saturating_sub(indexed);

    // (1) Lag computation is the saturating subtraction. A
    // regression that used wrapping subtraction would underflow
    // when `indexed > canonical`; we pin the saturating contract.
    assert_eq!(cursor.lag_checkpoints, lag);

    // (2) Failed override is dominant.
    if failed {
        assert_eq!(cursor.status, AnchorIndexerStatus::Failed);
    } else if replaying {
        // (3) Replaying takes precedence over the lag bands when not
        // failed.
        assert_eq!(cursor.status, AnchorIndexerStatus::Replaying);
    } else if lag == 0 {
        assert_eq!(cursor.status, AnchorIndexerStatus::Healthy);
    } else if lag <= 3 {
        assert_eq!(cursor.status, AnchorIndexerStatus::Lagging);
    } else {
        assert_eq!(cursor.status, AnchorIndexerStatus::Drifted);
    }

    // (4) The cursor's `lane` and `checked_at` echo the input. A
    // regression that lost these fields would break audit-log
    // correlation with the runtime indexer telemetry.
    assert_eq!(cursor.lane, lane);
    assert_eq!(cursor.checked_at, checked_at);
}

/// Witness-state shape, abstracted away from the receipt's
/// cryptographic content. The three variants mirror the production
/// `WitnessState` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelWitnessState {
    Pending,
    Witnessed,
    Stale,
}

/// Outcome shape for the model. Mirrors the algebra of the production
/// `evaluate_witness_policy` so each branch's fail-closed property is
/// pinnable in Kani.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelWitnessOutcome {
    /// Advisory accept: structural checks passed and either the
    /// policy is advisory (`require_public_witness == false`) or the
    /// state is `Witnessed` with valid receipt invariants under the
    /// advisory path.
    Accepted,
    /// Pending was rejected because `require_public_witness == true`.
    PendingNotAllowed,
    /// Witnessed was rejected because the advisory path refuses to
    /// honor a self-asserted Witnessed under
    /// `require_public_witness == true`.
    SelfAssertedWitnessed,
    /// Stale was rejected because the verifier-cache lookup failed.
    StaleNotPreviouslyVerified,
}

/// Algebra of `evaluate_witness_policy` (advisory variant):
///
/// - `Pending`   : accepted iff `require_public_witness == false`.
/// - `Witnessed` : the structural invariants
///   (`witness_root == batch.body.tree_root` and
///   `body_hash == batch_body_hash(batch)`) are checked by
///   `check_witnessed_invariants`. The advisory path then accepts
///   iff `require_public_witness == false`; otherwise it returns
///   `SelfAssertedWitnessed` because it cannot honor the receipt
///   without an `AnchorWitnessClient::verify_inclusion` round-trip.
/// - `Stale`     : accepted iff `require_public_witness == false`;
///   otherwise rejected with `StaleNotPreviouslyVerified` because
///   the advisory path has no verifier-owned cache to consult.
fn model_evaluate_witness_policy(
    state: ModelWitnessState,
    require_public_witness: bool,
    witnessed_invariants_hold: bool,
) -> ModelWitnessOutcome {
    match state {
        ModelWitnessState::Witnessed => {
            if !witnessed_invariants_hold {
                // The production path returns one of the
                // `WitnessReceipt*Mismatch` variants here; we
                // collapse all of them to a single rejection arm
                // because the algebra under test is the
                // require_public_witness gate. The concrete
                // mismatch variants are pinned by the runtime
                // tests in `src/witness.rs`.
                return ModelWitnessOutcome::SelfAssertedWitnessed;
            }
            if require_public_witness {
                ModelWitnessOutcome::SelfAssertedWitnessed
            } else {
                ModelWitnessOutcome::Accepted
            }
        }
        ModelWitnessState::Pending => {
            if require_public_witness {
                ModelWitnessOutcome::PendingNotAllowed
            } else {
                ModelWitnessOutcome::Accepted
            }
        }
        ModelWitnessState::Stale => {
            if require_public_witness {
                ModelWitnessOutcome::StaleNotPreviouslyVerified
            } else {
                ModelWitnessOutcome::Accepted
            }
        }
    }
}

/// This harness pins the algebra of `evaluate_witness_policy` (the
/// advisory variant). The fail-closed property is what
/// `verify_anchor_batch_with_witness_policy` relies on when the
/// caller does not supply a verifier client; a regression in the
/// advisory path that accepted Pending or Stale under
/// `require_public_witness == true` would silently downgrade the
/// audit-log integrity of every batch verifier that did not pass a
/// client.
///
/// Production entry: `chio_anchor::witness::evaluate_witness_policy`
/// (`pub fn` in `crates/economy/chio-anchor/src/witness.rs`). The full
/// `evaluate_witness_policy_with_verifier` async path is intractable
/// here (it transits canonical JSON + SHA-256 + an async client).
#[kani::proof]
#[kani::unwind(8)]
pub fn public_evaluate_witness_policy_advisory_fail_closed_model() {
    let pick: u8 = kani::any();
    kani::assume(pick < 3);
    let state = match pick {
        0 => ModelWitnessState::Pending,
        1 => ModelWitnessState::Witnessed,
        _ => ModelWitnessState::Stale,
    };
    let require_public_witness: bool = kani::any();
    let witnessed_invariants_hold: bool = kani::any();

    let outcome =
        model_evaluate_witness_policy(state, require_public_witness, witnessed_invariants_hold);

    // (1) Pending fail-closed under require_public_witness=true.
    if matches!(state, ModelWitnessState::Pending) && require_public_witness {
        assert_eq!(outcome, ModelWitnessOutcome::PendingNotAllowed);
    }

    // (2) Pending advisory accept under require_public_witness=false.
    if matches!(state, ModelWitnessState::Pending) && !require_public_witness {
        assert_eq!(outcome, ModelWitnessOutcome::Accepted);
    }

    if matches!(state, ModelWitnessState::Stale) && require_public_witness {
        assert_eq!(outcome, ModelWitnessOutcome::StaleNotPreviouslyVerified);
    }

    // (4) Stale advisory accept under require_public_witness=false.
    if matches!(state, ModelWitnessState::Stale) && !require_public_witness {
        assert_eq!(outcome, ModelWitnessOutcome::Accepted);
    }

    // (5) Witnessed self-asserted fail-closed under
    // require_public_witness=true (with structurally valid receipt
    // invariants). The advisory path refuses to honor a producer-
    // signed Witnessed without an active client.
    if matches!(state, ModelWitnessState::Witnessed)
        && require_public_witness
        && witnessed_invariants_hold
    {
        assert_eq!(outcome, ModelWitnessOutcome::SelfAssertedWitnessed);
    }

    if matches!(state, ModelWitnessState::Witnessed)
        && !require_public_witness
        && witnessed_invariants_hold
    {
        assert_eq!(outcome, ModelWitnessOutcome::Accepted);
    }

    if matches!(state, ModelWitnessState::Witnessed) && !witnessed_invariants_hold {
        assert_eq!(outcome, ModelWitnessOutcome::SelfAssertedWitnessed);
    }
}
