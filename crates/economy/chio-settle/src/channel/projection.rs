use chio_core::economic_continuity::{
    economic_effect_slot_from_head, EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1,
    EconomicEffectTerminalV1, EconomicRequestReplayV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTerminalResultV1, EconomicTransitionAuthorizationV1,
    EconomicTransitionProofVerifier, VerifiedEconomicStateView, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
};
use serde::Serialize;

mod cancellation;
mod dispatch;
mod prepared;
pub use cancellation::*;
pub use dispatch::*;
pub use prepared::*;

use super::validation::digest;
use super::{
    derive_channel_service_dispatch_idempotency_key, verify_channel_lifecycle_snapshot,
    ChannelError, ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1,
    ChannelLifecycleStatusV1, ChannelLifecycleViewV1, VerifiedAdmittedChannelReservationV1,
    VerifiedChannelOpenConsentV1, VerifiedChannelReceiptBindingV1, VerifiedChannelStateV1,
    VerifiedChannelTerminalOutcomeCommitmentV1, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    CHANNEL_LIFECYCLE_RESOURCE_FAMILY, CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
};

const CHANNEL_TERMINAL_TRANSITION_PROOF_SCHEMA: &str = "chio.channel.terminal-transition-proof.v1";
const CHANNEL_TERMINAL_TRANSITION_PROOF_DOMAIN: &[u8] =
    b"chio.channel.terminal-transition-proof.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelTerminalTransitionProofV1 {
    schema: String,
    open_intent_digest: String,
    open_digest: String,
    prior_state_digest: String,
    reservation_digest: String,
    operation_id: String,
    request: chio_core::economic_continuity::EconomicRequestBindingV1,
    provider: chio_core::economic_continuity::EconomicEffectTargetV1,
    receipt_id: String,
    receipt_digest: String,
    receipt_authority_digest: String,
    next_state_digest: String,
    obligation_atom_id: Option<String>,
    obligation_atom_digest: Option<String>,
    outcome_id: String,
    outcome_digest: String,
    source_checkpoint_digest: String,
    source_channel_head_digest: String,
    source_escrow_head_digest: String,
    source_effect_head_digest: String,
    terminal_channel_head_digest: String,
    terminal_escrow_head_digest: String,
    terminal_effect_head_digest: String,
    issued_at: u64,
}

impl ChannelTerminalTransitionProofV1 {
    fn digest(&self) -> Result<String, ChannelError> {
        digest(CHANNEL_TERMINAL_TRANSITION_PROOF_DOMAIN, self)
    }
}

#[derive(Debug, Clone)]
pub struct ChannelLifecycleProjectionV1 {
    current: VerifiedEconomicStateView,
    proof_digest: String,
    transitions: Vec<EconomicStateTransitionV1>,
    effect_slots: Vec<EconomicEffectSlotV1>,
    request_replays: Vec<EconomicRequestReplayV1>,
    operation_id: String,
    issued_at: u64,
    not_after_unix_ms: Option<u64>,
}

impl ChannelLifecycleProjectionV1 {
    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub fn transitions(&self) -> &[EconomicStateTransitionV1] {
        &self.transitions
    }

    #[must_use]
    pub fn effect_slots(&self) -> &[EconomicEffectSlotV1] {
        &self.effect_slots
    }

    #[must_use]
    pub fn request_replays(&self) -> &[EconomicRequestReplayV1] {
        &self.request_replays
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        Some(&self.operation_id)
    }

    #[must_use]
    pub const fn not_after_unix_ms(&self) -> Option<u64> {
        self.not_after_unix_ms
    }
}

pub fn compose_channel_terminal_transition(
    open: &VerifiedChannelOpenConsentV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    next_state: &VerifiedChannelStateV1,
    receipt: &VerifiedChannelReceiptBindingV1,
    outcome: &VerifiedChannelTerminalOutcomeCommitmentV1,
    current: &VerifiedEconomicStateView,
    issued_at: u64,
) -> Result<ChannelLifecycleProjectionV1, ChannelError> {
    let terminal_result = outcome.terminal_result();
    terminal_result
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let body = &reservation.artifact().body;
    let obligation_time_is_ordered = receipt.obligation_atom().is_none_or(|atom| {
        receipt.receipt_timestamp_unix_ms() <= atom.created_at_unix_ms()
            && outcome.terminalized_at_unix_ms() <= atom.created_at_unix_ms()
            && atom.created_at_unix_ms() <= issued_at
    });
    if issued_at < current.view().observed_at
        || issued_at < outcome.terminalized_at_unix_ms()
        || !obligation_time_is_ordered
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let open_intent_digest = open.intent().digest()?;
    let open_digest = open.artifact().digest()?;
    let prior_state_digest = body.prior_state_digest.clone();
    let reservation_digest = reservation.artifact().digest()?;
    let next_state_digest = next_state.digest()?;
    let outcome_body = &outcome.artifact().body;
    let scope_id = &open.intent().body.settlement_authority_scope_id;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: scope_id.clone(),
        resource_id: body.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: scope_id.clone(),
        resource_id: body.channel_id.clone(),
    };
    let snapshot = verify_channel_lifecycle_snapshot(current, scope_id, &body.channel_id)?;
    let admitted = reservation.snapshot();
    if snapshot.channel_head() != admitted.channel_head()
        || snapshot.escrow_head() != admitted.escrow_head()
        || current.view().checkpoint_sequence <= admitted.checkpoint_sequence()
        || current.view().checkpoint_digest == admitted.checkpoint_digest()
        || current.view().observed_at < admitted.observed_at_unix_ms()
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let current_channel_head = snapshot.channel_head();
    let current_escrow_head = snapshot.escrow_head();
    let effect_key = reservation.ready_effect().resource_head_key();
    let current_effect_head = current
        .view()
        .head(&effect_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let dispatch_effect = economic_effect_slot_from_head(current_effect_head)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let expected_idempotency_key = derive_channel_service_dispatch_idempotency_key(
        &body.operation_id,
        &body.reservation_id,
        body.next_sequence,
    )?;
    reservation
        .ready_effect()
        .validate_successor(&dispatch_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let next = next_state.body();
    if body.channel_id != open.artifact().body.channel_id
        || body.open_digest != open_digest
        || body.prior_state_digest != prior_state_digest
        || body.next_sequence != next.seq
        || receipt.channel_id() != body.channel_id
        || receipt.open_digest() != open_digest
        || receipt.reservation_digest() != reservation_digest
        || receipt.sequence() != body.next_sequence
        || outcome_body.operation_id != body.operation_id
        || outcome_body.reservation_id != body.reservation_id
        || outcome_body.reservation_digest != reservation_digest
        || outcome_body.receipt_id != receipt.receipt_id()
        || outcome_body.receipt_digest != receipt.receipt_digest()
        || next.channel_id != body.channel_id
        || next.prev_state_digest.as_deref() != Some(prior_state_digest.as_str())
        || next.receipt_id.as_deref() != Some(receipt.receipt_id())
        || next.receipt_digest.as_deref() != Some(receipt.receipt_digest())
        || next.receipt_authority_digest.as_deref() != Some(receipt.receipt_authority_digest())
        || next.obligation_atom_digest.as_deref() != receipt.obligation_atom_digest()
        || next.reservation_digest.as_deref() != Some(reservation_digest.as_str())
        || next.actual_charge.as_ref() != Some(receipt.actual_charge())
        || dispatch_effect.operation_id != body.operation_id
        || dispatch_effect.request.request_id != body.request_id
        || dispatch_effect.effect_kind != CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
        || dispatch_effect.resource_key != channel_key
        || dispatch_effect.resource_head_digest != snapshot.channel_head_digest()
        || dispatch_effect.parameters_digest != reservation_digest
        || dispatch_effect.idempotency_key != expected_idempotency_key
        || dispatch_effect.state != EconomicEffectStateV1::DispatchCommitted
        || dispatch_effect.terminal.is_some()
        || dispatch_effect.frost.is_some()
        || dispatch_effect.resource_head_key() != effect_key
        || current_effect_head.resource_key != effect_key
        || current_effect_head.head_version != 2
        || current_effect_head.resource_version != 2
        || current_effect_head.lifecycle_fence != 2
        || current_effect_head.lifecycle_state != "dispatch_committed"
        || current_effect_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || current_effect_head.effect_idempotency_key.as_deref()
            != Some(expected_idempotency_key.as_str())
        || current_effect_head.frost.is_some()
        || current_effect_head.terminal_result.is_some()
        || current_effect_head.predecessor_digest.as_deref()
            != Some(reservation.ready_effect_head_digest())
        || current_effect_head.trusted_clock_high_water < admitted.observed_at_unix_ms()
        || current_effect_head.trusted_clock_high_water > current.view().observed_at
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    let state_version = lifecycle
        .state_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let escrow_version = escrow
        .version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let lifecycle_fence = lifecycle
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let terminal_lifecycle = ChannelLifecycleViewV1 {
        schema: lifecycle.schema.clone(),
        channel_id: lifecycle.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: next_state_digest.clone(),
        latest_sequence: next.seq,
        state_version,
        lifecycle_fence,
        pending_close_body_digest: None,
        admitted_dispute_digest: lifecycle.admitted_dispute_digest.clone(),
        live_reservation_id: None,
        operation_id: None,
    };
    let terminal_escrow = ChannelEscrowReservationViewV1 {
        schema: escrow.schema.clone(),
        channel_id: escrow.channel_id.clone(),
        open_digest: escrow.open_digest.clone(),
        escrow_reference: escrow.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: escrow_version,
        lifecycle_fence,
        pending_close_body_digest: None,
    };
    terminal_lifecycle.validate()?;
    terminal_escrow.validate()?;
    let next_channel_head = successor_head(
        current_channel_head,
        &terminal_lifecycle,
        SuccessorHeadBinding {
            resource_version: state_version,
            lifecycle_fence,
            lifecycle_state: "open",
            operation_id: None,
            effect_idempotency_key: None,
            terminal_result: None,
        },
        issued_at,
    )?;
    let next_escrow_head = successor_head(
        current_escrow_head,
        &terminal_escrow,
        SuccessorHeadBinding {
            resource_version: escrow_version,
            lifecycle_fence,
            lifecycle_state: "open",
            operation_id: None,
            effect_idempotency_key: None,
            terminal_result: None,
        },
        issued_at,
    )?;
    let mut completed_effect = dispatch_effect.clone();
    completed_effect.state = EconomicEffectStateV1::Completed;
    completed_effect.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: terminal_result.result_id.clone(),
        result_digest: terminal_result.result_digest.clone(),
        result: terminal_result.result.clone(),
    });
    dispatch_effect
        .validate_successor(&completed_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let effect_resource_version = current_effect_head
        .resource_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let effect_lifecycle_fence = current_effect_head
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let next_effect_head = successor_head(
        current_effect_head,
        &completed_effect,
        SuccessorHeadBinding {
            resource_version: effect_resource_version,
            lifecycle_fence: effect_lifecycle_fence,
            lifecycle_state: "completed",
            operation_id: Some(body.operation_id.clone()),
            effect_idempotency_key: Some(expected_idempotency_key),
            terminal_result: Some(terminal_result.clone()),
        },
        issued_at,
    )?;
    let source_channel_head_digest = head_digest(current_channel_head)?;
    let source_escrow_head_digest = head_digest(current_escrow_head)?;
    let source_effect_head_digest = head_digest(current_effect_head)?;
    let proof = ChannelTerminalTransitionProofV1 {
        schema: CHANNEL_TERMINAL_TRANSITION_PROOF_SCHEMA.to_owned(),
        open_intent_digest,
        open_digest,
        prior_state_digest,
        reservation_digest,
        operation_id: body.operation_id.clone(),
        request: dispatch_effect.request.clone(),
        provider: dispatch_effect.target.clone(),
        receipt_id: receipt.receipt_id().to_owned(),
        receipt_digest: receipt.receipt_digest().to_owned(),
        receipt_authority_digest: receipt.receipt_authority_digest().to_owned(),
        next_state_digest,
        obligation_atom_id: receipt.obligation_atom_id().map(str::to_owned),
        obligation_atom_digest: receipt.obligation_atom_digest().map(str::to_owned),
        outcome_id: terminal_result.result_id.clone(),
        outcome_digest: terminal_result.result_digest.clone(),
        source_checkpoint_digest: current.view().checkpoint_digest.clone(),
        source_channel_head_digest: source_channel_head_digest.clone(),
        source_escrow_head_digest: source_escrow_head_digest.clone(),
        source_effect_head_digest: source_effect_head_digest.clone(),
        terminal_channel_head_digest: head_digest(&next_channel_head)?,
        terminal_escrow_head_digest: head_digest(&next_escrow_head)?,
        terminal_effect_head_digest: head_digest(&next_effect_head)?,
        issued_at,
    };
    let proof_digest = proof.digest()?;
    let mut transitions = vec![
        transition(
            channel_key,
            source_channel_head_digest,
            next_channel_head,
            &proof_digest,
        ),
        transition(
            escrow_key,
            source_escrow_head_digest,
            next_escrow_head,
            &proof_digest,
        ),
        transition(
            effect_key,
            source_effect_head_digest,
            next_effect_head,
            &proof_digest,
        ),
    ];
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    Ok(ChannelLifecycleProjectionV1 {
        current: current.clone(),
        proof_digest,
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: body.operation_id.clone(),
        issued_at,
        not_after_unix_ms: None,
    })
}

#[derive(Debug, Clone)]
pub struct ChannelLifecycleBatchVerifier {
    projection: ChannelLifecycleProjectionV1,
}

impl ChannelLifecycleBatchVerifier {
    #[must_use]
    pub const fn new(projection: ChannelLifecycleProjectionV1) -> Self {
        Self { projection }
    }
}

impl EconomicTransitionProofVerifier for ChannelLifecycleBatchVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::TransitionProofRejected(
            transition.resource_key.clone(),
        ))
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let rejected_key = batch
            .transitions
            .first()
            .ok_or(EconomicStateAnchorError::InvalidView(
                "channel batch has no transition",
            ))?
            .resource_key
            .clone();
        let rejected = || EconomicStateAnchorError::TransitionProofRejected(rejected_key.clone());
        let expected_sequence = current
            .view()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or_else(rejected)?;
        if current.view() != self.projection.current.view()
            || batch.anchor_id != current.view().anchor_id
            || batch.namespace != current.view().namespace
            || batch.checkpoint_sequence != expected_sequence
            || batch.previous_checkpoint_digest.as_deref()
                != Some(current.view().checkpoint_digest.as_str())
            || batch.transitions != self.projection.transitions
            || batch.effect_slots != self.projection.effect_slots
            || batch.request_replays != self.projection.request_replays
            || batch.operation_id.as_deref() != Some(self.projection.operation_id.as_str())
            || batch.issued_at != self.projection.issued_at
        {
            return Err(rejected());
        }
        Ok(vec![
            EconomicTransitionAuthorizationV1::Direct;
            batch.transitions.len()
        ])
    }
}

fn transition(
    resource_key: EconomicResourceKeyV1,
    expected_head_digest: String,
    next_head: EconomicResourceHeadV1,
    proof_digest: &str,
) -> EconomicStateTransitionV1 {
    EconomicStateTransitionV1 {
        resource_key,
        expected_head_digest: Some(expected_head_digest),
        next_head,
        transition_proof_digest: proof_digest.to_owned(),
        prepared_effect: None,
    }
}

struct SuccessorHeadBinding {
    resource_version: u64,
    lifecycle_fence: u64,
    lifecycle_state: &'static str,
    operation_id: Option<String>,
    effect_idempotency_key: Option<String>,
    terminal_result: Option<EconomicTerminalResultV1>,
}

fn successor_head<T: Serialize>(
    current: &EconomicResourceHeadV1,
    state: &T,
    binding: SuccessorHeadBinding,
    issued_at: u64,
) -> Result<EconomicResourceHeadV1, ChannelError> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(state)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: current
            .head_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        resource_version: binding.resource_version,
        lifecycle_fence: binding.lifecycle_fence,
        lifecycle_state: binding.lifecycle_state.to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        state,
        operation_id: binding.operation_id,
        effect_idempotency_key: binding.effect_idempotency_key,
        frost: None,
        terminal_result: binding.terminal_result,
        trusted_clock_high_water: issued_at,
        predecessor_digest: Some(head_digest(current)?),
    };
    head.validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(head)
}

fn head_digest(head: &EconomicResourceHeadV1) -> Result<String, ChannelError> {
    head.digest()
        .map_err(|_| ChannelError::AuthorityVerification)
}
