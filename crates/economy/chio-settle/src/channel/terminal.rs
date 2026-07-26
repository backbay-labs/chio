use chio_core::capability::scope::MonetaryAmount;
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicContentV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicEffectTerminalV1, EconomicResourceHeadV1, EconomicResourceKeyV1,
    EconomicStateBatchV1, EconomicStateTransitionV1, EconomicTerminalResultV1,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
};
use chio_credit::obligation::ObligationAtomV1;
use serde::de::DeserializeOwned;

use super::validation::{digest, validate_digest, validate_positive};
use super::{
    ChannelError, ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1,
    ChannelLifecycleStatusV1, ChannelLifecycleViewV1, VerifiedAdmittedChannelReservationV1,
    VerifiedChannelOpenConsentV1, VerifiedChannelReceiptBindingV1, VerifiedChannelStateV1,
    VerifiedChannelTerminalOutcomeCommitmentV1, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
};

pub const CHANNEL_SERVICE_DISPATCH_EFFECT_KIND: &str = "channel_service_dispatch";

const CHANNEL_SERVICE_DISPATCH_IDEMPOTENCY_DOMAIN: &[u8] =
    b"chio.channel.service-dispatch.idempotency.v1\0";

pub fn derive_channel_service_dispatch_idempotency_key(
    operation_id: &str,
    reservation_id: &str,
    sequence: u64,
) -> Result<String, ChannelError> {
    validate_digest("channel_service_operation_id", operation_id)?;
    validate_digest("channel_service_reservation_id", reservation_id)?;
    validate_positive("channel_service_sequence", sequence)?;
    digest(
        CHANNEL_SERVICE_DISPATCH_IDEMPOTENCY_DOMAIN,
        &(operation_id, reservation_id, sequence),
    )
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelTerminalAdvanceV1 {
    open: VerifiedChannelOpenConsentV1,
    reservation: VerifiedAdmittedChannelReservationV1,
    prior_state: VerifiedChannelStateV1,
    next_state: VerifiedChannelStateV1,
    receipt: VerifiedChannelReceiptBindingV1,
    current_view: VerifiedEconomicStateView,
    batch: EconomicStateBatchV1,
    terminal_lifecycle: ChannelLifecycleViewV1,
    terminal_escrow: ChannelEscrowReservationViewV1,
    completed_effect: EconomicEffectSlotV1,
    open_digest: String,
    reservation_digest: String,
    prior_state_digest: String,
    next_state_digest: String,
    prior_channel_head_digest: String,
    prior_escrow_head_digest: String,
    prior_effect_head_digest: String,
    terminal_channel_head_digest: String,
    terminal_escrow_head_digest: String,
    terminal_effect_head_digest: String,
    effect_result_id: String,
    effect_result_digest: String,
    effect_result: EconomicContentV1,
}

impl VerifiedChannelTerminalAdvanceV1 {
    #[must_use]
    pub fn channel_id(&self) -> &str {
        &self.next_state.body().channel_id
    }

    #[must_use]
    pub const fn open(&self) -> &VerifiedChannelOpenConsentV1 {
        &self.open
    }

    #[must_use]
    pub fn open_digest(&self) -> &str {
        &self.open_digest
    }

    #[must_use]
    pub const fn reservation(&self) -> &VerifiedAdmittedChannelReservationV1 {
        &self.reservation
    }

    #[must_use]
    pub const fn reservation_proposal(&self) -> &super::VerifiedChannelReservationProposalV1 {
        self.reservation.proposal()
    }

    #[must_use]
    pub fn reservation_id(&self) -> &str {
        &self.reservation.artifact().body.reservation_id
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }

    #[must_use]
    pub const fn prior_state(&self) -> &VerifiedChannelStateV1 {
        &self.prior_state
    }

    #[must_use]
    pub fn prior_state_digest(&self) -> &str {
        &self.prior_state_digest
    }

    #[must_use]
    pub const fn next_state(&self) -> &VerifiedChannelStateV1 {
        &self.next_state
    }

    #[must_use]
    pub fn next_state_digest(&self) -> &str {
        &self.next_state_digest
    }

    #[must_use]
    pub const fn receipt(&self) -> &VerifiedChannelReceiptBindingV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn actual_charge(&self) -> &MonetaryAmount {
        self.receipt.actual_charge()
    }

    #[must_use]
    pub fn obligation_atom_id(&self) -> Option<&str> {
        self.receipt.obligation_atom_id()
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> Option<&str> {
        self.receipt.obligation_atom_digest()
    }

    #[must_use]
    pub const fn obligation_atom(&self) -> Option<&ObligationAtomV1> {
        self.receipt.obligation_atom()
    }

    #[must_use]
    pub const fn current_view(&self) -> &VerifiedEconomicStateView {
        &self.current_view
    }

    #[must_use]
    pub const fn batch(&self) -> &EconomicStateBatchV1 {
        &self.batch
    }

    #[must_use]
    pub fn batch_id(&self) -> &str {
        &self.batch.batch_id
    }

    #[must_use]
    pub fn previous_checkpoint_digest(&self) -> &str {
        &self.current_view.view().checkpoint_digest
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.batch.checkpoint_digest
    }

    #[must_use]
    pub const fn batch_issued_at(&self) -> u64 {
        self.batch.issued_at
    }

    #[must_use]
    pub const fn terminal_lifecycle(&self) -> &ChannelLifecycleViewV1 {
        &self.terminal_lifecycle
    }

    #[must_use]
    pub const fn terminal_escrow(&self) -> &ChannelEscrowReservationViewV1 {
        &self.terminal_escrow
    }

    #[must_use]
    pub fn prior_channel_head_digest(&self) -> &str {
        &self.prior_channel_head_digest
    }

    #[must_use]
    pub fn prior_escrow_head_digest(&self) -> &str {
        &self.prior_escrow_head_digest
    }

    #[must_use]
    pub fn prior_effect_head_digest(&self) -> &str {
        &self.prior_effect_head_digest
    }

    #[must_use]
    pub fn terminal_channel_head_digest(&self) -> &str {
        &self.terminal_channel_head_digest
    }

    #[must_use]
    pub fn terminal_escrow_head_digest(&self) -> &str {
        &self.terminal_escrow_head_digest
    }

    #[must_use]
    pub fn terminal_effect_head_digest(&self) -> &str {
        &self.terminal_effect_head_digest
    }

    #[must_use]
    pub const fn effect_slot(&self) -> &EconomicEffectSlotV1 {
        &self.completed_effect
    }

    #[must_use]
    pub fn effect_head_digest(&self) -> &str {
        &self.terminal_effect_head_digest
    }

    #[must_use]
    pub fn effect_result_id(&self) -> &str {
        &self.effect_result_id
    }

    #[must_use]
    pub fn effect_result_digest(&self) -> &str {
        &self.effect_result_digest
    }

    #[must_use]
    pub fn effect_result(&self) -> &EconomicContentV1 {
        &self.effect_result
    }
}

pub fn verify_channel_terminal_advance(
    open: &VerifiedChannelOpenConsentV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    prior_state: &VerifiedChannelStateV1,
    next_state: &VerifiedChannelStateV1,
    receipt: &VerifiedChannelReceiptBindingV1,
    outcome: &VerifiedChannelTerminalOutcomeCommitmentV1,
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<VerifiedChannelTerminalAdvanceV1, ChannelError> {
    let body = &reservation.artifact().body;
    let admitted_snapshot = reservation.snapshot();
    let admitted_lifecycle = admitted_snapshot.lifecycle();
    let admitted_escrow = admitted_snapshot.escrow();
    let current_view = advance.current().view();
    let batch = advance.batch();
    let open_digest = open.artifact().digest()?;
    let reservation_digest = reservation.artifact().digest()?;
    let prior_state_digest = prior_state.digest()?;
    let next_state_digest = next_state.digest()?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: open.intent().body.settlement_authority_scope_id.clone(),
        resource_id: body.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: open.intent().body.settlement_authority_scope_id.clone(),
        resource_id: body.channel_id.clone(),
    };
    if batch.transitions.len() != 3
        || !batch.effect_slots.is_empty()
        || !batch.request_replays.is_empty()
        || batch
            .transitions
            .iter()
            .any(|transition| transition.prepared_effect.is_some())
        || batch.operation_id.as_deref() != Some(body.operation_id.as_str())
        || batch.previous_checkpoint_digest.as_deref()
            != Some(current_view.checkpoint_digest.as_str())
        || current_view.checkpoint_sequence <= admitted_snapshot.checkpoint_sequence()
        || current_view.checkpoint_digest == admitted_snapshot.checkpoint_digest()
        || current_view.observed_at < admitted_snapshot.observed_at_unix_ms()
        || batch.issued_at < current_view.observed_at
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let channel_transition = exact_transition(batch, &channel_key)?;
    let escrow_transition = exact_transition(batch, &escrow_key)?;
    let effect_transition = batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key.resource_family == "effect_slot")
        .ok_or(ChannelError::AuthorityVerification)?;
    if effect_transition.resource_key.scope_id != channel_key.scope_id
        || batch.transitions.iter().any(|transition| {
            transition.resource_key != channel_key
                && transition.resource_key != escrow_key
                && transition.resource_key != effect_transition.resource_key
        })
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let current_channel_head = current_view
        .head(&channel_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let current_escrow_head = current_view
        .head(&escrow_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let current_effect_head = current_view
        .head(&effect_transition.resource_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    if current_channel_head != admitted_snapshot.channel_head()
        || current_escrow_head != admitted_snapshot.escrow_head()
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let prior_channel_head_digest = head_digest(current_channel_head)?;
    let prior_escrow_head_digest = head_digest(current_escrow_head)?;
    let prior_effect_head_digest = head_digest(current_effect_head)?;
    if channel_transition.expected_head_digest.as_deref()
        != Some(prior_channel_head_digest.as_str())
        || escrow_transition.expected_head_digest.as_deref()
            != Some(prior_escrow_head_digest.as_str())
        || effect_transition.expected_head_digest.as_deref()
            != Some(prior_effect_head_digest.as_str())
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let terminal_lifecycle: ChannelLifecycleViewV1 = decode_head(&channel_transition.next_head)?;
    let terminal_escrow: ChannelEscrowReservationViewV1 =
        decode_head(&escrow_transition.next_head)?;
    let dispatch_effect: EconomicEffectSlotV1 = decode_head(current_effect_head)?;
    let completed_effect: EconomicEffectSlotV1 = decode_head(&effect_transition.next_head)?;
    terminal_lifecycle.validate()?;
    terminal_escrow.validate()?;
    reservation
        .ready_effect()
        .validate_successor(&dispatch_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    dispatch_effect
        .validate_successor(&completed_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let expected_state_version = admitted_lifecycle
        .state_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_escrow_version = admitted_escrow
        .version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_fence = admitted_lifecycle
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_effect_version = current_effect_head
        .resource_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_effect_fence = current_effect_head
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_idempotency_key = derive_channel_service_dispatch_idempotency_key(
        &body.operation_id,
        &body.reservation_id,
        body.next_sequence,
    )?;
    let Some(EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = completed_effect.terminal.as_ref()
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    let expected_terminal_result = EconomicTerminalResultV1 {
        result_id: result_id.clone(),
        result_digest: result_digest.clone(),
        result: result.clone(),
    };
    let obligation_matches_charge = matches!(
        (
            receipt.actual_charge().units,
            receipt.obligation_atom_id(),
            receipt.obligation_atom_digest(),
        ),
        (0, None, None) | (1.., Some(_), Some(_))
    );
    let obligation_time_is_ordered = match receipt.obligation_atom() {
        Some(atom) => {
            outcome.terminalized_at_unix_ms() <= atom.created_at_unix_ms()
                && atom.created_at_unix_ms() <= batch.issued_at
        }
        None => true,
    };
    let next = next_state.body();
    if body.channel_id != open.artifact().body.channel_id
        || body.open_digest != open_digest
        || body.prior_state_digest != prior_state_digest
        || body.next_sequence != next.seq
        || receipt.channel_id() != body.channel_id
        || receipt.open_digest() != open_digest
        || receipt.reservation_digest() != reservation_digest
        || receipt.sequence() != body.next_sequence
        || next.channel_id != body.channel_id
        || next.prev_state_digest.as_deref() != Some(prior_state_digest.as_str())
        || next.receipt_id.as_deref() != Some(receipt.receipt_id())
        || next.receipt_digest.as_deref() != Some(receipt.receipt_digest())
        || next.receipt_authority_digest.as_deref() != Some(receipt.receipt_authority_digest())
        || next.obligation_atom_digest.as_deref() != receipt.obligation_atom_digest()
        || next.reservation_digest.as_deref() != Some(reservation_digest.as_str())
        || next.actual_charge.as_ref() != Some(receipt.actual_charge())
        || !obligation_matches_charge
        || !obligation_time_is_ordered
        || outcome.terminal_result() != &expected_terminal_result
        || outcome.terminalized_at_unix_ms() > batch.issued_at
        || admitted_lifecycle.status != ChannelLifecycleStatusV1::Open
        || admitted_lifecycle.channel_id != body.channel_id
        || admitted_lifecycle.latest_state_digest != prior_state_digest
        || admitted_lifecycle.latest_sequence != prior_state.body().seq
        || admitted_lifecycle.live_reservation_id.as_deref() != Some(body.reservation_id.as_str())
        || admitted_lifecycle.operation_id.as_deref() != Some(body.operation_id.as_str())
        || admitted_escrow.status != ChannelEscrowReservationStatusV1::Open
        || admitted_escrow.channel_id != body.channel_id
        || admitted_escrow.open_digest != open_digest
        || admitted_escrow.escrow_reference != open.intent().body.escrow_reference
        || admitted_escrow.lifecycle_fence != admitted_lifecycle.lifecycle_fence
        || terminal_lifecycle.status != ChannelLifecycleStatusV1::Open
        || terminal_lifecycle.channel_id != body.channel_id
        || terminal_lifecycle.latest_state_digest != next_state_digest
        || terminal_lifecycle.latest_sequence != next.seq
        || terminal_lifecycle.state_version != expected_state_version
        || terminal_lifecycle.lifecycle_fence != expected_fence
        || terminal_lifecycle.pending_close_body_digest.is_some()
        || terminal_lifecycle.admitted_dispute_digest != admitted_lifecycle.admitted_dispute_digest
        || terminal_lifecycle.live_reservation_id.is_some()
        || terminal_lifecycle.operation_id.is_some()
        || terminal_escrow.status != ChannelEscrowReservationStatusV1::Open
        || terminal_escrow.channel_id != body.channel_id
        || terminal_escrow.open_digest != open_digest
        || terminal_escrow.escrow_reference != admitted_escrow.escrow_reference
        || terminal_escrow.version != expected_escrow_version
        || terminal_escrow.lifecycle_fence != expected_fence
        || terminal_escrow.pending_close_body_digest.is_some()
        || !released_head_matches(
            current_channel_head,
            channel_transition,
            expected_state_version,
            expected_fence,
            batch.issued_at,
        )?
        || !released_head_matches(
            current_escrow_head,
            escrow_transition,
            expected_escrow_version,
            expected_fence,
            batch.issued_at,
        )?
        || channel_transition.next_head.lifecycle_state != "open"
        || escrow_transition.next_head.lifecycle_state != "open"
        || dispatch_effect.operation_id != body.operation_id
        || dispatch_effect.request.request_id != body.request_id
        || dispatch_effect.effect_kind != CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
        || dispatch_effect.resource_key != channel_key
        || dispatch_effect.resource_head_digest != prior_channel_head_digest
        || dispatch_effect.admission_handoff.state
            != EconomicAdmissionHandoffStateV1::DispatchCommitted
        || dispatch_effect.parameters_digest != reservation_digest
        || dispatch_effect.idempotency_key != expected_idempotency_key
        || dispatch_effect.frost.is_some()
        || dispatch_effect.state != EconomicEffectStateV1::DispatchCommitted
        || dispatch_effect.terminal.is_some()
        || dispatch_effect.resource_head_key() != effect_transition.resource_key
        || current_effect_head.lifecycle_state != "dispatch_committed"
        || current_effect_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || current_effect_head.effect_idempotency_key.as_deref()
            != Some(expected_idempotency_key.as_str())
        || current_effect_head.frost.is_some()
        || current_effect_head.terminal_result.is_some()
        || current_effect_head.head_version != 2
        || current_effect_head.predecessor_digest.as_deref()
            != Some(reservation.ready_effect_head_digest())
        || current_effect_head.resource_version != current_effect_head.head_version
        || current_effect_head.lifecycle_fence != current_effect_head.head_version
        || current_effect_head.trusted_clock_high_water
            < reservation.snapshot().observed_at_unix_ms()
        || current_effect_head.trusted_clock_high_water > current_view.observed_at
        || completed_effect.state != EconomicEffectStateV1::Completed
        || completed_effect.resource_head_key() != effect_transition.resource_key
        || effect_transition.next_head.lifecycle_state != "completed"
        || effect_transition.next_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || effect_transition
            .next_head
            .effect_idempotency_key
            .as_deref()
            != Some(expected_idempotency_key.as_str())
        || effect_transition.next_head.frost.is_some()
        || effect_transition.next_head.terminal_result.as_ref() != Some(&expected_terminal_result)
        || effect_transition.next_head.resource_version != expected_effect_version
        || effect_transition.next_head.lifecycle_fence != expected_effect_fence
        || effect_transition.next_head.resource_version != effect_transition.next_head.head_version
        || effect_transition.next_head.lifecycle_fence != effect_transition.next_head.head_version
        || effect_transition.next_head.trusted_clock_high_water != batch.issued_at
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let effect_result_id = result_id.clone();
    let effect_result_digest = result_digest.clone();
    let effect_result = result.clone();
    Ok(VerifiedChannelTerminalAdvanceV1 {
        open: open.clone(),
        reservation: reservation.clone(),
        prior_state: prior_state.clone(),
        next_state: next_state.clone(),
        receipt: receipt.clone(),
        current_view: advance.current().clone(),
        batch: batch.clone(),
        terminal_lifecycle,
        terminal_escrow,
        completed_effect,
        open_digest,
        reservation_digest,
        prior_state_digest,
        next_state_digest,
        prior_channel_head_digest,
        prior_escrow_head_digest,
        prior_effect_head_digest,
        terminal_channel_head_digest: head_digest(&channel_transition.next_head)?,
        terminal_escrow_head_digest: head_digest(&escrow_transition.next_head)?,
        terminal_effect_head_digest: head_digest(&effect_transition.next_head)?,
        effect_result_id,
        effect_result_digest,
        effect_result,
    })
}

fn exact_transition<'a>(
    batch: &'a EconomicStateBatchV1,
    key: &EconomicResourceKeyV1,
) -> Result<&'a EconomicStateTransitionV1, ChannelError> {
    batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key == *key)
        .ok_or(ChannelError::AuthorityVerification)
}

fn decode_head<T: DeserializeOwned>(head: &EconomicResourceHeadV1) -> Result<T, ChannelError> {
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ChannelError::AuthorityVerification);
    };
    serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)
}

fn head_digest(head: &EconomicResourceHeadV1) -> Result<String, ChannelError> {
    head.digest()
        .map_err(|_| ChannelError::AuthorityVerification)
}

fn released_head_matches(
    current: &EconomicResourceHeadV1,
    transition: &EconomicStateTransitionV1,
    resource_version: u64,
    lifecycle_fence: u64,
    issued_at: u64,
) -> Result<bool, ChannelError> {
    let current_digest = head_digest(current)?;
    Ok(transition.next_head.resource_version == resource_version
        && transition.next_head.lifecycle_fence == lifecycle_fence
        && transition.next_head.trusted_clock_high_water == issued_at
        && transition.next_head.operation_id.is_none()
        && transition.next_head.effect_idempotency_key.is_none()
        && transition.next_head.frost.is_none()
        && transition.next_head.terminal_result.is_none()
        && transition.next_head.predecessor_digest == transition.expected_head_digest
        && transition.next_head.predecessor_digest.as_deref() == Some(current_digest.as_str()))
}
