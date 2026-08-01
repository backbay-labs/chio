use chio_core::economic_continuity::{
    economic_effect_slot_from_head, EconomicEffectSlotV1, EconomicEffectStateV1,
    EconomicEffectTargetV1, EconomicRequestBindingV1, EconomicRequestReplayV1,
    EconomicTransitionProofVerifier, VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
};
use serde::Serialize;

use super::super::validation::digest;
use super::super::{
    derive_channel_service_dispatch_idempotency_key, verify_channel_lifecycle_snapshot,
    ChannelError, VerifiedAdmittedChannelReservationV1, CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
};
use super::{
    head_digest, successor_head, transition, ChannelLifecycleBatchVerifier,
    ChannelLifecycleProjectionV1, SuccessorHeadBinding,
};

const CHANNEL_DISPATCH_TRANSITION_PROOF_SCHEMA: &str = "chio.channel.dispatch-transition-proof.v1";
const CHANNEL_DISPATCH_TRANSITION_PROOF_DOMAIN: &[u8] =
    b"chio.channel.dispatch-transition-proof.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelDispatchTransitionProofV1 {
    schema: String,
    reservation_proposal_digest: String,
    reservation_digest: String,
    operation_id: String,
    request: EconomicRequestBindingV1,
    request_replay: EconomicRequestReplayV1,
    provider: EconomicEffectTargetV1,
    source_checkpoint_sequence: u64,
    source_checkpoint_digest: String,
    ready_effect_digest: String,
    ready_effect_head_digest: String,
    dispatch_effect_digest: String,
    dispatch_effect_head_digest: String,
    issued_at: u64,
}

impl ChannelDispatchTransitionProofV1 {
    fn digest(&self) -> Result<String, ChannelError> {
        digest(CHANNEL_DISPATCH_TRANSITION_PROOF_DOMAIN, self)
    }
}

pub fn compose_channel_dispatch_transition(
    reservation: &VerifiedAdmittedChannelReservationV1,
    current: &VerifiedEconomicStateView,
    issued_at: u64,
) -> Result<ChannelLifecycleProjectionV1, ChannelError> {
    let body = &reservation.artifact().body;
    let ready_effect = reservation.ready_effect();
    let admitted = reservation.snapshot();
    let snapshot = verify_channel_lifecycle_snapshot(
        current,
        admitted.settlement_authority_scope_id(),
        &body.channel_id,
    )?;
    let effect_key = ready_effect.resource_head_key();
    let ready_head = current
        .view()
        .head(&effect_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let retained_effect = economic_effect_slot_from_head(ready_head)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let reservation_digest = reservation.artifact().digest()?;
    let expected_idempotency_key = derive_channel_service_dispatch_idempotency_key(
        &body.operation_id,
        &body.reservation_id,
        body.next_sequence,
    )?;
    let request_replay = EconomicRequestReplayV1 {
        request: ready_effect.request.clone(),
        operation_id: body.operation_id.clone(),
        effect_slot_ids: vec![ready_effect.slot_id.clone()],
    };
    request_replay
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let retained_replay = current
        .view()
        .request_replay(&ready_effect.request.key())
        .ok_or(ChannelError::AuthorityVerification)?;
    let ready_head_digest = head_digest(ready_head)?;
    let exact_checkpoint = current.view().checkpoint_sequence == admitted.checkpoint_sequence()
        && current.view().checkpoint_digest == admitted.checkpoint_digest();
    let later_checkpoint = current.view().checkpoint_sequence > admitted.checkpoint_sequence()
        && current.view().checkpoint_digest != admitted.checkpoint_digest();
    if !(exact_checkpoint || later_checkpoint)
        || current.view().observed_at < admitted.observed_at_unix_ms()
        || snapshot.lifecycle() != admitted.lifecycle()
        || snapshot.escrow() != admitted.escrow()
        || snapshot.channel_head_digest() != admitted.channel_head_digest()
        || snapshot.escrow_head_digest() != admitted.escrow_head_digest()
        || snapshot.channel_head() != admitted.channel_head()
        || snapshot.escrow_head() != admitted.escrow_head()
        || &retained_effect != ready_effect
        || retained_replay != &request_replay
        || ready_head_digest != reservation.ready_effect_head_digest()
        || ready_effect.operation_id != body.operation_id
        || ready_effect.request.request_id != body.request_id
        || ready_effect.effect_kind != CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
        || ready_effect.parameters_digest != reservation_digest
        || ready_effect.idempotency_key != expected_idempotency_key
        || ready_effect.state != EconomicEffectStateV1::Ready
        || ready_effect.terminal.is_some()
        || ready_effect.frost.is_some()
        || ready_head.head_version != 1
        || ready_head.resource_version != 1
        || ready_head.lifecycle_fence != 1
        || ready_head.lifecycle_state != "ready"
        || ready_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || ready_head.effect_idempotency_key.as_deref() != Some(expected_idempotency_key.as_str())
        || ready_head.frost.is_some()
        || ready_head.terminal_result.is_some()
        || ready_head.trusted_clock_high_water != admitted.observed_at_unix_ms()
        || ready_head.trusted_clock_high_water > current.view().observed_at
        || ready_head.predecessor_digest.is_some()
        || issued_at < reservation.accepted_at_unix_ms()
        || issued_at < current.view().observed_at
        || issued_at >= body.expires_at_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let mut dispatch_effect = ready_effect.clone();
    dispatch_effect.state = EconomicEffectStateV1::DispatchCommitted;
    ready_effect
        .validate_successor(&dispatch_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let dispatch_head = successor_head(
        ready_head,
        &dispatch_effect,
        SuccessorHeadBinding {
            resource_version: 2,
            lifecycle_fence: 2,
            lifecycle_state: "dispatch_committed",
            operation_id: Some(body.operation_id.clone()),
            effect_idempotency_key: Some(expected_idempotency_key),
            terminal_result: None,
        },
        issued_at,
    )?;
    let proof = ChannelDispatchTransitionProofV1 {
        schema: CHANNEL_DISPATCH_TRANSITION_PROOF_SCHEMA.to_owned(),
        reservation_proposal_digest: body.proposal_digest()?,
        reservation_digest,
        operation_id: body.operation_id.clone(),
        request: ready_effect.request.clone(),
        request_replay,
        provider: ready_effect.target.clone(),
        source_checkpoint_sequence: current.view().checkpoint_sequence,
        source_checkpoint_digest: current.view().checkpoint_digest.clone(),
        ready_effect_digest: ready_effect
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        ready_effect_head_digest: ready_head_digest.clone(),
        dispatch_effect_digest: dispatch_effect
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        dispatch_effect_head_digest: head_digest(&dispatch_head)?,
        issued_at,
    };
    let proof_digest = proof.digest()?;
    Ok(ChannelLifecycleProjectionV1 {
        current: current.clone(),
        proof_digest: proof_digest.clone(),
        transitions: vec![transition(
            effect_key,
            ready_head_digest,
            dispatch_head,
            &proof_digest,
        )],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: body.operation_id.clone(),
        issued_at,
        not_after_unix_ms: Some(body.expires_at_unix_ms),
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelDispatchAdvanceV1 {
    effect_slot: EconomicEffectSlotV1,
    request_replay: EconomicRequestReplayV1,
    reservation_digest: String,
    previous_checkpoint_digest: String,
}

impl VerifiedChannelDispatchAdvanceV1 {
    #[must_use]
    pub const fn effect_slot(&self) -> &EconomicEffectSlotV1 {
        &self.effect_slot
    }

    #[must_use]
    pub const fn request_replay(&self) -> &EconomicRequestReplayV1 {
        &self.request_replay
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }

    #[must_use]
    pub fn previous_checkpoint_digest(&self) -> &str {
        &self.previous_checkpoint_digest
    }
}

pub fn verify_channel_dispatch_advance(
    reservation: &VerifiedAdmittedChannelReservationV1,
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<VerifiedChannelDispatchAdvanceV1, ChannelError> {
    let projection = compose_channel_dispatch_transition(
        reservation,
        advance.current(),
        advance.batch().issued_at,
    )?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    verifier
        .verify_batch(advance.current(), advance.batch())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let transition = advance
        .batch()
        .transitions
        .first()
        .ok_or(ChannelError::AuthorityVerification)?;
    let effect_slot = economic_effect_slot_from_head(&transition.next_head)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let request_replay = advance
        .current()
        .view()
        .request_replay(&effect_slot.request.key())
        .ok_or(ChannelError::AuthorityVerification)?
        .clone();
    Ok(VerifiedChannelDispatchAdvanceV1 {
        effect_slot,
        request_replay,
        reservation_digest: reservation.artifact().digest()?,
        previous_checkpoint_digest: advance.current().view().checkpoint_digest.clone(),
    })
}
