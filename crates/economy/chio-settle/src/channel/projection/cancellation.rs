use chio_core::economic_continuity::{
    economic_effect_slot_from_head, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1, EconomicRequestBindingV1, EconomicRequestReplayV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::super::validation::{digest, validate_positive};
use super::super::{
    derive_channel_service_dispatch_idempotency_key, verify_channel_lifecycle_snapshot,
    ChannelError, ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1,
    ChannelLifecycleStatusV1, ChannelLifecycleViewV1, VerifiedAdmittedChannelReservationV1,
    CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY, CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
    CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
};
use super::{
    head_digest, successor_head, transition, ChannelLifecycleBatchVerifier,
    ChannelLifecycleProjectionV1, SuccessorHeadBinding,
};

pub const CHANNEL_PREDISPATCH_CANCELLATION_EVIDENCE_SCHEMA: &str =
    "chio.channel.predispatch-cancellation-evidence.v1";

const CHANNEL_PREDISPATCH_CANCELLATION_EVIDENCE_DOMAIN: &[u8] =
    b"chio.channel.predispatch-cancellation-evidence.digest.v1\0";
const CHANNEL_CANCELLATION_TRANSITION_PROOF_SCHEMA: &str =
    "chio.channel.cancellation-transition-proof.v1";
const CHANNEL_CANCELLATION_TRANSITION_PROOF_DOMAIN: &[u8] =
    b"chio.channel.cancellation-transition-proof.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPredispatchCancellationEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub reservation_proposal_digest: String,
    pub reservation_digest: String,
    pub channel_id: String,
    pub service_binding_digest: String,
    pub request: EconomicRequestBindingV1,
    pub admission_handoff: EconomicAdmissionHandoffV1,
    pub provider: EconomicEffectTargetV1,
    pub action_digest: String,
    pub parameters_digest: String,
    pub idempotency_key: String,
    pub source_checkpoint_sequence: u64,
    pub source_checkpoint_digest: String,
    pub source_channel_head_digest: String,
    pub source_escrow_head_digest: String,
    pub source_effect_head_digest: String,
    pub authenticated_clock_unix_ms: u64,
    pub issued_at: u64,
}

impl ChannelPredispatchCancellationEvidenceV1 {
    fn digest(&self) -> Result<String, ChannelError> {
        digest(CHANNEL_PREDISPATCH_CANCELLATION_EVIDENCE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelCancellationTransitionProofV1 {
    schema: String,
    evidence: ChannelPredispatchCancellationEvidenceV1,
    request_replay: EconomicRequestReplayV1,
    released_channel_head_digest: String,
    released_escrow_head_digest: String,
    terminal_effect_head_digest: String,
}

impl ChannelCancellationTransitionProofV1 {
    fn digest(&self) -> Result<String, ChannelError> {
        digest(CHANNEL_CANCELLATION_TRANSITION_PROOF_DOMAIN, self)
    }
}

pub fn compose_channel_cancellation_transition(
    reservation: &VerifiedAdmittedChannelReservationV1,
    current: &VerifiedEconomicStateView,
    issued_at: u64,
) -> Result<ChannelLifecycleProjectionV1, ChannelError> {
    validate_positive("cancellation_issued_at", issued_at)?;
    let body = &reservation.artifact().body;
    let admitted = reservation.snapshot();
    let ready_effect = reservation.ready_effect();
    let snapshot = verify_channel_lifecycle_snapshot(
        current,
        admitted.settlement_authority_scope_id(),
        &body.channel_id,
    )?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: admitted.settlement_authority_scope_id().to_owned(),
        resource_id: body.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: admitted.settlement_authority_scope_id().to_owned(),
        resource_id: body.channel_id.clone(),
    };
    let effect_key = ready_effect.resource_head_key();
    let channel_head = snapshot.channel_head();
    let escrow_head = snapshot.escrow_head();
    let effect_head = current
        .view()
        .head(&effect_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let retained_effect = economic_effect_slot_from_head(effect_head)
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
    let source_channel_head_digest = head_digest(channel_head)?;
    let source_escrow_head_digest = head_digest(escrow_head)?;
    let source_effect_head_digest = head_digest(effect_head)?;
    let source_clock = channel_head.trusted_clock_high_water;
    let exact_checkpoint = current.view().checkpoint_sequence == admitted.checkpoint_sequence()
        && current.view().checkpoint_digest == admitted.checkpoint_digest();
    let later_checkpoint = current.view().checkpoint_sequence > admitted.checkpoint_sequence()
        && current.view().checkpoint_digest != admitted.checkpoint_digest();
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    if !(exact_checkpoint || later_checkpoint)
        || current.view().observed_at < admitted.observed_at_unix_ms()
        || snapshot.lifecycle() != admitted.lifecycle()
        || snapshot.escrow() != admitted.escrow()
        || channel_head != admitted.channel_head()
        || escrow_head != admitted.escrow_head()
        || source_channel_head_digest != admitted.channel_head_digest()
        || source_escrow_head_digest != admitted.escrow_head_digest()
        || source_effect_head_digest != reservation.ready_effect_head_digest()
        || retained_effect != *ready_effect
        || retained_replay != &request_replay
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != body.channel_id
        || lifecycle.live_reservation_id.as_deref() != Some(body.reservation_id.as_str())
        || lifecycle.operation_id.as_deref() != Some(body.operation_id.as_str())
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != body.channel_id
        || escrow.open_digest != body.open_digest
        || escrow.lifecycle_fence != lifecycle.lifecycle_fence
        || channel_head.resource_version != lifecycle.state_version
        || channel_head.lifecycle_fence != lifecycle.lifecycle_fence
        || channel_head.lifecycle_state != "open"
        || channel_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || channel_head.frost.is_some()
        || channel_head.terminal_result.is_some()
        || channel_head.predecessor_digest.is_none()
        || escrow_head.resource_version != escrow.version
        || escrow_head.lifecycle_fence != escrow.lifecycle_fence
        || escrow_head.lifecycle_state != "open"
        || escrow_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || escrow_head.frost.is_some()
        || escrow_head.terminal_result.is_some()
        || escrow_head.predecessor_digest.is_none()
        || escrow_head.trusted_clock_high_water != source_clock
        || effect_head.trusted_clock_high_water != source_clock
        || source_clock < reservation.accepted_at_unix_ms()
        || source_clock > admitted.observed_at_unix_ms()
        || retained_effect.operation_id != body.operation_id
        || retained_effect.request.request_id != body.request_id
        || retained_effect.effect_kind != CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
        || retained_effect.resource_key != channel_key
        || retained_effect.resource_head_digest != source_channel_head_digest
        || retained_effect.parameters_digest != reservation_digest
        || retained_effect.idempotency_key != expected_idempotency_key
        || retained_effect.state != EconomicEffectStateV1::Ready
        || retained_effect.terminal.is_some()
        || retained_effect.frost.is_some()
        || effect_head.head_version != 1
        || effect_head.resource_version != 1
        || effect_head.lifecycle_fence != 1
        || effect_head.lifecycle_state != "ready"
        || effect_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || effect_head.effect_idempotency_key.as_deref() != Some(expected_idempotency_key.as_str())
        || effect_head.frost.is_some()
        || effect_head.terminal_result.is_some()
        || effect_head.predecessor_digest.is_some()
        || issued_at < reservation.accepted_at_unix_ms()
        || issued_at < current.view().observed_at
    {
        return Err(ChannelError::AuthorityVerification);
    }

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
    let released_lifecycle = ChannelLifecycleViewV1 {
        state_version,
        lifecycle_fence,
        live_reservation_id: None,
        operation_id: None,
        ..lifecycle.clone()
    };
    let released_escrow = ChannelEscrowReservationViewV1 {
        version: escrow_version,
        lifecycle_fence,
        ..escrow.clone()
    };
    released_lifecycle.validate()?;
    released_escrow.validate()?;
    let released_channel_head = successor_head(
        channel_head,
        &released_lifecycle,
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
    let released_escrow_head = successor_head(
        escrow_head,
        &released_escrow,
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
    let evidence = ChannelPredispatchCancellationEvidenceV1 {
        schema: CHANNEL_PREDISPATCH_CANCELLATION_EVIDENCE_SCHEMA.to_owned(),
        operation_id: body.operation_id.clone(),
        reservation_id: body.reservation_id.clone(),
        reservation_proposal_digest: body.proposal_digest()?,
        reservation_digest,
        channel_id: body.channel_id.clone(),
        service_binding_digest: body.service_binding_digest.clone(),
        request: ready_effect.request.clone(),
        admission_handoff: ready_effect.admission_handoff.clone(),
        provider: ready_effect.target.clone(),
        action_digest: ready_effect.action_digest.clone(),
        parameters_digest: ready_effect.parameters_digest.clone(),
        idempotency_key: ready_effect.idempotency_key.clone(),
        source_checkpoint_sequence: current.view().checkpoint_sequence,
        source_checkpoint_digest: current.view().checkpoint_digest.clone(),
        source_channel_head_digest,
        source_escrow_head_digest,
        source_effect_head_digest,
        authenticated_clock_unix_ms: source_clock,
        issued_at,
    };
    let proof_id = evidence.digest()?;
    let proof = EconomicContentV1::Inline {
        value: serde_json::to_value(&evidence)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    let proof_digest = proof
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let mut terminal_effect = ready_effect.clone();
    terminal_effect.state = EconomicEffectStateV1::NoEffect;
    terminal_effect.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::PreDispatch,
        proof_id,
        proof_digest,
        proof,
    });
    ready_effect
        .validate_successor(&terminal_effect)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let terminal_effect_head = successor_head(
        effect_head,
        &terminal_effect,
        SuccessorHeadBinding {
            resource_version: 2,
            lifecycle_fence: 2,
            lifecycle_state: "no_effect",
            operation_id: Some(body.operation_id.clone()),
            effect_idempotency_key: Some(expected_idempotency_key),
            terminal_result: None,
        },
        issued_at,
    )?;
    let proof = ChannelCancellationTransitionProofV1 {
        schema: CHANNEL_CANCELLATION_TRANSITION_PROOF_SCHEMA.to_owned(),
        evidence,
        request_replay,
        released_channel_head_digest: head_digest(&released_channel_head)?,
        released_escrow_head_digest: head_digest(&released_escrow_head)?,
        terminal_effect_head_digest: head_digest(&terminal_effect_head)?,
    };
    let transition_proof_digest = proof.digest()?;
    let mut transitions = vec![
        transition(
            channel_key,
            proof.evidence.source_channel_head_digest.clone(),
            released_channel_head,
            &transition_proof_digest,
        ),
        transition(
            escrow_key,
            proof.evidence.source_escrow_head_digest.clone(),
            released_escrow_head,
            &transition_proof_digest,
        ),
        transition(
            effect_key,
            proof.evidence.source_effect_head_digest.clone(),
            terminal_effect_head,
            &transition_proof_digest,
        ),
    ];
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    Ok(ChannelLifecycleProjectionV1 {
        current: current.clone(),
        proof_digest: transition_proof_digest,
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: body.operation_id.clone(),
        issued_at,
        not_after_unix_ms: None,
    })
}

#[derive(Debug, Clone)]
pub struct ChannelCancellationTransitionVerifierV1 {
    reservation: VerifiedAdmittedChannelReservationV1,
}

impl ChannelCancellationTransitionVerifierV1 {
    #[must_use]
    pub const fn new(reservation: VerifiedAdmittedChannelReservationV1) -> Self {
        Self { reservation }
    }
}

impl EconomicTransitionProofVerifier for ChannelCancellationTransitionVerifierV1 {
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
        let projection =
            compose_channel_cancellation_transition(&self.reservation, current, batch.issued_at)
                .map_err(|_| rejected_batch(batch))?;
        ChannelLifecycleBatchVerifier::new(projection).verify_batch(current, batch)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelCancellationAdvanceV1 {
    current_view: VerifiedEconomicStateView,
    batch: EconomicStateBatchV1,
    lifecycle: ChannelLifecycleViewV1,
    escrow: ChannelEscrowReservationViewV1,
    effect_slot: EconomicEffectSlotV1,
    request_replay: EconomicRequestReplayV1,
    evidence: ChannelPredispatchCancellationEvidenceV1,
    reservation_digest: String,
}

impl VerifiedChannelCancellationAdvanceV1 {
    #[must_use]
    pub const fn current_view(&self) -> &VerifiedEconomicStateView {
        &self.current_view
    }

    #[must_use]
    pub const fn batch(&self) -> &EconomicStateBatchV1 {
        &self.batch
    }

    #[must_use]
    pub const fn lifecycle(&self) -> &ChannelLifecycleViewV1 {
        &self.lifecycle
    }

    #[must_use]
    pub const fn escrow(&self) -> &ChannelEscrowReservationViewV1 {
        &self.escrow
    }

    #[must_use]
    pub const fn effect_slot(&self) -> &EconomicEffectSlotV1 {
        &self.effect_slot
    }

    #[must_use]
    pub const fn request_replay(&self) -> &EconomicRequestReplayV1 {
        &self.request_replay
    }

    #[must_use]
    pub const fn evidence(&self) -> &ChannelPredispatchCancellationEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }
}

pub fn verify_channel_cancellation_advance(
    reservation: &VerifiedAdmittedChannelReservationV1,
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<VerifiedChannelCancellationAdvanceV1, ChannelError> {
    let verifier = ChannelCancellationTransitionVerifierV1::new(reservation.clone());
    verifier
        .verify_batch(advance.current(), advance.batch())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let body = &reservation.artifact().body;
    let scope_id = reservation.snapshot().settlement_authority_scope_id();
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: scope_id.to_owned(),
        resource_id: body.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: scope_id.to_owned(),
        resource_id: body.channel_id.clone(),
    };
    let channel_transition = exact_transition(advance.batch(), &channel_key)?;
    let escrow_transition = exact_transition(advance.batch(), &escrow_key)?;
    let effect_transition = exact_transition(
        advance.batch(),
        &reservation.ready_effect().resource_head_key(),
    )?;
    let lifecycle = decode_head(&channel_transition.next_head)?;
    let escrow = decode_head(&escrow_transition.next_head)?;
    let effect_slot = economic_effect_slot_from_head(&effect_transition.next_head)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::PreDispatch,
        proof_id,
        proof_digest,
        proof,
    }) = &effect_slot.terminal
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    let evidence: ChannelPredispatchCancellationEvidenceV1 = decode_content(proof)?;
    if evidence.digest()? != *proof_id
        || proof
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?
            != *proof_digest
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let request_replay = advance
        .current()
        .view()
        .request_replay(&effect_slot.request.key())
        .ok_or(ChannelError::AuthorityVerification)?
        .clone();
    Ok(VerifiedChannelCancellationAdvanceV1 {
        current_view: advance.current().clone(),
        batch: advance.batch().clone(),
        lifecycle,
        escrow,
        effect_slot,
        request_replay,
        evidence,
        reservation_digest: reservation.artifact().digest()?,
    })
}

fn exact_transition<'a>(
    batch: &'a EconomicStateBatchV1,
    resource_key: &EconomicResourceKeyV1,
) -> Result<&'a EconomicStateTransitionV1, ChannelError> {
    batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key == *resource_key)
        .ok_or(ChannelError::AuthorityVerification)
}

fn decode_head<T: DeserializeOwned>(head: &EconomicResourceHeadV1) -> Result<T, ChannelError> {
    decode_content(&head.state)
}

fn decode_content<T: DeserializeOwned>(content: &EconomicContentV1) -> Result<T, ChannelError> {
    let EconomicContentV1::Inline { value } = content else {
        return Err(ChannelError::AuthorityVerification);
    };
    serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)
}

fn rejected_batch(batch: &EconomicStateBatchV1) -> EconomicStateAnchorError {
    match batch.transitions.first() {
        Some(transition) => {
            EconomicStateAnchorError::TransitionProofRejected(transition.resource_key.clone())
        }
        None => {
            EconomicStateAnchorError::InvalidView("channel cancellation batch has no transition")
        }
    }
}
