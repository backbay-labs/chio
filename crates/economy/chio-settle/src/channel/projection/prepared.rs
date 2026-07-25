use chio_core::economic_continuity::{
    EconomicActionAuthorizationV1, EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
    EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1,
    EconomicPreparedEffectV1, EconomicRequestBindingV1, EconomicRequestReplayV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateTransitionV1,
    CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
};
use serde::{Deserialize, Serialize};

use super::super::state::next_sequence;
use super::super::validation::{
    digest, parse_base_units, validate_digest, validate_positive, validate_text,
};
use super::super::{
    derive_channel_reservation_id, derive_channel_service_dispatch_idempotency_key,
    verify_channel_lifecycle_snapshot, ChannelError, ChannelEscrowReservationStatusV1,
    ChannelEscrowReservationViewV1, ChannelLifecycleStatusV1, ChannelLifecycleViewV1,
    ChannelReservationBodyV1, ChannelStateBodyV1, SignedChannelOpenIntentV1, SignedChannelOpenV1,
    SignedChannelStateV1, VerifiedAdmittedChannelOpenV1, VerifiedChannelReservationProposalV1,
    VerifiedChannelStateV1, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    CHANNEL_LIFECYCLE_RESOURCE_FAMILY, CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
};
use super::{
    head_digest, successor_head, transition, ChannelLifecycleProjectionV1, SuccessorHeadBinding,
};

pub const CHANNEL_PREPARED_RESERVATION_SCHEMA: &str = "chio.channel.prepared-reservation.v1";

const CHANNEL_SERVICE_BINDING_DIGEST_DOMAIN: &[u8] = b"chio.channel.service-binding.digest.v1\0";
const CHANNEL_PREPARED_RESERVATION_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.prepared-reservation.digest.v1\0";
const CHANNEL_RESERVATION_TRANSITION_PROOF_SCHEMA: &str =
    "chio.channel.reservation-transition-proof.v1";
const CHANNEL_RESERVATION_TRANSITION_PROOF_DOMAIN: &[u8] =
    b"chio.channel.reservation-transition-proof.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelServiceBindingV1 {
    pub request: EconomicRequestBindingV1,
    pub admission_handoff: EconomicAdmissionHandoffV1,
    pub provider: EconomicEffectTargetV1,
    pub action_digest: String,
}

impl ChannelServiceBindingV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        self.request
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        self.admission_handoff
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        self.provider
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        validate_digest("channel_service_action_digest", &self.action_digest)?;
        if self.admission_handoff.state != EconomicAdmissionHandoffStateV1::DispatchCommitted {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(CHANNEL_SERVICE_BINDING_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stateKind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetainedChannelStateV1 {
    Initial { body: Box<ChannelStateBodyV1> },
    Signed { state: Box<SignedChannelStateV1> },
}

impl RetainedChannelStateV1 {
    pub(super) fn from_verified(state: &VerifiedChannelStateV1) -> Self {
        match state.payee_signature() {
            Some(payee_signature) => Self::Signed {
                state: Box::new(SignedChannelStateV1 {
                    body: state.body().clone(),
                    payee_signature: payee_signature.clone(),
                }),
            },
            None => Self::Initial {
                body: Box::new(state.body().clone()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPreparedReservationV1 {
    pub schema: String,
    pub signed_open_intent: SignedChannelOpenIntentV1,
    pub signed_open: SignedChannelOpenV1,
    pub prior_state: RetainedChannelStateV1,
    pub reservation: ChannelReservationBodyV1,
    pub service: ChannelServiceBindingV1,
    pub lifecycle: ChannelLifecycleViewV1,
    pub escrow: ChannelEscrowReservationViewV1,
    pub channel_head_digest: String,
    pub escrow_head_digest: String,
    pub anchor_id: String,
    pub namespace: String,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub observed_at_unix_ms: u64,
}

impl ChannelPreparedReservationV1 {
    #[must_use]
    pub const fn reservation(&self) -> &ChannelReservationBodyV1 {
        &self.reservation
    }

    #[must_use]
    pub const fn service(&self) -> &ChannelServiceBindingV1 {
        &self.service
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        if self.schema != CHANNEL_PREPARED_RESERVATION_SCHEMA {
            return Err(ChannelError::InvalidField(
                "channel_prepared_reservation_schema",
            ));
        }
        self.signed_open_intent.digest()?;
        self.signed_open.digest()?;
        match &self.prior_state {
            RetainedChannelStateV1::Initial { body } => body.validate()?,
            RetainedChannelStateV1::Signed { state } => {
                state.digest()?;
            }
        }
        self.reservation.validate()?;
        self.service.validate()?;
        self.lifecycle.validate()?;
        self.escrow.validate()?;
        validate_digest(
            "channel_prepared_channel_head_digest",
            &self.channel_head_digest,
        )?;
        validate_digest(
            "channel_prepared_escrow_head_digest",
            &self.escrow_head_digest,
        )?;
        validate_text("channel_prepared_anchor_id", &self.anchor_id)?;
        validate_text("channel_prepared_namespace", &self.namespace)?;
        validate_positive(
            "channel_prepared_checkpoint_sequence",
            self.checkpoint_sequence,
        )?;
        validate_digest(
            "channel_prepared_checkpoint_digest",
            &self.checkpoint_digest,
        )?;
        validate_positive("channel_prepared_observed_at", self.observed_at_unix_ms)?;
        digest(CHANNEL_PREPARED_RESERVATION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelPreparedReservationV1 {
    prepared: ChannelPreparedReservationV1,
    open: VerifiedAdmittedChannelOpenV1,
    prior: VerifiedChannelStateV1,
    current: chio_core::economic_continuity::VerifiedEconomicStateView,
}

impl VerifiedChannelPreparedReservationV1 {
    #[must_use]
    pub const fn prepared(&self) -> &ChannelPreparedReservationV1 {
        &self.prepared
    }

    pub(crate) const fn current(
        &self,
    ) -> &chio_core::economic_continuity::VerifiedEconomicStateView {
        &self.current
    }
}

pub fn prepare_channel_reservation(
    open: &VerifiedAdmittedChannelOpenV1,
    prior: &VerifiedChannelStateV1,
    current: &chio_core::economic_continuity::VerifiedEconomicStateView,
    reservation: ChannelReservationBodyV1,
    service: ChannelServiceBindingV1,
) -> Result<ChannelPreparedReservationV1, ChannelError> {
    let snapshot = verify_channel_lifecycle_snapshot(
        current,
        &open.consent().intent().body.settlement_authority_scope_id,
        &open.consent().artifact().body.channel_id,
    )?;
    let prepared = ChannelPreparedReservationV1 {
        schema: CHANNEL_PREPARED_RESERVATION_SCHEMA.to_owned(),
        signed_open_intent: open.consent().intent().clone(),
        signed_open: open.consent().artifact().clone(),
        prior_state: RetainedChannelStateV1::from_verified(prior),
        reservation,
        service,
        lifecycle: snapshot.lifecycle().clone(),
        escrow: snapshot.escrow().clone(),
        channel_head_digest: snapshot.channel_head_digest().to_owned(),
        escrow_head_digest: snapshot.escrow_head_digest().to_owned(),
        anchor_id: current.view().anchor_id.clone(),
        namespace: current.view().namespace.clone(),
        checkpoint_sequence: current.view().checkpoint_sequence,
        checkpoint_digest: current.view().checkpoint_digest.clone(),
        observed_at_unix_ms: current.view().observed_at,
    };
    validate_prepared(
        &prepared,
        open,
        prior,
        current,
        &prepared.reservation,
        &prepared.service,
    )?;
    Ok(prepared)
}

pub fn verify_channel_prepared_reservation(
    prepared: &ChannelPreparedReservationV1,
    open: &VerifiedAdmittedChannelOpenV1,
    prior: &VerifiedChannelStateV1,
    current: &chio_core::economic_continuity::VerifiedEconomicStateView,
    expected_reservation: &ChannelReservationBodyV1,
    expected_service: &ChannelServiceBindingV1,
) -> Result<VerifiedChannelPreparedReservationV1, ChannelError> {
    validate_prepared(
        prepared,
        open,
        prior,
        current,
        expected_reservation,
        expected_service,
    )?;
    Ok(VerifiedChannelPreparedReservationV1 {
        prepared: prepared.clone(),
        open: open.clone(),
        prior: prior.clone(),
        current: current.clone(),
    })
}

fn validate_prepared(
    prepared: &ChannelPreparedReservationV1,
    open: &VerifiedAdmittedChannelOpenV1,
    prior: &VerifiedChannelStateV1,
    current: &chio_core::economic_continuity::VerifiedEconomicStateView,
    expected_reservation: &ChannelReservationBodyV1,
    expected_service: &ChannelServiceBindingV1,
) -> Result<(), ChannelError> {
    let consent = open.consent();
    let intent = consent.intent();
    let open_artifact = consent.artifact();
    let body = &prepared.reservation;
    body.validate()?;
    prepared.service.validate()?;
    expected_reservation.validate()?;
    expected_service.validate()?;
    let snapshot = verify_channel_lifecycle_snapshot(
        current,
        &intent.body.settlement_authority_scope_id,
        &open_artifact.body.channel_id,
    )?;
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    let open_digest = open_artifact.digest()?;
    let prior_digest = prior.digest()?;
    let expected_sequence = next_sequence(prior.body().seq)?;
    let expected_reservation_id = derive_channel_reservation_id(
        &body.channel_id,
        &open_digest,
        &body.request_id,
        body.next_sequence,
        &prior_digest,
    )?;
    let remaining = intent
        .body
        .bound
        .units
        .checked_sub(prior.body().cumulative_owed.units)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let channel_expiry_unix_ms = intent
        .body
        .channel_expiry_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    intent
        .body
        .asset_binding
        .verify_round_trip(&body.maximum_charge, &body.maximum_token_base_units)?;
    intent.body.asset_binding.verify_round_trip(
        &prior.body().cumulative_owed,
        &prior.body().cumulative_token_base_units,
    )?;
    if prepared.schema != CHANNEL_PREPARED_RESERVATION_SCHEMA
        || &prepared.signed_open_intent != intent
        || &prepared.signed_open != open_artifact
        || prepared.prior_state != RetainedChannelStateV1::from_verified(prior)
        || body != expected_reservation
        || &prepared.service != expected_service
        || &prepared.lifecycle != lifecycle
        || &prepared.escrow != escrow
        || prepared.channel_head_digest != snapshot.channel_head_digest()
        || prepared.escrow_head_digest != snapshot.escrow_head_digest()
        || prepared.anchor_id != current.view().anchor_id
        || prepared.namespace != current.view().namespace
        || prepared.checkpoint_sequence != current.view().checkpoint_sequence
        || prepared.checkpoint_digest != current.view().checkpoint_digest
        || prepared.observed_at_unix_ms != current.view().observed_at
        || snapshot.channel_head() != open.snapshot().channel_head()
        || snapshot.escrow_head() != open.snapshot().escrow_head()
        || body.reservation_id != expected_reservation_id
        || body.channel_id != open_artifact.body.channel_id
        || body.open_digest != open_digest
        || open_artifact.body.open_intent_digest != intent.digest()?
        || body.request_id != prepared.service.request.request_id
        || body.service_binding_digest != prepared.service.digest()?
        || body.next_sequence != expected_sequence
        || body.prior_state_digest != prior_digest
        || body.maximum_charge.currency != intent.body.currency
        || body.maximum_charge.units > remaining
        || parse_base_units(&body.maximum_token_base_units)?
            > parse_base_units(&intent.body.bound_token_base_units)?
        || prior.body().cumulative_owed.currency != intent.body.currency
        || prior.body().asset_binding_digest != intent.body.asset_binding.digest()?
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.latest_state_digest != prior_digest
        || lifecycle.latest_sequence != prior.body().seq
        || lifecycle.state_version != body.channel_state_expected_version
        || lifecycle.lifecycle_fence != body.lifecycle_fence
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.open_digest != open_digest
        || escrow.escrow_reference != intent.body.escrow_reference
        || body.expires_at_unix_ms <= current.view().observed_at
        || body.expires_at_unix_ms > channel_expiry_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelReservationTransitionProofV1 {
    schema: String,
    open_intent_digest: String,
    open_digest: String,
    prior_state_digest: String,
    reservation_proposal_digest: String,
    reservation_digest: String,
    operation_id: String,
    request: EconomicRequestBindingV1,
    provider: EconomicEffectTargetV1,
    source_checkpoint_digest: String,
    source_channel_head_digest: String,
    source_escrow_head_digest: String,
    terminal_channel_head_digest: String,
    terminal_escrow_head_digest: String,
    ready_effect_digest: String,
    ready_effect_head_digest: String,
    issued_at: u64,
}

impl ChannelReservationTransitionProofV1 {
    fn digest(&self) -> Result<String, ChannelError> {
        digest(CHANNEL_RESERVATION_TRANSITION_PROOF_DOMAIN, self)
    }
}

pub fn compose_channel_reservation_transition(
    verified: &VerifiedChannelPreparedReservationV1,
    proposal: &VerifiedChannelReservationProposalV1,
    issued_at: u64,
) -> Result<ChannelLifecycleProjectionV1, ChannelError> {
    let prepared = &verified.prepared;
    let body = &prepared.reservation;
    if &proposal.artifact().body != body
        || issued_at < proposal.accepted_at_unix_ms()
        || issued_at < verified.current.view().observed_at
        || issued_at >= body.expires_at_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    validate_prepared(
        prepared,
        &verified.open,
        &verified.prior,
        &verified.current,
        body,
        &prepared.service,
    )?;
    let lifecycle = &prepared.lifecycle;
    let escrow = &prepared.escrow;
    let lifecycle_fence = lifecycle
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let state_version = lifecycle
        .state_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let escrow_version = escrow
        .version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let reserved_lifecycle = ChannelLifecycleViewV1 {
        state_version,
        lifecycle_fence,
        live_reservation_id: Some(body.reservation_id.clone()),
        operation_id: Some(body.operation_id.clone()),
        ..lifecycle.clone()
    };
    let reserved_escrow = ChannelEscrowReservationViewV1 {
        version: escrow_version,
        lifecycle_fence,
        ..escrow.clone()
    };
    reserved_lifecycle.validate()?;
    reserved_escrow.validate()?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: prepared
            .signed_open_intent
            .body
            .settlement_authority_scope_id
            .clone(),
        resource_id: body.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: prepared
            .signed_open_intent
            .body
            .settlement_authority_scope_id
            .clone(),
        resource_id: body.channel_id.clone(),
    };
    let current_channel_head = verified
        .current
        .view()
        .head(&channel_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let current_escrow_head = verified
        .current
        .view()
        .head(&escrow_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let idempotency_key = derive_channel_service_dispatch_idempotency_key(
        &body.operation_id,
        &body.reservation_id,
        body.next_sequence,
    )?;
    let next_channel_head = successor_head(
        current_channel_head,
        &reserved_lifecycle,
        SuccessorHeadBinding {
            resource_version: state_version,
            lifecycle_fence,
            lifecycle_state: "open",
            operation_id: Some(body.operation_id.clone()),
            effect_idempotency_key: Some(idempotency_key.clone()),
            terminal_result: None,
        },
        issued_at,
    )?;
    let next_escrow_head = successor_head(
        current_escrow_head,
        &reserved_escrow,
        SuccessorHeadBinding {
            resource_version: escrow_version,
            lifecycle_fence,
            lifecycle_state: "open",
            operation_id: Some(body.operation_id.clone()),
            effect_idempotency_key: Some(idempotency_key.clone()),
            terminal_result: None,
        },
        issued_at,
    )?;
    let reservation_digest = proposal.artifact().digest()?;
    let mut ready_effect = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: verified.current.view().anchor_id.clone(),
        namespace: verified.current.view().namespace.clone(),
        resource_key: channel_key.clone(),
        operation_id: body.operation_id.clone(),
        effect_kind: CHANNEL_SERVICE_DISPATCH_EFFECT_KIND.to_owned(),
        request: prepared.service.request.clone(),
        admission_handoff: prepared.service.admission_handoff.clone(),
        target: prepared.service.provider.clone(),
        action_digest: prepared.service.action_digest.clone(),
        parameters_digest: reservation_digest.clone(),
        resource_head_digest: head_digest(&next_channel_head)?,
        frost: None,
        idempotency_key: idempotency_key.clone(),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    ready_effect.slot_id = ready_effect
        .recompute_slot_id()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    ready_effect
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let ready_effect_digest = ready_effect
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let ready_effect_head = ready_effect_head(&ready_effect, issued_at)?;
    let request_replay = EconomicRequestReplayV1 {
        request: ready_effect.request.clone(),
        operation_id: body.operation_id.clone(),
        effect_slot_ids: vec![ready_effect.slot_id.clone()],
    };
    request_replay
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let source_channel_head_digest = head_digest(current_channel_head)?;
    let source_escrow_head_digest = head_digest(current_escrow_head)?;
    let proof = ChannelReservationTransitionProofV1 {
        schema: CHANNEL_RESERVATION_TRANSITION_PROOF_SCHEMA.to_owned(),
        open_intent_digest: prepared.signed_open_intent.digest()?,
        open_digest: prepared.signed_open.digest()?,
        prior_state_digest: verified.prior.digest()?,
        reservation_proposal_digest: body.proposal_digest()?,
        reservation_digest,
        operation_id: body.operation_id.clone(),
        request: ready_effect.request.clone(),
        provider: ready_effect.target.clone(),
        source_checkpoint_digest: verified.current.view().checkpoint_digest.clone(),
        source_channel_head_digest: source_channel_head_digest.clone(),
        source_escrow_head_digest: source_escrow_head_digest.clone(),
        terminal_channel_head_digest: head_digest(&next_channel_head)?,
        terminal_escrow_head_digest: head_digest(&next_escrow_head)?,
        ready_effect_digest: ready_effect_digest.clone(),
        ready_effect_head_digest: head_digest(&ready_effect_head)?,
        issued_at,
    };
    let proof_digest = proof.digest()?;
    let mut channel_transition = transition(
        channel_key,
        source_channel_head_digest,
        next_channel_head,
        &proof_digest,
    );
    channel_transition.prepared_effect = Some(EconomicPreparedEffectV1 {
        operation_id: body.operation_id.clone(),
        action_digest: ready_effect.action_digest.clone(),
        effect_slot_id: ready_effect.slot_id.clone(),
        effect_slot_digest: ready_effect_digest,
        authorization: EconomicActionAuthorizationV1::Direct,
    });
    let mut transitions = vec![
        channel_transition,
        transition(
            escrow_key,
            source_escrow_head_digest,
            next_escrow_head,
            &proof_digest,
        ),
        EconomicStateTransitionV1 {
            resource_key: ready_effect.resource_head_key(),
            expected_head_digest: None,
            next_head: ready_effect_head,
            transition_proof_digest: proof_digest.clone(),
            prepared_effect: None,
        },
    ];
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    Ok(ChannelLifecycleProjectionV1 {
        current: verified.current.clone(),
        proof_digest,
        transitions,
        effect_slots: vec![ready_effect],
        request_replays: vec![request_replay],
        operation_id: body.operation_id.clone(),
        issued_at,
        not_after_unix_ms: Some(body.expires_at_unix_ms),
    })
}

fn ready_effect_head(
    effect: &EconomicEffectSlotV1,
    issued_at: u64,
) -> Result<EconomicResourceHeadV1, ChannelError> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(effect)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: effect.anchor_id.clone(),
        namespace: effect.namespace.clone(),
        resource_key: effect.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        state,
        operation_id: Some(effect.operation_id.clone()),
        effect_idempotency_key: Some(effect.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: issued_at,
        predecessor_digest: None,
    };
    head.validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(head)
}
