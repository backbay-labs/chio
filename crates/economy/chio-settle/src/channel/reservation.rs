use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicContentV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicRequestReplayV1, EconomicResourceHeadV1, EconomicResourceKeyV1,
    VerifiedEconomicStateView,
};
use serde::{Deserialize, Serialize};

use super::state::next_sequence;
use super::validation::{
    digest, parse_base_units, validate_currency, validate_digest, validate_positive, validate_text,
};
use super::{
    ChannelError, ChannelEscrowReservationStatusV1, ChannelLifecycleStatusV1, ChannelOpenTrustV1,
    ChannelSignatureV1, VerifiedAdmittedChannelOpenV1, VerifiedChannelLifecycleSnapshotV1,
    VerifiedChannelStateV1, CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
    CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
};

pub const CHANNEL_RESERVATION_SCHEMA: &str = "chio.channel.reservation.v1";

const CHANNEL_RESERVATION_ID_DOMAIN: &[u8] = b"chio.channel.reservation.id.v1\0";
const CHANNEL_RESERVATION_PROPOSAL_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.reservation-proposal.digest.v1\0";
const CHANNEL_RESERVATION_DIGEST_DOMAIN: &[u8] = b"chio.channel.reservation.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReservationBodyV1 {
    pub schema: String,
    pub reservation_id: String,
    pub channel_id: String,
    pub open_digest: String,
    pub request_id: String,
    pub operation_id: String,
    pub next_sequence: u64,
    pub prior_state_digest: String,
    pub service_binding_digest: String,
    pub receipt_authority_digest: String,
    pub maximum_charge: MonetaryAmount,
    pub maximum_token_base_units: String,
    pub expires_at_unix_ms: u64,
    pub disposition_expected_version: u64,
    pub channel_state_expected_version: u64,
    pub lifecycle_fence: u64,
}

impl ChannelReservationBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_RESERVATION_SCHEMA {
            return Err(ChannelError::InvalidField("channel_reservation_schema"));
        }
        for (field, value) in [
            ("reservation_id", &self.reservation_id),
            ("reservation_channel_id", &self.channel_id),
            ("reservation_open_digest", &self.open_digest),
            ("reservation_prior_state_digest", &self.prior_state_digest),
            (
                "reservation_service_binding_digest",
                &self.service_binding_digest,
            ),
            (
                "reservation_receipt_authority_digest",
                &self.receipt_authority_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        validate_text("reservation_request_id", &self.request_id)?;
        validate_digest("reservation_operation_id", &self.operation_id)?;
        validate_currency(&self.maximum_charge.currency)?;
        for (field, value) in [
            ("reservation_next_sequence", self.next_sequence),
            ("reservation_maximum_charge", self.maximum_charge.units),
            ("reservation_expiry", self.expires_at_unix_ms),
            (
                "reservation_disposition_version",
                self.disposition_expected_version,
            ),
            (
                "reservation_channel_state_version",
                self.channel_state_expected_version,
            ),
            ("reservation_lifecycle_fence", self.lifecycle_fence),
        ] {
            validate_positive(field, value)?;
        }
        if parse_base_units(&self.maximum_token_base_units)? == 0 {
            return Err(ChannelError::InvalidField(
                "reservation_maximum_token_base_units",
            ));
        }
        if self.disposition_expected_version != 1 {
            return Err(ChannelError::InvalidField(
                "reservation_disposition_version",
            ));
        }
        Ok(())
    }

    pub fn proposal_digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(CHANNEL_RESERVATION_PROPOSAL_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelReservationV1 {
    pub body: ChannelReservationBodyV1,
    pub payer_signature: ChannelSignatureV1,
    pub authority_signature: ChannelSignatureV1,
}

impl SignedChannelReservationV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(CHANNEL_RESERVATION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelReservationProposalV1 {
    reservation: SignedChannelReservationV1,
    accepted_at_unix_ms: u64,
    settlement_authority_scope_id: String,
    escrow_reference: super::ChannelEscrowReferenceV1,
}

impl VerifiedChannelReservationProposalV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelReservationV1 {
        &self.reservation
    }

    #[must_use]
    pub const fn accepted_at_unix_ms(&self) -> u64 {
        self.accepted_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReservationAuthorityV1 {
    pub authority_id: String,
    pub authority_key_epoch: u64,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub authority_key: PublicKey,
    pub trusted_time_unix_ms: u64,
}

impl ChannelReservationAuthorityV1 {
    pub(super) fn validate(&self) -> Result<(), ChannelError> {
        validate_text("channel_authority_id", &self.authority_id)?;
        validate_positive("channel_authority_key_epoch", self.authority_key_epoch)?;
        validate_positive("channel_authority_trusted_time", self.trusted_time_unix_ms)
    }
}

pub fn derive_channel_reservation_id(
    channel_id: &str,
    open_digest: &str,
    request_id: &str,
    next_sequence: u64,
    prior_state_digest: &str,
) -> Result<String, ChannelError> {
    validate_digest("reservation_channel_id", channel_id)?;
    validate_digest("reservation_open_digest", open_digest)?;
    validate_text("reservation_request_id", request_id)?;
    validate_positive("reservation_next_sequence", next_sequence)?;
    validate_digest("reservation_prior_state_digest", prior_state_digest)?;
    digest(
        CHANNEL_RESERVATION_ID_DOMAIN,
        &(
            channel_id,
            open_digest,
            request_id,
            next_sequence,
            prior_state_digest,
        ),
    )
}

pub fn verify_channel_reservation_proposal(
    reservation: &SignedChannelReservationV1,
    open: &VerifiedAdmittedChannelOpenV1,
    prior: &VerifiedChannelStateV1,
    authority: &ChannelReservationAuthorityV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelReservationProposalV1, ChannelError> {
    let lifecycle = open.snapshot().lifecycle();
    let open = open.consent();
    let intent = open.intent();
    let open_artifact = open.artifact();
    let prior_digest = prior.digest()?;
    let prior = prior.body();
    reservation.body.validate()?;
    prior.validate()?;
    lifecycle.validate()?;
    authority.validate()?;
    trust.validate()?;
    let body = &reservation.body;
    reservation.payer_signature.verify(
        body,
        &trust.payer_id,
        trust.payer_key_epoch,
        &trust.payer_key,
    )?;
    reservation.authority_signature.verify(
        body,
        &authority.authority_id,
        authority.authority_key_epoch,
        &authority.authority_key,
    )?;
    let open_digest = open_artifact.digest()?;
    let expected_reservation_id = derive_channel_reservation_id(
        &body.channel_id,
        &open_digest,
        &body.request_id,
        body.next_sequence,
        &prior_digest,
    )?;
    let expected_sequence = next_sequence(prior.seq)?;
    let expected_asset_digest = intent.body.asset_binding.digest()?;
    let remaining = intent
        .body
        .bound
        .units
        .checked_sub(prior.cumulative_owed.units)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let channel_expiry_ms = intent
        .body
        .channel_expiry_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    intent
        .body
        .asset_binding
        .verify_round_trip(&body.maximum_charge, &body.maximum_token_base_units)?;
    intent
        .body
        .asset_binding
        .verify_round_trip(&prior.cumulative_owed, &prior.cumulative_token_base_units)?;
    if body.reservation_id != expected_reservation_id
        || body.channel_id != open_artifact.body.channel_id
        || body.channel_id != prior.channel_id
        || body.open_digest != open_digest
        || open_artifact.body.open_intent_digest != intent.digest()?
        || body.next_sequence != expected_sequence
        || body.prior_state_digest != prior_digest
        || body.maximum_charge.currency != intent.body.currency
        || body.maximum_charge.units > remaining
        || parse_base_units(&body.maximum_token_base_units)?
            > parse_base_units(&intent.body.bound_token_base_units)?
        || prior.cumulative_owed.currency != intent.body.currency
        || prior.asset_binding_digest != expected_asset_digest
        || !trust.matches_intent(&intent.body)
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != body.channel_id
        || lifecycle.latest_state_digest != prior_digest
        || lifecycle.latest_sequence != prior.seq
        || lifecycle.state_version != body.channel_state_expected_version
        || lifecycle.lifecycle_fence != body.lifecycle_fence
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || body.expires_at_unix_ms <= authority.trusted_time_unix_ms
        || body.expires_at_unix_ms <= trust.trusted_time_unix_ms
        || body.expires_at_unix_ms > channel_expiry_ms
        || authority.trusted_time_unix_ms != trust.trusted_time_unix_ms
        || prior.seq == 0 && open_artifact.body.initial_state_digest != prior_digest
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelReservationProposalV1 {
        reservation: reservation.clone(),
        accepted_at_unix_ms: authority.trusted_time_unix_ms,
        settlement_authority_scope_id: intent.body.settlement_authority_scope_id.clone(),
        escrow_reference: intent.body.escrow_reference.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedAdmittedChannelReservationV1 {
    proposal: VerifiedChannelReservationProposalV1,
    snapshot: VerifiedChannelLifecycleSnapshotV1,
    ready_effect: EconomicEffectSlotV1,
    ready_effect_head_digest: String,
}

impl VerifiedAdmittedChannelReservationV1 {
    #[must_use]
    pub const fn proposal(&self) -> &VerifiedChannelReservationProposalV1 {
        &self.proposal
    }

    #[must_use]
    pub const fn snapshot(&self) -> &VerifiedChannelLifecycleSnapshotV1 {
        &self.snapshot
    }

    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelReservationV1 {
        self.proposal.artifact()
    }

    #[must_use]
    pub const fn accepted_at_unix_ms(&self) -> u64 {
        self.proposal.accepted_at_unix_ms()
    }

    #[must_use]
    pub const fn ready_effect(&self) -> &EconomicEffectSlotV1 {
        &self.ready_effect
    }

    #[must_use]
    pub fn ready_effect_head_digest(&self) -> &str {
        &self.ready_effect_head_digest
    }
}

pub fn verify_admitted_channel_reservation(
    proposal: &VerifiedChannelReservationProposalV1,
    prepared: &super::VerifiedChannelPreparedReservationV1,
    current: &VerifiedEconomicStateView,
) -> Result<VerifiedAdmittedChannelReservationV1, ChannelError> {
    let body = &proposal.artifact().body;
    let prepared_plan = prepared.prepared();
    let service = &prepared_plan.service;
    let prepared_current = prepared.current();
    let snapshot = super::verify_channel_lifecycle_snapshot(
        current,
        &proposal.settlement_authority_scope_id,
        &body.channel_id,
    )?;
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    let expected_state_version = body
        .channel_state_expected_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_fence = body
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let prior_sequence = body
        .next_sequence
        .checked_sub(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let ready_effect_head = exact_ready_effect_head(current, &body.operation_id)?;
    let ready_effect = decode_effect_head(ready_effect_head)?;
    ready_effect
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let reservation_digest = proposal.artifact().digest()?;
    let expected_idempotency_key = super::derive_channel_service_dispatch_idempotency_key(
        &body.operation_id,
        &body.reservation_id,
        body.next_sequence,
    )?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: proposal.settlement_authority_scope_id.clone(),
        resource_id: body.channel_id.clone(),
    };
    let ready_effect_head_digest = ready_effect_head
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let expected_replay = EconomicRequestReplayV1 {
        request: service.request.clone(),
        operation_id: body.operation_id.clone(),
        effect_slot_ids: vec![ready_effect.slot_id.clone()],
    };
    expected_replay
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let retained_replay = current
        .view()
        .request_replay(&service.request.key())
        .ok_or(ChannelError::AuthorityVerification)?;
    let prepared_snapshot = super::verify_channel_lifecycle_snapshot(
        prepared_current,
        &proposal.settlement_authority_scope_id,
        &body.channel_id,
    )?;
    let expected_channel_head_version = prepared_snapshot
        .channel_head()
        .head_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_escrow_head_version = prepared_snapshot
        .escrow_head()
        .head_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let authored_at_unix_ms = snapshot.channel_head().trusted_clock_high_water;
    if lifecycle.status != ChannelLifecycleStatusV1::Open
        || &prepared_plan.reservation != body
        || prepared_plan.signed_open.body.channel_id != body.channel_id
        || body.service_binding_digest != service.digest()?
        || current.view().checkpoint_sequence <= prepared_plan.checkpoint_sequence
        || current.view().checkpoint_digest == prepared_plan.checkpoint_digest
        || current.view().observed_at < prepared_plan.observed_at_unix_ms
        || prepared_snapshot.channel_head_digest() != prepared_plan.channel_head_digest
        || prepared_snapshot.escrow_head_digest() != prepared_plan.escrow_head_digest
        || snapshot.channel_head().predecessor_digest.as_deref()
            != Some(prepared_plan.channel_head_digest.as_str())
        || snapshot.escrow_head().predecessor_digest.as_deref()
            != Some(prepared_plan.escrow_head_digest.as_str())
        || snapshot.channel_head().head_version != expected_channel_head_version
        || snapshot.escrow_head().head_version != expected_escrow_head_version
        || lifecycle.latest_state_digest != body.prior_state_digest
        || lifecycle.latest_sequence != prior_sequence
        || lifecycle.state_version != expected_state_version
        || lifecycle.lifecycle_fence != expected_fence
        || lifecycle.live_reservation_id.as_deref() != Some(&body.reservation_id)
        || lifecycle.operation_id.as_deref() != Some(&body.operation_id)
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.open_digest != body.open_digest
        || escrow.escrow_reference != proposal.escrow_reference
        || snapshot.escrow_head().trusted_clock_high_water != authored_at_unix_ms
        || ready_effect_head.trusted_clock_high_water != authored_at_unix_ms
        || authored_at_unix_ms < proposal.accepted_at_unix_ms
        || authored_at_unix_ms < prepared_plan.observed_at_unix_ms
        || authored_at_unix_ms > snapshot.observed_at_unix_ms()
        || snapshot.observed_at_unix_ms() < proposal.accepted_at_unix_ms
        || snapshot.observed_at_unix_ms() >= body.expires_at_unix_ms
        || ready_effect.anchor_id != current.view().anchor_id
        || ready_effect.namespace != current.view().namespace
        || ready_effect.operation_id != body.operation_id
        || ready_effect.effect_kind != CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
        || ready_effect.request != service.request
        || ready_effect.request.request_id != body.request_id
        || ready_effect.admission_handoff != service.admission_handoff
        || ready_effect.target != service.provider
        || ready_effect.action_digest != service.action_digest
        || ready_effect.resource_key != channel_key
        || ready_effect.resource_head_digest != snapshot.channel_head_digest()
        || ready_effect.admission_handoff.state
            != EconomicAdmissionHandoffStateV1::DispatchCommitted
        || ready_effect.parameters_digest != reservation_digest
        || ready_effect.idempotency_key != expected_idempotency_key
        || ready_effect.frost.is_some()
        || ready_effect.state != EconomicEffectStateV1::Ready
        || ready_effect.terminal.is_some()
        || ready_effect_head.resource_key != ready_effect.resource_head_key()
        || ready_effect_head.head_version != 1
        || ready_effect_head.resource_version != 1
        || ready_effect_head.lifecycle_fence != 1
        || ready_effect_head.lifecycle_state != "ready"
        || ready_effect_head.operation_id.as_deref() != Some(body.operation_id.as_str())
        || ready_effect_head.effect_idempotency_key.as_deref()
            != Some(expected_idempotency_key.as_str())
        || ready_effect_head.frost.is_some()
        || ready_effect_head.terminal_result.is_some()
        || ready_effect_head.predecessor_digest.is_some()
        || retained_replay != &expected_replay
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedAdmittedChannelReservationV1 {
        proposal: proposal.clone(),
        snapshot,
        ready_effect,
        ready_effect_head_digest,
    })
}

fn exact_ready_effect_head<'a>(
    current: &'a VerifiedEconomicStateView,
    operation_id: &str,
) -> Result<&'a EconomicResourceHeadV1, ChannelError> {
    let mut matches = current.view().heads.iter().filter(|head| {
        head.resource_key.resource_family == "effect_slot"
            && head.operation_id.as_deref() == Some(operation_id)
    });
    let head = matches.next().ok_or(ChannelError::AuthorityVerification)?;
    if matches.next().is_some() {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(head)
}

fn decode_effect_head(head: &EconomicResourceHeadV1) -> Result<EconomicEffectSlotV1, ChannelError> {
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ChannelError::AuthorityVerification);
    };
    serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)
}

#[cfg(test)]
mod proposal_digest_tests {
    use super::*;

    fn body() -> ChannelReservationBodyV1 {
        ChannelReservationBodyV1 {
            schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
            reservation_id: "11".repeat(32),
            channel_id: "22".repeat(32),
            open_digest: "33".repeat(32),
            request_id: "request-1".to_owned(),
            operation_id: "44".repeat(32),
            next_sequence: 1,
            prior_state_digest: "55".repeat(32),
            service_binding_digest: "66".repeat(32),
            receipt_authority_digest: "77".repeat(32),
            maximum_charge: MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            },
            maximum_token_base_units: "10000000".to_owned(),
            expires_at_unix_ms: 2_000,
            disposition_expected_version: 1,
            channel_state_expected_version: 1,
            lifecycle_fence: 2,
        }
    }

    #[test]
    fn reservation_proposal_digest_binds_the_unsigned_body() -> Result<(), ChannelError> {
        let proposal = body();
        let digest = proposal.proposal_digest()?;
        let mut substituted = proposal;
        substituted.maximum_charge.units += 1;

        assert_ne!(digest, substituted.proposal_digest()?);
        Ok(())
    }
}
