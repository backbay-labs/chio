use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::economic_continuity::EconomicFrostBindingV1;
#[cfg(test)]
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicEffectSlotV1, EconomicEffectStateV1,
};
use chio_core::signed_artifact::CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA;
use chio_federation::frost::VerifiedFrostAuthorization;
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, parse_base_units, validate_digest, validate_positive, validate_text,
};
use super::{
    channel_close_frost_action, ChannelCloseKindV1, ChannelError, ChannelEscrowReferenceV1,
    VerifiedEffectiveChannelCloseV1,
};

const CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.release-authorization.digest.v1\0";
const SIGNED_CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.release-authorization.signed-digest.v1\0";

pub const CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND: &str = "channel_release_root_publication";
pub const CHANNEL_RELEASE_BROADCAST_EFFECT_KIND: &str = "channel_release_broadcast";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReleaseAuthorizationBindingV1 {
    channel_id: String,
    escrow_reference: ChannelEscrowReferenceV1,
    open_digest: String,
    close_digest: String,
    close_body_digest: String,
    effective_close_digest: String,
    final_state_digest: String,
    final_state_sequence: u64,
    final_cumulative_owed: MonetaryAmount,
    channel_state_version: u64,
    escrow_reservation_version: u64,
    lifecycle_fence: u64,
    bound_token_base_units: String,
    expected_release_token_base_units: String,
    expected_refund_token_base_units: String,
    asset_binding_digest: String,
    original_web3_dispatch_digest: String,
    original_operator: String,
    original_operator_key_hash: String,
    payee_beneficiary_address: String,
    channel_expiry_unix_ms: u64,
    dispute_deadline_unix_ms: u64,
    close_submission_cutoff_unix_ms: u64,
    escrow_deadline_unix_ms: u64,
    publisher_fence: u64,
    authorized_at_unix_ms: u64,
    frost: EconomicFrostBindingV1,
    frost_scope_id: String,
    frost_resource_id: String,
    frost_resource_version: u64,
    frost_resource_fence: u64,
    frost_roster_digest: String,
    frost_key_epoch: u64,
    frost_issued_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReleaseMutationBindingV1 {
    pub operation_id: String,
    pub effect_slot_id: String,
    pub scope_id: String,
    pub effect_kind: String,
    pub idempotency_key: String,
    pub call_digest: String,
    pub resource_head_digest: String,
}

impl ChannelReleaseMutationBindingV1 {
    fn validate(&self, expected_effect_kind: &'static str) -> Result<(), ChannelError> {
        for (field, value) in [
            ("release_operation_id", &self.operation_id),
            ("release_effect_slot_id", &self.effect_slot_id),
            ("release_idempotency_key", &self.idempotency_key),
            ("release_call_digest", &self.call_digest),
            ("release_resource_head_digest", &self.resource_head_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_text("release_effect_scope_id", &self.scope_id)?;
        validate_text("release_effect_kind", &self.effect_kind)?;
        if self.effect_kind != expected_effect_kind {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReleaseAuthorizationBodyV1 {
    pub schema: String,
    pub authority: ChannelReleaseAuthorizationBindingV1,
    pub publication_root: String,
    pub root_publication: ChannelReleaseMutationBindingV1,
    pub release_broadcast: ChannelReleaseMutationBindingV1,
}

impl ChannelReleaseAuthorizationBodyV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA {
            return Err(ChannelError::InvalidField("release_authorization_schema"));
        }
        validate_digest("release_publication_root", &self.publication_root)?;
        self.root_publication
            .validate(CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND)?;
        self.release_broadcast
            .validate(CHANNEL_RELEASE_BROADCAST_EFFECT_KIND)?;
        if self.root_publication.operation_id == self.release_broadcast.operation_id
            || self.root_publication.effect_slot_id == self.release_broadcast.effect_slot_id
            || self.root_publication.idempotency_key == self.release_broadcast.idempotency_key
            || self.root_publication.call_digest == self.release_broadcast.call_digest
            || self.root_publication.scope_id != self.authority.frost_scope_id
            || self.release_broadcast.scope_id != self.authority.frost_scope_id
        {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }

    #[must_use]
    pub fn authority(&self) -> &ChannelReleaseAuthorizationBindingV1 {
        &self.authority
    }

    #[must_use]
    pub fn publication_root(&self) -> &str {
        &self.publication_root
    }

    #[must_use]
    pub fn root_publication(&self) -> &ChannelReleaseMutationBindingV1 {
        &self.root_publication
    }

    #[must_use]
    pub fn release_broadcast(&self) -> &ChannelReleaseMutationBindingV1 {
        &self.release_broadcast
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelReleaseAuthorizationV1 {
    pub body: ChannelReleaseAuthorizationBodyV1,
    pub publisher_signature: super::ChannelSignatureV1,
}

impl SignedChannelReleaseAuthorizationV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(SIGNED_CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReleasePublisherTrustV1 {
    pub publisher_id: String,
    pub publisher_key_epoch: u64,
    pub publisher_key: PublicKey,
}

impl ChannelReleasePublisherTrustV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_text("release_publisher_id", &self.publisher_id)?;
        validate_positive("release_publisher_key_epoch", self.publisher_key_epoch)
    }
}

impl ChannelReleaseAuthorizationBindingV1 {
    #[must_use]
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    #[must_use]
    pub fn escrow_reference(&self) -> &ChannelEscrowReferenceV1 {
        &self.escrow_reference
    }

    #[must_use]
    pub fn open_digest(&self) -> &str {
        &self.open_digest
    }

    #[must_use]
    pub fn close_digest(&self) -> &str {
        &self.close_digest
    }

    #[must_use]
    pub fn close_body_digest(&self) -> &str {
        &self.close_body_digest
    }

    #[must_use]
    pub fn effective_close_digest(&self) -> &str {
        &self.effective_close_digest
    }

    #[must_use]
    pub fn final_state_digest(&self) -> &str {
        &self.final_state_digest
    }

    #[must_use]
    pub const fn final_state_sequence(&self) -> u64 {
        self.final_state_sequence
    }

    #[must_use]
    pub const fn final_cumulative_owed(&self) -> &MonetaryAmount {
        &self.final_cumulative_owed
    }

    #[must_use]
    pub const fn channel_state_version(&self) -> u64 {
        self.channel_state_version
    }

    #[must_use]
    pub const fn escrow_reservation_version(&self) -> u64 {
        self.escrow_reservation_version
    }

    #[must_use]
    pub const fn lifecycle_fence(&self) -> u64 {
        self.lifecycle_fence
    }

    #[must_use]
    pub fn bound_token_base_units(&self) -> &str {
        &self.bound_token_base_units
    }

    #[must_use]
    pub fn expected_release_token_base_units(&self) -> &str {
        &self.expected_release_token_base_units
    }

    #[must_use]
    pub fn expected_refund_token_base_units(&self) -> &str {
        &self.expected_refund_token_base_units
    }

    #[must_use]
    pub fn asset_binding_digest(&self) -> &str {
        &self.asset_binding_digest
    }

    #[must_use]
    pub fn original_web3_dispatch_digest(&self) -> &str {
        &self.original_web3_dispatch_digest
    }

    #[must_use]
    pub fn original_operator(&self) -> &str {
        &self.original_operator
    }

    #[must_use]
    pub fn original_operator_key_hash(&self) -> &str {
        &self.original_operator_key_hash
    }

    #[must_use]
    pub fn payee_beneficiary_address(&self) -> &str {
        &self.payee_beneficiary_address
    }

    #[must_use]
    pub const fn channel_expiry_unix_ms(&self) -> u64 {
        self.channel_expiry_unix_ms
    }

    #[must_use]
    pub const fn dispute_deadline_unix_ms(&self) -> u64 {
        self.dispute_deadline_unix_ms
    }

    #[must_use]
    pub const fn close_submission_cutoff_unix_ms(&self) -> u64 {
        self.close_submission_cutoff_unix_ms
    }

    #[must_use]
    pub const fn escrow_deadline_unix_ms(&self) -> u64 {
        self.escrow_deadline_unix_ms
    }

    #[must_use]
    pub const fn publisher_fence(&self) -> u64 {
        self.publisher_fence
    }

    #[must_use]
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.authorized_at_unix_ms
    }

    #[must_use]
    pub const fn frost(&self) -> &EconomicFrostBindingV1 {
        &self.frost
    }

    #[must_use]
    pub fn frost_scope_id(&self) -> &str {
        &self.frost_scope_id
    }

    #[must_use]
    pub fn frost_resource_id(&self) -> &str {
        &self.frost_resource_id
    }

    #[must_use]
    pub const fn frost_resource_version(&self) -> u64 {
        self.frost_resource_version
    }

    #[must_use]
    pub const fn frost_resource_fence(&self) -> u64 {
        self.frost_resource_fence
    }

    #[must_use]
    pub fn frost_roster_digest(&self) -> &str {
        &self.frost_roster_digest
    }

    #[must_use]
    pub const fn frost_key_epoch(&self) -> u64 {
        self.frost_key_epoch
    }

    #[must_use]
    pub const fn frost_issued_at_unix_ms(&self) -> u64 {
        self.frost_issued_at_unix_ms
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelReleaseAuthorizationV1 {
    close: VerifiedEffectiveChannelCloseV1,
    binding: ChannelReleaseAuthorizationBindingV1,
    authorization_digest: String,
}

impl VerifiedChannelReleaseAuthorizationV1 {
    #[must_use]
    pub const fn close(&self) -> &VerifiedEffectiveChannelCloseV1 {
        &self.close
    }

    #[must_use]
    pub const fn binding(&self) -> &ChannelReleaseAuthorizationBindingV1 {
        &self.binding
    }

    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedSignedChannelReleaseAuthorizationV1 {
    artifact: SignedChannelReleaseAuthorizationV1,
    authority: VerifiedChannelReleaseAuthorizationV1,
    digest: String,
}

impl VerifiedSignedChannelReleaseAuthorizationV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelReleaseAuthorizationV1 {
        &self.artifact
    }

    #[must_use]
    pub const fn body(&self) -> &ChannelReleaseAuthorizationBodyV1 {
        &self.artifact.body
    }

    #[must_use]
    pub const fn authority(&self) -> &VerifiedChannelReleaseAuthorizationV1 {
        &self.authority
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[cfg(test)]
pub(crate) fn verify_channel_release_dispatch_slot(
    authorization: &VerifiedSignedChannelReleaseAuthorizationV1,
    slot: &EconomicEffectSlotV1,
) -> Result<(), ChannelError> {
    let body = authorization.body();
    let authority = authorization.authority().binding();
    let release = body.release_broadcast();
    if body.authority() != authority
        || slot.slot_id != release.effect_slot_id
        || slot.operation_id != release.operation_id
        || slot.resource_key.resource_family != "channel_escrow_reservation"
        || slot.resource_key.scope_id != release.scope_id
        || slot.resource_key.scope_id != authority.frost_scope_id()
        || slot.resource_key.resource_id != authority.channel_id()
        || slot.resource_key.resource_id != authority.frost_resource_id()
        || slot.effect_kind != release.effect_kind
        || slot.effect_kind != CHANNEL_RELEASE_BROADCAST_EFFECT_KIND
        || slot.idempotency_key != release.idempotency_key
        || slot.parameters_digest != release.call_digest
        || slot.resource_head_digest != release.resource_head_digest
        || slot.action_digest != authority.frost().action_digest
        || slot.frost.as_ref() != Some(authority.frost())
        || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::MutationSubmitted
        || slot.state != EconomicEffectStateV1::DispatchCommitted
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(())
}

pub fn build_channel_release_authorization_body(
    authority: &VerifiedChannelReleaseAuthorizationV1,
    publication_root: String,
    root_publication: ChannelReleaseMutationBindingV1,
    release_broadcast: ChannelReleaseMutationBindingV1,
) -> Result<ChannelReleaseAuthorizationBodyV1, ChannelError> {
    let body = ChannelReleaseAuthorizationBodyV1 {
        schema: CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA.to_owned(),
        authority: authority.binding().clone(),
        publication_root,
        root_publication,
        release_broadcast,
    };
    body.validate()?;
    Ok(body)
}

pub fn verify_signed_channel_release_authorization(
    artifact: &SignedChannelReleaseAuthorizationV1,
    authority: &VerifiedChannelReleaseAuthorizationV1,
    trust: &ChannelReleasePublisherTrustV1,
    trusted_time_unix_ms: u64,
) -> Result<VerifiedSignedChannelReleaseAuthorizationV1, ChannelError> {
    trust.validate()?;
    artifact.body.validate()?;
    validate_positive("release_trusted_time", trusted_time_unix_ms)?;
    if artifact.body.authority != *authority.binding()
        || trusted_time_unix_ms < authority.binding().authorized_at_unix_ms()
        || trusted_time_unix_ms >= authority.binding().close_submission_cutoff_unix_ms()
        || trusted_time_unix_ms >= authority.binding().escrow_deadline_unix_ms()
    {
        return Err(ChannelError::AuthorityVerification);
    }
    artifact.publisher_signature.verify(
        &artifact.body,
        &trust.publisher_id,
        trust.publisher_key_epoch,
        &trust.publisher_key,
    )?;
    let digest = artifact.digest()?;
    Ok(VerifiedSignedChannelReleaseAuthorizationV1 {
        artifact: artifact.clone(),
        authority: authority.clone(),
        digest,
    })
}

#[derive(Debug, Clone)]
pub(super) struct ChannelReleaseFrostFacts {
    pub(super) authorization_slot_id: String,
    pub(super) authorization_id: String,
    pub(super) action_digest: String,
    pub(super) signed_envelope_digest: String,
    pub(super) scope_id: String,
    pub(super) resource_id: String,
    pub(super) resource_version: u64,
    pub(super) resource_fence: u64,
    pub(super) roster_digest: String,
    pub(super) key_epoch: u64,
    pub(super) issued_at_unix_ms: u64,
    pub(super) current: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelReleasePreparationFacts {
    pub(crate) dispatch_digest: String,
    pub(crate) chain_id: String,
    pub(crate) escrow_contract: String,
    pub(crate) escrow_id: String,
    pub(crate) token_address: String,
    pub(crate) token_symbol: String,
    pub(crate) beneficiary_address: String,
    pub(crate) operator: String,
    pub(crate) operator_key_hash: String,
    pub(crate) protocol_minor_unit_decimals: u8,
    pub(crate) token_decimals: u8,
    pub(crate) escrow_bound: MonetaryAmount,
    pub(crate) release_amount: MonetaryAmount,
    pub(crate) release_token_base_units: String,
}

pub fn verify_channel_release_authorization(
    close: &VerifiedEffectiveChannelCloseV1,
    frost: &VerifiedFrostAuthorization,
    publisher_fence: u64,
    trusted_time_unix_ms: u64,
) -> Result<VerifiedChannelReleaseAuthorizationV1, ChannelError> {
    let action = channel_close_frost_action(close, publisher_fence)?;
    if frost.verify_action_preimage(&action).is_err() {
        return Err(ChannelError::AuthorityVerification);
    }
    verify_channel_release_authorization_parts(
        close,
        &ChannelReleaseFrostFacts {
            authorization_slot_id: frost.authorization_slot_id().to_owned(),
            authorization_id: frost.authorization_id().to_owned(),
            action_digest: frost.action_digest().to_owned(),
            signed_envelope_digest: frost.proof_digest().to_owned(),
            scope_id: frost.scope_id().to_owned(),
            resource_id: frost.resource_id().to_owned(),
            resource_version: frost.resource_version(),
            resource_fence: frost.resource_fence(),
            roster_digest: frost.roster_digest().to_owned(),
            key_epoch: frost.key_epoch(),
            issued_at_unix_ms: frost.issued_at(),
            current: frost.is_current_at(trusted_time_unix_ms),
        },
        publisher_fence,
        trusted_time_unix_ms,
    )
}

pub(super) fn verify_channel_release_authorization_parts(
    close: &VerifiedEffectiveChannelCloseV1,
    frost: &ChannelReleaseFrostFacts,
    publisher_fence: u64,
    trusted_time_unix_ms: u64,
) -> Result<VerifiedChannelReleaseAuthorizationV1, ChannelError> {
    validate_positive("release_publisher_fence", publisher_fence)?;
    validate_positive("release_trusted_time", trusted_time_unix_ms)?;
    for (field, value) in [
        ("release_frost_slot_id", &frost.authorization_slot_id),
        ("release_frost_authorization_id", &frost.authorization_id),
        ("release_frost_action_digest", &frost.action_digest),
        (
            "release_frost_signed_envelope_digest",
            &frost.signed_envelope_digest,
        ),
        ("release_frost_roster_digest", &frost.roster_digest),
    ] {
        validate_digest(field, value)?;
    }
    validate_text("release_frost_scope_id", &frost.scope_id)?;
    validate_text("release_frost_resource_id", &frost.resource_id)?;
    validate_positive("release_frost_resource_version", frost.resource_version)?;
    validate_positive("release_frost_resource_fence", frost.resource_fence)?;
    validate_positive("release_frost_key_epoch", frost.key_epoch)?;

    let verified_close = close.close();
    let close_body = &verified_close.artifact().body;
    let open = verified_close.open();
    let intent = &open.intent().body;
    let state = close.effective_state().body();
    let snapshot = close.snapshot();
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    let close_digest = verified_close.artifact().digest()?;
    let close_body_digest = close_body.digest()?;
    let final_state_digest = close.effective_state().digest()?;
    let action = channel_close_frost_action(close, publisher_fence)?;
    let expected_action_digest = action
        .action_digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let channel_expiry_unix_ms = intent
        .channel_expiry_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let close_submission_cutoff_unix_ms = intent
        .close_submission_cutoff_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let escrow_deadline_unix_ms = intent
        .fixed_finality_broadcast_margin_secs
        .checked_add(intent.close_submission_cutoff_unix_secs)
        .and_then(|deadline| deadline.checked_mul(1_000))
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let release = parse_base_units(close.expected_release_token_base_units())?;
    let refund = parse_base_units(close.expected_refund_after_release_token_base_units())?;
    let bound = parse_base_units(&intent.bound_token_base_units)?;
    let frost_binding = EconomicFrostBindingV1 {
        authorization_slot_id: frost.authorization_slot_id.clone(),
        authorization_id: frost.authorization_id.clone(),
        action_digest: frost.action_digest.clone(),
        signed_envelope_digest: frost.signed_envelope_digest.clone(),
    };
    frost_binding
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;

    if !frost.current
        || frost.scope_id != snapshot.settlement_authority_scope_id()
        || frost.resource_id != close_body.channel_id
        || frost.resource_version != lifecycle.state_version
        || frost.resource_fence != lifecycle.lifecycle_fence
        || frost.action_digest != expected_action_digest
        || frost.issued_at_unix_ms < snapshot.observed_at_unix_ms()
        || frost.issued_at_unix_ms > trusted_time_unix_ms
        || snapshot.observed_at_unix_ms() > trusted_time_unix_ms
        || trusted_time_unix_ms >= close_submission_cutoff_unix_ms
        || trusted_time_unix_ms >= escrow_deadline_unix_ms
        || close_body.close_kind == ChannelCloseKindV1::Contested
            && trusted_time_unix_ms < close_body.dispute_deadline_unix_ms
        || close_body.open_digest != open.artifact().digest()?
        || close_body.channel_id != lifecycle.channel_id
        || close_body.channel_state_version != lifecycle.state_version
        || close_body.escrow_reservation_version != escrow.version
        || close_body.lifecycle_fence != lifecycle.lifecycle_fence
        || close.effective_close_digest().is_empty()
        || state.channel_id != close_body.channel_id
        || state.seq != lifecycle.latest_sequence
        || final_state_digest != lifecycle.latest_state_digest
        || state.cumulative_owed.currency != intent.currency
        || state.cumulative_owed.units > intent.bound.units
        || intent
            .asset_binding
            .token_base_units(&state.cumulative_owed)?
            != close.expected_release_token_base_units()
        || release.checked_add(refund) != Some(bound)
        || close_submission_cutoff_unix_ms >= escrow_deadline_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }

    let binding = ChannelReleaseAuthorizationBindingV1 {
        channel_id: close_body.channel_id.clone(),
        escrow_reference: intent.escrow_reference.clone(),
        open_digest: close_body.open_digest.clone(),
        close_digest,
        close_body_digest,
        effective_close_digest: close.effective_close_digest().to_owned(),
        final_state_digest,
        final_state_sequence: state.seq,
        final_cumulative_owed: state.cumulative_owed.clone(),
        channel_state_version: lifecycle.state_version,
        escrow_reservation_version: escrow.version,
        lifecycle_fence: lifecycle.lifecycle_fence,
        bound_token_base_units: intent.bound_token_base_units.clone(),
        expected_release_token_base_units: close.expected_release_token_base_units().to_owned(),
        expected_refund_token_base_units: close
            .expected_refund_after_release_token_base_units()
            .to_owned(),
        asset_binding_digest: intent.asset_binding.digest()?,
        original_web3_dispatch_digest: intent.original_web3_dispatch_digest.clone(),
        original_operator: intent.original_operator.clone(),
        original_operator_key_hash: intent.original_operator_key_hash.clone(),
        payee_beneficiary_address: intent.payee_beneficiary_address.clone(),
        channel_expiry_unix_ms,
        dispute_deadline_unix_ms: close_body.dispute_deadline_unix_ms,
        close_submission_cutoff_unix_ms,
        escrow_deadline_unix_ms,
        publisher_fence,
        authorized_at_unix_ms: trusted_time_unix_ms,
        frost: frost_binding,
        frost_scope_id: frost.scope_id.clone(),
        frost_resource_id: frost.resource_id.clone(),
        frost_resource_version: frost.resource_version,
        frost_resource_fence: frost.resource_fence,
        frost_roster_digest: frost.roster_digest.clone(),
        frost_key_epoch: frost.key_epoch,
        frost_issued_at_unix_ms: frost.issued_at_unix_ms,
    };
    let authorization_digest = digest(CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN, &binding)?;
    Ok(VerifiedChannelReleaseAuthorizationV1 {
        close: close.clone(),
        binding,
        authorization_digest,
    })
}

pub(crate) fn verify_channel_release_preparation_parts(
    authorization: &VerifiedChannelReleaseAuthorizationV1,
    facts: &ChannelReleasePreparationFacts,
) -> Result<(), ChannelError> {
    let intent = &authorization.close().close().open().intent().body;
    let binding = authorization.binding();
    intent.validate()?;
    if facts.dispatch_digest != binding.original_web3_dispatch_digest
        || facts.chain_id != intent.asset_binding.chain_id
        || facts.escrow_contract != intent.escrow_reference.escrow_contract
        || facts.escrow_id != intent.escrow_reference.escrow_id
        || facts.token_address != intent.asset_binding.token_address
        || facts.token_symbol != intent.asset_binding.token_symbol
        || facts.beneficiary_address != intent.payee_beneficiary_address
        || facts.operator != intent.original_operator
        || facts.operator_key_hash != intent.original_operator_key_hash
        || facts.protocol_minor_unit_decimals != intent.asset_binding.protocol_minor_unit_decimals
        || facts.token_decimals != intent.asset_binding.token_decimals
        || facts.escrow_bound != intent.bound
        || facts.release_amount
            != authorization
                .close()
                .effective_state()
                .body()
                .cumulative_owed
        || facts.release_token_base_units != binding.expected_release_token_base_units
        || intent
            .asset_binding
            .token_base_units(&facts.release_amount)?
            != facts.release_token_base_units
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(())
}
