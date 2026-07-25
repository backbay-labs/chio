use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::economic_continuity::VerifiedEconomicStateView;
use chio_core::web3::trust_profile::Web3FinalityMode;
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, validate_digest, validate_positive, validate_text, I_JSON_MAX_SAFE_INTEGER,
};
use super::{
    verify_channel_funding_evidence, ChannelAssetBindingV1, ChannelError, ChannelEscrowReferenceV1,
    ChannelEscrowReservationStatusV1, ChannelFundingAuthorityV1, ChannelLifecycleStatusV1,
    ChannelSignatureV1, ChannelStateBodyV1, SignedChannelFundingEvidenceV1,
    VerifiedChannelLifecycleSnapshotV1, VerifiedChannelStateV1,
};

pub const CHANNEL_DISPUTE_POLICY_SCHEMA: &str = "chio.channel.dispute-policy.v1";
pub const CHANNEL_OPEN_INTENT_SCHEMA: &str = "chio.channel.open-intent.v1";
pub const CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA: &str = "chio.channel.funding-acknowledgement.v1";
pub const CHANNEL_OPEN_SCHEMA: &str = "chio.channel.open.v1";

const DISPUTE_POLICY_DIGEST_DOMAIN: &[u8] = b"chio.channel.dispute-policy.digest.v1\0";
const OPEN_INTENT_DIGEST_DOMAIN: &[u8] = b"chio.channel.open-intent.digest.v1\0";
const FUNDING_ACKNOWLEDGEMENT_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.funding-acknowledgement.digest.v1\0";
const CHANNEL_OPEN_DIGEST_DOMAIN: &[u8] = b"chio.channel.open.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDisputeTierV1 {
    pub upper_bound_units: u64,
    pub dispute_window_secs: u64,
    pub required_confirmations: u64,
    pub finality_mode: Web3FinalityMode,
}

impl ChannelDisputeTierV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        if self.upper_bound_units == 0 {
            return Err(ChannelError::InvalidField("dispute_tier_upper_bound"));
        }
        validate_positive("dispute_tier_window", self.dispute_window_secs)?;
        validate_positive(
            "dispute_tier_required_confirmations",
            self.required_confirmations,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDisputePolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub fixed_finality_broadcast_margin_secs: u64,
    pub tiers: Vec<ChannelDisputeTierV1>,
}

impl ChannelDisputePolicyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_DISPUTE_POLICY_SCHEMA {
            return Err(ChannelError::InvalidField("channel_dispute_policy_schema"));
        }
        validate_text("channel_dispute_policy_id", &self.policy_id)?;
        validate_positive(
            "fixed_finality_broadcast_margin",
            self.fixed_finality_broadcast_margin_secs,
        )?;
        if self.tiers.is_empty()
            || !self
                .tiers
                .windows(2)
                .all(|pair| pair[0].upper_bound_units < pair[1].upper_bound_units)
            || self.tiers.last().map(|tier| tier.upper_bound_units) != Some(I_JSON_MAX_SAFE_INTEGER)
        {
            return Err(ChannelError::InvalidField("channel_dispute_tiers"));
        }
        for tier in &self.tiers {
            tier.validate()?;
        }
        if self
            .tiers
            .iter()
            .any(|tier| tier.finality_mode != Web3FinalityMode::L1Finalized)
            || self.tiers.windows(2).any(|pair| {
                pair[1].dispute_window_secs < pair[0].dispute_window_secs
                    || pair[1].required_confirmations < pair[0].required_confirmations
            })
        {
            return Err(ChannelError::InvalidField("channel_dispute_tiers"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(DISPUTE_POLICY_DIGEST_DOMAIN, self)
    }

    fn tier_for(&self, units: u64) -> Result<&ChannelDisputeTierV1, ChannelError> {
        self.validate()?;
        self.tiers
            .iter()
            .find(|tier| units <= tier.upper_bound_units)
            .ok_or(ChannelError::InvalidField("channel_dispute_tiers"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelOpenIntentBodyV1 {
    pub schema: String,
    pub open_intent_id: String,
    pub payer_id: String,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub payer_key: PublicKey,
    pub payer_key_epoch: u64,
    pub payer_refund_address: String,
    pub payee_id: String,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub payee_key: PublicKey,
    pub payee_key_epoch: u64,
    pub payee_beneficiary_address: String,
    pub settlement_authority_scope_id: String,
    pub currency: String,
    pub bound: MonetaryAmount,
    pub asset_binding: ChannelAssetBindingV1,
    pub bound_token_base_units: String,
    pub channel_expiry_unix_secs: u64,
    pub dispute_tier_upper_bound_units: u64,
    pub dispute_window_secs: u64,
    pub required_confirmations: u64,
    pub finality_mode: Web3FinalityMode,
    pub fixed_finality_broadcast_margin_secs: u64,
    pub close_submission_cutoff_unix_secs: u64,
    pub original_web3_dispatch_digest: String,
    pub escrow_reference: ChannelEscrowReferenceV1,
    pub funding_evidence_digest: String,
    pub original_operator: String,
    pub original_operator_key_hash: String,
    pub participant_snapshot_digest: String,
}

impl ChannelOpenIntentBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_OPEN_INTENT_SCHEMA {
            return Err(ChannelError::InvalidField("channel_open_intent_schema"));
        }
        validate_digest("open_intent_id", &self.open_intent_id)?;
        validate_text("channel_payer_id", &self.payer_id)?;
        validate_positive("channel_payer_key_epoch", self.payer_key_epoch)?;
        validate_text("channel_payee_id", &self.payee_id)?;
        validate_positive("channel_payee_key_epoch", self.payee_key_epoch)?;
        validate_text(
            "settlement_authority_scope_id",
            &self.settlement_authority_scope_id,
        )?;
        super::validation::validate_currency(&self.currency)?;
        if self.bound.units == 0
            || self.bound.units > I_JSON_MAX_SAFE_INTEGER
            || self.bound.currency != self.currency
        {
            return Err(ChannelError::InvalidField("channel_bound"));
        }
        self.asset_binding.validate()?;
        self.escrow_reference.validate()?;
        for (field, value) in [
            (
                "original_web3_dispatch_digest",
                &self.original_web3_dispatch_digest,
            ),
            ("funding_evidence_digest", &self.funding_evidence_digest),
            (
                "original_operator_key_hash",
                &self.original_operator_key_hash,
            ),
            (
                "participant_snapshot_digest",
                &self.participant_snapshot_digest,
            ),
        ] {
            if field == "original_operator_key_hash" {
                super::validation::validate_evm_hash(field, value)?;
            } else {
                validate_digest(field, value)?;
            }
        }
        super::validation::validate_evm_address(
            "payer_refund_address",
            &self.payer_refund_address,
        )?;
        super::validation::validate_evm_address(
            "payee_beneficiary_address",
            &self.payee_beneficiary_address,
        )?;
        super::validation::validate_evm_address("original_operator", &self.original_operator)?;
        super::validation::parse_base_units(&self.bound_token_base_units)?;
        for (field, value) in [
            ("channel_expiry", self.channel_expiry_unix_secs),
            (
                "dispute_tier_upper_bound",
                self.dispute_tier_upper_bound_units,
            ),
            ("dispute_window", self.dispute_window_secs),
            ("required_confirmations", self.required_confirmations),
            (
                "fixed_finality_broadcast_margin",
                self.fixed_finality_broadcast_margin_secs,
            ),
            (
                "close_submission_cutoff",
                self.close_submission_cutoff_unix_secs,
            ),
        ] {
            validate_positive(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelOpenIntentV1 {
    pub body: ChannelOpenIntentBodyV1,
    pub payer_signature: ChannelSignatureV1,
    pub payee_signature: ChannelSignatureV1,
}

impl SignedChannelOpenIntentV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(OPEN_INTENT_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelOpenTrustV1 {
    pub payer_id: String,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub payer_key: PublicKey,
    pub payer_key_epoch: u64,
    pub payee_id: String,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub payee_key: PublicKey,
    pub payee_key_epoch: u64,
    pub settlement_authority_scope_id: String,
    pub original_web3_dispatch_digest: String,
    pub participant_snapshot_digest: String,
    pub trusted_time_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelOpenIntentV1 {
    intent: SignedChannelOpenIntentV1,
    funding_authority: ChannelFundingAuthorityV1,
    funding_evidence_expires_at_unix_ms: u64,
}

impl VerifiedChannelOpenIntentV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelOpenIntentV1 {
        &self.intent
    }
}

impl ChannelOpenTrustV1 {
    pub(super) fn validate(&self) -> Result<(), ChannelError> {
        validate_text("trusted_payer_id", &self.payer_id)?;
        validate_positive("trusted_payer_key_epoch", self.payer_key_epoch)?;
        validate_text("trusted_payee_id", &self.payee_id)?;
        validate_positive("trusted_payee_key_epoch", self.payee_key_epoch)?;
        validate_text(
            "trusted_settlement_authority_scope_id",
            &self.settlement_authority_scope_id,
        )?;
        validate_digest(
            "trusted_original_web3_dispatch_digest",
            &self.original_web3_dispatch_digest,
        )?;
        validate_digest(
            "trusted_participant_snapshot_digest",
            &self.participant_snapshot_digest,
        )?;
        validate_positive("trusted_time_unix_ms", self.trusted_time_unix_ms)
    }

    pub(super) fn matches_intent(&self, intent: &ChannelOpenIntentBodyV1) -> bool {
        intent.payer_id == self.payer_id
            && intent.payer_key == self.payer_key
            && intent.payer_key_epoch == self.payer_key_epoch
            && intent.payee_id == self.payee_id
            && intent.payee_key == self.payee_key
            && intent.payee_key_epoch == self.payee_key_epoch
            && intent.settlement_authority_scope_id == self.settlement_authority_scope_id
            && intent.original_web3_dispatch_digest == self.original_web3_dispatch_digest
            && intent.participant_snapshot_digest == self.participant_snapshot_digest
    }
}

pub fn verify_channel_open_intent(
    intent: &SignedChannelOpenIntentV1,
    funding: &SignedChannelFundingEvidenceV1,
    funding_authority: &ChannelFundingAuthorityV1,
    policy: &ChannelDisputePolicyV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelOpenIntentV1, ChannelError> {
    intent.body.validate()?;
    trust.validate()?;
    policy.validate()?;
    verify_channel_funding_evidence(funding, funding_authority)?;
    let body = &intent.body;
    let tier = policy.tier_for(body.bound.units)?;
    body.payer_signature_binding(&intent.payer_signature, trust)?;
    body.payee_signature_binding(&intent.payee_signature, trust)?;
    body.asset_binding
        .verify_round_trip(&body.bound, &body.bound_token_base_units)?;
    let minimum_cutoff = body
        .channel_expiry_unix_secs
        .checked_add(body.dispute_window_secs)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_cutoff = funding
        .body
        .escrow_terms
        .deadline_unix_secs
        .checked_sub(policy.fixed_finality_broadcast_margin_secs)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if body.payer_id != trust.payer_id
        || body.payer_key != trust.payer_key
        || body.payer_key_epoch != trust.payer_key_epoch
        || body.payee_id != trust.payee_id
        || body.payee_key != trust.payee_key
        || body.payee_key_epoch != trust.payee_key_epoch
        || body.payer_id == body.payee_id
        || body.payer_key == body.payee_key
        || body.settlement_authority_scope_id != trust.settlement_authority_scope_id
        || body.asset_binding.settlement_policy_digest != policy.digest()?
        || body.asset_binding != funding.body.asset_binding
        || body.escrow_reference != funding.body.escrow_reference
        || body.funding_evidence_digest != funding.digest()?
        || body.bound_token_base_units != funding.body.escrow_terms.max_token_base_units
        || body.bound_token_base_units != funding.body.escrow_state.deposited_token_base_units
        || funding.body.escrow_state.released_token_base_units != "0"
        || funding.body.escrow_state.refunded_token_base_units != "0"
        || funding.body.escrow_state.refunded
        || body.payer_refund_address != funding.body.escrow_terms.depositor
        || body.payee_beneficiary_address != funding.body.escrow_terms.beneficiary
        || body.original_operator != funding.body.escrow_terms.operator
        || body.original_operator_key_hash != funding.body.escrow_terms.operator_key_hash
        || body.original_web3_dispatch_digest != trust.original_web3_dispatch_digest
        || body.participant_snapshot_digest != trust.participant_snapshot_digest
        || body.currency != body.asset_binding.currency
        || body.dispute_tier_upper_bound_units != tier.upper_bound_units
        || body.dispute_window_secs != tier.dispute_window_secs
        || body.required_confirmations != tier.required_confirmations
        || body.finality_mode != tier.finality_mode
        || body.fixed_finality_broadcast_margin_secs != policy.fixed_finality_broadcast_margin_secs
        || funding.body.block_pin.required_confirmations != tier.required_confirmations
        || funding.body.block_pin.finality_mode != tier.finality_mode
        || body.close_submission_cutoff_unix_secs != expected_cutoff
        || expected_cutoff >= funding.body.escrow_terms.deadline_unix_secs
        || expected_cutoff < minimum_cutoff
        || funding.body.evidence_expires_at_unix_ms <= trust.trusted_time_unix_ms
        || body.channel_expiry_unix_secs <= trust.trusted_time_unix_ms / 1_000
        || funding_authority.trusted_time_unix_ms != trust.trusted_time_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelOpenIntentV1 {
        intent: intent.clone(),
        funding_authority: funding_authority.clone(),
        funding_evidence_expires_at_unix_ms: funding.body.evidence_expires_at_unix_ms,
    })
}

impl ChannelOpenIntentBodyV1 {
    fn payer_signature_binding(
        &self,
        signature: &ChannelSignatureV1,
        trust: &ChannelOpenTrustV1,
    ) -> Result<(), ChannelError> {
        signature.verify(
            self,
            &trust.payer_id,
            trust.payer_key_epoch,
            &trust.payer_key,
        )
    }

    fn payee_signature_binding(
        &self,
        signature: &ChannelSignatureV1,
        trust: &ChannelOpenTrustV1,
    ) -> Result<(), ChannelError> {
        signature.verify(
            self,
            &trust.payee_id,
            trust.payee_key_epoch,
            &trust.payee_key,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelEscrowReservationStateV1 {
    Unreserved,
    Opening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelFundingAcknowledgementBodyV1 {
    pub schema: String,
    pub open_intent_digest: String,
    pub escrow_reference: ChannelEscrowReferenceV1,
    pub prior_state: ChannelEscrowReservationStateV1,
    pub prior_version: u64,
    pub prior_head_digest: String,
    pub new_state: ChannelEscrowReservationStateV1,
    pub new_version: u64,
    pub anchored_head_digest: String,
    pub reserved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl ChannelFundingAcknowledgementBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA {
            return Err(ChannelError::InvalidField("funding_acknowledgement_schema"));
        }
        validate_digest("ack_open_intent_digest", &self.open_intent_digest)?;
        self.escrow_reference.validate()?;
        validate_positive("ack_prior_version", self.prior_version)?;
        validate_digest("ack_prior_head_digest", &self.prior_head_digest)?;
        validate_positive("ack_new_version", self.new_version)?;
        validate_digest("ack_anchored_head_digest", &self.anchored_head_digest)?;
        validate_positive("ack_reserved_at", self.reserved_at_unix_ms)?;
        validate_positive("ack_expires_at", self.expires_at_unix_ms)?;
        let next = self
            .prior_version
            .checked_add(1)
            .filter(|version| *version <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        if self.prior_state != ChannelEscrowReservationStateV1::Unreserved
            || self.new_state != ChannelEscrowReservationStateV1::Opening
            || self.new_version != next
            || self.expires_at_unix_ms <= self.reserved_at_unix_ms
        {
            return Err(ChannelError::IllegalTransition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelFundingAcknowledgementV1 {
    pub body: ChannelFundingAcknowledgementBodyV1,
    pub authority_signature: ChannelSignatureV1,
}

impl SignedChannelFundingAcknowledgementV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(FUNDING_ACKNOWLEDGEMENT_DIGEST_DOMAIN, self)
    }
}

pub fn verify_channel_funding_acknowledgement(
    acknowledgement: &SignedChannelFundingAcknowledgementV1,
    intent: &SignedChannelOpenIntentV1,
    authority: &ChannelFundingAuthorityV1,
) -> Result<(), ChannelError> {
    acknowledgement.body.validate()?;
    authority.validate()?;
    acknowledgement.authority_signature.verify(
        &acknowledgement.body,
        &authority.authority_id,
        authority.authority_key_epoch,
        &authority.authority_key,
    )?;
    if acknowledgement.body.open_intent_digest != intent.digest()?
        || acknowledgement.body.escrow_reference != intent.body.escrow_reference
        || acknowledgement.body.reserved_at_unix_ms > authority.trusted_time_unix_ms
        || acknowledgement.body.expires_at_unix_ms <= authority.trusted_time_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelOpenBodyV1 {
    pub schema: String,
    pub channel_id: String,
    pub open_intent_digest: String,
    pub funding_acknowledgement_digest: String,
    pub initial_state_digest: String,
    pub opened_at_unix_ms: u64,
}

impl ChannelOpenBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_OPEN_SCHEMA {
            return Err(ChannelError::InvalidField("channel_open_schema"));
        }
        for (field, value) in [
            ("channel_id", &self.channel_id),
            ("open_intent_digest", &self.open_intent_digest),
            (
                "funding_acknowledgement_digest",
                &self.funding_acknowledgement_digest,
            ),
            ("initial_state_digest", &self.initial_state_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_positive("channel_opened_at", self.opened_at_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelOpenV1 {
    pub body: ChannelOpenBodyV1,
    pub payer_signature: ChannelSignatureV1,
    pub payee_signature: ChannelSignatureV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelOpenConsentV1 {
    open: SignedChannelOpenV1,
    intent: SignedChannelOpenIntentV1,
    initial_state: VerifiedChannelStateV1,
}

impl VerifiedChannelOpenConsentV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelOpenV1 {
        &self.open
    }

    #[must_use]
    pub const fn intent(&self) -> &SignedChannelOpenIntentV1 {
        &self.intent
    }

    #[must_use]
    pub const fn initial_state(&self) -> &VerifiedChannelStateV1 {
        &self.initial_state
    }
}

impl SignedChannelOpenV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(CHANNEL_OPEN_DIGEST_DOMAIN, self)
    }
}

pub fn derive_channel_id(
    open_intent_digest: &str,
    funding_acknowledgement_digest: &str,
) -> Result<String, ChannelError> {
    validate_digest("open_intent_digest", open_intent_digest)?;
    validate_digest(
        "funding_acknowledgement_digest",
        funding_acknowledgement_digest,
    )?;
    digest(
        b"",
        &(
            "chio.channel.id.v1",
            open_intent_digest,
            funding_acknowledgement_digest,
        ),
    )
}

pub fn verify_channel_open_consent(
    open: &SignedChannelOpenV1,
    verified_intent: &VerifiedChannelOpenIntentV1,
    acknowledgement: &SignedChannelFundingAcknowledgementV1,
    authority: &ChannelFundingAuthorityV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelOpenConsentV1, ChannelError> {
    let intent = verified_intent.artifact();
    open.body.validate()?;
    trust.validate()?;
    verify_channel_funding_acknowledgement(acknowledgement, intent, authority)?;
    open.payer_signature.verify(
        &open.body,
        &trust.payer_id,
        trust.payer_key_epoch,
        &trust.payer_key,
    )?;
    open.payee_signature.verify(
        &open.body,
        &trust.payee_id,
        trust.payee_key_epoch,
        &trust.payee_key,
    )?;
    let intent_digest = intent.digest()?;
    let acknowledgement_digest = acknowledgement.digest()?;
    let channel_id = derive_channel_id(&intent_digest, &acknowledgement_digest)?;
    let initial_state = ChannelStateBodyV1::initial(
        channel_id.clone(),
        intent.body.currency.clone(),
        intent.body.asset_binding.digest()?,
    )?;
    let channel_expiry_unix_ms = intent
        .body
        .channel_expiry_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if !trust.matches_intent(&intent.body)
        || !verified_intent
            .funding_authority
            .same_configuration(authority)
        || authority.trusted_time_unix_ms < verified_intent.funding_authority.trusted_time_unix_ms
        || open.body.channel_id != channel_id
        || open.body.open_intent_digest != intent_digest
        || open.body.funding_acknowledgement_digest != acknowledgement_digest
        || open.body.initial_state_digest != initial_state.digest()?
        || open.body.opened_at_unix_ms > trust.trusted_time_unix_ms
        || open.body.opened_at_unix_ms < acknowledgement.body.reserved_at_unix_ms
        || open.body.opened_at_unix_ms >= acknowledgement.body.expires_at_unix_ms
        || trust.trusted_time_unix_ms >= acknowledgement.body.expires_at_unix_ms
        || open.body.opened_at_unix_ms >= channel_expiry_unix_ms
        || trust.trusted_time_unix_ms >= channel_expiry_unix_ms
        || trust.trusted_time_unix_ms >= verified_intent.funding_evidence_expires_at_unix_ms
        || authority.trusted_time_unix_ms != trust.trusted_time_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelOpenConsentV1 {
        open: open.clone(),
        intent: intent.clone(),
        initial_state: VerifiedChannelStateV1::initial(initial_state),
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedAdmittedChannelOpenV1 {
    consent: VerifiedChannelOpenConsentV1,
    snapshot: VerifiedChannelLifecycleSnapshotV1,
}

impl VerifiedAdmittedChannelOpenV1 {
    #[must_use]
    pub const fn consent(&self) -> &VerifiedChannelOpenConsentV1 {
        &self.consent
    }

    #[must_use]
    pub const fn snapshot(&self) -> &VerifiedChannelLifecycleSnapshotV1 {
        &self.snapshot
    }
}

pub fn verify_admitted_channel_open(
    consent: &VerifiedChannelOpenConsentV1,
    current: &VerifiedEconomicStateView,
) -> Result<VerifiedAdmittedChannelOpenV1, ChannelError> {
    let open_digest = consent.artifact().digest()?;
    let snapshot = super::verify_channel_lifecycle_snapshot(
        current,
        &consent.intent().body.settlement_authority_scope_id,
        &consent.artifact().body.channel_id,
    )?;
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    if lifecycle.status != ChannelLifecycleStatusV1::Open
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.open_digest != open_digest
        || escrow.escrow_reference != consent.intent().body.escrow_reference
        || lifecycle.latest_sequence == 0
            && lifecycle.latest_state_digest != consent.artifact().body.initial_state_digest
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedAdmittedChannelOpenV1 {
        consent: consent.clone(),
        snapshot,
    })
}
