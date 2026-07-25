use chio_core::crypto::PublicKey;
use chio_core::web3::trust_profile::Web3FinalityMode;
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, parse_base_units, validate_chain_id, validate_digest, validate_evm_address,
    validate_evm_hash, validate_positive, validate_text, I_JSON_MAX_SAFE_INTEGER,
};
use super::{ChannelAssetBindingV1, ChannelError, ChannelSignatureV1};

pub const CHANNEL_FUNDING_EVIDENCE_SCHEMA: &str = "chio.channel.funding-evidence.v1";

const ESCROW_CREATED_EVENT_SIGNATURE: &str =
    "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)";

const FUNDING_EVIDENCE_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.funding-evidence.body.digest.v1\0";
const FUNDING_EVIDENCE_DIGEST_DOMAIN: &[u8] = b"chio.channel.funding-evidence.digest.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelFinalityStatusV1 {
    Finalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelEscrowReferenceV1 {
    pub chain_id: String,
    pub escrow_contract: String,
    pub escrow_id: String,
}

impl ChannelEscrowReferenceV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        validate_chain_id(&self.chain_id)?;
        validate_evm_address("escrow_contract", &self.escrow_contract)?;
        validate_evm_hash("escrow_id", &self.escrow_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelEscrowTermsV1 {
    pub capability_id: String,
    pub depositor: String,
    pub beneficiary: String,
    pub token_address: String,
    pub max_token_base_units: String,
    pub deadline_unix_secs: u64,
    pub operator: String,
    pub operator_key_hash: String,
}

impl ChannelEscrowTermsV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_evm_hash("capability_id", &self.capability_id)?;
        validate_evm_address("depositor", &self.depositor)?;
        validate_evm_address("beneficiary", &self.beneficiary)?;
        validate_evm_address("escrow_token", &self.token_address)?;
        parse_base_units(&self.max_token_base_units)?;
        validate_positive("escrow_deadline", self.deadline_unix_secs)?;
        validate_evm_address("escrow_operator", &self.operator)?;
        validate_evm_hash("operator_key_hash", &self.operator_key_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelEscrowStateV1 {
    pub deposited_token_base_units: String,
    pub released_token_base_units: String,
    pub refunded_token_base_units: String,
    pub refunded: bool,
}

impl ChannelEscrowStateV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        let deposited = parse_base_units(&self.deposited_token_base_units)?;
        let released = parse_base_units(&self.released_token_base_units)?;
        let refunded = parse_base_units(&self.refunded_token_base_units)?;
        let total = released
            .checked_add(refunded)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        if total > deposited
            || !self.refunded && refunded != 0
            || self.refunded && total != deposited
        {
            return Err(ChannelError::InvalidField("escrow_state"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelEscrowCreatedEventV1 {
    pub transaction_hash: String,
    pub transaction_to: String,
    pub transaction_succeeded: bool,
    pub receipt_block_number: u64,
    pub receipt_block_hash: String,
    pub log_emitter: String,
    pub log_index: u64,
    pub event_signature: String,
    pub escrow_id: String,
    pub capability_id: String,
    pub depositor: String,
    pub beneficiary: String,
    pub token_address: String,
    pub max_token_base_units: String,
    pub deadline_unix_secs: u64,
    pub operator: String,
}

impl ChannelEscrowCreatedEventV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_evm_hash("creation_transaction_hash", &self.transaction_hash)?;
        validate_evm_address("creation_transaction_to", &self.transaction_to)?;
        validate_positive("creation_receipt_block_number", self.receipt_block_number)?;
        validate_evm_hash("creation_receipt_block_hash", &self.receipt_block_hash)?;
        validate_evm_address("creation_log_emitter", &self.log_emitter)?;
        if self.log_index > I_JSON_MAX_SAFE_INTEGER {
            return Err(ChannelError::InvalidField("creation_log_index"));
        }
        validate_evm_hash("creation_event_signature", &self.event_signature)?;
        validate_evm_hash("creation_escrow_id", &self.escrow_id)?;
        validate_evm_hash("creation_capability_id", &self.capability_id)?;
        validate_evm_address("creation_depositor", &self.depositor)?;
        validate_evm_address("creation_beneficiary", &self.beneficiary)?;
        validate_evm_address("creation_token", &self.token_address)?;
        parse_base_units(&self.max_token_base_units)?;
        validate_positive("creation_deadline", self.deadline_unix_secs)?;
        validate_evm_address("creation_operator", &self.operator)?;
        if !self.transaction_succeeded
            || self.event_signature != channel_escrow_created_event_signature()
        {
            return Err(ChannelError::InvalidField("creation_transaction_status"));
        }
        Ok(())
    }
}

pub fn channel_escrow_created_event_signature() -> String {
    format!(
        "{:#x}",
        alloy_primitives::keccak256(ESCROW_CREATED_EVENT_SIGNATURE.as_bytes())
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPinnedStateReadV1 {
    pub contract: String,
    pub block_number: u64,
    pub block_hash: String,
    pub call_data_digest: String,
    pub return_data_digest: String,
}

impl ChannelPinnedStateReadV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_evm_address("state_read_contract", &self.contract)?;
        validate_positive("state_read_block_number", self.block_number)?;
        validate_evm_hash("state_read_block_hash", &self.block_hash)?;
        validate_evm_hash("state_read_call_data_digest", &self.call_data_digest)?;
        validate_evm_hash("state_read_return_data_digest", &self.return_data_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelTokenObservationV1 {
    pub token_address: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub allowed: bool,
    pub escrow_contract: String,
    pub block_number: u64,
    pub block_hash: String,
}

impl ChannelTokenObservationV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_evm_address("observed_token_address", &self.token_address)?;
        validate_text("observed_token_symbol", &self.token_symbol)?;
        validate_evm_address("observed_token_escrow_contract", &self.escrow_contract)?;
        validate_positive("observed_token_block_number", self.block_number)?;
        validate_evm_hash("observed_token_block_hash", &self.block_hash)?;
        if !self.allowed {
            return Err(ChannelError::InvalidField("observed_token_allowed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelIdentityRegistryObservationV1 {
    pub registry_contract: String,
    pub operator: String,
    pub active: bool,
    pub operator_key_hash: String,
    pub block_number: u64,
    pub block_hash: String,
}

impl ChannelIdentityRegistryObservationV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_evm_address("identity_registry_contract", &self.registry_contract)?;
        validate_evm_address("identity_operator", &self.operator)?;
        validate_evm_hash("identity_operator_key_hash", &self.operator_key_hash)?;
        validate_positive("identity_block_number", self.block_number)?;
        validate_evm_hash("identity_block_hash", &self.block_hash)?;
        if !self.active {
            return Err(ChannelError::InvalidField("identity_operator_active"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelBlockPinV1 {
    pub block_number: u64,
    pub block_hash: String,
    pub block_timestamp_unix_secs: u64,
    pub observed_at_unix_ms: u64,
    pub required_confirmations: u64,
    pub observed_confirmations: u64,
    pub finalized_head_number: u64,
    pub finalized_head_hash: String,
    pub finality_mode: Web3FinalityMode,
    pub finality_status: ChannelFinalityStatusV1,
}

impl ChannelBlockPinV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_positive("funding_block_number", self.block_number)?;
        validate_evm_hash("funding_block_hash", &self.block_hash)?;
        validate_positive("funding_block_timestamp", self.block_timestamp_unix_secs)?;
        validate_positive("funding_observed_at", self.observed_at_unix_ms)?;
        validate_positive(
            "funding_required_confirmations",
            self.required_confirmations,
        )?;
        validate_positive("funding_finalized_head_number", self.finalized_head_number)?;
        validate_evm_hash("funding_finalized_head_hash", &self.finalized_head_hash)?;
        let confirmations = self
            .finalized_head_number
            .checked_sub(self.block_number)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        if self.observed_confirmations < self.required_confirmations
            || self.observed_confirmations != confirmations
            || self.finality_mode != Web3FinalityMode::L1Finalized
            || self
                .block_timestamp_unix_secs
                .checked_mul(1_000)
                .filter(|timestamp| *timestamp <= self.observed_at_unix_ms)
                .is_none()
        {
            return Err(ChannelError::InvalidField("funding_finality"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelFundingEvidenceBodyV1 {
    pub schema: String,
    pub escrow_reference: ChannelEscrowReferenceV1,
    pub escrow_terms: ChannelEscrowTermsV1,
    pub escrow_state: ChannelEscrowStateV1,
    pub escrow_state_read: ChannelPinnedStateReadV1,
    pub creation_event: ChannelEscrowCreatedEventV1,
    pub identity_observation: ChannelIdentityRegistryObservationV1,
    pub token_observation: ChannelTokenObservationV1,
    pub asset_binding: ChannelAssetBindingV1,
    pub block_pin: ChannelBlockPinV1,
    pub evidence_expires_at_unix_ms: u64,
}

impl ChannelFundingEvidenceBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_FUNDING_EVIDENCE_SCHEMA {
            return Err(ChannelError::InvalidField("funding_evidence_schema"));
        }
        self.escrow_reference.validate()?;
        self.escrow_terms.validate()?;
        self.escrow_state.validate()?;
        self.escrow_state_read.validate()?;
        self.creation_event.validate()?;
        self.identity_observation.validate()?;
        self.token_observation.validate()?;
        self.asset_binding.validate()?;
        self.block_pin.validate()?;
        validate_positive("funding_evidence_expiry", self.evidence_expires_at_unix_ms)?;
        if self.escrow_reference.chain_id != self.asset_binding.chain_id
            || self.escrow_terms.token_address != self.asset_binding.token_address
            || self.creation_event.escrow_id != self.escrow_reference.escrow_id
            || self.creation_event.transaction_to != self.escrow_reference.escrow_contract
            || self.creation_event.log_emitter != self.escrow_reference.escrow_contract
            || self.creation_event.receipt_block_number != self.block_pin.block_number
            || self.creation_event.receipt_block_hash != self.block_pin.block_hash
            || self.creation_event.capability_id != self.escrow_terms.capability_id
            || self.creation_event.depositor != self.escrow_terms.depositor
            || self.creation_event.beneficiary != self.escrow_terms.beneficiary
            || self.creation_event.token_address != self.escrow_terms.token_address
            || self.creation_event.max_token_base_units != self.escrow_terms.max_token_base_units
            || self.creation_event.deadline_unix_secs != self.escrow_terms.deadline_unix_secs
            || self.creation_event.operator != self.escrow_terms.operator
            || self.escrow_state_read.contract != self.escrow_reference.escrow_contract
            || self.escrow_state_read.block_number != self.block_pin.block_number
            || self.escrow_state_read.block_hash != self.block_pin.block_hash
            || self.identity_observation.operator != self.escrow_terms.operator
            || self.identity_observation.operator_key_hash != self.escrow_terms.operator_key_hash
            || self.identity_observation.block_number != self.block_pin.block_number
            || self.identity_observation.block_hash != self.block_pin.block_hash
            || self.token_observation.token_address != self.escrow_terms.token_address
            || self.token_observation.token_symbol != self.asset_binding.token_symbol
            || self.token_observation.token_decimals != self.asset_binding.token_decimals
            || self.token_observation.escrow_contract != self.escrow_reference.escrow_contract
            || self.token_observation.block_number != self.block_pin.block_number
            || self.token_observation.block_hash != self.block_pin.block_hash
            || self.evidence_expires_at_unix_ms <= self.block_pin.observed_at_unix_ms
        {
            return Err(ChannelError::InvalidField("funding_evidence_binding"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(FUNDING_EVIDENCE_BODY_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelFundingEvidenceV1 {
    pub body: ChannelFundingEvidenceBodyV1,
    pub authority_signature: ChannelSignatureV1,
}

impl SignedChannelFundingEvidenceV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(FUNDING_EVIDENCE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelFundingAuthorityV1 {
    pub authority_id: String,
    pub authority_key_epoch: u64,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub authority_key: PublicKey,
    pub trusted_time_unix_ms: u64,
    pub chain_id: String,
    pub escrow_contract: String,
    pub identity_registry_contract: String,
    pub token_address: String,
    pub token_symbol: String,
    pub currency: String,
    pub protocol_minor_unit_decimals: u8,
    pub token_decimals: u8,
    pub settlement_policy_digest: String,
    pub minimum_confirmations: u64,
    pub finality_mode: Web3FinalityMode,
}

impl ChannelFundingAuthorityV1 {
    pub(super) fn validate(&self) -> Result<(), ChannelError> {
        validate_text("funding_authority_id", &self.authority_id)?;
        validate_positive("funding_authority_key_epoch", self.authority_key_epoch)?;
        validate_positive("trusted_time_unix_ms", self.trusted_time_unix_ms)?;
        validate_chain_id(&self.chain_id)?;
        validate_evm_address("trusted_escrow_contract", &self.escrow_contract)?;
        validate_evm_address(
            "trusted_identity_registry_contract",
            &self.identity_registry_contract,
        )?;
        validate_evm_address("trusted_token_address", &self.token_address)?;
        validate_text("trusted_token_symbol", &self.token_symbol)?;
        super::validation::validate_currency(&self.currency)?;
        validate_digest(
            "trusted_settlement_policy_digest",
            &self.settlement_policy_digest,
        )?;
        validate_positive("trusted_minimum_confirmations", self.minimum_confirmations)?;
        if self.finality_mode != Web3FinalityMode::L1Finalized {
            return Err(ChannelError::InvalidField("trusted_finality_mode"));
        }
        Ok(())
    }

    pub(super) fn same_configuration(&self, other: &Self) -> bool {
        self.authority_id == other.authority_id
            && self.authority_key_epoch == other.authority_key_epoch
            && self.authority_key == other.authority_key
            && self.chain_id == other.chain_id
            && self.escrow_contract == other.escrow_contract
            && self.identity_registry_contract == other.identity_registry_contract
            && self.token_address == other.token_address
            && self.token_symbol == other.token_symbol
            && self.currency == other.currency
            && self.protocol_minor_unit_decimals == other.protocol_minor_unit_decimals
            && self.token_decimals == other.token_decimals
            && self.settlement_policy_digest == other.settlement_policy_digest
            && self.minimum_confirmations == other.minimum_confirmations
            && self.finality_mode == other.finality_mode
    }
}

pub fn verify_channel_funding_evidence(
    evidence: &SignedChannelFundingEvidenceV1,
    authority: &ChannelFundingAuthorityV1,
) -> Result<(), ChannelError> {
    authority.validate()?;
    evidence.body.validate()?;
    evidence.authority_signature.verify(
        &evidence.body,
        &authority.authority_id,
        authority.authority_key_epoch,
        &authority.authority_key,
    )?;
    let body = &evidence.body;
    if body.block_pin.observed_at_unix_ms > authority.trusted_time_unix_ms
        || body.evidence_expires_at_unix_ms <= authority.trusted_time_unix_ms
        || body.escrow_reference.chain_id != authority.chain_id
        || body.escrow_reference.escrow_contract != authority.escrow_contract
        || body.identity_observation.registry_contract != authority.identity_registry_contract
        || body.asset_binding.token_address != authority.token_address
        || body.asset_binding.token_symbol != authority.token_symbol
        || body.asset_binding.currency != authority.currency
        || body.asset_binding.protocol_minor_unit_decimals != authority.protocol_minor_unit_decimals
        || body.asset_binding.token_decimals != authority.token_decimals
        || body.asset_binding.settlement_policy_digest != authority.settlement_policy_digest
        || body.block_pin.required_confirmations != authority.minimum_confirmations
        || body.block_pin.finality_mode != authority.finality_mode
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(())
}
