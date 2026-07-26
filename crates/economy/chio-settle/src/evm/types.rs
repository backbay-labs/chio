//! EVM settlement wire and snapshot data types.

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmCall {
    pub from_address: String,
    pub to_address: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedErc20Approval {
    pub owner_address: String,
    pub token_address: String,
    pub spender_address: String,
    pub amount_minor_units: u128,
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedRootPublication {
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowDispatchRequest {
    pub dispatch_id: String,
    pub issued_at: u64,
    pub trust_profile_id: String,
    pub contract_package_id: String,
    pub capability_id: String,
    pub depositor_address: String,
    pub beneficiary_address: String,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    pub settlement_path: Web3SettlementPath,
    pub oracle_evidence_required_for_fx: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowCreate {
    pub expected_escrow_id: String,
    pub capability_commitment: String,
    pub settlement_amount_minor_units: u128,
    pub dispatch: Web3SettlementDispatchArtifact,
    pub(super) call: PreparedEvmCall,
}

impl PreparedEscrowCreate {
    #[must_use]
    pub fn commitment(&self) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.dispatch.chain_id.clone(),
            lane_kind: match self.dispatch.settlement_path {
                Web3SettlementPath::DualSignature => "evm_dual_signature",
                Web3SettlementPath::MerkleProof => "evm_merkle_proof",
            }
            .to_string(),
            capability_commitment: self.capability_commitment.clone(),
            receipt_reference: self.dispatch.escrow_id.clone(),
            operator_identity: self.dispatch.beneficiary_address.clone(),
            settlement_amount: self.dispatch.settlement_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscrowExecutionAmount {
    Full,
    Partial(MonetaryAmount),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedMerkleRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_hash: String,
    pub receipt_leaf_hash: String,
    pub merkle_root: String,
    pub partial: bool,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub(super) call: PreparedEvmCall,
}

impl PreparedMerkleRelease {
    #[must_use]
    pub fn commitment(
        &self,
        capability_commitment: String,
        operator_identity: String,
    ) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.chain_id.clone(),
            lane_kind: "evm_merkle_proof".to_string(),
            capability_commitment,
            receipt_reference: self.receipt_hash.clone(),
            operator_identity,
            settlement_amount: self.observed_amount.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedAuthorizedChannelMerkleReleaseV1 {
    pub(super) release: PreparedMerkleRelease,
    pub(super) authorization: crate::channel::ChannelReleaseAuthorizationBindingV1,
    pub(super) authorization_digest: String,
}

impl PreparedAuthorizedChannelMerkleReleaseV1 {
    #[must_use]
    pub const fn authorization(&self) -> &crate::channel::ChannelReleaseAuthorizationBindingV1 {
        &self.authorization
    }

    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    #[must_use]
    pub fn publication_root(&self) -> &str {
        &self.release.merkle_root
    }

    pub fn canonical_call(&self) -> Result<Vec<u8>, SettlementError> {
        canonical_json_bytes(&self.release.call)
            .map_err(|error| SettlementError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmSignature {
    pub v: u8,
    pub r: String,
    pub s: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DualSignReleaseInput {
    pub(super) operator_private_key_hex: zeroize::Zeroizing<String>,
    pub observed_amount: MonetaryAmount,
}

impl DualSignReleaseInput {
    #[must_use]
    pub fn new(
        operator_private_key_hex: impl Into<String>,
        observed_amount: MonetaryAmount,
    ) -> Self {
        Self {
            operator_private_key_hex: zeroize::Zeroizing::new(operator_private_key_hex.into()),
            observed_amount,
        }
    }
}

impl std::fmt::Debug for DualSignReleaseInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DualSignReleaseInput")
            .field("operator_private_key_hex", &"[REDACTED]")
            .field("observed_amount", &self.observed_amount)
            .finish()
    }
}

#[cfg(test)]
mod dual_sign_release_input_tests {
    use super::*;

    #[test]
    fn debug_redacts_operator_private_key() {
        let input = DualSignReleaseInput::new(
            "private-key-material",
            MonetaryAmount {
                units: 1,
                currency: "USD".to_string(),
            },
        );

        let debug = format!("{input:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-key-material"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DualSignRegistryEvidence {
    pub chain_id: String,
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub block_number: u64,
    pub block_hash: String,
    pub observed_at: u64,
    pub operator_key_hash: String,
    pub settlement_key: String,
    pub registered_at: u64,
    pub operator_epoch: u64,
    pub active: bool,
}

impl From<DualSignRegistryEvidence>
    for chio_core::web3::settlement::Web3SettlementIdentityRegistryEvidence
{
    fn from(evidence: DualSignRegistryEvidence) -> Self {
        Self {
            chain_id: evidence.chain_id,
            identity_registry_contract: evidence.identity_registry_contract,
            operator_address: evidence.operator_address,
            block_number: evidence.block_number,
            block_hash: evidence.block_hash,
            observed_at: evidence.observed_at,
            operator_key_hash: evidence.operator_key_hash,
            settlement_key: evidence.settlement_key,
            registered_at: evidence.registered_at,
            operator_epoch: evidence.operator_epoch,
            active: evidence.active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DualSignRegistryEvidenceBinding {
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub settlement_key: String,
}

impl From<DualSignRegistryEvidenceBinding>
    for chio_core::web3::settlement::Web3SettlementIdentityRegistryEvidenceBinding
{
    fn from(binding: DualSignRegistryEvidenceBinding) -> Self {
        Self {
            identity_registry_contract: binding.identity_registry_contract,
            operator_address: binding.operator_address,
            settlement_key: binding.settlement_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDualSignRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_hash: String,
    pub digest: String,
    pub operator_epoch: u64,
    pub identity_registry_evidence: DualSignRegistryEvidence,
    pub identity_registry_evidence_binding: DualSignRegistryEvidenceBinding,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub signature: EvmSignature,
    pub(super) call: PreparedEvmCall,
}

impl PreparedDualSignRelease {
    #[must_use]
    pub fn commitment(
        &self,
        capability_commitment: String,
        operator_identity: String,
    ) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.chain_id.clone(),
            lane_kind: "evm_dual_signature".to_string(),
            capability_commitment,
            receipt_reference: self.receipt_hash.clone(),
            operator_identity,
            settlement_amount: self.observed_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowRefund {
    pub escrow_id: String,
    pub chain_id: String,
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondLockRequest {
    pub principal_address: String,
    pub bond: SignedCreditBond,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondLock {
    pub vault_id: String,
    pub bond_id_hash: String,
    pub facility_id_hash: String,
    pub operator_key_hash: String,
    pub collateral_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondRelease {
    pub vault_id: String,
    pub chain_id: String,
    pub operator_key_hash: String,
    pub evidence_hash: String,
    pub merkle_root: String,
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondImpair {
    pub vault_id: String,
    pub chain_id: String,
    pub operator_key_hash: String,
    pub evidence_hash: String,
    pub merkle_root: String,
    pub slash_amount_minor_units: u128,
    pub(super) call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondExpiry {
    pub vault_id: String,
    pub chain_id: String,
    pub(super) call: PreparedEvmCall,
}

mod sealed {
    use super::PreparedEvmCall;

    pub trait Sealed {
        fn call(&self) -> &PreparedEvmCall;
    }
}

pub trait PreparedEvmSubmission: sealed::Sealed {}

pub(super) fn prepared_submission_call<T: PreparedEvmSubmission + ?Sized>(
    prepared: &T,
) -> &PreparedEvmCall {
    sealed::Sealed::call(prepared)
}

macro_rules! prepared_evm_call_access {
    ($($type:ty),+ $(,)?) => {
        $(
            impl $type {
                #[must_use]
                pub const fn call(&self) -> &PreparedEvmCall {
                    &self.call
                }
            }

        )+
    };
}

macro_rules! prepared_evm_submission {
    ($($type:ty),+ $(,)?) => {
        $(

            impl sealed::Sealed for $type {
                fn call(&self) -> &PreparedEvmCall {
                    &self.call
                }
            }

            impl PreparedEvmSubmission for $type {}
        )+
    };
}

prepared_evm_call_access!(
    PreparedErc20Approval,
    PreparedRootPublication,
    PreparedEscrowCreate,
    PreparedMerkleRelease,
    PreparedDualSignRelease,
    PreparedEscrowRefund,
    PreparedBondLock,
    PreparedBondRelease,
    PreparedBondImpair,
    PreparedBondExpiry,
);

prepared_evm_submission!(
    PreparedErc20Approval,
    PreparedEscrowCreate,
    PreparedBondLock,
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmLogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmTransactionReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub status: bool,
    pub from_address: String,
    pub to_address: String,
    pub gas_used: u64,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<EvmLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EscrowSnapshot {
    pub escrow_id: String,
    pub depositor_address: String,
    pub beneficiary_address: String,
    pub deadline: u64,
    pub deposited_minor_units: u128,
    pub released_minor_units: u128,
    pub refunded: bool,
    pub remaining_minor_units: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmBondSnapshot {
    pub vault_id: String,
    pub principal_address: String,
    pub operator_key_hash: String,
    pub expires_at: u64,
    pub observed_at: u64,
    pub locked_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub reserve_requirement_ratio_bps: u16,
    pub slashed_minor_units: u128,
    pub released: bool,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcEnvelope {
    #[serde(rename = "jsonrpc")]
    pub(super) _jsonrpc: String,
    #[serde(rename = "id")]
    pub(super) _id: u64,
    pub(super) result: Option<Value>,
    pub(super) error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcError {
    pub(super) code: i64,
    pub(super) message: String,
    pub(super) data: Option<Value>,
}
