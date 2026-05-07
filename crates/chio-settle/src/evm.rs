use std::str::FromStr;
use std::thread;
use std::time::Duration;

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::MonetaryAmount;
use chio_core::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CreditBondLifecycleState,
    SignedCapitalExecutionInstruction, SignedCreditBond,
};
use chio_core::hashing::Hash;
use chio_core::merkle::leaf_hash;
use chio_core::receipt::ChioReceipt;
use chio_core::web3::{
    validate_web3_settlement_dispatch, validate_web3_settlement_execution_receipt,
    verify_anchor_inclusion_proof, verify_web3_identity_binding, AnchorInclusionProof,
    SignedWeb3IdentityBinding, Web3KeyBindingPurpose, Web3SettlementDispatchArtifact,
    Web3SettlementExecutionReceiptArtifact, Web3SettlementLifecycleState, Web3SettlementPath,
    Web3SettlementSupportBoundary, CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA,
    CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use chio_egress_contract::{client_builder_with_contract, send_with_contract};
use chio_web3_bindings::{ChioMerkleProof, IChioBondVault, IChioEscrow};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    ops::ensure_settlement_completion_flow_binding, SettlementChainConfig, SettlementCommitment,
    SettlementError,
};

sol! {
    interface IERC20ApproveOnly {
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmCall {
    pub from_address: String,
    pub to_address: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedErc20Approval {
    pub owner_address: String,
    pub token_address: String,
    pub spender_address: String,
    pub amount_minor_units: u128,
    pub call: PreparedEvmCall,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowCreate {
    pub expected_escrow_id: String,
    pub capability_commitment: String,
    pub settlement_amount_minor_units: u128,
    pub dispatch: Web3SettlementDispatchArtifact,
    pub call: PreparedEvmCall,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedMerkleRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_leaf_hash: String,
    pub merkle_root: String,
    pub partial: bool,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub call: PreparedEvmCall,
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
            receipt_reference: self.receipt_leaf_hash.clone(),
            operator_identity,
            settlement_amount: self.observed_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmSignature {
    pub v: u8,
    pub r: String,
    pub s: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DualSignReleaseInput {
    pub operator_private_key_hex: String,
    pub observed_amount: MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDualSignRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_hash: String,
    pub digest: String,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub signature: EvmSignature,
    pub call: PreparedEvmCall,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowRefund {
    pub escrow_id: String,
    pub chain_id: String,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondLockRequest {
    pub principal_address: String,
    pub bond: SignedCreditBond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondLock {
    pub vault_id: String,
    pub bond_id_hash: String,
    pub facility_id_hash: String,
    pub collateral_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondRelease {
    pub vault_id: String,
    pub chain_id: String,
    pub evidence_hash: String,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondImpair {
    pub vault_id: String,
    pub chain_id: String,
    pub evidence_hash: String,
    pub slash_amount_minor_units: u128,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondExpiry {
    pub vault_id: String,
    pub chain_id: String,
    pub call: PreparedEvmCall,
}

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
    pub expires_at: u64,
    pub locked_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub reserve_requirement_ratio_bps: u16,
    pub slashed_minor_units: u128,
    pub released: bool,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: u64,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub fn scale_chio_amount_to_token_minor_units(
    amount: &MonetaryAmount,
    config: &SettlementChainConfig,
) -> Result<u128, SettlementError> {
    config.validate()?;
    let chio_decimals = u32::from(config.policy.chio_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let amount_units = u128::from(amount.units);
    if token_decimals >= chio_decimals {
        let scale = 10_u128
            .checked_pow(token_decimals - chio_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        amount_units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))
    } else {
        let divisor = 10_u128
            .checked_pow(chio_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if amount_units % divisor != 0 {
            return Err(SettlementError::InvalidInput(
                "Chio amount cannot be represented exactly in settlement token units".to_string(),
            ));
        }
        Ok(amount_units / divisor)
    }
}

pub(crate) fn scale_token_minor_units_to_chio_amount(
    units: u128,
    currency: &str,
    config: &SettlementChainConfig,
) -> Result<MonetaryAmount, SettlementError> {
    let chio_decimals = u32::from(config.policy.chio_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let chio_units = if token_decimals >= chio_decimals {
        let divisor = 10_u128
            .checked_pow(token_decimals - chio_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if !units.is_multiple_of(divisor) {
            return Err(SettlementError::InvalidInput(
                "token amount cannot be represented exactly in Chio units".to_string(),
            ));
        }
        units / divisor
    } else {
        let scale = 10_u128
            .checked_pow(chio_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))?
    };
    let amount = u64::try_from(chio_units)
        .map_err(|_| SettlementError::InvalidInput("Chio amount does not fit u64".to_string()))?;
    Ok(MonetaryAmount {
        units: amount,
        currency: currency.to_string(),
    })
}

pub fn prepare_erc20_approval(
    token_address: &str,
    owner_address: &str,
    spender_address: &str,
    amount_minor_units: u128,
) -> Result<PreparedErc20Approval, SettlementError> {
    let spender = parse_address(spender_address, "spender_address")?;
    let amount = U256::from(amount_minor_units);
    let call = IERC20ApproveOnly::approveCall { spender, amount };
    Ok(PreparedErc20Approval {
        owner_address: owner_address.to_string(),
        token_address: token_address.to_string(),
        spender_address: spender_address.to_string(),
        amount_minor_units,
        call: PreparedEvmCall {
            from_address: owner_address.to_string(),
            to_address: token_address.to_string(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_web3_escrow_dispatch(
    config: &SettlementChainConfig,
    request: &EscrowDispatchRequest,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEscrowCreate, SettlementError> {
    config.validate()?;
    ensure_instruction_ready(
        config,
        &request.capital_instruction,
        &request.beneficiary_address,
    )?;
    ensure_settlement_binding(config, binding, Web3KeyBindingPurpose::Settle)?;

    if request.dispatch_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "dispatch_id is required".to_string(),
        ));
    }
    if request.capability_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "capability_id is required".to_string(),
        ));
    }

    let settlement_amount = request
        .capital_instruction
        .body
        .amount
        .clone()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch("capital instruction amount is required".to_string())
        })?;
    let amount_minor_units = scale_chio_amount_to_token_minor_units(&settlement_amount, config)?;
    let operator_key_hash = keccak256(binding.certificate.chio_public_key.as_bytes());
    let terms = IChioEscrow::EscrowTerms {
        capabilityId: hash_string_id(&request.capability_id),
        depositor: parse_address(&request.depositor_address, "depositor_address")?,
        beneficiary: parse_address(&request.beneficiary_address, "beneficiary_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        maxAmount: U256::from(amount_minor_units),
        deadline: U256::from(request.capital_instruction.body.execution_window.not_after),
        operator: parse_address(&config.operator_address, "operator_address")?,
        operatorKeyHash: operator_key_hash,
    };

    let derive_call = IChioEscrow::deriveEscrowIdCall {
        terms: terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let expected_escrow_id = IChioEscrow::deriveEscrowIdCall::abi_decode_returns(&result_bytes)
        .map_err(|error| {
            SettlementError::Serialization(format!("deriveEscrowId decode failed: {error}"))
        })?;
    let expected_escrow_id = format_b256(expected_escrow_id);
    let create_call_data = encode_call(IChioEscrow::createEscrowCall { terms });

    let dispatch = Web3SettlementDispatchArtifact {
        schema: CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
        dispatch_id: request.dispatch_id.clone(),
        issued_at: request.issued_at,
        trust_profile_id: request.trust_profile_id.clone(),
        contract_package_id: request.contract_package_id.clone(),
        chain_id: config.chain_id.clone(),
        capital_instruction: request.capital_instruction.clone(),
        bond: None,
        settlement_path: request.settlement_path,
        settlement_amount: settlement_amount.clone(),
        escrow_id: expected_escrow_id.clone(),
        escrow_contract: config.escrow_contract.clone(),
        bond_vault_contract: config.bond_vault_contract.clone(),
        beneficiary_address: request.beneficiary_address.clone(),
        support_boundary: Web3SettlementSupportBoundary {
            real_dispatch_supported: true,
            anchor_proof_required: request.settlement_path == Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: request.oracle_evidence_required_for_fx,
            custody_boundary_explicit: true,
            reversal_supported: true,
        },
        note: request.note.clone(),
    };
    validate_web3_settlement_dispatch(&dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;

    Ok(PreparedEscrowCreate {
        expected_escrow_id,
        capability_commitment: format_b256(hash_string_id(&request.capability_id)),
        settlement_amount_minor_units: amount_minor_units,
        dispatch,
        call: PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: create_call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_merkle_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    amount: EscrowExecutionAmount,
) -> Result<PreparedMerkleRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if dispatch.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "dispatch chain_id {} does not match config {}",
            dispatch.chain_id, config.chain_id
        )));
    }
    if dispatch.settlement_path != Web3SettlementPath::MerkleProof {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the Merkle settlement path".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
        if chain_anchor.chain_id != dispatch.chain_id {
            return Err(SettlementError::InvalidDispatch(
                "anchor proof chain does not match the settlement dispatch".to_string(),
            ));
        }
    }

    let proof = ChioMerkleProof {
        audit_path: anchor_proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(anchor_proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(anchor_proof.receipt_inclusion.proof.tree_size as u64),
    };
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let leaf = leaf_hash(&receipt_bytes);
    let observed_amount = match amount {
        EscrowExecutionAmount::Full => dispatch.settlement_amount.clone(),
        EscrowExecutionAmount::Partial(amount) => amount,
    };
    let amount_minor_units = scale_chio_amount_to_token_minor_units(&observed_amount, config)?;
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let call = if observed_amount == dispatch.settlement_amount {
        IChioEscrow::releaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            settledAmount: U256::from(amount_minor_units),
        }
        .abi_encode()
    } else {
        IChioEscrow::partialReleaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            amount: U256::from(amount_minor_units),
        }
        .abi_encode()
    };

    Ok(PreparedMerkleRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_leaf_hash: leaf.to_hex_prefixed(),
        merkle_root: anchor_proof.receipt_inclusion.merkle_root.to_hex_prefixed(),
        partial: observed_amount != dispatch.settlement_amount,
        settlement_amount_minor_units: amount_minor_units,
        observed_amount,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: format!("0x{}", hex::encode(call)),
            gas_limit: None,
        },
    })
}

pub fn prepare_dual_sign_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    receipt: &ChioReceipt,
    input: &DualSignReleaseInput,
) -> Result<PreparedDualSignRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if dispatch.settlement_path != Web3SettlementPath::DualSignature {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the dual-signature path".to_string(),
        ));
    }
    let verified = receipt
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "receipt signature verification failed".to_string(),
        ));
    }
    if input.observed_amount != dispatch.settlement_amount {
        return Err(SettlementError::Unsupported(
            "dual-signature release is bounded to full settlement on the official stack"
                .to_string(),
        ));
    }
    let amount_minor_units =
        scale_chio_amount_to_token_minor_units(&input.observed_amount, config)?;
    let receipt_hash = keccak256(
        canonical_json_bytes(&receipt.body())
            .map_err(|error| SettlementError::Serialization(error.to_string()))?,
    );
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let digest = dual_sign_digest(
        config,
        &config.escrow_contract,
        &escrow_id,
        &receipt_hash,
        amount_minor_units,
    )?;
    let signature = sign_digest(&input.operator_private_key_hex, &digest)?;

    let call = IChioEscrow::releaseWithSignatureCall {
        escrowId: escrow_id,
        receiptHash: receipt_hash,
        settledAmount: U256::from(amount_minor_units),
        v: signature.v,
        r: parse_b256_hex(&signature.r, "signature.r")?,
        s: parse_b256_hex(&signature.s, "signature.s")?,
    };

    Ok(PreparedDualSignRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_hash: format_b256(receipt_hash),
        digest: format_b256(digest),
        settlement_amount_minor_units: amount_minor_units,
        observed_amount: input.observed_amount.clone(),
        signature,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_escrow_refund(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    caller_address: &str,
) -> Result<PreparedEscrowRefund, SettlementError> {
    config.validate()?;
    let call = IChioEscrow::refundCall {
        escrowId: parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?,
    };
    Ok(PreparedEscrowRefund {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_bond_lock(
    config: &SettlementChainConfig,
    request: &BondLockRequest,
) -> Result<PreparedBondLock, SettlementError> {
    config.validate()?;
    let verified = request
        .bond
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "credit bond signature verification failed".to_string(),
        ));
    }
    if request.bond.body.lifecycle_state != CreditBondLifecycleState::Active {
        return Err(SettlementError::InvalidDispatch(
            "bond lifecycle must be active before on-chain lock".to_string(),
        ));
    }
    let terms = request.bond.body.report.terms.clone().ok_or_else(|| {
        SettlementError::InvalidDispatch("credit bond terms are required".to_string())
    })?;
    let collateral_minor_units =
        scale_chio_amount_to_token_minor_units(&terms.collateral_amount, config)?;
    let reserve_requirement_minor_units =
        scale_chio_amount_to_token_minor_units(&terms.reserve_requirement_amount, config)?;
    let bond_terms = IChioBondVault::BondTerms {
        bondId: hash_string_id(&request.bond.body.bond_id),
        facilityId: hash_string_id(&terms.facility_id),
        principal: parse_address(&request.principal_address, "principal_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        collateralAmount: U256::from(collateral_minor_units),
        reserveRequirementAmount: U256::from(reserve_requirement_minor_units),
        expiresAt: U256::from(request.bond.body.expires_at),
        reserveRequirementRatioBps: terms.reserve_ratio_bps,
        operator: parse_address(&config.operator_address, "operator_address")?,
    };
    let derive_call = IChioBondVault::deriveVaultIdCall {
        terms: bond_terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let vault_id =
        IChioBondVault::deriveVaultIdCall::abi_decode_returns(&result_bytes).map_err(|error| {
            SettlementError::Serialization(format!("deriveVaultId decode failed: {error}"))
        })?;
    let call_data = encode_call(IChioBondVault::lockBondCall { terms: bond_terms });

    Ok(PreparedBondLock {
        vault_id: format_b256(vault_id),
        bond_id_hash: format_b256(hash_string_id(&request.bond.body.bond_id)),
        facility_id_hash: format_b256(hash_string_id(&terms.facility_id)),
        collateral_minor_units,
        reserve_requirement_minor_units,
        call: PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_release(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondRelease, SettlementError> {
    config.validate()?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IChioBondVault::releaseBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondRelease {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_impair(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    slash_amount: &MonetaryAmount,
    beneficiaries: &[String],
    shares: &[MonetaryAmount],
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondImpair, SettlementError> {
    config.validate()?;
    if beneficiaries.is_empty() || beneficiaries.len() != shares.len() {
        return Err(SettlementError::InvalidInput(
            "beneficiaries and shares must be non-empty and aligned".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let slash_amount_minor_units = scale_chio_amount_to_token_minor_units(slash_amount, config)?;
    let mut share_units = Vec::with_capacity(shares.len());
    let mut total = 0_u128;
    for share in shares {
        let scaled = scale_chio_amount_to_token_minor_units(share, config)?;
        total = total
            .checked_add(scaled)
            .ok_or_else(|| SettlementError::InvalidInput("slash shares overflowed".to_string()))?;
        share_units.push(U256::from(scaled));
    }
    if total != slash_amount_minor_units {
        return Err(SettlementError::InvalidInput(
            "slash shares must sum to slash_amount".to_string(),
        ));
    }
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IChioBondVault::impairBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        slashAmount: U256::from(slash_amount_minor_units),
        beneficiaries: beneficiaries
            .iter()
            .map(|value| parse_address(value, "beneficiary"))
            .collect::<Result<Vec<_>, _>>()?,
        shares: share_units,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondImpair {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        slash_amount_minor_units,
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_expiry(
    config: &SettlementChainConfig,
    vault_id: &str,
    caller_address: &str,
) -> Result<PreparedBondExpiry, SettlementError> {
    config.validate()?;
    let call = IChioBondVault::expireReleaseCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    Ok(PreparedBondExpiry {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn finalize_escrow_dispatch(
    prepared: &PreparedEscrowCreate,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedEscrowCreate, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before escrow identity could be finalized",
            receipt.tx_hash
        )));
    }
    let escrow_id = extract_escrow_created_id(receipt, &prepared.call.to_address)?;
    let mut finalized = prepared.clone();
    finalized.expected_escrow_id = escrow_id.clone();
    finalized.dispatch.escrow_id = escrow_id;
    Ok(finalized)
}

pub fn finalize_bond_lock(
    prepared: &PreparedBondLock,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedBondLock, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before bond identity could be finalized",
            receipt.tx_hash
        )));
    }
    let (vault_id, bond_id_hash, facility_id_hash) =
        extract_bond_locked_identity(receipt, &prepared.call.to_address)?;
    if bond_id_hash != prepared.bond_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected bond {}, observed {}",
            prepared.bond_id_hash, bond_id_hash
        )));
    }
    if facility_id_hash != prepared.facility_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected facility {}, observed {}",
            prepared.facility_id_hash, facility_id_hash
        )));
    }
    let mut finalized = prepared.clone();
    finalized.vault_id = vault_id;
    Ok(finalized)
}

pub async fn static_validate_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    eth_call_raw(config, call).await
}

pub async fn estimate_call_gas(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<u64, SettlementError> {
    let result = rpc_call(config, "eth_estimateGas", json!([request_value(call)])).await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            SettlementError::Rpc("eth_estimateGas returned non-string".to_string())
        })?,
    )
}

pub async fn submit_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    let mut request = request_value(call);
    let gas_limit = match call.gas_limit {
        Some(gas_limit) => gas_limit,
        None => estimate_call_gas(config, call)
            .await?
            .saturating_mul(12)
            .saturating_div(10)
            .saturating_add(50_000),
    };
    request["gas"] = Value::String(format!("0x{gas_limit:x}"));
    let result = rpc_call(config, "eth_sendTransaction", json!([request])).await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_sendTransaction returned non-string".to_string()))
}

pub async fn confirm_transaction(
    config: &SettlementChainConfig,
    tx_hash: &str,
) -> Result<EvmTransactionReceipt, SettlementError> {
    for _ in 0..100 {
        let result = rpc_call(config, "eth_getTransactionReceipt", json!([tx_hash])).await?;
        if result.is_null() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let block_hash = result
            .get("blockHash")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing blockHash".to_string()))?
            .to_string();
        let block_number = parse_hex_u64(
            result
                .get("blockNumber")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing blockNumber".to_string()))?,
        )?;
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .map(|value| value == "0x1")
            .unwrap_or(false);
        let gas_used = parse_hex_u64(
            result
                .get("gasUsed")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing gasUsed".to_string()))?,
        )?;
        let from_address = result
            .get("from")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing from".to_string()))?
            .to_string();
        let to_address = result
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing to".to_string()))?
            .to_string();
        let logs = result
            .get("logs")
            .and_then(Value::as_array)
            .ok_or_else(|| SettlementError::Rpc("receipt missing logs".to_string()))?
            .iter()
            .map(parse_log_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let block = rpc_call(config, "eth_getBlockByHash", json!([block_hash, false])).await?;
        let observed_at = parse_hex_u64(
            block
                .get("timestamp")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("block missing timestamp".to_string()))?,
        )?;
        return Ok(EvmTransactionReceipt {
            tx_hash: tx_hash.to_string(),
            block_number,
            block_hash,
            status,
            from_address,
            to_address,
            gas_used,
            observed_at,
            logs,
        });
    }
    Err(SettlementError::Rpc(format!(
        "timed out waiting for transaction receipt {tx_hash}"
    )))
}

pub async fn read_escrow_snapshot(
    config: &SettlementChainConfig,
    escrow_id: &str,
) -> Result<EscrowSnapshot, SettlementError> {
    let call = IChioEscrow::getEscrowCall {
        escrowId: parse_b256_hex(escrow_id, "escrow_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioEscrow::getEscrowCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getEscrow decode failed: {error}"))
    })?;
    let deposited_minor_units = u256_to_u128(decoded.deposited, "escrow.deposited")?;
    let released_minor_units = u256_to_u128(decoded.released, "escrow.released")?;
    Ok(EscrowSnapshot {
        escrow_id: escrow_id.to_string(),
        depositor_address: format!("{:?}", decoded.terms.depositor),
        beneficiary_address: format!("{:?}", decoded.terms.beneficiary),
        deadline: decoded.terms.deadline.to::<u64>(),
        deposited_minor_units,
        released_minor_units,
        refunded: decoded.refunded,
        remaining_minor_units: deposited_minor_units.saturating_sub(released_minor_units),
    })
}

pub async fn read_bond_snapshot(
    config: &SettlementChainConfig,
    vault_id: &str,
) -> Result<EvmBondSnapshot, SettlementError> {
    let call = IChioBondVault::getBondCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioBondVault::getBondCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getBond decode failed: {error}"))
    })?;
    Ok(EvmBondSnapshot {
        vault_id: vault_id.to_string(),
        principal_address: format!("{:?}", decoded.terms.principal),
        expires_at: decoded.terms.expiresAt.to::<u64>(),
        locked_minor_units: u256_to_u128(decoded.lockedAmount, "bond.lockedAmount")?,
        reserve_requirement_minor_units: u256_to_u128(
            decoded.terms.reserveRequirementAmount,
            "bond.terms.reserveRequirementAmount",
        )?,
        reserve_requirement_ratio_bps: decoded.terms.reserveRequirementRatioBps,
        slashed_minor_units: u256_to_u128(decoded.slashedAmount, "bond.slashedAmount")?,
        released: decoded.released,
        expired: decoded.expired,
    })
}

pub fn build_failure_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    failure_reference: String,
    failure_reason: String,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let amount = dispatch.settlement_amount.clone();
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: chio_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: failure_reference,
            amount: amount.clone(),
        },
        lifecycle_state: Web3SettlementLifecycleState::Failed,
        settlement_reference,
        reconciled_anchor_proof: None,
        oracle_evidence: None,
        settled_amount: amount,
        reversal_of: None,
        failure_reason: Some(failure_reason),
        note: Some(
            "Runtime-marked failure after bounded retry or validation exhaustion.".to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}

pub fn build_reversal_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    tx_hash: String,
    observed_amount: MonetaryAmount,
    reversal_of: String,
    charged_back: bool,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: chio_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: tx_hash,
            amount: observed_amount.clone(),
        },
        lifecycle_state: if charged_back {
            Web3SettlementLifecycleState::ChargedBack
        } else {
            Web3SettlementLifecycleState::Reversed
        },
        settlement_reference,
        reconciled_anchor_proof: None,
        oracle_evidence: None,
        settled_amount: observed_amount,
        reversal_of: Some(reversal_of),
        failure_reason: None,
        note: Some(
            "Runtime-projected compensating settlement after dispute or operator recovery."
                .to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}

fn ensure_instruction_ready(
    config: &SettlementChainConfig,
    instruction: &SignedCapitalExecutionInstruction,
    beneficiary_address: &str,
) -> Result<(), SettlementError> {
    let verified = instruction
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "capital execution instruction signature verification failed".to_string(),
        ));
    }
    if instruction.body.action != CapitalExecutionInstructionAction::TransferFunds {
        return Err(SettlementError::InvalidDispatch(
            "only transfer_funds is supported by the official settlement runtime".to_string(),
        ));
    }
    if instruction.body.rail.kind != CapitalExecutionRailKind::Web3 {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction rail.kind must be web3".to_string(),
        ));
    }
    if instruction.body.rail.jurisdiction.as_deref() != Some(config.chain_id.as_str()) {
        return Err(SettlementError::InvalidDispatch(format!(
            "capital instruction jurisdiction {:?} does not match {}",
            instruction.body.rail.jurisdiction, config.chain_id
        )));
    }
    if instruction.body.amount.is_none() {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction amount is required".to_string(),
        ));
    }
    let governed_receipt_id = instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction governed_receipt_id is required".to_string(),
            )
        })?;
    if governed_receipt_id.trim().is_empty() {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction governed_receipt_id cannot be empty".to_string(),
        ));
    }
    let completion_flow_row_id = instruction
        .body
        .completion_flow_row_id
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction completion_flow_row_id is required".to_string(),
            )
        })?;
    ensure_settlement_completion_flow_binding(completion_flow_row_id, governed_receipt_id)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if !instruction
        .body
        .support_boundary
        .automatic_dispatch_supported
    {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction must explicitly enable automatic dispatch".to_string(),
        ));
    }
    let destination = instruction
        .body
        .rail
        .destination_account_ref
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction destination_account_ref is required".to_string(),
            )
        })?;
    if destination != beneficiary_address {
        return Err(SettlementError::InvalidDispatch(
            "beneficiary address must match capital instruction destination_account_ref"
                .to_string(),
        ));
    }
    parse_address(beneficiary_address, "beneficiary_address")?;
    Ok(())
}

fn ensure_settlement_binding(
    config: &SettlementChainConfig,
    binding: &SignedWeb3IdentityBinding,
    purpose: Web3KeyBindingPurpose,
) -> Result<(), SettlementError> {
    verify_web3_identity_binding(binding)
        .map_err(|error| SettlementError::InvalidBinding(error.to_string()))?;
    if !binding.certificate.purpose.contains(&purpose) {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not include {:?} purpose",
            purpose
        )));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &config.chain_id)
    {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not cover {}",
            config.chain_id
        )));
    }
    if binding.certificate.settlement_address != config.operator_address {
        return Err(SettlementError::InvalidBinding(
            "binding settlement address does not match the configured operator".to_string(),
        ));
    }
    Ok(())
}

fn proof_components(
    anchor_proof: &AnchorInclusionProof,
) -> Result<(ChioMerkleProof, B256, B256), SettlementError> {
    let proof = ChioMerkleProof {
        audit_path: anchor_proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(anchor_proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(anchor_proof.receipt_inclusion.proof.tree_size as u64),
    };
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let evidence_hash = hash_to_b256(&leaf_hash(&receipt_bytes));
    let root = hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root);
    Ok((proof, root, evidence_hash))
}

fn dual_sign_digest(
    config: &SettlementChainConfig,
    escrow_contract: &str,
    escrow_id: &B256,
    receipt_hash: &B256,
    amount_minor_units: u128,
) -> Result<B256, SettlementError> {
    let chain_id = parse_eip155_chain_id(&config.chain_id)?;
    let mut packed = Vec::with_capacity(32 + 20 + 32 + 32 + 32);
    packed.extend_from_slice(&u256_to_bytes32(U256::from(chain_id)));
    packed.extend_from_slice(parse_address(escrow_contract, "escrow_contract")?.as_slice());
    packed.extend_from_slice(escrow_id.as_slice());
    packed.extend_from_slice(receipt_hash.as_slice());
    packed.extend_from_slice(&u256_to_bytes32(U256::from(amount_minor_units)));
    Ok(keccak256(packed))
}

fn sign_digest(private_key_hex: &str, digest: &B256) -> Result<EvmSignature, SettlementError> {
    let secp = Secp256k1::new();
    let raw = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Signature(error.to_string()))?;
    let secret =
        SecretKey::from_byte_array(raw.try_into().map_err(|_| {
            SettlementError::Signature("expected a 32-byte private key".to_string())
        })?)
        .map_err(|error| SettlementError::Signature(error.to_string()))?;
    let message = Message::from_digest(*digest.as_ref());
    let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(message, &secret);
    let (recovery_id, bytes) = signature.serialize_compact();
    let v = 27 + i32::from(recovery_id) as u8;
    let r = format!("0x{}", hex::encode(&bytes[..32]));
    let s = format!("0x{}", hex::encode(&bytes[32..]));
    Ok(EvmSignature { v, r, s })
}

fn parse_log_entry(value: &Value) -> Result<EvmLogEntry, SettlementError> {
    let address = value
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing address".to_string()))?;
    parse_address(address, "log.address")?;
    let topics = value
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| SettlementError::Rpc("log missing topics".to_string()))?
        .iter()
        .map(|topic| {
            topic
                .as_str()
                .ok_or_else(|| SettlementError::Rpc("log topic was not a string".to_string()))
                .and_then(|topic| {
                    parse_b256_hex(topic, "log.topic")?;
                    Ok(topic.to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing data".to_string()))?
        .to_string();
    decode_hex_bytes(&data)?;
    let log_index = value
        .get("logIndex")
        .and_then(Value::as_str)
        .map(parse_hex_u64)
        .transpose()?;
    Ok(EvmLogEntry {
        address: address.to_string(),
        topics,
        data,
        log_index,
    })
}

fn extract_escrow_created_id(
    receipt: &EvmTransactionReceipt,
    escrow_contract: &str,
) -> Result<String, SettlementError> {
    extract_event_topic(
        receipt,
        escrow_contract,
        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
        1,
        "escrow_id",
    )
}

fn extract_bond_locked_identity(
    receipt: &EvmTransactionReceipt,
    bond_vault_contract: &str,
) -> Result<(String, String, String), SettlementError> {
    let log = find_single_contract_event(
        receipt,
        bond_vault_contract,
        "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
    )?;
    Ok((
        extract_topic_hex(log, 1, "vault_id")?,
        extract_topic_hex(log, 2, "bond_id")?,
        extract_topic_hex(log, 3, "facility_id")?,
    ))
}

fn extract_event_topic(
    receipt: &EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
    topic_index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let log = find_single_contract_event(receipt, contract_address, event_signature)?;
    extract_topic_hex(log, topic_index, field)
}

fn find_single_contract_event<'a>(
    receipt: &'a EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
) -> Result<&'a EvmLogEntry, SettlementError> {
    let contract = normalize_address(contract_address);
    let signature_hash = event_signature_hash(event_signature);
    let mut matches = receipt.logs.iter().filter(|log| {
        normalize_address(&log.address) == contract
            && log.topics.first().map(|topic| normalize_b256(topic)) == Some(signature_hash.clone())
    });
    let first = matches.next().ok_or_else(|| {
        SettlementError::InvalidDispatch(format!(
            "transaction {} did not emit {event_signature} from {contract_address}",
            receipt.tx_hash
        ))
    })?;
    if matches.next().is_some() {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} emitted multiple {event_signature} events from {contract_address}",
            receipt.tx_hash
        )));
    }
    Ok(first)
}

fn extract_topic_hex(
    log: &EvmLogEntry,
    index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let topic = log.topics.get(index).ok_or_else(|| {
        SettlementError::InvalidDispatch(format!("{field} missing from contract event topics"))
    })?;
    Ok(format_b256(parse_b256_hex(topic, field)?))
}

fn event_signature_hash(signature: &str) -> String {
    format_b256(keccak256(signature.as_bytes()))
}

fn normalize_address(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn normalize_b256(value: &str) -> String {
    value.to_ascii_lowercase()
}

async fn eth_call_raw(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    let result = rpc_call(config, "eth_call", json!([request_value(call), "latest"])).await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_call returned non-string".to_string()))
}

async fn rpc_call(
    config: &SettlementChainConfig,
    method: &str,
    params: Value,
) -> Result<Value, SettlementError> {
    config.validate_rpc_egress_contract()?;
    let contract = &config.egress_contract;
    let client = client_builder_with_contract(contract)
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build: {error}")))?;
    let request = client
        .post(&config.rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build request: {error}")))?;
    let response = send_with_contract(contract, &client, request)
        .await
        .map_err(|error| {
            SettlementError::Rpc(format!(
                "HttpEgressContract rejects settlement RPC dispatch: {error}"
            ))
        })?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(SettlementError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    envelope
        .result
        .ok_or_else(|| SettlementError::Rpc(format!("{method} returned no result")))
}

fn request_value(call: &PreparedEvmCall) -> Value {
    let mut value = json!({
        "from": call.from_address,
        "to": call.to_address,
        "data": call.data,
    });
    if let Some(gas_limit) = call.gas_limit {
        value["gas"] = Value::String(format!("0x{gas_limit:x}"));
    }
    value
}

fn parse_eip155_chain_id(chain_id: &str) -> Result<u64, SettlementError> {
    let raw = chain_id
        .strip_prefix("eip155:")
        .ok_or_else(|| SettlementError::Unsupported(format!("unsupported chain id {chain_id}")))?;
    raw.parse::<u64>()
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))
}

fn encode_call<C: SolCall>(call: C) -> String {
    format!("0x{}", hex::encode(call.abi_encode()))
}

fn parse_address(value: &str, field: &str) -> Result<Address, SettlementError> {
    Address::from_str(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))
}

fn parse_b256_hex(value: &str, field: &str) -> Result<B256, SettlementError> {
    let hash = Hash::from_hex(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))?;
    Ok(hash_to_b256(&hash))
}

fn hash_to_b256(hash: &Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

fn hash_string_id(value: &str) -> B256 {
    keccak256(value.as_bytes())
}

fn format_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, SettlementError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Serialization(error.to_string()))
}

fn parse_hex_u64(value: &str) -> Result<u64, SettlementError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| SettlementError::Rpc(error.to_string()))
}

fn u256_to_u128(value: U256, field: &str) -> Result<u128, SettlementError> {
    let limbs = value.into_limbs();
    if limbs[2] != 0 || limbs[3] != 0 {
        return Err(SettlementError::InvalidInput(format!(
            "{field} does not fit u128"
        )));
    }
    Ok((u128::from(limbs[1]) << 64) | u128::from(limbs[0]))
}

fn u256_to_bytes32(value: U256) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    value.to_be_bytes::<32>().clone_into(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SettlementPolicyConfig;
    use chio_core::credit::{
        CapitalBookQuery, CapitalBookSourceKind, CapitalExecutionAuthorityStep,
        CapitalExecutionInstructionArtifact, CapitalExecutionInstructionSupportBoundary,
        CapitalExecutionIntendedState, CapitalExecutionRail, CapitalExecutionReconciledState,
        CapitalExecutionRole, CapitalExecutionWindow, CreditBondArtifact, CreditBondDisposition,
        CreditBondFinding, CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport,
        CreditBondSupportBoundary, CreditBondTerms, CreditFacilityCapitalSource,
        CreditScorecardBand, CreditScorecardConfidence, CreditScorecardSummary,
        ExposureLedgerQuery, ExposureLedgerSummary,
    };
    use chio_core::crypto::Keypair;
    use chio_core::hashing::sha256_hex;
    use chio_core::receipt::{ChioReceiptBody, Decision, SignedExportEnvelope, ToolCallAction};
    use chio_core::web3::{Web3IdentityBindingCertificate, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA};
    use chio_core::web3::{Web3SettlementDispatchArtifact, Web3SettlementLifecycleState};
    use secp256k1::ecdsa::RecoveryId;
    use secp256k1::PublicKey as SecpPublicKey;
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    trait TestResultOk<T, E> {
        fn test_expect(self, context: &'static str) -> T;
        fn test_unwrap(self) -> T;
    }

    impl<T, E> TestResultOk<T, E> for Result<T, E> {
        fn test_expect(self, context: &'static str) -> T {
            match self {
                Ok(value) => value,
                Err(_) => panic!("{context}"),
            }
        }

        fn test_unwrap(self) -> T {
            match self {
                Ok(value) => value,
                Err(_) => panic!("expected Ok result"),
            }
        }
    }

    trait TestResultErr<T, E> {
        fn test_expect_err(self, context: &'static str) -> E;
    }

    impl<T, E> TestResultErr<T, E> for Result<T, E> {
        fn test_expect_err(self, context: &'static str) -> E {
            match self {
                Ok(_) => panic!("{context} unexpectedly succeeded"),
                Err(error) => error,
            }
        }
    }

    fn sample_config() -> SettlementChainConfig {
        sample_config_with_rpc_url("http://127.0.0.1:8545".to_string())
    }

    fn sample_config_with_rpc_url(rpc_url: String) -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: "eip155:31337".to_string(),
            network_name: "Ganache".to_string(),
            egress_contract: crate::settlement_devnet_rpc_egress_contract(&rpc_url)
                .test_expect("devnet egress contract"),
            rpc_url,
            escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
            bond_vault_contract: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
            identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
            root_registry_contract: "0x3a167ACFC3348a8f8df11BF383aF3cA86a8A2B42".to_string(),
            operator_address: "0x8d6d63c22D114C18C2a0dA6Db0A8972Ed9C40343".to_string(),
            settlement_token_symbol: "mUSDC".to_string(),
            settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
            oracle: crate::SettlementOracleConfig::default(),
            evidence_substrate: crate::SettlementEvidenceConfig::default(),
            policy: SettlementPolicyConfig::default(),
        }
    }

    fn hostname_rpc_contract(authority: &str) -> chio_egress_contract::HttpEgressContract {
        chio_egress_contract::HttpEgressContract {
            tenant_egress_namespace: "chio-settle-evm-unit-rpc".to_string(),
            allowed_schemes: std::collections::BTreeSet::from(["https".to_string()]),
            allowed_authority_set: std::collections::BTreeSet::from([authority.to_string()]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 64 * 1024 * 1024,
        }
    }

    struct MockJsonRpcServer {
        base_url: String,
        requests: Arc<Mutex<Vec<Value>>>,
        handle: thread::JoinHandle<()>,
    }

    struct MockRawHttpServer {
        base_url: String,
        handle: thread::JoinHandle<()>,
    }

    impl MockJsonRpcServer {
        fn spawn(responses: Vec<Value>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind mock RPC listener");
            let address = listener.local_addr().test_expect("listener address");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let request_log = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) =
                        listener.accept().test_expect("accept mock RPC connection");
                    let request = read_http_request(&mut stream);
                    request_log
                        .lock()
                        .test_expect("request log lock")
                        .push(parse_json_request(&request));
                    write_http_json_response(&mut stream, 200, &response);
                }
            });
            Self {
                base_url: format!("http://{}", address),
                requests,
                handle,
            }
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn requests(&self) -> Vec<Value> {
            self.requests.lock().test_expect("request log lock").clone()
        }

        fn join(self) {
            self.handle
                .join()
                .test_expect("mock RPC thread should exit cleanly");
        }
    }

    impl MockRawHttpServer {
        fn spawn(response: String) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").test_expect("bind mock raw HTTP listener");
            let address = listener.local_addr().test_expect("listener address");
            let base_url = format!("http://{}", address);
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener
                    .accept()
                    .test_expect("accept mock raw HTTP request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .test_expect("set read timeout");
                let _request = read_http_request(&mut stream);
                stream
                    .write_all(response.as_bytes())
                    .test_expect("write mock raw HTTP response");
                stream.flush().test_expect("flush mock raw HTTP response");
            });
            Self { base_url, handle }
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn join(self) {
            self.handle
                .join()
                .test_expect("mock raw HTTP thread should exit cleanly");
        }
    }

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    fn hex_dispatch() -> Web3SettlementDispatchArtifact {
        let mut dispatch = sample_dispatch();
        dispatch.escrow_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        dispatch.settlement_path = Web3SettlementPath::DualSignature;
        dispatch.support_boundary.anchor_proof_required = false;
        dispatch.support_boundary.oracle_evidence_required_for_fx = false;
        dispatch
    }

    fn sample_primary_proof() -> AnchorInclusionProof {
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
        ))
        .test_expect("parse primary proof example")
    }

    fn operator_keypair() -> Keypair {
        Keypair::from_seed(&[7u8; 32])
    }

    fn instruction_keypair() -> Keypair {
        Keypair::from_seed(&[9u8; 32])
    }

    fn bond_keypair() -> Keypair {
        Keypair::from_seed(&[11u8; 32])
    }

    fn sample_binding_for_config(config: &SettlementChainConfig) -> SignedWeb3IdentityBinding {
        let operator = operator_keypair();
        let certificate = Web3IdentityBindingCertificate {
            schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
            chio_identity: format!("did:chio:{}", operator.public_key().to_hex()),
            chio_public_key: operator.public_key(),
            chain_scope: vec![config.chain_id.clone()],
            purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
            settlement_address: config.operator_address.clone(),
            issued_at: 1_743_292_800,
            expires_at: 1_774_828_800,
            nonce: "evm-unit-binding".to_string(),
        };
        let (signature, _) = operator
            .sign_canonical(&certificate)
            .test_expect("binding signature");
        SignedWeb3IdentityBinding {
            certificate,
            signature,
        }
    }

    fn sample_capital_instruction(
        config: &SettlementChainConfig,
        beneficiary_address: &str,
        instruction_id: &str,
        amount_units: u64,
    ) -> SignedCapitalExecutionInstruction {
        let keypair = instruction_keypair();
        SignedExportEnvelope::sign(
            CapitalExecutionInstructionArtifact {
                schema: chio_core::credit::CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA
                    .to_string(),
                instruction_id: instruction_id.to_string(),
                issued_at: 1_743_292_800,
                query: CapitalBookQuery::default(),
                subject_key: "subject-1".to_string(),
                source_id: "capital-source:facility:facility-1".to_string(),
                source_kind: CapitalBookSourceKind::FacilityCommitment,
                governed_receipt_id: Some(format!("governed-{instruction_id}")),
                completion_flow_row_id: Some(format!(
                    "economic-completion-flow:governed-{instruction_id}"
                )),
                action: CapitalExecutionInstructionAction::TransferFunds,
                owner_role: CapitalExecutionRole::OperatorTreasury,
                counterparty_role: CapitalExecutionRole::AgentCounterparty,
                counterparty_id: "subject-1".to_string(),
                amount: Some(MonetaryAmount {
                    units: amount_units,
                    currency: "USD".to_string(),
                }),
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 1_743_292_700,
                        expires_at: 1_743_300_000,
                        note: Some("governed release".to_string()),
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-devnet".to_string(),
                        approved_at: 1_743_292_750,
                        expires_at: 1_743_300_000,
                        note: Some("official web3 stack".to_string()),
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 1_743_292_800,
                    not_after: 1_743_300_000,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Web3,
                    rail_id: "ganache-devnet-usdc".to_string(),
                    custody_provider_id: "custodian-devnet".to_string(),
                    source_account_ref: Some("vault:facility-main".to_string()),
                    destination_account_ref: Some(beneficiary_address.to_string()),
                    jurisdiction: Some(config.chain_id.clone()),
                },
                intended_state: CapitalExecutionIntendedState::PendingExecution,
                reconciled_state: CapitalExecutionReconciledState::NotObserved,
                related_instruction_id: None,
                observed_execution: None,
                support_boundary: CapitalExecutionInstructionSupportBoundary {
                    capital_book_authoritative: true,
                    external_execution_authoritative: false,
                    automatic_dispatch_supported: true,
                    custody_neutral_instruction_supported: false,
                },
                evidence_refs: Vec::new(),
                description: "release escrow over the unit-test devnet".to_string(),
            },
            &keypair,
        )
        .test_expect("capital instruction")
    }

    fn sample_receipt(
        keypair: &Keypair,
        capability_id: &str,
        receipt_id: &str,
        amount_units: u64,
        beneficiary_address: &str,
    ) -> ChioReceipt {
        ChioReceipt::sign(
            ChioReceiptBody {
                id: receipt_id.to_string(),
                timestamp: 1_743_292_800,
                capability_id: capability_id.to_string(),
                tool_server: "chio-settle".to_string(),
                tool_name: "release_escrow".to_string(),
                action: ToolCallAction::from_parameters(json!({
                    "amount": amount_units,
                    "currency": "USD",
                    "to": beneficiary_address,
                }))
                .test_expect("receipt params"),
                decision: Decision::Allow,
                content_hash: sha256_hex(format!("settlement:{receipt_id}").as_bytes()),
                policy_hash: sha256_hex(b"policy:web3"),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            keypair,
        )
        .test_expect("receipt")
    }

    fn sample_credit_bond(
        bond_id: &str,
        facility_id: &str,
        collateral_units: u64,
        reserve_units: u64,
    ) -> SignedCreditBond {
        let keypair = bond_keypair();
        SignedCreditBond::sign(
            CreditBondArtifact {
                schema: chio_core::credit::CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: bond_id.to_string(),
                issued_at: 1_743_292_800,
                expires_at: 1_743_300_000,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: chio_core::credit::CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 1_743_292_800,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: ExposureLedgerSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        active_decisions: 0,
                        superseded_decisions: 0,
                        actionable_receipts: 0,
                        pending_settlement_receipts: 0,
                        failed_settlement_receipts: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        truncated_receipts: false,
                        truncated_decisions: false,
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.97,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: Some(facility_id.to_string()),
                    terms: Some(CreditBondTerms {
                        facility_id: facility_id.to_string(),
                        credit_limit: MonetaryAmount {
                            units: collateral_units.saturating_mul(10),
                            currency: "USD".to_string(),
                        },
                        collateral_amount: MonetaryAmount {
                            units: collateral_units,
                            currency: "USD".to_string(),
                        },
                        reserve_requirement_amount: MonetaryAmount {
                            units: reserve_units,
                            currency: "USD".to_string(),
                        },
                        outstanding_exposure_amount: MonetaryAmount {
                            units: 0,
                            currency: "USD".to_string(),
                        },
                        reserve_ratio_bps: 10_000,
                        coverage_ratio_bps: 10_000,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: vec![CreditBondFinding {
                        code: CreditBondReasonCode::ReserveHeld,
                        description: "reserve state is held".to_string(),
                        evidence_refs: Vec::new(),
                    }],
                },
            },
            &keypair,
        )
        .test_expect("credit bond")
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        })
    }

    fn rpc_error(code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": code,
                "message": message,
            },
        })
    }

    fn encode_hex(data: Vec<u8>) -> String {
        format!("0x{}", hex::encode(data))
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).test_expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8(request).test_expect("request should be valid UTF-8")
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn parse_json_request(request: &str) -> Value {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        serde_json::from_str(body).test_expect("request body should be JSON")
    }

    fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http_status_text(status),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .test_expect("write mock response");
    }

    fn http_status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    #[test]
    fn amount_scaling_matches_usdc_convention() {
        let config = sample_config();
        let scaled = scale_chio_amount_to_token_minor_units(
            &MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
            &config,
        )
        .test_unwrap();
        assert_eq!(scaled, 1_500_000);
        let restored = scale_token_minor_units_to_chio_amount(scaled, "USD", &config).test_unwrap();
        assert_eq!(restored.units, 150);
    }

    #[test]
    fn dual_sign_digest_and_signature_are_recoverable() {
        let config = sample_config();
        let escrow_id = parse_b256_hex(
            "0x9e7e9d75ef18f8924a938f06c9838a8d6c6b9600dba88b35d28f6d54e2a71803",
            "escrow_id",
        )
        .test_unwrap();
        let receipt_hash = parse_b256_hex(
            "0x8d4f1c4eff7a6ec4cb9f3d5347ea50ccaa43d562e2eb06b1e0dab0633d14c0e3",
            "receipt_hash",
        )
        .test_unwrap();
        let digest = dual_sign_digest(
            &config,
            &config.escrow_contract,
            &escrow_id,
            &receipt_hash,
            1_500_000,
        )
        .test_unwrap();
        let signature = sign_digest(
            "0x1000000000000000000000000000000000000000000000000000000000000002",
            &digest,
        )
        .test_unwrap();
        let message = Message::from_digest(*digest.as_ref());
        let secp = Secp256k1::new();
        let recovery_id = RecoveryId::try_from((signature.v - 27) as i32).test_unwrap();
        let mut bytes = [0_u8; 64];
        bytes[..32]
            .copy_from_slice(&hex::decode(signature.r.trim_start_matches("0x")).test_unwrap());
        bytes[32..]
            .copy_from_slice(&hex::decode(signature.s.trim_start_matches("0x")).test_unwrap());
        let recoverable = RecoverableSignature::from_compact(&bytes, recovery_id).test_unwrap();
        let recovered = secp.recover_ecdsa(message, &recoverable).test_unwrap();
        let expected = SecpPublicKey::from_secret_key(
            &secp,
            &SecretKey::from_byte_array(
                hex::decode("1000000000000000000000000000000000000000000000000000000000000002")
                    .test_unwrap()
                    .try_into()
                    .test_unwrap(),
            )
            .test_unwrap(),
        );
        assert_eq!(recovered, expected);
    }

    #[test]
    fn prepares_erc20_approval_call_payloads() {
        let prepared = prepare_erc20_approval(
            "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8",
            "0x1000000000000000000000000000000000000001",
            "0x1000000000000000000000000000000000000002",
            42_000,
        )
        .test_unwrap();

        assert_eq!(prepared.amount_minor_units, 42_000);
        assert_eq!(prepared.call.from_address, prepared.owner_address);
        assert_eq!(prepared.call.to_address, prepared.token_address);
        assert!(prepared.call.data.starts_with("0x095ea7b3"));
    }

    #[test]
    fn prepares_refund_and_bond_expiry_calls() {
        let config = sample_config();
        let dispatch = hex_dispatch();

        let refund = prepare_escrow_refund(
            &config,
            &dispatch,
            "0x1000000000000000000000000000000000000009",
        )
        .test_unwrap();
        assert_eq!(refund.escrow_id, dispatch.escrow_id);
        assert_eq!(refund.call.to_address, config.escrow_contract);
        assert!(refund.call.data.starts_with("0x"));

        let expiry = prepare_bond_expiry(
            &config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0x1000000000000000000000000000000000000009",
        )
        .test_unwrap();
        assert_eq!(expiry.chain_id, config.chain_id);
        assert_eq!(expiry.call.to_address, config.bond_vault_contract);
    }

    #[test]
    fn builds_failure_and_reversal_receipts() {
        let dispatch = hex_dispatch();

        let failure = build_failure_receipt(
            &dispatch,
            "exec-failed".to_string(),
            "settlement-ref".to_string(),
            "tx-failed".to_string(),
            "node rejected tx".to_string(),
        )
        .test_unwrap();
        assert_eq!(
            failure.lifecycle_state,
            Web3SettlementLifecycleState::Failed
        );
        assert_eq!(failure.failure_reason.as_deref(), Some("node rejected tx"));

        let reversal = build_reversal_receipt(
            &dispatch,
            "exec-reversed".to_string(),
            "settlement-ref".to_string(),
            "tx-reverse".to_string(),
            dispatch.settlement_amount.clone(),
            "exec-failed".to_string(),
            true,
        )
        .test_unwrap();
        assert_eq!(
            reversal.lifecycle_state,
            Web3SettlementLifecycleState::ChargedBack
        );
        assert_eq!(reversal.reversal_of.as_deref(), Some("exec-failed"));
    }

    #[test]
    fn finalize_escrow_dispatch_reads_the_created_id_from_receipt_logs() {
        let dispatch = hex_dispatch();
        let prepared = PreparedEscrowCreate {
            expected_escrow_id: "0xdeadbeef".to_string(),
            capability_commitment: "0xfeedface".to_string(),
            settlement_amount_minor_units: 1_500_000,
            dispatch: dispatch.clone(),
            call: PreparedEvmCall {
                from_address: dispatch
                    .capital_instruction
                    .body
                    .rail
                    .destination_account_ref
                    .clone()
                    .unwrap_or_default(),
                to_address: dispatch.escrow_contract.clone(),
                data: "0x".to_string(),
                gas_limit: None,
            },
        };
        let observed_id = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let receipt = EvmTransactionReceipt {
            tx_hash: "0xabc".to_string(),
            block_number: 1,
            block_hash: "0x01".to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: dispatch.escrow_contract.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![EvmLogEntry {
                address: dispatch.escrow_contract.clone(),
                topics: vec![
                    event_signature_hash(
                        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
                    ),
                    observed_id.to_string(),
                ],
                data: "0x".to_string(),
                log_index: Some(0),
            }],
        };

        let finalized = finalize_escrow_dispatch(&prepared, &receipt).test_unwrap();

        assert_eq!(finalized.expected_escrow_id, observed_id);
        assert_eq!(finalized.dispatch.escrow_id, observed_id);
    }

    #[test]
    fn finalize_bond_lock_reads_identity_topics_from_receipt_logs() {
        let bond_id_hash = format_b256(hash_string_id("bond-1"));
        let facility_id_hash = format_b256(hash_string_id("facility-1"));
        let prepared = PreparedBondLock {
            vault_id: "0xold".to_string(),
            bond_id_hash: bond_id_hash.clone(),
            facility_id_hash: facility_id_hash.clone(),
            collateral_minor_units: 5,
            reserve_requirement_minor_units: 2,
            call: PreparedEvmCall {
                from_address: "0x1000000000000000000000000000000000000001".to_string(),
                to_address: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
                data: "0x".to_string(),
                gas_limit: None,
            },
        };
        let vault_id = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let receipt = EvmTransactionReceipt {
            tx_hash: "0xdef".to_string(),
            block_number: 1,
            block_hash: "0x02".to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: prepared.call.to_address.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![EvmLogEntry {
                address: prepared.call.to_address.clone(),
                topics: vec![
                    event_signature_hash(
                        "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
                    ),
                    vault_id.to_string(),
                    bond_id_hash,
                    facility_id_hash,
                ],
                data: "0x".to_string(),
                log_index: Some(0),
            }],
        };

        let finalized = finalize_bond_lock(&prepared, &receipt).test_unwrap();

        assert_eq!(finalized.vault_id, vault_id);
    }

    #[tokio::test]
    async fn rpc_helpers_cover_static_validation_gas_estimation_and_submission() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!("0xdeadbeef")),
            rpc_result(json!("0x5208")),
            rpc_result(json!("0x5208")),
            rpc_result(json!(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
        ]);
        let config = sample_config_with_rpc_url(server.base_url());
        let call = PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: None,
        };

        let validation = static_validate_call(&config, &call)
            .await
            .test_expect("eth_call should succeed");
        let estimated = estimate_call_gas(&config, &call)
            .await
            .test_expect("gas estimate should succeed");
        let tx_hash = submit_call(&config, &call)
            .await
            .test_expect("submission should succeed");

        let requests = server.requests();
        server.join();

        assert_eq!(validation, "0xdeadbeef");
        assert_eq!(estimated, 21_000);
        assert_eq!(
            tx_hash,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(requests[0]["method"], "eth_call");
        assert_eq!(requests[1]["method"], "eth_estimateGas");
        assert_eq!(requests[2]["method"], "eth_estimateGas");
        assert_eq!(requests[3]["method"], "eth_sendTransaction");
        assert_eq!(requests[3]["params"][0]["gas"], json!("0x125c0"));
    }

    #[test]
    fn rpc_config_accepts_hostname_rpc_url_with_pinned_resolver() {
        let mut config = sample_config();
        config.rpc_url = "https://mainnet-rpc.example.com".to_string();
        config.egress_contract = hostname_rpc_contract("mainnet-rpc.example.com");

        config
            .validate_rpc_egress_contract()
            .test_expect("hostname RPC dispatch is resolver-enforced");
    }

    #[tokio::test]
    async fn submit_call_respects_explicit_gas_limit() {
        let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ))]);
        let config = sample_config_with_rpc_url(server.base_url());
        let call = PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: Some(50_000),
        };

        let tx_hash = submit_call(&config, &call)
            .await
            .test_expect("submission should succeed");

        let requests = server.requests();
        server.join();

        assert_eq!(
            tx_hash,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "eth_sendTransaction");
        assert_eq!(requests[0]["params"][0]["gas"], json!("0xc350"));
    }

    #[tokio::test]
    async fn submit_call_rejects_rpc_redirects() {
        let server = MockRawHttpServer::spawn(
            "HTTP/1.1 302 Found\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
        let config = sample_config_with_rpc_url(server.base_url());
        let call = PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: Some(50_000),
        };

        let error = submit_call(&config, &call)
            .await
            .test_expect_err("submission RPC redirect should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("redirect chain length"),
            "unexpected settlement RPC redirect denial: {message}"
        );
    }

    #[tokio::test]
    async fn submit_call_rejects_oversized_rpc_responses() {
        let server = MockRawHttpServer::spawn(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
        let config = sample_config_with_rpc_url(server.base_url());
        let call = PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: Some(50_000),
        };

        let error = submit_call(&config, &call)
            .await
            .test_expect_err("oversized submission RPC response should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("response size"),
            "unexpected settlement RPC response-size denial: {message}"
        );
    }

    #[tokio::test]
    async fn confirm_transaction_decodes_receipt_and_block() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": [{
                    "address": "0x1000000000000000000000000000000000000002",
                    "topics": [
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                    ],
                    "data": "0x",
                    "logIndex": "0x0"
                }]
            })),
            rpc_result(json!({ "timestamp": "0x6553f100" })),
        ]);
        let config = sample_config_with_rpc_url(server.base_url());

        let receipt = confirm_transaction(
            &config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .test_expect("receipt should decode");

        let requests = server.requests();
        server.join();

        assert_eq!(receipt.block_number, 100);
        assert_eq!(receipt.block_hash, "0xabc");
        assert!(receipt.status);
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.observed_at, 1_700_000_000);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(requests[0]["method"], "eth_getTransactionReceipt");
        assert_eq!(requests[1]["method"], "eth_getBlockByHash");
    }

    #[tokio::test]
    async fn confirm_transaction_surfaces_rpc_and_shape_failures() {
        let error_server = MockJsonRpcServer::spawn(vec![rpc_error(-32000, "boom")]);
        let error_config = sample_config_with_rpc_url(error_server.base_url());
        let error = confirm_transaction(
            &error_config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .test_expect_err("RPC error should fail");
        error_server.join();
        assert!(matches!(error, SettlementError::Rpc(_)));

        let missing_server = MockJsonRpcServer::spawn(vec![rpc_result(json!({
            "blockNumber": "0x64",
            "status": "0x1",
            "gasUsed": "0x5208",
            "from": "0x1000000000000000000000000000000000000001",
            "to": "0x1000000000000000000000000000000000000002",
            "logs": []
        }))]);
        let missing_config = sample_config_with_rpc_url(missing_server.base_url());
        let error = confirm_transaction(
            &missing_config,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .test_expect_err("missing block hash should fail");
        missing_server.join();
        assert!(error.to_string().contains("receipt missing blockHash"));
    }

    #[tokio::test]
    async fn snapshot_readers_decode_contract_state() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                    terms: IChioEscrow::EscrowTerms {
                        capabilityId: B256::from([0x11; 32]),
                        depositor: Address::from_str("0x1000000000000000000000000000000000000001")
                            .test_unwrap(),
                        beneficiary: Address::from_str(
                            "0x1000000000000000000000000000000000000002",
                        )
                        .test_unwrap(),
                        token: Address::from_str("0x1000000000000000000000000000000000000003")
                            .test_unwrap(),
                        maxAmount: U256::from(1_500_000_u64),
                        deadline: U256::from(1_700_003_000_u64),
                        operator: Address::from_str("0x1000000000000000000000000000000000000004")
                            .test_unwrap(),
                        operatorKeyHash: B256::from([0x22; 32]),
                    },
                    deposited: U256::from(1_500_000_u64),
                    released: U256::from(250_000_u64),
                    refunded: true,
                })
            ))),
            rpc_result(json!(encode_hex(
                IChioBondVault::getBondCall::abi_encode_returns(&IChioBondVault::getBondReturn {
                    terms: IChioBondVault::BondTerms {
                        bondId: B256::from([0x31; 32]),
                        facilityId: B256::from([0x32; 32]),
                        principal: Address::from_str("0x1000000000000000000000000000000000000005",)
                            .test_unwrap(),
                        token: Address::from_str("0x1000000000000000000000000000000000000006")
                            .test_unwrap(),
                        collateralAmount: U256::from(2_000_000_u64),
                        reserveRequirementAmount: U256::from(250_000_u64),
                        expiresAt: U256::from(1_800_000_000_u64),
                        reserveRequirementRatioBps: 2500,
                        operator: Address::from_str("0x1000000000000000000000000000000000000007",)
                            .test_unwrap(),
                    },
                    lockedAmount: U256::from(2_000_000_u64),
                    slashedAmount: U256::from(125_000_u64),
                    released: false,
                    expired: true,
                })
            ))),
        ]);
        let config = sample_config_with_rpc_url(server.base_url());

        let escrow = read_escrow_snapshot(
            &config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .test_expect("escrow snapshot should decode");
        let bond = read_bond_snapshot(
            &config,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .test_expect("bond snapshot should decode");

        let requests = server.requests();
        server.join();

        assert_eq!(escrow.deadline, 1_700_003_000);
        assert_eq!(escrow.deposited_minor_units, 1_500_000);
        assert_eq!(escrow.released_minor_units, 250_000);
        assert_eq!(escrow.remaining_minor_units, 1_250_000);
        assert!(escrow.refunded);
        assert_eq!(bond.expires_at, 1_800_000_000);
        assert_eq!(bond.locked_minor_units, 2_000_000);
        assert_eq!(bond.reserve_requirement_minor_units, 250_000);
        assert_eq!(bond.reserve_requirement_ratio_bps, 2500);
        assert_eq!(bond.slashed_minor_units, 125_000);
        assert!(!bond.released);
        assert!(bond.expired);
        assert_eq!(requests[0]["method"], "eth_call");
        assert_eq!(requests[1]["method"], "eth_call");
    }

    #[tokio::test]
    async fn prepare_web3_escrow_dispatch_derives_expected_identity() {
        let expected_escrow_id = B256::from([0x33; 32]);
        let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
            IChioEscrow::deriveEscrowIdCall::abi_encode_returns(&expected_escrow_id)
        )))]);
        let config = sample_config_with_rpc_url(server.base_url());
        let binding = sample_binding_for_config(&config);
        let request = EscrowDispatchRequest {
            dispatch_id: "dispatch-unit-1".to_string(),
            issued_at: 1_743_292_800,
            trust_profile_id: "chio.unit".to_string(),
            contract_package_id: "chio.contracts.unit".to_string(),
            capability_id: "cap-escrow-unit".to_string(),
            depositor_address: "0x1000000000000000000000000000000000000001".to_string(),
            beneficiary_address: "0x1000000000000000000000000000000000000002".to_string(),
            capital_instruction: sample_capital_instruction(
                &config,
                "0x1000000000000000000000000000000000000002",
                "cei-unit-1",
                150,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("unit escrow dispatch".to_string()),
        };

        let prepared = prepare_web3_escrow_dispatch(&config, &request, &binding)
            .await
            .test_expect("dispatch should prepare");

        let requests = server.requests();
        server.join();

        assert_eq!(prepared.expected_escrow_id, format_b256(expected_escrow_id));
        assert_eq!(prepared.dispatch.escrow_id, format_b256(expected_escrow_id));
        assert_eq!(prepared.settlement_amount_minor_units, 1_500_000);
        assert_eq!(
            prepared.capability_commitment,
            format_b256(hash_string_id("cap-escrow-unit"))
        );
        assert_eq!(prepared.call.to_address, config.escrow_contract);
        assert_eq!(prepared.commitment().lane_kind, "evm_merkle_proof");
        assert_eq!(requests[0]["method"], "eth_call");
    }

    #[tokio::test]
    async fn prepare_web3_escrow_dispatch_rejects_binding_and_instruction_mismatches() {
        let config = sample_config();
        let mut binding = sample_binding_for_config(&config);
        binding.certificate.purpose = vec![Web3KeyBindingPurpose::Anchor];
        binding.signature = operator_keypair()
            .sign_canonical(&binding.certificate)
            .test_expect("binding signature")
            .0;

        let valid_request = EscrowDispatchRequest {
            dispatch_id: "dispatch-unit-2".to_string(),
            issued_at: 1_743_292_800,
            trust_profile_id: "chio.unit".to_string(),
            contract_package_id: "chio.contracts.unit".to_string(),
            capability_id: "cap-escrow-unit".to_string(),
            depositor_address: "0x1000000000000000000000000000000000000001".to_string(),
            beneficiary_address: "0x1000000000000000000000000000000000000002".to_string(),
            capital_instruction: sample_capital_instruction(
                &config,
                "0x1000000000000000000000000000000000000002",
                "cei-unit-2",
                150,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: None,
        };

        let binding_error = prepare_web3_escrow_dispatch(&config, &valid_request, &binding)
            .await
            .test_expect_err("binding without settle purpose should fail");
        assert!(binding_error
            .to_string()
            .contains("binding does not include Settle purpose"));

        let mismatch_request = EscrowDispatchRequest {
            capital_instruction: sample_capital_instruction(
                &config,
                "0x1000000000000000000000000000000000000003",
                "cei-unit-3",
                150,
            ),
            ..valid_request.clone()
        };
        let binding = sample_binding_for_config(&config);
        let instruction_error = prepare_web3_escrow_dispatch(&config, &mismatch_request, &binding)
            .await
            .test_expect_err("mismatched beneficiary should fail");
        assert!(instruction_error.to_string().contains(
            "beneficiary address must match capital instruction destination_account_ref"
        ));

        let mut provenance_request = valid_request;
        provenance_request
            .capital_instruction
            .body
            .completion_flow_row_id = Some("economic-completion-flow:other-receipt".to_string());
        let provenance_error = prepare_web3_escrow_dispatch(&config, &provenance_request, &binding)
            .await
            .test_expect_err("mismatched completion-flow provenance should fail");
        drop(provenance_error);
    }

    #[test]
    fn prepare_merkle_release_and_dual_sign_release_cover_full_and_partial_paths() {
        let mut config = sample_config();
        let proof = sample_primary_proof();
        let mut dispatch = sample_dispatch();
        dispatch.escrow_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        config.chain_id = dispatch.chain_id.clone();
        config.escrow_contract = dispatch.escrow_contract.clone();

        let full = prepare_merkle_release(&config, &dispatch, &proof, EscrowExecutionAmount::Full)
            .test_expect("full merkle release should prepare");
        let partial_amount = MonetaryAmount {
            units: dispatch.settlement_amount.units / 2,
            currency: dispatch.settlement_amount.currency.clone(),
        };
        let partial = prepare_merkle_release(
            &config,
            &dispatch,
            &proof,
            EscrowExecutionAmount::Partial(partial_amount.clone()),
        )
        .test_expect("partial merkle release should prepare");

        assert!(!full.partial);
        assert!(partial.partial);
        assert_eq!(full.escrow_id, dispatch.escrow_id);
        assert_eq!(full.call.to_address, config.escrow_contract);
        assert_eq!(partial.observed_amount, partial_amount);
        assert!(partial.settlement_amount_minor_units < full.settlement_amount_minor_units);

        let dual_dispatch = hex_dispatch();
        let mut dual_config = config.clone();
        dual_config.chain_id = dual_dispatch.chain_id.clone();
        dual_config.escrow_contract = dual_dispatch.escrow_contract.clone();
        let receipt = sample_receipt(
            &operator_keypair(),
            "cap-dual-unit",
            "rcpt-dual-unit",
            dual_dispatch.settlement_amount.units,
            &dual_dispatch.beneficiary_address,
        );
        let release =
            prepare_dual_sign_release(
                &dual_config,
                &dual_dispatch,
                &receipt,
                &DualSignReleaseInput {
                    operator_private_key_hex:
                        "0x1000000000000000000000000000000000000000000000000000000000000002"
                            .to_string(),
                    observed_amount: dual_dispatch.settlement_amount.clone(),
                },
            )
            .test_expect("dual-sign release should prepare");

        assert_eq!(release.call.to_address, dual_config.escrow_contract);
        assert_eq!(release.observed_amount, dual_dispatch.settlement_amount);
        assert!(release.signature.v >= 27);
        assert!(release.digest.starts_with("0x"));
    }

    #[tokio::test]
    async fn prepare_bond_lock_release_and_impair_cover_positive_paths() {
        let expected_vault_id = B256::from([0x44; 32]);
        let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
            IChioBondVault::deriveVaultIdCall::abi_encode_returns(&expected_vault_id)
        )))]);
        let config = sample_config_with_rpc_url(server.base_url());
        let bond = sample_credit_bond("bond-unit", "facility-unit", 400, 250);
        let prepared = prepare_bond_lock(
            &config,
            &BondLockRequest {
                principal_address: "0x1000000000000000000000000000000000000005".to_string(),
                bond,
            },
        )
        .await
        .test_expect("bond lock should prepare");

        let requests = server.requests();
        server.join();

        assert_eq!(prepared.vault_id, format_b256(expected_vault_id));
        assert_eq!(prepared.collateral_minor_units, 4_000_000);
        assert_eq!(prepared.reserve_requirement_minor_units, 2_500_000);
        assert_eq!(prepared.call.to_address, config.bond_vault_contract);
        assert_eq!(requests[0]["method"], "eth_call");

        let release = prepare_bond_release(
            &config,
            &prepared.vault_id,
            &config.operator_address,
            &sample_primary_proof(),
        )
        .test_expect("bond release should prepare");
        let impair = prepare_bond_impair(
            &config,
            &prepared.vault_id,
            &config.operator_address,
            &MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            },
            &["0x1000000000000000000000000000000000000006".to_string()],
            &[MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }],
            &sample_primary_proof(),
        )
        .test_expect("bond impair should prepare");

        assert_eq!(release.call.to_address, config.bond_vault_contract);
        assert_eq!(release.vault_id, prepared.vault_id);
        assert_eq!(impair.slash_amount_minor_units, 2_500_000);
        assert_eq!(impair.call.to_address, config.bond_vault_contract);
    }

    #[test]
    fn settlement_prep_helpers_fail_closed_on_invalid_inputs() {
        let config = sample_config();
        let invalid_dispatch = hex_dispatch();
        let share_error = prepare_bond_impair(
            &config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0x1000000000000000000000000000000000000001",
            &MonetaryAmount {
                units: 10,
                currency: "USD".to_string(),
            },
            &["0x1000000000000000000000000000000000000002".to_string()],
            &[MonetaryAmount {
                units: 9,
                currency: "USD".to_string(),
            }],
            &sample_primary_proof(),
        )
        .test_expect_err("mismatched shares should fail");
        assert!(share_error
            .to_string()
            .contains("slash shares must sum to slash_amount"));

        let finalize_error = finalize_escrow_dispatch(
            &PreparedEscrowCreate {
                expected_escrow_id: "0xdeadbeef".to_string(),
                capability_commitment: "0xfeedface".to_string(),
                settlement_amount_minor_units: 1_500_000,
                dispatch: invalid_dispatch.clone(),
                call: PreparedEvmCall {
                    from_address: invalid_dispatch.beneficiary_address.clone(),
                    to_address: invalid_dispatch.escrow_contract.clone(),
                    data: "0x".to_string(),
                    gas_limit: None,
                },
            },
            &EvmTransactionReceipt {
                tx_hash: "0xabc".to_string(),
                block_number: 1,
                block_hash: "0x01".to_string(),
                status: false,
                from_address: "0x1000000000000000000000000000000000000001".to_string(),
                to_address: invalid_dispatch.escrow_contract.clone(),
                gas_used: 21_000,
                observed_at: 1_744_000_000,
                logs: vec![],
            },
        )
        .test_expect_err("failed receipt should fail closed");
        assert!(finalize_error
            .to_string()
            .contains("failed before escrow identity could be finalized"));
    }

    #[test]
    fn helper_parsers_and_request_serialization_fail_closed() {
        let request = request_value(&PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: Some(21_000),
        });
        assert_eq!(request["gas"], serde_json::json!("0x5208"));

        let chain_error = parse_eip155_chain_id("solana:mainnet").test_expect_err("unsupported id");
        assert!(matches!(chain_error, SettlementError::Unsupported(_)));

        let log_error = parse_log_entry(&serde_json::json!({
            "address": "0x1000000000000000000000000000000000000001",
            "topics": ["0x1111111111111111111111111111111111111111111111111111111111111111"],
            "data": "not-hex"
        }))
        .test_expect_err("bad log payload");
        assert!(matches!(log_error, SettlementError::Serialization(_)));

        let overflow = u256_to_u128(U256::from_limbs([0, 0, 1, 0]), "field")
            .test_expect_err("overflowed u128");
        assert!(matches!(overflow, SettlementError::InvalidInput(_)));
    }
}
