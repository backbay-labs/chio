use bs58::decode as bs58_decode;
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::MonetaryAmount;
use chio_core::receipt::ChioReceipt;
use chio_core::web3::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3KeyBindingPurpose,
};
use serde::{Deserialize, Serialize};

use crate::config::SettlementEvidenceConfig;
use crate::{SettlementCommitment, SettlementError};

pub const SOLANA_ED25519_PROGRAM_ID: &str = "Ed25519SigVerify111111111111111111111111111";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SolanaSettlementConfig {
    pub chain_id: String,
    pub cluster: String,
    pub program_id: String,
    pub settlement_mint: String,
    pub chio_minor_unit_decimals: u8,
    pub token_minor_unit_decimals: u8,
    #[serde(default)]
    pub evidence_substrate: SettlementEvidenceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaSettlementRequest {
    pub dispatch_id: String,
    pub capability_id: String,
    pub payer_address: String,
    pub beneficiary_address: String,
    pub settlement_amount: MonetaryAmount,
    pub recent_blockhash: String,
    pub receipt: ChioReceipt,
    pub binding: SignedWeb3IdentityBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedSolanaSettlement {
    pub dispatch_id: String,
    pub chain_id: String,
    pub cluster: String,
    pub program_id: String,
    pub payer_address: String,
    pub beneficiary_address: String,
    pub settlement_mint: String,
    pub capability_commitment: String,
    pub receipt_hash: String,
    pub settlement_amount_minor_units: u64,
    pub recent_blockhash: String,
    pub ed25519_program_id: String,
    pub ed25519_signature: String,
    pub chio_public_key: String,
    pub instruction_data_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl PreparedSolanaSettlement {
    #[must_use]
    pub fn commitment(&self, settlement_amount: MonetaryAmount) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.chain_id.clone(),
            lane_kind: "solana_native_ed25519".to_string(),
            capability_commitment: self.capability_commitment.clone(),
            receipt_reference: self.receipt_hash.clone(),
            operator_identity: self.beneficiary_address.clone(),
            settlement_amount,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommitmentConsistencyReport {
    pub left_chain_id: String,
    pub right_chain_id: String,
    pub same_capability_commitment: bool,
    pub same_receipt_reference: bool,
    pub same_operator_identity: bool,
    pub same_amount: bool,
    pub overall_consistent: bool,
}

pub fn verify_solana_binding_and_receipt(
    chain_id: &str,
    receipt: &ChioReceipt,
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), SettlementError> {
    verify_web3_identity_binding(binding)
        .map_err(|error| SettlementError::InvalidBinding(error.to_string()))?;
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Settle)
    {
        return Err(SettlementError::InvalidBinding(
            "binding does not include settle purpose".to_string(),
        ));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|scope| scope == chain_id)
    {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not cover {chain_id}"
        )));
    }
    bs58_decode(&binding.certificate.settlement_address)
        .into_vec()
        .map_err(|error| SettlementError::InvalidBinding(error.to_string()))?;
    let verified = receipt
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "receipt Ed25519 signature verification failed".to_string(),
        ));
    }
    if receipt.kernel_key != binding.certificate.chio_public_key {
        return Err(SettlementError::InvalidBinding(
            "receipt kernel key must match the Solana settlement binding public key".to_string(),
        ));
    }
    Ok(())
}

pub fn prepare_solana_settlement(
    config: &SolanaSettlementConfig,
    request: &SolanaSettlementRequest,
) -> Result<PreparedSolanaSettlement, SettlementError> {
    config.validate()?;
    if config.chain_id.trim().is_empty()
        || config.cluster.trim().is_empty()
        || config.program_id.trim().is_empty()
        || config.settlement_mint.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "solana settlement config is incomplete".to_string(),
        ));
    }
    verify_solana_binding_and_receipt(&config.chain_id, &request.receipt, &request.binding)?;
    for (value, field) in [
        (request.payer_address.as_str(), "payer_address"),
        (request.beneficiary_address.as_str(), "beneficiary_address"),
        (request.recent_blockhash.as_str(), "recent_blockhash"),
    ] {
        bs58_decode(value)
            .into_vec()
            .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))?;
    }
    let scale = 10_u64
        .checked_pow(u32::from(
            config
                .token_minor_unit_decimals
                .checked_sub(config.chio_minor_unit_decimals)
                .ok_or_else(|| {
                    SettlementError::InvalidInput(
                        "token decimals must be >= Chio decimals for Solana settlement".to_string(),
                    )
                })?,
        ))
        .ok_or_else(|| SettlementError::InvalidInput("amount scaling overflowed".to_string()))?;
    let settlement_amount_minor_units = request
        .settlement_amount
        .units
        .checked_mul(scale)
        .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))?;
    let receipt_hash = chio_core::hashing::sha256(
        &canonical_json_bytes(&request.receipt.body())
            .map_err(|error| SettlementError::Serialization(error.to_string()))?,
    );
    let instruction_payload = serde_json::json!({
        "schema": "chio.settle.solana-release.v1",
        "dispatchId": request.dispatch_id,
        "capabilityCommitment": chio_core::hashing::sha256(request.capability_id.as_bytes()).to_hex_prefixed(),
        "receiptHash": receipt_hash.to_hex_prefixed(),
        "payer": request.payer_address,
        "beneficiary": request.beneficiary_address,
        "mint": config.settlement_mint,
        "amountMinorUnits": settlement_amount_minor_units,
        "recentBlockhash": request.recent_blockhash,
    });
    let instruction_data_hex = hex::encode(
        canonical_json_bytes(&instruction_payload)
            .map_err(|error| SettlementError::Serialization(error.to_string()))?,
    );
    Ok(PreparedSolanaSettlement {
        dispatch_id: request.dispatch_id.clone(),
        chain_id: config.chain_id.clone(),
        cluster: config.cluster.clone(),
        program_id: config.program_id.clone(),
        payer_address: request.payer_address.clone(),
        beneficiary_address: request.beneficiary_address.clone(),
        settlement_mint: config.settlement_mint.clone(),
        capability_commitment: chio_core::hashing::sha256(request.capability_id.as_bytes())
            .to_hex_prefixed(),
        receipt_hash: receipt_hash.to_hex_prefixed(),
        settlement_amount_minor_units,
        recent_blockhash: request.recent_blockhash.clone(),
        ed25519_program_id: SOLANA_ED25519_PROGRAM_ID.to_string(),
        ed25519_signature: request.receipt.signature.to_hex(),
        chio_public_key: request.receipt.kernel_key.to_hex(),
        instruction_data_hex,
        note: request.note.clone(),
    })
}

impl SolanaSettlementConfig {
    pub fn validate(&self) -> Result<(), SettlementError> {
        self.evidence_substrate.validate()?;
        Ok(())
    }
}

pub fn compare_commitments(
    left: &SettlementCommitment,
    right: &SettlementCommitment,
) -> CommitmentConsistencyReport {
    let same_capability_commitment = left.capability_commitment == right.capability_commitment;
    let same_receipt_reference = left.receipt_reference == right.receipt_reference;
    let same_operator_identity = left.operator_identity == right.operator_identity;
    let same_amount = left.settlement_amount == right.settlement_amount;
    CommitmentConsistencyReport {
        left_chain_id: left.chain_id.clone(),
        right_chain_id: right.chain_id.clone(),
        same_capability_commitment,
        same_receipt_reference,
        same_operator_identity,
        same_amount,
        overall_consistent: same_capability_commitment
            && same_receipt_reference
            && same_operator_identity
            && same_amount,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_core::web3::{SignedWeb3IdentityBinding, Web3IdentityBindingCertificate};
    use serde_json::json;

    use chio_test_support::prelude::*;

    fn sample_request() -> (SolanaSettlementConfig, SolanaSettlementRequest) {
        let keypair = Keypair::from_seed_hex(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .test_unwrap();
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rcpt-sol-1".to_string(),
                timestamp: 1_743_292_800,
                capability_id: "cap-sol-1".to_string(),
                tool_server: "chio-settle".to_string(),
                tool_name: "release_escrow".to_string(),
                action: ToolCallAction::from_parameters(json!({"amount": 125})).test_unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content".to_string(),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_unwrap();
        let binding = SignedWeb3IdentityBinding {
            certificate: Web3IdentityBindingCertificate {
                schema: chio_core::web3::CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
                chio_identity: format!("did:chio:{}", keypair.public_key().to_hex()),
                chio_public_key: keypair.public_key(),
                chain_scope: vec!["solana:mainnet".to_string()],
                purpose: vec![Web3KeyBindingPurpose::Settle],
                settlement_address: "9xQeWvG816bUx9EPjHmaT23yvVMm82oVxDgRmi1hM2Xy".to_string(),
                issued_at: 1_743_292_800,
                expires_at: 1_774_828_800,
                nonce: "nonce".to_string(),
            },
            signature: {
                let certificate = Web3IdentityBindingCertificate {
                    schema: chio_core::web3::CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
                    chio_identity: format!("did:chio:{}", keypair.public_key().to_hex()),
                    chio_public_key: keypair.public_key(),
                    chain_scope: vec!["solana:mainnet".to_string()],
                    purpose: vec![Web3KeyBindingPurpose::Settle],
                    settlement_address: "9xQeWvG816bUx9EPjHmaT23yvVMm82oVxDgRmi1hM2Xy".to_string(),
                    issued_at: 1_743_292_800,
                    expires_at: 1_774_828_800,
                    nonce: "nonce".to_string(),
                };
                keypair.sign_canonical(&certificate).test_unwrap().0
            },
        };
        (
            SolanaSettlementConfig {
                chain_id: "solana:mainnet".to_string(),
                cluster: "mainnet-beta".to_string(),
                program_id: "11111111111111111111111111111111".to_string(),
                settlement_mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                chio_minor_unit_decimals: 2,
                token_minor_unit_decimals: 6,
                evidence_substrate: SettlementEvidenceConfig::default(),
            },
            SolanaSettlementRequest {
                dispatch_id: "dispatch-sol-1".to_string(),
                capability_id: "cap-sol-1".to_string(),
                payer_address: "9xQeWvG816bUx9EPjHmaT23yvVMm82oVxDgRmi1hM2Xy".to_string(),
                beneficiary_address: "7Yzjsq4LwTnQL4Z1cdq9VHtV6nRvWmvMRdqsiE9zraFM".to_string(),
                settlement_amount: MonetaryAmount {
                    units: 125,
                    currency: "USD".to_string(),
                },
                recent_blockhash: "8f1dWnLxkn6Ne1ASt1MSQd6hw2yffA9H9n1tFoZT3zh7".to_string(),
                receipt,
                binding,
                note: None,
            },
        )
    }

    #[test]
    fn solana_path_verifies_binding_and_receipt() {
        let (config, request) = sample_request();
        let prepared = prepare_solana_settlement(&config, &request).test_unwrap();
        assert_eq!(prepared.settlement_amount_minor_units, 1_250_000);
        assert_eq!(prepared.ed25519_program_id, SOLANA_ED25519_PROGRAM_ID);
    }

    #[test]
    fn solana_path_rejects_invalid_evidence_substrate() {
        let (mut config, request) = sample_request();
        config.evidence_substrate.checkpoint_statements = false;

        let error = prepare_solana_settlement(&config, &request).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("kernel-signed checkpoint statements"));
    }

    #[test]
    fn commitment_comparison_detects_parity() {
        let left = SettlementCommitment {
            chain_id: "eip155:8453".to_string(),
            lane_kind: "evm_dual_signature".to_string(),
            capability_commitment: "0x01".to_string(),
            receipt_reference: "0x02".to_string(),
            operator_identity: "operator".to_string(),
            settlement_amount: MonetaryAmount {
                units: 10,
                currency: "USD".to_string(),
            },
        };
        let right = SettlementCommitment {
            chain_id: "solana:mainnet".to_string(),
            lane_kind: "solana_native_ed25519".to_string(),
            capability_commitment: "0x01".to_string(),
            receipt_reference: "0x02".to_string(),
            operator_identity: "operator".to_string(),
            settlement_amount: MonetaryAmount {
                units: 10,
                currency: "USD".to_string(),
            },
        };
        let report = compare_commitments(&left, &right);
        assert!(report.overall_consistent);
    }
}
