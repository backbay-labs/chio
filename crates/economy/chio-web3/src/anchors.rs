use alloy_primitives::keccak256;
use serde::{Deserialize, Serialize};

pub use chio_core_types::oracle::OracleConversionEvidence;

use crate::canonical::canonical_json_bytes;
use crate::crypto::{Keypair, PublicKey, Signature, SigningAlgorithm};
use crate::error::Web3ContractError;
use crate::hashing::Hash;
use crate::identity::{
    validate_web3_identity_binding, verify_web3_identity_binding, SignedWeb3IdentityBinding,
    Web3KeyBindingPurpose,
};
use crate::merkle::{leaf_hash, MerkleProof};
use crate::receipt::body::ChioReceipt;
use crate::validation::{ensure_non_empty, evm_addresses_match};

pub const CHIO_CHECKPOINT_STATEMENT_SCHEMA: &str = "chio.checkpoint_statement.v1";
pub const CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA: &str = "chio.anchor-inclusion-proof.v1";
pub const CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA: &str = "chio.oracle-conversion-evidence.v1";
pub const CHIO_LINK_ORACLE_AUTHORITY: &str = "chio_link_runtime_v1";
pub const CHIO_ANCHOR_CONTROL_STATE_SCHEMA: &str = "chio.anchor.control-state.v1";
pub const CHIO_ANCHOR_CONTROL_TRACE_SCHEMA: &str = "chio.anchor.control-trace.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ReceiptInclusion {
    pub checkpoint_seq: u64,
    pub merkle_root: Hash,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3CheckpointStatement {
    pub schema: String,
    pub checkpoint_seq: u64,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub tree_size: u64,
    pub merkle_root: Hash,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainAnchorRecord {
    pub chain_id: String,
    pub contract_address: String,
    pub operator_address: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub operator_key_hash: String,
    pub operator_epoch: u64,
    pub anchored_merkle_root: Hash,
    pub anchored_checkpoint_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3BitcoinAnchor {
    pub method: String,
    pub ots_proof_b64: String,
    pub bitcoin_block_height: u64,
    pub bitcoin_block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SuperRootInclusion {
    pub super_root: Hash,
    pub proof: MerkleProof,
    pub aggregated_checkpoint_start: u64,
    pub aggregated_checkpoint_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorInclusionProof {
    pub schema: String,
    pub receipt: ChioReceipt,
    pub receipt_inclusion: Web3ReceiptInclusion,
    pub checkpoint_statement: Web3CheckpointStatement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_anchor: Option<Web3ChainAnchorRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin_anchor: Option<Web3BitcoinAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_root_inclusion: Option<Web3SuperRootInclusion>,
    pub key_binding_certificate: SignedWeb3IdentityBinding,
}

pub(crate) fn expected_operator_key_hash(
    public_key: &PublicKey,
) -> Result<Hash, Web3ContractError> {
    if public_key.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(Web3ContractError::InvalidBinding(format!(
            "operator key hash requires an Ed25519 public key, got {:?}",
            public_key.algorithm()
        )));
    }
    Ok(Hash::from_bytes(*keccak256(public_key.as_bytes()).as_ref()))
}

pub fn validate_oracle_conversion_evidence(
    evidence: &OracleConversionEvidence,
) -> Result<(), Web3ContractError> {
    if evidence.schema != CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    for field in [
        &evidence.base,
        &evidence.quote,
        &evidence.authority,
        &evidence.source,
        &evidence.feed_address,
        &evidence.original_currency,
        &evidence.grant_currency,
    ] {
        ensure_non_empty(field, "oracle_conversion_evidence.field")?;
    }
    if evidence.authority != CHIO_LINK_ORACLE_AUTHORITY {
        return Err(Web3ContractError::InvalidProof(format!(
            "oracle conversion evidence authority {} is unsupported",
            evidence.authority
        )));
    }
    if evidence.rate_denominator == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence rate_denominator must be non-zero".to_string(),
        ));
    }
    if evidence.max_age_seconds == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence max_age_seconds must be non-zero".to_string(),
        ));
    }
    if evidence.cache_age_seconds > evidence.max_age_seconds {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence is stale".to_string(),
        ));
    }
    if evidence.original_cost_units == 0 || evidence.converted_cost_units == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence cost units must be non-zero".to_string(),
        ));
    }
    if evidence.base != evidence.original_currency {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence base must match original_currency".to_string(),
        ));
    }
    if evidence.quote != evidence.grant_currency {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence quote must match grant_currency".to_string(),
        ));
    }
    let expected_converted_cost_units = expected_oracle_converted_cost_units(evidence)?;
    if evidence.converted_cost_units != expected_converted_cost_units {
        return Err(Web3ContractError::InvalidProof(format!(
            "oracle conversion evidence converted_cost_units must equal {expected_converted_cost_units}"
        )));
    }
    Ok(())
}

pub fn sign_oracle_conversion_evidence(
    evidence: &mut OracleConversionEvidence,
    keypair: &Keypair,
) -> Result<(), Web3ContractError> {
    evidence.oracle_public_key = Some(keypair.public_key());
    evidence.signature = None;
    let body = oracle_conversion_evidence_signature_body(evidence);
    let (signature, _) = keypair.sign_canonical(&body).map_err(|error| {
        Web3ContractError::InvalidProof(format!(
            "oracle conversion evidence signing failed: {error}"
        ))
    })?;
    evidence.signature = Some(signature);
    Ok(())
}

pub fn verify_oracle_conversion_evidence_signature(
    evidence: &OracleConversionEvidence,
    trusted_oracle_keys: &[PublicKey],
) -> Result<(), Web3ContractError> {
    if trusted_oracle_keys.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "trusted public settlement oracle keys missing".to_string(),
        ));
    }
    let oracle_public_key = evidence.oracle_public_key.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("oracle conversion evidence signer key missing".to_string())
    })?;
    if !trusted_oracle_keys
        .iter()
        .any(|trusted_key| trusted_key == oracle_public_key)
    {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence signer key is not trusted".to_string(),
        ));
    }
    let signature = evidence.signature.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("oracle conversion evidence signature missing".to_string())
    })?;
    let body = oracle_conversion_evidence_signature_body(evidence);
    let signature_valid = oracle_public_key
        .verify_canonical(&body, signature)
        .map_err(|error| {
            Web3ContractError::InvalidProof(format!(
                "oracle conversion evidence signature verification failed: {error}"
            ))
        })?;
    if signature_valid {
        Ok(())
    } else {
        Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence signature verification failed".to_string(),
        ))
    }
}

fn oracle_conversion_evidence_signature_body(
    evidence: &OracleConversionEvidence,
) -> OracleConversionEvidence {
    let mut body = evidence.clone();
    body.signature = None;
    body
}

fn expected_oracle_converted_cost_units(
    evidence: &OracleConversionEvidence,
) -> Result<u64, Web3ContractError> {
    let base_minor_units = oracle_minor_units_per_unit(&evidence.original_currency)?;
    let quote_minor_units = oracle_minor_units_per_unit(&evidence.grant_currency)?;
    let numerator = u128::from(evidence.original_cost_units)
        .checked_mul(u128::from(evidence.rate_numerator))
        .and_then(|value| value.checked_mul(quote_minor_units))
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "oracle conversion evidence numerator overflowed".to_string(),
            )
        })?;
    let denominator = base_minor_units
        .checked_mul(u128::from(evidence.rate_denominator))
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "oracle conversion evidence denominator overflowed".to_string(),
            )
        })?;
    let converted = numerator.div_ceil(denominator);
    u64::try_from(converted).map_err(|_| {
        Web3ContractError::InvalidProof(
            "oracle conversion evidence converted_cost_units overflowed".to_string(),
        )
    })
}

fn oracle_minor_units_per_unit(currency: &str) -> Result<u128, Web3ContractError> {
    match currency {
        "USD" | "EUR" | "GBP" => Ok(100),
        "JPY" => Ok(1),
        "USDC" | "USDT" => Ok(1_000_000),
        "BTC" => Ok(100_000_000),
        "ETH" | "LINK" => Ok(1_000_000_000_000_000_000),
        other => Err(Web3ContractError::InvalidProof(format!(
            "oracle conversion evidence currency {other} is unsupported"
        ))),
    }
}
pub fn validate_anchor_inclusion_proof(
    proof: &AnchorInclusionProof,
) -> Result<(), Web3ContractError> {
    if proof.schema != CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(proof.schema.clone()));
    }
    validate_web3_identity_binding(&proof.key_binding_certificate)?;
    if proof.receipt.id.trim().is_empty() {
        return Err(Web3ContractError::MissingField(
            "anchor_inclusion.receipt.id",
        ));
    }
    if proof.receipt_inclusion.proof.tree_size == 0 {
        return Err(Web3ContractError::InvalidProof(
            "anchor inclusion proof tree_size must be non-zero".to_string(),
        ));
    }
    if proof.receipt_inclusion.proof.leaf_index >= proof.receipt_inclusion.proof.tree_size {
        return Err(Web3ContractError::InvalidProof(
            "anchor inclusion proof leaf_index exceeds tree_size".to_string(),
        ));
    }
    if proof.receipt_inclusion.checkpoint_seq != proof.checkpoint_statement.checkpoint_seq {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion checkpoint_seq must match checkpoint statement".to_string(),
        ));
    }
    if proof.receipt_inclusion.merkle_root != proof.checkpoint_statement.merkle_root {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion merkle_root must match checkpoint statement".to_string(),
        ));
    }
    if proof.checkpoint_statement.schema != CHIO_CHECKPOINT_STATEMENT_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            proof.checkpoint_statement.schema.clone(),
        ));
    }
    if proof.checkpoint_statement.batch_start_seq > proof.checkpoint_statement.batch_end_seq {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement batch_start_seq must be <= batch_end_seq".to_string(),
        ));
    }
    if proof.checkpoint_statement.tree_size == 0 {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement tree_size must be non-zero".to_string(),
        ));
    }
    if proof.checkpoint_statement.tree_size as usize != proof.receipt_inclusion.proof.tree_size {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement tree_size must match receipt inclusion proof".to_string(),
        ));
    }
    if let Some(chain_anchor) = proof.chain_anchor.as_ref() {
        ensure_non_empty(
            &chain_anchor.chain_id,
            "anchor_inclusion.chain_anchor.chain_id",
        )?;
        ensure_non_empty(
            &chain_anchor.contract_address,
            "anchor_inclusion.chain_anchor.contract_address",
        )?;
        ensure_non_empty(
            &chain_anchor.operator_address,
            "anchor_inclusion.chain_anchor.operator_address",
        )?;
        ensure_non_empty(
            &chain_anchor.tx_hash,
            "anchor_inclusion.chain_anchor.tx_hash",
        )?;
        ensure_non_empty(
            &chain_anchor.block_hash,
            "anchor_inclusion.chain_anchor.block_hash",
        )?;
        let operator_key_hash =
            Hash::from_hex(&chain_anchor.operator_key_hash).map_err(|error| {
                Web3ContractError::InvalidBinding(format!(
                    "chain anchor operator_key_hash must be a 32-byte hex hash: {error}"
                ))
            })?;
        if operator_key_hash == Hash::zero() {
            return Err(Web3ContractError::InvalidBinding(
                "chain anchor operator_key_hash must not be zero".to_string(),
            ));
        }
        if chain_anchor.operator_epoch == 0 {
            return Err(Web3ContractError::InvalidBinding(
                "chain anchor operator_epoch must be non-zero".to_string(),
            ));
        }
        let expected_operator_key =
            expected_operator_key_hash(&proof.key_binding_certificate.certificate.chio_public_key)?;
        if operator_key_hash != expected_operator_key {
            return Err(Web3ContractError::InvalidBinding(
                "chain anchor operator_key_hash must match binding certificate public key"
                    .to_string(),
            ));
        }
        if chain_anchor.anchored_checkpoint_seq != proof.checkpoint_statement.checkpoint_seq {
            return Err(Web3ContractError::InvalidProof(
                "chain anchor checkpoint seq must match checkpoint statement".to_string(),
            ));
        }
        if chain_anchor.anchored_merkle_root != proof.checkpoint_statement.merkle_root {
            return Err(Web3ContractError::InvalidProof(
                "chain anchor root must match checkpoint statement".to_string(),
            ));
        }
        if !evm_addresses_match(
            &chain_anchor.operator_address,
            &proof.key_binding_certificate.certificate.settlement_address,
        )? {
            return Err(Web3ContractError::InvalidBinding(
                "chain anchor operator address must match settlement binding".to_string(),
            ));
        }
        if !proof
            .key_binding_certificate
            .certificate
            .purpose
            .contains(&Web3KeyBindingPurpose::Anchor)
        {
            return Err(Web3ContractError::InvalidBinding(
                "anchor proof requires a binding certificate scoped to anchor".to_string(),
            ));
        }
        if !proof
            .key_binding_certificate
            .certificate
            .chain_scope
            .iter()
            .any(|chain_id| chain_id == &chain_anchor.chain_id)
        {
            return Err(Web3ContractError::InvalidBinding(format!(
                "binding certificate does not cover anchor chain {}",
                chain_anchor.chain_id
            )));
        }
    }
    if let Some(bitcoin_anchor) = proof.bitcoin_anchor.as_ref() {
        ensure_non_empty(
            &bitcoin_anchor.method,
            "anchor_inclusion.bitcoin_anchor.method",
        )?;
        ensure_non_empty(
            &bitcoin_anchor.ots_proof_b64,
            "anchor_inclusion.bitcoin_anchor.ots_proof_b64",
        )?;
        ensure_non_empty(
            &bitcoin_anchor.bitcoin_block_hash,
            "anchor_inclusion.bitcoin_anchor.bitcoin_block_hash",
        )?;
        if proof.super_root_inclusion.is_none() {
            return Err(Web3ContractError::InvalidProof(
                "Bitcoin anchor requires super-root inclusion metadata".to_string(),
            ));
        }
    }
    if let Some(super_root) = proof.super_root_inclusion.as_ref() {
        if super_root.aggregated_checkpoint_start > super_root.aggregated_checkpoint_end {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion checkpoint range must be ordered".to_string(),
            ));
        }
        if proof.checkpoint_statement.checkpoint_seq < super_root.aggregated_checkpoint_start
            || proof.checkpoint_statement.checkpoint_seq > super_root.aggregated_checkpoint_end
        {
            return Err(Web3ContractError::InvalidProof(
                "checkpoint statement must fall within the super-root aggregation range"
                    .to_string(),
            ));
        }
        if super_root.proof.tree_size == 0 {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion tree_size must be non-zero".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn verify_checkpoint_statement(
    statement: &Web3CheckpointStatement,
) -> Result<(), Web3ContractError> {
    let body = checkpoint_statement_body(statement);
    let verified = statement
        .kernel_key
        .verify_canonical(&body, &statement.signature)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if !verified {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement signature verification failed".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_anchor_inclusion_proof(
    proof: &AnchorInclusionProof,
) -> Result<(), Web3ContractError> {
    validate_anchor_inclusion_proof(proof)?;
    let receipt_verified = proof
        .receipt
        .verify_signature()
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if !receipt_verified {
        return Err(Web3ContractError::InvalidProof(
            "receipt signature verification failed".to_string(),
        ));
    }
    verify_web3_identity_binding(&proof.key_binding_certificate)?;
    verify_checkpoint_statement(&proof.checkpoint_statement)?;
    if proof.key_binding_certificate.certificate.chio_public_key != proof.receipt.kernel_key {
        return Err(Web3ContractError::InvalidBinding(
            "binding certificate public key must match receipt kernel_key".to_string(),
        ));
    }
    if proof.checkpoint_statement.kernel_key != proof.receipt.kernel_key {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement kernel_key must match receipt kernel_key".to_string(),
        ));
    }

    let receipt_body = proof.receipt.body();
    let receipt_bytes = canonical_json_bytes(&receipt_body)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    let receipt_leaf = leaf_hash(&receipt_bytes);
    if !proof
        .receipt_inclusion
        .proof
        .verify_hash(receipt_leaf, &proof.receipt_inclusion.merkle_root)
    {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion Merkle proof verification failed".to_string(),
        ));
    }
    if let Some(super_root) = proof.super_root_inclusion.as_ref() {
        if !super_root
            .proof
            .verify_hash(proof.receipt_inclusion.merkle_root, &super_root.super_root)
        {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion verification failed".to_string(),
            ));
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Web3CheckpointStatementBody {
    schema: String,
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: Hash,
    issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_checkpoint_sha256: Option<String>,
    kernel_key: PublicKey,
}

pub(crate) fn checkpoint_statement_body(
    statement: &Web3CheckpointStatement,
) -> Web3CheckpointStatementBody {
    Web3CheckpointStatementBody {
        schema: statement.schema.clone(),
        checkpoint_seq: statement.checkpoint_seq,
        batch_start_seq: statement.batch_start_seq,
        batch_end_seq: statement.batch_end_seq,
        tree_size: statement.tree_size,
        merkle_root: statement.merkle_root,
        issued_at: statement.issued_at,
        previous_checkpoint_sha256: statement.previous_checkpoint_sha256.clone(),
        kernel_key: statement.kernel_key.clone(),
    }
}
