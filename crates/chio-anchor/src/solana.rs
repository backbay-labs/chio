use chio_core::web3::anchors::AnchorInclusionProof;
use chio_kernel::checkpoint::KernelCheckpoint;
use serde::{Deserialize, Serialize};

use crate::AnchorError;

pub const SOLANA_MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedSolanaMemoPublication {
    pub schema: String,
    pub chain_id: String,
    pub operator_pubkey: String,
    pub memo_program_id: String,
    pub memo_data: String,
    pub anchored_merkle_root: chio_core::hashing::Hash,
    pub anchored_checkpoint_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaMemoAnchorRecord {
    pub chain_id: String,
    pub operator_pubkey: String,
    pub memo_program_id: String,
    pub tx_signature: String,
    pub slot: u64,
    pub block_time: u64,
    pub memo_data: String,
    pub anchored_merkle_root: chio_core::hashing::Hash,
    pub anchored_checkpoint_seq: u64,
}

impl SolanaMemoAnchorRecord {
    #[must_use]
    pub fn from_prepared(
        prepared: &PreparedSolanaMemoPublication,
        tx_signature: String,
        slot: u64,
        block_time: u64,
    ) -> Self {
        Self {
            chain_id: prepared.chain_id.clone(),
            operator_pubkey: prepared.operator_pubkey.clone(),
            memo_program_id: prepared.memo_program_id.clone(),
            tx_signature,
            slot,
            block_time,
            memo_data: prepared.memo_data.clone(),
            anchored_merkle_root: prepared.anchored_merkle_root,
            anchored_checkpoint_seq: prepared.anchored_checkpoint_seq,
        }
    }
}

pub fn prepare_solana_memo_publication(
    checkpoint: &KernelCheckpoint,
    chain_id: &str,
    operator_pubkey: &str,
) -> Result<PreparedSolanaMemoPublication, AnchorError> {
    if chain_id.trim().is_empty() || operator_pubkey.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "Solana publication requires chain_id and operator_pubkey".to_string(),
        ));
    }
    Ok(PreparedSolanaMemoPublication {
        schema: "chio.anchor.solana-memo-publication.v1".to_string(),
        chain_id: chain_id.to_string(),
        operator_pubkey: operator_pubkey.to_string(),
        memo_program_id: SOLANA_MEMO_PROGRAM_ID.to_string(),
        memo_data: format!(
            "Chio:{}:{}:{}",
            checkpoint.body.checkpoint_seq,
            checkpoint.body.merkle_root.to_hex_prefixed(),
            checkpoint.body.issued_at
        ),
        anchored_merkle_root: checkpoint.body.merkle_root,
        anchored_checkpoint_seq: checkpoint.body.checkpoint_seq,
    })
}

pub fn verify_solana_anchor(
    proof: &AnchorInclusionProof,
    solana: &SolanaMemoAnchorRecord,
) -> Result<(), AnchorError> {
    if solana.memo_program_id != SOLANA_MEMO_PROGRAM_ID {
        return Err(AnchorError::Verification(format!(
            "Solana anchor must use the memo program {}; got {}",
            SOLANA_MEMO_PROGRAM_ID, solana.memo_program_id
        )));
    }
    if solana.tx_signature.trim().is_empty() {
        return Err(AnchorError::Verification(
            "Solana anchor transaction signature must be non-empty".to_string(),
        ));
    }
    if solana.anchored_checkpoint_seq != proof.checkpoint_statement.checkpoint_seq {
        return Err(AnchorError::Verification(format!(
            "Solana anchor checkpoint {} does not match primary checkpoint {}",
            solana.anchored_checkpoint_seq, proof.checkpoint_statement.checkpoint_seq
        )));
    }
    if solana.anchored_merkle_root != proof.checkpoint_statement.merkle_root {
        return Err(AnchorError::Verification(
            "Solana anchor root does not match the primary checkpoint root".to_string(),
        ));
    }
    let expected_memo = format!(
        "Chio:{}:{}:{}",
        proof.checkpoint_statement.checkpoint_seq,
        proof.checkpoint_statement.merkle_root.to_hex_prefixed(),
        proof.checkpoint_statement.issued_at
    );
    if solana.memo_data != expected_memo {
        return Err(AnchorError::Verification(
            "Solana anchor memo payload does not match the canonical checkpoint encoding"
                .to_string(),
        ));
    }
    Ok(())
}
