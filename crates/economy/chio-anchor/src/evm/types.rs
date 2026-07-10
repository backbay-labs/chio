use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AnchorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmAnchorTarget {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
}

impl EvmAnchorTarget {
    pub fn validate(&self) -> Result<(), AnchorError> {
        super::parse_validated_evm_anchor_target(self).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatedEvmAnchorTarget {
    pub(crate) operator: Address,
    pub(crate) publisher: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmRootPublication {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub checkpoint_seq: u64,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub tree_size: u64,
    pub merkle_root: chio_core::hashing::Hash,
    pub operator_key_hash: String,
    pub call_data: String,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDelegateRegistration {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub delegate_address: String,
    pub expires_at: u64,
    pub call_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub operator_key_hash: String,
    pub operator_epoch: u64,
    pub published_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationGuard {
    pub chain_id: String,
    pub operator_address: String,
    pub operator_key_hash: String,
    pub publisher_address: String,
    pub latest_checkpoint_seq: u64,
    pub next_checkpoint_seq_min: u64,
    pub publisher_authorized: bool,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcEnvelope {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: u64,
    pub(super) result: Option<Value>,
    pub(super) error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcError {
    pub(super) code: i64,
    pub(super) message: String,
}
