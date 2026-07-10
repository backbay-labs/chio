use chio_core::web3::anchors::Web3ChainAnchorRecord;
use chio_kernel::checkpoint::KernelCheckpoint;

use super::types::{EvmAnchorTarget, EvmPublicationReceipt};

pub fn build_chain_anchor_record(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    confirmed: &EvmPublicationReceipt,
) -> Web3ChainAnchorRecord {
    Web3ChainAnchorRecord {
        chain_id: target.chain_id.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        tx_hash: confirmed.tx_hash.clone(),
        block_number: confirmed.block_number,
        block_hash: confirmed.block_hash.clone(),
        operator_key_hash: confirmed.operator_key_hash.clone(),
        operator_epoch: confirmed.operator_epoch,
        anchored_merkle_root: checkpoint.body.merkle_root,
        anchored_checkpoint_seq: checkpoint.body.checkpoint_seq,
    }
}
