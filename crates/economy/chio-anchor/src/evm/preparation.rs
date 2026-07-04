use std::str::FromStr;

use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use chio_core::web3::identity::{SignedWeb3IdentityBinding, Web3KeyBindingPurpose};
use chio_kernel::checkpoint::KernelCheckpoint;
use chio_web3_bindings::IChioRootRegistry;

use crate::AnchorError;

use super::hashing::hash_to_b256;
use super::types::{EvmAnchorTarget, PreparedDelegateRegistration, PreparedEvmRootPublication};
use super::validation::{parse_nonzero_evm_address, parse_validated_evm_anchor_target};
use super::{operator_key_hash, operator_key_hash_hex};

pub fn prepare_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEvmRootPublication, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Anchor)
    {
        return Err(AnchorError::InvalidBinding(
            "binding certificate does not include anchor purpose".to_string(),
        ));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &target.chain_id)
    {
        return Err(AnchorError::InvalidBinding(format!(
            "binding certificate does not cover {}",
            target.chain_id
        )));
    }
    let binding_operator = parse_nonzero_evm_address(
        "binding settlement address",
        &binding.certificate.settlement_address,
    )?;
    if binding_operator != validated_target.operator {
        return Err(AnchorError::InvalidBinding(format!(
            "binding settlement address {} does not match operator address {}",
            binding.certificate.settlement_address, target.operator_address
        )));
    }
    let call = IChioRootRegistry::publishRootCall {
        operator: validated_target.operator,
        merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
        checkpointSeq: checkpoint.body.checkpoint_seq,
        batchStartSeq: checkpoint.body.batch_start_seq,
        batchEndSeq: checkpoint.body.batch_end_seq,
        treeSize: checkpoint.body.tree_size as u64,
        operatorKeyHash: operator_key_hash(binding)?,
    };

    Ok(PreparedEvmRootPublication {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        publisher_address: target.publisher_address.clone(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        batch_start_seq: checkpoint.body.batch_start_seq,
        batch_end_seq: checkpoint.body.batch_end_seq,
        tree_size: checkpoint.body.tree_size as u64,
        merkle_root: checkpoint.body.merkle_root,
        operator_key_hash: operator_key_hash_hex(binding)?,
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
        requires_delegate_authorization: validated_target.publisher != validated_target.operator,
    })
}

pub fn prepare_delegate_registration(
    target: &EvmAnchorTarget,
    delegate_address: &str,
    expires_at: u64,
) -> Result<PreparedDelegateRegistration, AnchorError> {
    parse_validated_evm_anchor_target(target)?;
    if delegate_address.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "delegate address is required".to_string(),
        ));
    }
    if expires_at == 0 {
        return Err(AnchorError::InvalidInput(
            "delegate expiry must be non-zero".to_string(),
        ));
    }

    let delegate = Address::from_str(delegate_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let call = IChioRootRegistry::registerDelegateCall {
        delegate,
        expiresAt: expires_at,
    };
    Ok(PreparedDelegateRegistration {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        delegate_address: delegate_address.to_string(),
        expires_at,
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
    })
}
