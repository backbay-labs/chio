use alloy_primitives::{keccak256, FixedBytes, B256};
use chio_core::crypto::SigningAlgorithm;
use chio_core::web3::identity::SignedWeb3IdentityBinding;

use crate::AnchorError;

pub fn operator_key_hash(binding: &SignedWeb3IdentityBinding) -> Result<B256, AnchorError> {
    if !matches!(
        binding.certificate.chio_public_key.algorithm(),
        SigningAlgorithm::Ed25519
    ) {
        return Err(AnchorError::InvalidBinding(format!(
            "anchor identity binding requires an Ed25519 chio_public_key, got {:?}",
            binding.certificate.chio_public_key.algorithm()
        )));
    }
    Ok(keccak256(binding.certificate.chio_public_key.as_bytes()))
}

pub fn operator_key_hash_hex(binding: &SignedWeb3IdentityBinding) -> Result<String, AnchorError> {
    Ok(format!(
        "0x{}",
        hex::encode(operator_key_hash(binding)?.as_slice())
    ))
}

pub(super) fn hash_to_b256(hash: &chio_core::hashing::Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

pub(super) fn parse_hex_u64(value: &str) -> Result<u64, AnchorError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| AnchorError::Rpc(error.to_string()))
}
