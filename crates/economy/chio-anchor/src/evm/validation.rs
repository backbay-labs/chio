use std::str::FromStr;

use alloy_primitives::Address;
use reqwest::Url;

use crate::AnchorError;

use super::types::{EvmAnchorTarget, ValidatedEvmAnchorTarget};

pub(crate) fn parse_validated_evm_anchor_target(
    target: &EvmAnchorTarget,
) -> Result<ValidatedEvmAnchorTarget, AnchorError> {
    validate_evm_chain_id(&target.chain_id)?;
    validate_evm_rpc_url(&target.rpc_url)?;
    let _contract = parse_nonzero_evm_address("contract address", &target.contract_address)?;
    let operator = parse_nonzero_evm_address("operator address", &target.operator_address)?;
    let publisher = parse_nonzero_evm_address("publisher address", &target.publisher_address)?;
    Ok(ValidatedEvmAnchorTarget {
        operator,
        publisher,
    })
}

fn validate_evm_chain_id(chain_id: &str) -> Result<(), AnchorError> {
    let suffix = chain_id.strip_prefix("eip155:").ok_or_else(|| {
        AnchorError::InvalidInput(
            "EVM anchor chain_id must use the eip155:<decimal-chain-id> format".to_string(),
        )
    })?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AnchorError::InvalidInput(
            "EVM anchor chain_id must use a non-empty decimal eip155 chain id".to_string(),
        ));
    }
    if suffix.len() > 1 && suffix.starts_with('0') {
        return Err(AnchorError::InvalidInput(
            "EVM anchor chain_id must be canonical and omit leading zeroes".to_string(),
        ));
    }
    Ok(())
}

fn validate_evm_rpc_url(rpc_url: &str) -> Result<(), AnchorError> {
    if rpc_url.trim() != rpc_url {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must not include surrounding whitespace".to_string(),
        ));
    }
    let url = Url::parse(rpc_url).map_err(|error| {
        AnchorError::InvalidInput(format!("invalid anchor EVM RPC URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must use http or https".to_string(),
        ));
    }
    if url.host_str().is_none() {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must include a host".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn parse_nonzero_evm_address(
    label: &str,
    address: &str,
) -> Result<Address, AnchorError> {
    if address.trim() != address {
        return Err(AnchorError::InvalidInput(format!(
            "{label} must not include surrounding whitespace"
        )));
    }
    let parsed = Address::from_str(address).map_err(|error| {
        AnchorError::InvalidInput(format!("{label} is not a valid EVM address: {error}"))
    })?;
    if parsed == Address::from([0_u8; 20]) {
        return Err(AnchorError::InvalidInput(format!(
            "{label} must not be the zero address"
        )));
    }
    Ok(parsed)
}
