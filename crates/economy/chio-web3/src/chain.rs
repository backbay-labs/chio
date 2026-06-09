use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::Web3ContractError;
use crate::validation::ensure_non_empty;

pub const CHIO_WEB3_CHAIN_CONFIGURATION_SCHEMA: &str = "chio.web3-chain-configuration.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3ChainRole {
    Primary,
    Secondary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainDeployment {
    pub chain_id: String,
    pub network_name: String,
    pub role: Web3ChainRole,
    pub settlement_token_symbol: String,
    pub settlement_token_address: String,
    pub root_registry_address: String,
    pub escrow_address: String,
    pub bond_vault_address: String,
    pub identity_registry_address: String,
    pub price_resolver_address: String,
    pub operator_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainGasProfile {
    pub chain_id: String,
    pub publish_root_gas: u64,
    pub dual_sign_settlement_gas: u64,
    pub merkle_settlement_gas: u64,
    pub bond_release_gas: u64,
    pub price_read_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainConfiguration {
    pub schema: String,
    pub package_id: String,
    pub primary_chain_id: String,
    pub deployments: Vec<Web3ChainDeployment>,
    pub gas_profiles: Vec<Web3ChainGasProfile>,
}

pub fn validate_web3_chain_configuration(
    configuration: &Web3ChainConfiguration,
) -> Result<(), Web3ContractError> {
    if configuration.schema != CHIO_WEB3_CHAIN_CONFIGURATION_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            configuration.schema.clone(),
        ));
    }
    ensure_non_empty(
        &configuration.package_id,
        "web3_chain_configuration.package_id",
    )?;
    ensure_non_empty(
        &configuration.primary_chain_id,
        "web3_chain_configuration.primary_chain_id",
    )?;
    if configuration.deployments.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.deployments",
        ));
    }
    if configuration.gas_profiles.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.gas_profiles",
        ));
    }

    let mut deployment_ids = HashSet::new();
    let mut primary_count = 0usize;
    for deployment in &configuration.deployments {
        ensure_non_empty(
            &deployment.chain_id,
            "web3_chain_configuration.deployments.chain_id",
        )?;
        ensure_non_empty(
            &deployment.network_name,
            "web3_chain_configuration.deployments.network_name",
        )?;
        ensure_non_empty(
            &deployment.settlement_token_symbol,
            "web3_chain_configuration.deployments.settlement_token_symbol",
        )?;
        ensure_evm_address(
            &deployment.settlement_token_address,
            "web3_chain_configuration.deployments.settlement_token_address",
        )?;
        ensure_evm_address(
            &deployment.root_registry_address,
            "web3_chain_configuration.deployments.root_registry_address",
        )?;
        ensure_evm_address(
            &deployment.escrow_address,
            "web3_chain_configuration.deployments.escrow_address",
        )?;
        ensure_evm_address(
            &deployment.bond_vault_address,
            "web3_chain_configuration.deployments.bond_vault_address",
        )?;
        ensure_evm_address(
            &deployment.identity_registry_address,
            "web3_chain_configuration.deployments.identity_registry_address",
        )?;
        ensure_evm_address(
            &deployment.price_resolver_address,
            "web3_chain_configuration.deployments.price_resolver_address",
        )?;
        ensure_evm_address(
            &deployment.operator_address,
            "web3_chain_configuration.deployments.operator_address",
        )?;
        if !deployment_ids.insert(deployment.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(
                deployment.chain_id.clone(),
            ));
        }
        if deployment.role == Web3ChainRole::Primary {
            primary_count += 1;
            if deployment.chain_id != configuration.primary_chain_id {
                return Err(Web3ContractError::InvalidBinding(format!(
                    "primary deployment {} does not match primary_chain_id {}",
                    deployment.chain_id, configuration.primary_chain_id
                )));
            }
        }
    }
    if primary_count != 1 {
        return Err(Web3ContractError::InvalidBinding(
            "web3 chain configuration must declare exactly one primary deployment".to_string(),
        ));
    }

    let mut gas_profiles = HashSet::new();
    for gas in &configuration.gas_profiles {
        ensure_non_empty(
            &gas.chain_id,
            "web3_chain_configuration.gas_profiles.chain_id",
        )?;
        if !deployment_ids.contains(gas.chain_id.as_str()) {
            return Err(Web3ContractError::UnknownReference(gas.chain_id.clone()));
        }
        if !gas_profiles.insert(gas.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(gas.chain_id.clone()));
        }
        for metric in [
            gas.publish_root_gas,
            gas.dual_sign_settlement_gas,
            gas.merkle_settlement_gas,
            gas.bond_release_gas,
            gas.price_read_gas,
        ] {
            if metric == 0 {
                return Err(Web3ContractError::InvalidBinding(format!(
                    "gas profile {} must not contain zero-valued gas assumptions",
                    gas.chain_id
                )));
            }
        }
    }

    Ok(())
}

fn ensure_evm_address(address: &str, field: &'static str) -> Result<(), Web3ContractError> {
    ensure_non_empty(address, field)?;
    let Some(hex) = address.strip_prefix("0x") else {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must be a 0x-prefixed EVM address"
        )));
    };
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must be exactly 20 bytes of hex"
        )));
    }
    let normalized = hex.to_ascii_lowercase();
    if normalized.bytes().all(|byte| byte == b'0') {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must not be the zero address"
        )));
    }
    if normalized
        .as_bytes()
        .windows(2)
        .all(|window| window[0] == window[1])
    {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must not use a repeated-byte sentinel address"
        )));
    }
    let bytes = normalized.as_bytes();
    if bytes[1..39].iter().all(|byte| *byte == b'0') {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must not use a low-numbered sentinel address"
        )));
    }
    Ok(())
}
