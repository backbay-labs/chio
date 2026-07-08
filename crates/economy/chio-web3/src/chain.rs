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
    pub deployment_status: String,
    pub settlement_token_symbol: String,
    pub live_external_addresses: Option<Web3ChainExternalAddresses>,
    pub planned_contract_addresses: Option<Web3ChainContractAddresses>,
    pub deployed_contract_addresses: Option<Web3ChainContractAddresses>,
    pub planned_operator_address: Option<String>,
    pub deployed_operator_address: Option<String>,
    pub deployment_plan: Option<Web3ChainDeploymentPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainExternalAddresses {
    pub settlement_token_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainContractAddresses {
    pub root_registry_address: String,
    pub escrow_address: String,
    pub bond_vault_address: String,
    pub identity_registry_address: String,
    pub price_resolver_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainDeploymentPlan {
    pub source_manifest_path: String,
    pub source_manifest_sha256: String,
    pub create2_factory_address: Option<String>,
    pub create2_factory_source: String,
    pub salt_namespace: String,
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
            &deployment.deployment_status,
            "web3_chain_configuration.deployments.deployment_status",
        )?;
        ensure_non_empty(
            &deployment.settlement_token_symbol,
            "web3_chain_configuration.deployments.settlement_token_symbol",
        )?;
        let template_blocked =
            deployment.deployment_status == "template_blocked_pending_external_assurance";
        ensure_chain_deployment_addresses(deployment, template_blocked)?;
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

fn ensure_chain_deployment_addresses(
    deployment: &Web3ChainDeployment,
    template_blocked: bool,
) -> Result<(), Web3ContractError> {
    let Some(external_addresses) = deployment.live_external_addresses.as_ref() else {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.deployments.live_external_addresses",
        ));
    };
    ensure_evm_address(
        &external_addresses.settlement_token_address,
        "web3_chain_configuration.deployments.live_external_addresses.settlement_token_address",
    )?;

    if template_blocked {
        if deployment.deployed_contract_addresses.is_some() {
            return Err(Web3ContractError::InvalidBinding(
                "template-blocked deployments must keep deployed_contract_addresses null"
                    .to_string(),
            ));
        }
        if deployment.deployed_operator_address.is_some() {
            return Err(Web3ContractError::InvalidBinding(
                "template-blocked deployments must keep deployed_operator_address null".to_string(),
            ));
        }
        let Some(planned_addresses) = deployment.planned_contract_addresses.as_ref() else {
            return Err(Web3ContractError::MissingField(
                "web3_chain_configuration.deployments.planned_contract_addresses",
            ));
        };
        ensure_planned_contract_addresses(planned_addresses)?;
        let Some(operator_address) = deployment.planned_operator_address.as_deref() else {
            return Err(Web3ContractError::MissingField(
                "web3_chain_configuration.deployments.planned_operator_address",
            ));
        };
        ensure_evm_address(
            operator_address,
            "web3_chain_configuration.deployments.planned_operator_address",
        )?;
        let Some(plan) = deployment.deployment_plan.as_ref() else {
            return Err(Web3ContractError::MissingField(
                "web3_chain_configuration.deployments.deployment_plan",
            ));
        };
        ensure_deployment_plan(plan)?;
        return Ok(());
    }

    if deployment.planned_contract_addresses.is_some()
        || deployment.planned_operator_address.is_some()
        || deployment.deployment_plan.is_some()
    {
        return Err(Web3ContractError::InvalidBinding(
            "deployed chain configurations must omit planned contract, operator, and deployment-plan fields"
                .to_string(),
        ));
    }
    let Some(deployed_addresses) = deployment.deployed_contract_addresses.as_ref() else {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.deployments.deployed_contract_addresses",
        ));
    };
    ensure_deployed_contract_addresses(deployed_addresses)?;
    let Some(operator_address) = deployment.deployed_operator_address.as_deref() else {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.deployments.deployed_operator_address",
        ));
    };
    ensure_evm_address(
        operator_address,
        "web3_chain_configuration.deployments.deployed_operator_address",
    )
}

fn ensure_planned_contract_addresses(
    addresses: &Web3ChainContractAddresses,
) -> Result<(), Web3ContractError> {
    ensure_evm_address(
        &addresses.root_registry_address,
        "web3_chain_configuration.deployments.planned_contract_addresses.root_registry_address",
    )?;
    ensure_evm_address(
        &addresses.escrow_address,
        "web3_chain_configuration.deployments.planned_contract_addresses.escrow_address",
    )?;
    ensure_evm_address(
        &addresses.bond_vault_address,
        "web3_chain_configuration.deployments.planned_contract_addresses.bond_vault_address",
    )?;
    ensure_evm_address(
        &addresses.identity_registry_address,
        "web3_chain_configuration.deployments.planned_contract_addresses.identity_registry_address",
    )?;
    ensure_evm_address(
        &addresses.price_resolver_address,
        "web3_chain_configuration.deployments.planned_contract_addresses.price_resolver_address",
    )
}

fn ensure_deployed_contract_addresses(
    addresses: &Web3ChainContractAddresses,
) -> Result<(), Web3ContractError> {
    ensure_evm_address(
        &addresses.root_registry_address,
        "web3_chain_configuration.deployments.deployed_contract_addresses.root_registry_address",
    )?;
    ensure_evm_address(
        &addresses.escrow_address,
        "web3_chain_configuration.deployments.deployed_contract_addresses.escrow_address",
    )?;
    ensure_evm_address(
        &addresses.bond_vault_address,
        "web3_chain_configuration.deployments.deployed_contract_addresses.bond_vault_address",
    )?;
    ensure_evm_address(
        &addresses.identity_registry_address,
        "web3_chain_configuration.deployments.deployed_contract_addresses.identity_registry_address",
    )?;
    ensure_evm_address(
        &addresses.price_resolver_address,
        "web3_chain_configuration.deployments.deployed_contract_addresses.price_resolver_address",
    )
}

fn ensure_deployment_plan(plan: &Web3ChainDeploymentPlan) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &plan.source_manifest_path,
        "web3_chain_configuration.deployments.deployment_plan.source_manifest_path",
    )?;
    ensure_sha256_hex(
        &plan.source_manifest_sha256,
        "web3_chain_configuration.deployments.deployment_plan.source_manifest_sha256",
    )?;
    if let Some(factory_address) = plan.create2_factory_address.as_deref() {
        ensure_evm_address(
            factory_address,
            "web3_chain_configuration.deployments.deployment_plan.create2_factory_address",
        )?;
    }
    ensure_non_empty(
        &plan.create2_factory_source,
        "web3_chain_configuration.deployments.deployment_plan.create2_factory_source",
    )?;
    ensure_non_empty(
        &plan.salt_namespace,
        "web3_chain_configuration.deployments.deployment_plan.salt_namespace",
    )
}

fn ensure_sha256_hex(value: &str, field: &'static str) -> Result<(), Web3ContractError> {
    ensure_non_empty(value, field)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must be exactly 32 bytes of hex"
        )));
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
