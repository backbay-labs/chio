use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::Web3ContractError;
use crate::validation::{ensure_b256_hex, ensure_non_empty, ensure_unique_strings};

pub const CHIO_WEB3_CONTRACT_PACKAGE_SCHEMA: &str = "chio.web3-contract-package.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3ContractKind {
    RootRegistry,
    Escrow,
    BondVault,
    IdentityRegistry,
    PriceResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3BindingLanguage {
    Rust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ContractInterface {
    pub contract_id: String,
    pub kind: Web3ContractKind,
    pub interface_name: String,
    pub abi_reference: String,
    pub implementation_reference: String,
    pub creation_bytecode_hash: String,
    pub deployed_runtime_codehash: String,
    pub immutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3BindingTarget {
    pub language: Web3BindingLanguage,
    pub crate_path: String,
    pub module_name: String,
    pub contract_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ContractPackage {
    pub schema: String,
    pub package_id: String,
    pub version: String,
    pub chio_contract_version: String,
    pub contracts: Vec<Web3ContractInterface>,
    pub bindings: Vec<Web3BindingTarget>,
    pub deferred_capabilities: Vec<String>,
}

pub fn validate_web3_contract_package(
    package: &Web3ContractPackage,
) -> Result<(), Web3ContractError> {
    if package.schema != CHIO_WEB3_CONTRACT_PACKAGE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(package.schema.clone()));
    }
    ensure_non_empty(&package.package_id, "web3_contract_package.package_id")?;
    ensure_non_empty(&package.version, "web3_contract_package.version")?;
    ensure_non_empty(
        &package.chio_contract_version,
        "web3_contract_package.chio_contract_version",
    )?;
    if package.contracts.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_contract_package.contracts",
        ));
    }
    if package.bindings.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_contract_package.bindings",
        ));
    }

    let mut contract_ids = HashSet::new();
    let mut contract_kinds = HashSet::new();
    for contract in &package.contracts {
        ensure_non_empty(
            &contract.contract_id,
            "web3_contract_package.contracts.contract_id",
        )?;
        ensure_non_empty(
            &contract.interface_name,
            "web3_contract_package.contracts.interface_name",
        )?;
        ensure_non_empty(
            &contract.abi_reference,
            "web3_contract_package.contracts.abi_reference",
        )?;
        ensure_non_empty(
            &contract.implementation_reference,
            "web3_contract_package.contracts.implementation_reference",
        )?;
        ensure_b256_hex(
            &contract.creation_bytecode_hash,
            "web3_contract_package.contracts.creation_bytecode_hash",
        )?;
        ensure_b256_hex(
            &contract.deployed_runtime_codehash,
            "web3_contract_package.contracts.deployed_runtime_codehash",
        )?;
        if !contract_ids.insert(contract.contract_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(
                contract.contract_id.clone(),
            ));
        }
        if !contract_kinds.insert(contract.kind) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "web3_contract_package.contract_kind:{:?}",
                contract.kind
            )));
        }
    }
    for required in [
        Web3ContractKind::RootRegistry,
        Web3ContractKind::Escrow,
        Web3ContractKind::BondVault,
        Web3ContractKind::IdentityRegistry,
        Web3ContractKind::PriceResolver,
    ] {
        if !contract_kinds.contains(&required) {
            return Err(Web3ContractError::UnknownReference(format!(
                "missing required contract kind {:?}",
                required
            )));
        }
    }

    for binding in &package.bindings {
        ensure_non_empty(
            &binding.crate_path,
            "web3_contract_package.bindings.crate_path",
        )?;
        ensure_non_empty(
            &binding.module_name,
            "web3_contract_package.bindings.module_name",
        )?;
        if binding.contract_ids.is_empty() {
            return Err(Web3ContractError::MissingField(
                "web3_contract_package.bindings.contract_ids",
            ));
        }
        ensure_unique_strings(
            &binding.contract_ids,
            "web3_contract_package.bindings.contract_ids",
        )?;
        for contract_id in &binding.contract_ids {
            if !contract_ids.contains(contract_id.as_str()) {
                return Err(Web3ContractError::UnknownReference(contract_id.clone()));
            }
        }
    }

    ensure_unique_strings(
        &package.deferred_capabilities,
        "web3_contract_package.deferred_capabilities",
    )?;

    Ok(())
}
