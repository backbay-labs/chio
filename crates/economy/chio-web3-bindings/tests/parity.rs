#![cfg(feature = "web3")]

use std::collections::BTreeSet;

use chio_core::web3::anchors::CHIO_LINK_ORACLE_AUTHORITY;
use chio_core::web3::chain::{
    validate_web3_chain_configuration, Web3ChainConfiguration, Web3ChainRole,
};
use chio_core::web3::contracts::{
    validate_web3_contract_package, Web3BindingLanguage, Web3ContractPackage,
};
use chio_core::web3::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementExecutionReceiptArtifact,
};
use chio_link::config::{ARBITRUM_ONE_CAIP2, BASE_MAINNET_CAIP2};
use chio_web3_bindings::{
    IChioBondVault, IChioEscrow, IChioIdentityRegistry, IChioPriceResolver, IChioRootRegistry,
    CHIO_BOND_VAULT_ARTIFACT, CHIO_BOND_VAULT_INTERFACE_ARTIFACT, CHIO_ESCROW_ARTIFACT,
    CHIO_ESCROW_INTERFACE_ARTIFACT, CHIO_IDENTITY_REGISTRY_ARTIFACT,
    CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT, CHIO_PRICE_RESOLVER_ARTIFACT,
    CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT, CHIO_ROOT_REGISTRY_ARTIFACT,
    CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT,
};
use serde_json::Value;

fn abi_items(value: &Value) -> &[Value] {
    if let Some(items) = value.as_array() {
        items
    } else {
        value["abi"]
            .as_array()
            .unwrap_or_else(|| panic!("ABI JSON must contain an abi array"))
    }
}

fn canonical_param_type(param: &Value) -> String {
    let ty = param["type"]
        .as_str()
        .unwrap_or_else(|| panic!("ABI parameter type is required"));
    if let Some(suffix) = ty.strip_prefix("tuple") {
        let components = param["components"]
            .as_array()
            .unwrap_or_else(|| panic!("tuple ABI parameter must define components"));
        let inner = components
            .iter()
            .map(canonical_param_type)
            .collect::<Vec<_>>()
            .join(",");
        format!("({inner}){suffix}")
    } else {
        ty.to_string()
    }
}

fn signature_set(artifact: &str, kind: &str) -> BTreeSet<String> {
    let parsed: Value = serde_json::from_str(artifact)
        .unwrap_or_else(|error| panic!("parse ABI artifact: {error}"));
    let mut signatures = BTreeSet::new();
    for item in abi_items(&parsed)
        .iter()
        .filter(|item| item["type"].as_str() == Some(kind))
    {
        let name = item["name"]
            .as_str()
            .unwrap_or_else(|| panic!("{kind} ABI item name is required"));
        let inputs = item["inputs"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} ABI item inputs are required"));
        let parameters = inputs
            .iter()
            .map(canonical_param_type)
            .collect::<Vec<_>>()
            .join(",");
        let signature = format!("{name}({parameters})");
        assert!(
            signatures.insert(signature.clone()),
            "duplicate {kind} ABI signature: {signature}"
        );
    }
    signatures
}

fn generated_signature_set(signatures: &[&str]) -> BTreeSet<String> {
    signatures
        .iter()
        .map(|signature| (*signature).to_string())
        .collect()
}

#[test]
#[should_panic(expected = "duplicate function ABI signature")]
fn signature_set_rejects_duplicate_abi_entries() {
    let artifact = r#"{
        "abi": [
            {"type": "function", "name": "release", "inputs": [{"type": "bytes32"}]},
            {"type": "function", "name": "release", "inputs": [{"type": "bytes32"}]}
        ]
    }"#;

    let _ = signature_set(artifact, "function");
}

fn assert_generated_bindings_match_interface_artifact(
    artifact: &str,
    function_signatures: &[&str],
    event_signatures: Option<&[&str]>,
    error_signatures: Option<&[&str]>,
) {
    assert_eq!(
        generated_signature_set(function_signatures),
        signature_set(artifact, "function"),
        "function signatures drifted between generated bindings and interface artifact",
    );
    if let Some(signatures) = event_signatures {
        assert_eq!(
            generated_signature_set(signatures),
            signature_set(artifact, "event"),
            "event signatures drifted between generated bindings and interface artifact",
        );
    }
    if let Some(signatures) = error_signatures {
        assert_eq!(
            generated_signature_set(signatures),
            signature_set(artifact, "error"),
            "error signatures drifted between generated bindings and interface artifact",
        );
    }
}

fn assert_interface_subset_of_implementation(
    interface_artifact: &str,
    implementation_artifact: &str,
) {
    for kind in ["function", "event", "error"] {
        let interface_signatures = signature_set(interface_artifact, kind);
        let implementation_signatures = signature_set(implementation_artifact, kind);
        assert!(
            interface_signatures.is_subset(&implementation_signatures),
            "{kind} signatures from the interface artifact must remain implemented by the contract artifact",
        );
    }
}

#[test]
fn generated_bindings_track_compiled_interface_artifacts() {
    assert_generated_bindings_match_interface_artifact(
        CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT,
        IChioRootRegistry::IChioRootRegistryCalls::SIGNATURES,
        Some(IChioRootRegistry::IChioRootRegistryEvents::SIGNATURES),
        None,
    );
    assert_generated_bindings_match_interface_artifact(
        CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT,
        IChioIdentityRegistry::IChioIdentityRegistryCalls::SIGNATURES,
        Some(IChioIdentityRegistry::IChioIdentityRegistryEvents::SIGNATURES),
        None,
    );
    assert_generated_bindings_match_interface_artifact(
        CHIO_ESCROW_INTERFACE_ARTIFACT,
        IChioEscrow::IChioEscrowCalls::SIGNATURES,
        Some(IChioEscrow::IChioEscrowEvents::SIGNATURES),
        None,
    );
    assert_generated_bindings_match_interface_artifact(
        CHIO_BOND_VAULT_INTERFACE_ARTIFACT,
        IChioBondVault::IChioBondVaultCalls::SIGNATURES,
        Some(IChioBondVault::IChioBondVaultEvents::SIGNATURES),
        None,
    );
    assert_generated_bindings_match_interface_artifact(
        CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT,
        IChioPriceResolver::IChioPriceResolverCalls::SIGNATURES,
        None,
        None,
    );
}

#[test]
fn official_contract_implementations_cover_the_interface_surface() {
    assert_interface_subset_of_implementation(
        CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT,
        CHIO_ROOT_REGISTRY_ARTIFACT,
    );
    assert_interface_subset_of_implementation(
        CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT,
        CHIO_IDENTITY_REGISTRY_ARTIFACT,
    );
    assert_interface_subset_of_implementation(CHIO_ESCROW_INTERFACE_ARTIFACT, CHIO_ESCROW_ARTIFACT);
    assert_interface_subset_of_implementation(
        CHIO_BOND_VAULT_INTERFACE_ARTIFACT,
        CHIO_BOND_VAULT_ARTIFACT,
    );
    assert_interface_subset_of_implementation(
        CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT,
        CHIO_PRICE_RESOLVER_ARTIFACT,
    );
}

#[test]
fn standards_and_runtime_constants_remain_in_sync() {
    let contract_package: Web3ContractPackage = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
    ))
    .unwrap_or_else(|error| panic!("parse web3 contract package standard: {error}"));
    validate_web3_contract_package(&contract_package)
        .unwrap_or_else(|error| panic!("validate web3 contract package standard: {error:?}"));

    let chain_configuration: Web3ChainConfiguration = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap_or_else(|error| panic!("parse web3 chain configuration standard: {error}"));
    validate_web3_chain_configuration(&chain_configuration)
        .unwrap_or_else(|error| panic!("validate web3 chain configuration standard: {error:?}"));

    let settlement_receipt: Web3SettlementExecutionReceiptArtifact = serde_json::from_str(
        include_str!("../../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"),
    )
    .unwrap_or_else(|error| panic!("parse web3 settlement receipt standard: {error}"));
    validate_web3_settlement_execution_receipt(&settlement_receipt)
        .unwrap_or_else(|error| panic!("validate web3 settlement receipt standard: {error:?}"));

    assert_eq!(contract_package.package_id, chain_configuration.package_id);
    assert_eq!(
        contract_package.package_id,
        settlement_receipt.dispatch.contract_package_id
    );

    let binding = contract_package
        .bindings
        .iter()
        .find(|binding| binding.language == Web3BindingLanguage::Rust)
        .unwrap_or_else(|| panic!("web3 contract package must include a Rust binding target"));
    assert_eq!(
        binding.crate_path,
        "crates/economy/chio-web3-bindings/src/lib.rs"
    );
    assert_eq!(binding.module_name, "chio_web3_bindings");
    assert_eq!(
        binding.contract_ids,
        contract_package
            .contracts
            .iter()
            .map(|contract| contract.contract_id.clone())
            .collect::<Vec<_>>()
    );

    assert_eq!(chain_configuration.primary_chain_id, BASE_MAINNET_CAIP2);
    for contract in &contract_package.contracts {
        let artifact = match contract.contract_id.as_str() {
            "chio.root-registry" => CHIO_ROOT_REGISTRY_ARTIFACT,
            "chio.escrow" => CHIO_ESCROW_ARTIFACT,
            "chio.bond-vault" => CHIO_BOND_VAULT_ARTIFACT,
            "chio.identity-registry" => CHIO_IDENTITY_REGISTRY_ARTIFACT,
            "chio.price-resolver" => CHIO_PRICE_RESOLVER_ARTIFACT,
            other => panic!("unexpected web3 contract id in package: {other}"),
        };
        let parsed: Value = serde_json::from_str(artifact)
            .unwrap_or_else(|error| panic!("parse artifact for {}: {error}", contract.contract_id));
        assert_eq!(
            contract.creation_bytecode_hash,
            parsed["creationBytecodeHash"]
                .as_str()
                .unwrap_or_else(|| panic!(
                    "{} artifact missing creationBytecodeHash",
                    contract.contract_id
                ))
        );
        assert_eq!(
            contract.deployed_runtime_codehash,
            parsed["deployedRuntimeCodehash"]
                .as_str()
                .unwrap_or_else(|| panic!(
                    "{} artifact missing deployedRuntimeCodehash",
                    contract.contract_id
                ))
        );
    }

    let deployment_ids = chain_configuration
        .deployments
        .iter()
        .map(|deployment| deployment.chain_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        deployment_ids,
        BTreeSet::from([BASE_MAINNET_CAIP2, ARBITRUM_ONE_CAIP2])
    );
    assert!(chain_configuration.deployments.iter().any(|deployment| {
        deployment.chain_id == BASE_MAINNET_CAIP2 && deployment.role == Web3ChainRole::Primary
    }));
    assert!(chain_configuration.deployments.iter().any(|deployment| {
        deployment.chain_id == ARBITRUM_ONE_CAIP2 && deployment.role == Web3ChainRole::Secondary
    }));

    let oracle_evidence = settlement_receipt
        .oracle_evidence
        .as_ref()
        .unwrap_or_else(|| panic!("settlement receipt example must include oracle evidence"));
    assert_eq!(oracle_evidence.authority, CHIO_LINK_ORACLE_AUTHORITY);

    let abi_references = contract_package
        .contracts
        .iter()
        .map(|contract| contract.abi_reference.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        abi_references,
        BTreeSet::from([
            "contracts/artifacts/interfaces/IChioBondVault.json",
            "contracts/artifacts/interfaces/IChioEscrow.json",
            "contracts/artifacts/interfaces/IChioIdentityRegistry.json",
            "contracts/artifacts/interfaces/IChioPriceResolver.json",
            "contracts/artifacts/interfaces/IChioRootRegistry.json",
        ])
    );
}
