//! Alloy bindings and packaged artifacts for the official Chio web3 contract family.
//!
//! This crate is the Rust-side integration target for the Solidity package in
//! `contracts/`. It exposes:
//!
//! - `alloy::sol!` bindings derived from the compiled interface artifacts
//! - bundled ABI JSON emitted from the local contract compiler
//! - bundled deployment and qualification artifacts for the local devnet harness

#![cfg(feature = "web3")]

pub mod interfaces;

pub use interfaces::{
    ChioMerkleProof, IChioBondVault, IChioEscrow, IChioIdentityRegistry, IChioPriceResolver,
    IChioRootRegistry,
};

pub const CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT: &str =
    include_str!("../artifacts/interfaces/IChioRootRegistry.json");
pub const CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT: &str =
    include_str!("../artifacts/interfaces/IChioIdentityRegistry.json");
pub const CHIO_ESCROW_INTERFACE_ARTIFACT: &str =
    include_str!("../artifacts/interfaces/IChioEscrow.json");
pub const CHIO_BOND_VAULT_INTERFACE_ARTIFACT: &str =
    include_str!("../artifacts/interfaces/IChioBondVault.json");
pub const CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT: &str =
    include_str!("../artifacts/interfaces/IChioPriceResolver.json");

pub const CHIO_ROOT_REGISTRY_ARTIFACT: &str = include_str!("../artifacts/ChioRootRegistry.json");
pub const CHIO_IDENTITY_REGISTRY_ARTIFACT: &str =
    include_str!("../artifacts/ChioIdentityRegistry.json");
pub const CHIO_ESCROW_ARTIFACT: &str = include_str!("../artifacts/ChioEscrow.json");
pub const CHIO_BOND_VAULT_ARTIFACT: &str = include_str!("../artifacts/ChioBondVault.json");
pub const CHIO_PRICE_RESOLVER_ARTIFACT: &str = include_str!("../artifacts/ChioPriceResolver.json");

/// Historical local-devnet deployment fixture for parser and integration tests.
/// This is not release approval or a mainnet promotion gate.
pub const CHIO_LOCAL_DEVNET_DEPLOYMENT: &str = include_str!("../deployments/local-devnet.json");
/// Historical local-devnet qualification fixture embedded for Rust tests.
/// This is not release approval or a mainnet promotion gate.
pub const CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT: &str =
    include_str!("../reports/local-devnet-qualification.json");

#[cfg(test)]
mod tests {
    use alloy::primitives::keccak256;
    use serde_json::Value;

    use super::{
        CHIO_BOND_VAULT_ARTIFACT, CHIO_BOND_VAULT_INTERFACE_ARTIFACT, CHIO_ESCROW_ARTIFACT,
        CHIO_ESCROW_INTERFACE_ARTIFACT, CHIO_IDENTITY_REGISTRY_ARTIFACT,
        CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT, CHIO_LOCAL_DEVNET_DEPLOYMENT,
        CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT, CHIO_PRICE_RESOLVER_ARTIFACT,
        CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT, CHIO_ROOT_REGISTRY_ARTIFACT,
        CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT,
    };

    fn parse_contract_artifact(name: &str, body: &str) -> Value {
        let parsed: Value =
            serde_json::from_str(body).unwrap_or_else(|error| panic!("parse {name}: {error}"));
        assert_eq!(parsed["contractName"], name);
        let abi = parsed["abi"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} artifact ABI must be an array"));
        assert!(!abi.is_empty(), "{name} artifact ABI must not be empty");
        parsed
    }

    fn assert_contract_artifact(name: &str, body: &str) {
        let parsed = parse_contract_artifact(name, body);
        let bytecode = parsed["bytecode"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} implementation bytecode must be present"));
        assert!(
            !bytecode.is_empty(),
            "{name} implementation bytecode must not be empty"
        );
        let deployed_bytecode = parsed["deployedBytecode"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} deployed runtime bytecode must be present"));
        assert!(
            !deployed_bytecode.is_empty(),
            "{name} deployed runtime bytecode must not be empty"
        );
        assert_eq!(
            parsed["creationBytecodeHash"].as_str(),
            Some(bytecode_hash(bytecode).as_str()),
            "{name} creation bytecode hash must match bytecode"
        );
        assert_eq!(
            parsed["deployedRuntimeCodehash"].as_str(),
            Some(bytecode_hash(deployed_bytecode).as_str()),
            "{name} deployed runtime codehash must match deployedBytecode"
        );
    }

    fn assert_interface_artifact(name: &str, body: &str) {
        let parsed = parse_contract_artifact(name, body);
        let bytecode = parsed["bytecode"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} interface bytecode must be present"));
        assert!(
            bytecode.is_empty(),
            "{name} interface artifact must not carry implementation bytecode"
        );
        let deployed_bytecode = parsed["deployedBytecode"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} interface deployedBytecode must be present"));
        assert!(
            deployed_bytecode.is_empty(),
            "{name} interface artifact must not carry deployed runtime bytecode"
        );
        assert_eq!(parsed["creationBytecodeHash"].as_str(), Some(""));
        assert_eq!(parsed["deployedRuntimeCodehash"].as_str(), Some(""));
    }

    fn bytecode_hash(bytecode: &str) -> String {
        let bytes = hex_to_bytes(bytecode);
        format!("0x{}", bytes_to_hex(keccak256(bytes).as_slice()))
    }

    fn hex_to_bytes(value: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(value.len() / 2);
        let mut chars = value.as_bytes().chunks_exact(2);
        for chunk in &mut chars {
            let high = hex_value(chunk[0]);
            let low = hex_value(chunk[1]);
            bytes.push((high << 4) | low);
        }
        assert!(chars.remainder().is_empty(), "bytecode hex must be even");
        bytes
    }

    fn hex_value(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("bytecode contains non-hex character"),
        }
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    #[test]
    fn bundled_contract_artifacts_parse() {
        assert_contract_artifact("ChioRootRegistry", CHIO_ROOT_REGISTRY_ARTIFACT);
        assert_contract_artifact("ChioIdentityRegistry", CHIO_IDENTITY_REGISTRY_ARTIFACT);
        assert_contract_artifact("ChioEscrow", CHIO_ESCROW_ARTIFACT);
        assert_contract_artifact("ChioBondVault", CHIO_BOND_VAULT_ARTIFACT);
        assert_contract_artifact("ChioPriceResolver", CHIO_PRICE_RESOLVER_ARTIFACT);
    }

    #[test]
    #[should_panic(expected = "implementation bytecode must not be empty")]
    fn implementation_artifact_validation_rejects_empty_bytecode() {
        assert_contract_artifact(
            "ChioEscrow",
            r#"{"contractName":"ChioEscrow","abi":[{"type":"function","name":"dispatch","inputs":[]}],"bytecode":""}"#,
        );
    }

    #[test]
    fn bundled_interface_artifacts_parse() {
        assert_interface_artifact("IChioRootRegistry", CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT);
        assert_interface_artifact(
            "IChioIdentityRegistry",
            CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT,
        );
        assert_interface_artifact("IChioEscrow", CHIO_ESCROW_INTERFACE_ARTIFACT);
        assert_interface_artifact("IChioBondVault", CHIO_BOND_VAULT_INTERFACE_ARTIFACT);
        assert_interface_artifact("IChioPriceResolver", CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT);
    }

    #[test]
    fn bundled_devnet_artifacts_parse() {
        let deployment: Value = serde_json::from_str(CHIO_LOCAL_DEVNET_DEPLOYMENT)
            .unwrap_or_else(|error| panic!("parse local devnet deployment: {error}"));
        assert_eq!(
            deployment["manifest_id"],
            "chio.web3-deployment.local-devnet.v1"
        );

        let qualification: Value = serde_json::from_str(CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT)
            .unwrap_or_else(|error| panic!("parse local devnet qualification report: {error}"));
        assert_eq!(
            qualification["report_id"],
            "chio.web3-contract-qualification.local-devnet.v1"
        );
        assert!(qualification["checks"].is_array());
    }
}
