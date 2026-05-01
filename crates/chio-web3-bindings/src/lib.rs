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
    include_str!("../../../contracts/artifacts/interfaces/IChioRootRegistry.json");
pub const CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IChioIdentityRegistry.json");
pub const CHIO_ESCROW_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IChioEscrow.json");
pub const CHIO_BOND_VAULT_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IChioBondVault.json");
pub const CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/interfaces/IChioPriceResolver.json");

pub const CHIO_ROOT_REGISTRY_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ChioRootRegistry.json");
pub const CHIO_IDENTITY_REGISTRY_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ChioIdentityRegistry.json");
pub const CHIO_ESCROW_ARTIFACT: &str = include_str!("../../../contracts/artifacts/ChioEscrow.json");
pub const CHIO_BOND_VAULT_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ChioBondVault.json");
pub const CHIO_PRICE_RESOLVER_ARTIFACT: &str =
    include_str!("../../../contracts/artifacts/ChioPriceResolver.json");

pub const CHIO_LOCAL_DEVNET_DEPLOYMENT: &str =
    include_str!("../../../contracts/deployments/local-devnet.json");
pub const CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT: &str =
    include_str!("../../../contracts/reports/local-devnet-qualification.json");

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        CHIO_BOND_VAULT_ARTIFACT, CHIO_BOND_VAULT_INTERFACE_ARTIFACT, CHIO_ESCROW_ARTIFACT,
        CHIO_ESCROW_INTERFACE_ARTIFACT, CHIO_IDENTITY_REGISTRY_ARTIFACT,
        CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT, CHIO_LOCAL_DEVNET_DEPLOYMENT,
        CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT, CHIO_PRICE_RESOLVER_ARTIFACT,
        CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT, CHIO_ROOT_REGISTRY_ARTIFACT,
        CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT,
    };

    fn assert_contract_artifact(name: &str, body: &str) {
        let parsed: Value =
            serde_json::from_str(body).unwrap_or_else(|error| panic!("parse {name}: {error}"));
        assert_eq!(parsed["contractName"], name);
        assert!(parsed["abi"].is_array());
        assert!(parsed["bytecode"].as_str().is_some());
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
    fn bundled_interface_artifacts_parse() {
        assert_contract_artifact("IChioRootRegistry", CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT);
        assert_contract_artifact(
            "IChioIdentityRegistry",
            CHIO_IDENTITY_REGISTRY_INTERFACE_ARTIFACT,
        );
        assert_contract_artifact("IChioEscrow", CHIO_ESCROW_INTERFACE_ARTIFACT);
        assert_contract_artifact("IChioBondVault", CHIO_BOND_VAULT_INTERFACE_ARTIFACT);
        assert_contract_artifact("IChioPriceResolver", CHIO_PRICE_RESOLVER_INTERFACE_ARTIFACT);
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
