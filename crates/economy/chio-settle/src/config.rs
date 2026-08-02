use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use chio_core::web3::trust_profile::Web3FinalityMode;
use chio_egress_contract::HttpEgressContract;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::SettlementError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSubstrateMode {
    #[default]
    LocalKernelSignedCheckpointV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementEvidenceConfig {
    #[serde(default)]
    pub mode: EvidenceSubstrateMode,
    #[serde(default = "default_evidence_flag")]
    pub durable_receipts: bool,
    #[serde(default = "default_evidence_flag")]
    pub checkpoint_statements: bool,
    #[serde(default = "default_evidence_flag")]
    pub signer_matches_receipts: bool,
}

impl Default for SettlementEvidenceConfig {
    fn default() -> Self {
        Self {
            mode: EvidenceSubstrateMode::LocalKernelSignedCheckpointV1,
            durable_receipts: true,
            checkpoint_statements: true,
            signer_matches_receipts: true,
        }
    }
}

impl SettlementEvidenceConfig {
    pub fn validate(&self) -> Result<(), SettlementError> {
        match self.mode {
            EvidenceSubstrateMode::LocalKernelSignedCheckpointV1 => {}
        }

        if !self.durable_receipts {
            return Err(SettlementError::invalid_input(
                "web3 settlement requires durable local receipt storage",
            ));
        }
        if !self.checkpoint_statements {
            return Err(SettlementError::invalid_input(
                "web3 settlement requires kernel-signed checkpoint statements",
            ));
        }
        if !self.signer_matches_receipts {
            return Err(SettlementError::invalid_input(
                "web3 settlement requires checkpoint signer equality with receipt kernel keys",
            ));
        }
        Ok(())
    }
}

fn default_evidence_flag() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SettlementOracleAuthority {
    #[default]
    ChioLinkReceiptEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementOracleConfig {
    #[serde(default)]
    pub authority: SettlementOracleAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_resolver_contract: Option<String>,
}

impl Default for SettlementOracleConfig {
    fn default() -> Self {
        Self {
            authority: SettlementOracleAuthority::ChioLinkReceiptEvidence,
            price_resolver_contract: None,
        }
    }
}

impl SettlementOracleConfig {
    pub fn validate(&self) -> Result<(), SettlementError> {
        match self.authority {
            SettlementOracleAuthority::ChioLinkReceiptEvidence => {}
        }

        if self
            .price_resolver_contract
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(SettlementError::invalid_input(
                "settlement oracle price_resolver_contract must not be empty",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementAmountTier {
    pub upper_bound_units: u64,
    pub dispute_window_secs: u64,
    pub min_confirmations: u32,
    pub finality_mode: Web3FinalityMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementPolicyConfig {
    pub chio_minor_unit_decimals: u8,
    pub token_minor_unit_decimals: u8,
    /// EVM destinations the operator permits a finding impairment to pay.
    /// An empty set denies every finding impairment.
    #[serde(default)]
    pub finding_impairment_destination_allowlist: BTreeSet<String>,
    pub tiers: Vec<SettlementAmountTier>,
}

impl Default for SettlementPolicyConfig {
    fn default() -> Self {
        Self {
            chio_minor_unit_decimals: 2,
            token_minor_unit_decimals: 6,
            finding_impairment_destination_allowlist: BTreeSet::new(),
            tiers: vec![
                SettlementAmountTier {
                    upper_bound_units: 1_000,
                    dispute_window_secs: 0,
                    min_confirmations: 1,
                    finality_mode: Web3FinalityMode::OptimisticL2,
                },
                SettlementAmountTier {
                    upper_bound_units: 100_000,
                    dispute_window_secs: 3_600,
                    min_confirmations: 1,
                    finality_mode: Web3FinalityMode::OptimisticL2,
                },
                SettlementAmountTier {
                    upper_bound_units: 1_000_000,
                    dispute_window_secs: 14_400,
                    min_confirmations: 12,
                    finality_mode: Web3FinalityMode::L1Finalized,
                },
                SettlementAmountTier {
                    upper_bound_units: u64::MAX,
                    dispute_window_secs: 86_400,
                    min_confirmations: 64,
                    finality_mode: Web3FinalityMode::L1Finalized,
                },
            ],
        }
    }
}

impl SettlementPolicyConfig {
    pub fn validate(&self) -> Result<(), SettlementError> {
        if self.tiers.is_empty() {
            return Err(SettlementError::invalid_input(
                "settlement policy requires at least one amount tier",
            ));
        }
        if self.token_minor_unit_decimals < self.chio_minor_unit_decimals {
            return Err(SettlementError::invalid_input(
                "token decimals must be >= Chio monetary minor-unit decimals",
            ));
        }
        if self
            .finding_impairment_destination_allowlist
            .iter()
            .any(|destination| destination.trim().is_empty())
        {
            return Err(SettlementError::invalid_input(
                "finding impairment destination allowlist entries must not be empty",
            ));
        }
        let mut last_bound = 0_u64;
        for (index, tier) in self.tiers.iter().enumerate() {
            if tier.upper_bound_units < last_bound {
                return Err(SettlementError::invalid_input(format!(
                    "settlement tier {index} upper bound regresses"
                )));
            }
            if tier.min_confirmations == 0 {
                return Err(SettlementError::invalid_input(format!(
                    "settlement tier {index} must require at least one confirmation"
                )));
            }
            last_bound = tier.upper_bound_units;
        }
        Ok(())
    }

    #[must_use]
    pub fn tier_for_amount(&self, units: u64) -> &SettlementAmountTier {
        self.tiers
            .iter()
            .find(|tier| units <= tier.upper_bound_units)
            .unwrap_or_else(|| match self.tiers.last() {
                Some(tier) => tier,
                None => unreachable!("settlement policy is validated before use"),
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementChainConfig {
    pub chain_id: String,
    pub network_name: String,
    pub rpc_url: String,
    pub egress_contract: HttpEgressContract,
    pub escrow_contract: String,
    pub bond_vault_contract: String,
    pub identity_registry_contract: String,
    pub root_registry_contract: String,
    pub operator_address: String,
    pub settlement_token_symbol: String,
    pub settlement_token_address: String,
    #[serde(default)]
    pub oracle: SettlementOracleConfig,
    #[serde(default)]
    pub evidence_substrate: SettlementEvidenceConfig,
    pub policy: SettlementPolicyConfig,
}

impl SettlementChainConfig {
    pub fn validate(&self) -> Result<(), SettlementError> {
        for (value, label) in [
            (self.chain_id.as_str(), "chain_id"),
            (self.network_name.as_str(), "network_name"),
            (self.rpc_url.as_str(), "rpc_url"),
            (self.escrow_contract.as_str(), "escrow_contract"),
            (self.bond_vault_contract.as_str(), "bond_vault_contract"),
            (
                self.identity_registry_contract.as_str(),
                "identity_registry_contract",
            ),
            (
                self.root_registry_contract.as_str(),
                "root_registry_contract",
            ),
            (self.operator_address.as_str(), "operator_address"),
            (
                self.settlement_token_symbol.as_str(),
                "settlement_token_symbol",
            ),
            (
                self.settlement_token_address.as_str(),
                "settlement_token_address",
            ),
        ] {
            if value.trim().is_empty() {
                return Err(SettlementError::invalid_input(format!(
                    "settlement config {label} is required"
                )));
            }
        }
        self.oracle.validate()?;
        self.evidence_substrate.validate()?;
        self.policy.validate()?;
        self.validate_rpc_egress_contract()?;
        Ok(())
    }

    pub fn validate_rpc_egress_contract(&self) -> Result<(), SettlementError> {
        self.egress_contract
            .validate_dispatchable_with_pinned_dns()
            .map_err(|error| {
                SettlementError::invalid_input(format!(
                    "invalid settlement RPC HttpEgressContract: {error}"
                ))
            })?;
        // Validate scheme/authority and reject IP-literal loopback/link-local
        // hosts here. Hostname address-class is enforced at connect time by the
        // contract's pinned ContractDnsResolver (see client_builder_with_contract),
        // so this validation does not resolve DNS itself: a config-time lookup
        // would be redundant, fail offline, and be open to TOCTOU drift.
        self.egress_contract
            .enforce_url(&self.rpc_url, 0)
            .map_err(|error| {
                SettlementError::invalid_input(format!(
                    "settlement RPC URL is not allowed by HttpEgressContract: {error}"
                ))
            })?;
        Ok(())
    }
}

pub fn settlement_devnet_rpc_egress_contract(
    rpc_url: &str,
) -> Result<HttpEgressContract, SettlementError> {
    devnet_rpc_egress_contract_for_url("chio-settle-devnet-rpc", rpc_url)
}

fn devnet_rpc_egress_contract_for_url(
    namespace: &str,
    rpc_url: &str,
) -> Result<HttpEgressContract, SettlementError> {
    let url = Url::parse(rpc_url)
        .map_err(|error| SettlementError::invalid_input(format!("invalid RPC URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| SettlementError::invalid_input("RPC URL must include a host"))?;
    if !rpc_host_is_loopback(host) {
        return Err(SettlementError::invalid_input(
            "devnet settlement RPC egress contract requires a loopback RPC URL",
        ));
    }

    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(url.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(normalized_rpc_authority(&url, host));
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 64 * 1024 * 1024,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            SettlementError::invalid_input(format!(
                "invalid settlement RPC HttpEgressContract: {error}"
            ))
        })?;
    contract.enforce_url_with_dns(rpc_url, 0).map_err(|error| {
        SettlementError::invalid_input(format!(
            "settlement RPC URL is not allowed by HttpEgressContract: {error}"
        ))
    })?;
    Ok(contract)
}

fn normalized_rpc_authority(url: &Url, host: &str) -> String {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn rpc_host_is_loopback(host: &str) -> bool {
    matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "localhost" | "localhost.localdomain"
    ) || host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevnetContracts {
    pub identity_registry: String,
    pub root_registry: String,
    pub escrow: String,
    pub bond_vault: String,
    pub price_resolver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevnetMocks {
    pub eth_usd_feed: String,
    pub sequencer_uptime_feed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevnetAccounts {
    pub admin: String,
    pub operator: String,
    pub delegate: String,
    pub beneficiary: String,
    pub depositor: String,
    pub principal: String,
    pub outsider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalDevnetDeployment {
    pub manifest_id: String,
    pub network_name: String,
    pub chain_id: String,
    pub rpc_url: String,
    pub deployed_at: String,
    pub operator_address: String,
    pub operator_epoch: u64,
    pub delegate_address: String,
    pub settlement_token_symbol: String,
    pub settlement_token_address: String,
    pub contracts: DevnetContracts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mocks: Option<DevnetMocks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<DevnetAccounts>,
}

impl LocalDevnetDeployment {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SettlementError> {
        let body = fs::read_to_string(path.as_ref())
            .map_err(|error| SettlementError::Serialization(error.to_string()))?;
        serde_json::from_str(&body)
            .map_err(|error| SettlementError::Serialization(error.to_string()))
    }

    pub fn into_chain_config(self) -> Result<SettlementChainConfig, SettlementError> {
        let egress_contract = settlement_devnet_rpc_egress_contract(&self.rpc_url)?;
        Ok(SettlementChainConfig {
            chain_id: self.chain_id,
            network_name: self.network_name,
            rpc_url: self.rpc_url,
            egress_contract,
            escrow_contract: self.contracts.escrow,
            bond_vault_contract: self.contracts.bond_vault,
            identity_registry_contract: self.contracts.identity_registry,
            root_registry_contract: self.contracts.root_registry,
            operator_address: self.operator_address,
            settlement_token_symbol: self.settlement_token_symbol,
            settlement_token_address: self.settlement_token_address,
            oracle: SettlementOracleConfig {
                authority: SettlementOracleAuthority::ChioLinkReceiptEvidence,
                price_resolver_contract: Some(self.contracts.price_resolver),
            },
            evidence_substrate: SettlementEvidenceConfig::default(),
            policy: SettlementPolicyConfig::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_test_support::prelude::*;

    fn sample_chain_config() -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: "eip155:8453".to_string(),
            network_name: "base-mainnet".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            egress_contract: settlement_devnet_rpc_egress_contract("http://127.0.0.1:8545")
                .test_unwrap(),
            escrow_contract: "0x1000000000000000000000000000000000000001".to_string(),
            bond_vault_contract: "0x2000000000000000000000000000000000000001".to_string(),
            identity_registry_contract: "0x3000000000000000000000000000000000000001".to_string(),
            root_registry_contract: "0x4000000000000000000000000000000000000001".to_string(),
            operator_address: "0x5000000000000000000000000000000000000001".to_string(),
            settlement_token_symbol: "USDC".to_string(),
            settlement_token_address: "0x6000000000000000000000000000000000000001".to_string(),
            oracle: SettlementOracleConfig::default(),
            evidence_substrate: SettlementEvidenceConfig::default(),
            policy: SettlementPolicyConfig::default(),
        }
    }

    #[test]
    fn oracle_config_defaults_to_chio_link_receipt_evidence() {
        let config = sample_chain_config();
        assert_eq!(
            config.oracle.authority,
            SettlementOracleAuthority::ChioLinkReceiptEvidence
        );
        assert!(config.oracle.price_resolver_contract.is_none());
    }

    #[test]
    fn evidence_substrate_requires_durable_receipts() {
        let mut config = sample_chain_config();
        config.evidence_substrate.durable_receipts = false;

        let error = config.validate().test_unwrap_err();
        assert!(error.to_string().contains("durable local receipt storage"));
    }

    #[test]
    fn evidence_substrate_requires_checkpoint_statements() {
        let mut config = sample_chain_config();
        config.evidence_substrate.checkpoint_statements = false;

        let error = config.validate().test_unwrap_err();
        assert!(error
            .to_string()
            .contains("kernel-signed checkpoint statements"));
    }

    #[test]
    fn local_devnet_maps_price_resolver_as_reference_contract() {
        let deployment = LocalDevnetDeployment {
            manifest_id: "chio.web3-deployment.local-devnet.v1".to_string(),
            network_name: "ganache-devnet".to_string(),
            chain_id: "eip155:31337".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            deployed_at: "2026-04-02T00:00:00Z".to_string(),
            operator_address: "0x5000000000000000000000000000000000000001".to_string(),
            operator_epoch: 1,
            delegate_address: "0x5000000000000000000000000000000000000002".to_string(),
            settlement_token_symbol: "USDC".to_string(),
            settlement_token_address: "0x6000000000000000000000000000000000000001".to_string(),
            contracts: DevnetContracts {
                identity_registry: "0x1000000000000000000000000000000000000001".to_string(),
                root_registry: "0x1000000000000000000000000000000000000002".to_string(),
                escrow: "0x1000000000000000000000000000000000000003".to_string(),
                bond_vault: "0x1000000000000000000000000000000000000004".to_string(),
                price_resolver: "0x1000000000000000000000000000000000000005".to_string(),
            },
            mocks: None,
            accounts: None,
        };

        let config = deployment.into_chain_config().test_unwrap();
        assert_eq!(
            config.oracle.authority,
            SettlementOracleAuthority::ChioLinkReceiptEvidence
        );
        assert_eq!(
            config.oracle.price_resolver_contract.as_deref(),
            Some("0x1000000000000000000000000000000000000005")
        );
    }

    #[test]
    fn chain_config_requires_matching_rpc_egress_contract() {
        let mut config = sample_chain_config();
        config.egress_contract =
            settlement_devnet_rpc_egress_contract("http://127.0.0.1:9545").test_unwrap();

        let error = config.validate().test_unwrap_err();

        assert!(error.to_string().contains("HttpEgressContract"));
    }

    #[test]
    fn chain_config_does_not_self_authorize_rpc_url_authority() {
        for rpc_url in [
            "http://127.0.0.1:8545",
            "http://10.0.0.5:8545",
            "http://192.168.1.20:8545",
            "http://203.0.113.10:8545",
        ] {
            let mut config = sample_chain_config();
            config.rpc_url = rpc_url.to_string();
            config.egress_contract =
                settlement_devnet_rpc_egress_contract("http://127.0.0.1:9545").test_unwrap();

            let error = config.validate().test_unwrap_err();

            assert!(
                error.to_string().contains("HttpEgressContract"),
                "unexpected self-authorization denial for {rpc_url}: {error}"
            );
        }
    }

    #[test]
    fn devnet_rpc_egress_contract_only_authorizes_loopback() {
        assert!(settlement_devnet_rpc_egress_contract("http://127.0.0.1:8545").is_ok());
        assert!(settlement_devnet_rpc_egress_contract("http://localhost:8545").is_ok());
        for rpc_url in [
            "http://10.0.0.5:8545",
            "http://192.168.1.20:8545",
            "http://172.16.0.2:8545",
            "http://203.0.113.10:8545",
        ] {
            let error = settlement_devnet_rpc_egress_contract(rpc_url).test_unwrap_err();
            assert!(
                error.to_string().contains("requires a loopback RPC URL"),
                "unexpected devnet egress error for {rpc_url}: {error}"
            );
        }
    }
}
