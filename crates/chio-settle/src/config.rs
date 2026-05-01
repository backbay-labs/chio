use std::fs;
use std::path::Path;

use chio_core::web3::Web3FinalityMode;
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
            return Err(SettlementError::InvalidInput(
                "web3 settlement requires durable local receipt storage".to_string(),
            ));
        }
        if !self.checkpoint_statements {
            return Err(SettlementError::InvalidInput(
                "web3 settlement requires kernel-signed checkpoint statements".to_string(),
            ));
        }
        if !self.signer_matches_receipts {
            return Err(SettlementError::InvalidInput(
                "web3 settlement requires checkpoint signer equality with receipt kernel keys"
                    .to_string(),
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
            return Err(SettlementError::InvalidInput(
                "settlement oracle price_resolver_contract must not be empty".to_string(),
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
    pub tiers: Vec<SettlementAmountTier>,
}

impl Default for SettlementPolicyConfig {
    fn default() -> Self {
        Self {
            chio_minor_unit_decimals: 2,
            token_minor_unit_decimals: 6,
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
            return Err(SettlementError::InvalidInput(
                "settlement policy requires at least one amount tier".to_string(),
            ));
        }
        if self.token_minor_unit_decimals < self.chio_minor_unit_decimals {
            return Err(SettlementError::InvalidInput(
                "token decimals must be >= Chio monetary minor-unit decimals".to_string(),
            ));
        }
        let mut last_bound = 0_u64;
        for (index, tier) in self.tiers.iter().enumerate() {
            if tier.upper_bound_units < last_bound {
                return Err(SettlementError::InvalidInput(format!(
                    "settlement tier {index} upper bound regresses"
                )));
            }
            if tier.min_confirmations == 0 {
                return Err(SettlementError::InvalidInput(format!(
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
                return Err(SettlementError::InvalidInput(format!(
                    "settlement config {label} is required"
                )));
            }
        }
        self.oracle.validate()?;
        self.evidence_substrate.validate()?;
        self.policy.validate()?;
        Ok(())
    }
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

    #[must_use]
    pub fn into_chain_config(self) -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: self.chain_id,
            network_name: self.network_name,
            rpc_url: self.rpc_url,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait TestResultErr<T, E> {
        fn test_unwrap_err(self) -> E;
    }

    impl<T, E> TestResultErr<T, E> for Result<T, E>
    where
        T: std::fmt::Debug,
    {
        fn test_unwrap_err(self) -> E {
            match self {
                Ok(value) => panic!("expected Err result, got Ok: {value:?}"),
                Err(error) => error,
            }
        }
    }

    fn sample_chain_config() -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: "eip155:8453".to_string(),
            network_name: "base-mainnet".to_string(),
            rpc_url: "https://example.invalid".to_string(),
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

        let config = deployment.into_chain_config();
        assert_eq!(
            config.oracle.authority,
            SettlementOracleAuthority::ChioLinkReceiptEvidence
        );
        assert_eq!(
            config.oracle.price_resolver_contract.as_deref(),
            Some("0x1000000000000000000000000000000000000005")
        );
    }
}
