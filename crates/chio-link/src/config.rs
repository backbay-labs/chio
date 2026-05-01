use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::PriceOracleError;

pub const BASE_MAINNET_CHAIN_ID: u64 = 8453;
pub const BASE_MAINNET_CAIP2: &str = "eip155:8453";
pub const BASE_MAINNET_SEQUENCER_UPTIME_FEED: &str = "0xBCF85224fc0756B9Fa45aA7892530B47e10b6433";
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42_161;
pub const ARBITRUM_ONE_CAIP2: &str = "eip155:42161";
pub const ARBITRUM_ONE_SEQUENCER_UPTIME_FEED: &str = "0xFdB631F5EE196F0ed6FAa767959853A9F217697D";
pub const DEFAULT_REFRESH_INTERVAL_SECONDS: u64 = 60;
pub const DEFAULT_MAX_PRICE_AGE_SECONDS: u64 = 600;
pub const DEFAULT_DIVERGENCE_THRESHOLD_BPS: u32 = 500;
pub const DEFAULT_MARGIN_BPS: u32 = 200;
pub const DEFAULT_TWAP_WINDOW_SECONDS: u64 = 600;
pub const DEFAULT_TWAP_MAX_OBSERVATIONS: usize = 10;
pub const DEFAULT_SEQUENCER_GRACE_PERIOD_SECONDS: u64 = 300;
pub const DEFAULT_DEGRADED_MODE_EXTRA_STALE_SECONDS: u64 = 300;
pub const DEFAULT_DEGRADED_MODE_EXTRA_MARGIN_BPS: u32 = 800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleBackendKind {
    Chainlink,
    Pyth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainlinkNetworkConfig {
    pub chain_id: u64,
    pub label: String,
    pub caip2: String,
    pub rpc_endpoint: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_uptime_feed: Option<String>,
    pub sequencer_grace_period_seconds: u64,
}

impl ChainlinkNetworkConfig {
    #[must_use]
    pub fn base_mainnet(rpc_endpoint: impl Into<String>) -> Self {
        Self {
            chain_id: BASE_MAINNET_CHAIN_ID,
            label: "base-mainnet".to_string(),
            caip2: BASE_MAINNET_CAIP2.to_string(),
            rpc_endpoint: rpc_endpoint.into(),
            enabled: true,
            sequencer_uptime_feed: Some(BASE_MAINNET_SEQUENCER_UPTIME_FEED.to_string()),
            sequencer_grace_period_seconds: DEFAULT_SEQUENCER_GRACE_PERIOD_SECONDS,
        }
    }

    #[must_use]
    pub fn arbitrum_one(rpc_endpoint: impl Into<String>) -> Self {
        Self {
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            label: "arbitrum-one".to_string(),
            caip2: ARBITRUM_ONE_CAIP2.to_string(),
            rpc_endpoint: rpc_endpoint.into(),
            enabled: false,
            sequencer_uptime_feed: Some(ARBITRUM_ONE_SEQUENCER_UPTIME_FEED.to_string()),
            sequencer_grace_period_seconds: DEFAULT_SEQUENCER_GRACE_PERIOD_SECONDS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythNetworkConfig {
    pub hermes_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainlinkFeedConfig {
    pub address: String,
    pub decimals: u8,
    pub heartbeat_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythFeedConfig {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DegradedModePolicy {
    pub enabled: bool,
    pub max_stale_age_seconds: u64,
    pub extra_margin_bps: u32,
}

impl DegradedModePolicy {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_stale_age_seconds: DEFAULT_DEGRADED_MODE_EXTRA_STALE_SECONDS,
            extra_margin_bps: DEFAULT_DEGRADED_MODE_EXTRA_MARGIN_BPS,
        }
    }

    #[must_use]
    pub fn conservative_default() -> Self {
        Self {
            enabled: true,
            max_stale_age_seconds: DEFAULT_DEGRADED_MODE_EXTRA_STALE_SECONDS,
            extra_margin_bps: DEFAULT_DEGRADED_MODE_EXTRA_MARGIN_BPS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairPolicy {
    pub max_age_seconds: u64,
    pub divergence_threshold_bps: u32,
    pub exchange_rate_margin_bps: u32,
    pub twap_enabled: bool,
    pub twap_window_seconds: u64,
    pub twap_max_observations: usize,
    pub stable_pair: bool,
    pub degraded_mode: DegradedModePolicy,
}

impl PairPolicy {
    #[must_use]
    pub fn volatile_default() -> Self {
        Self {
            max_age_seconds: DEFAULT_MAX_PRICE_AGE_SECONDS,
            divergence_threshold_bps: DEFAULT_DIVERGENCE_THRESHOLD_BPS,
            exchange_rate_margin_bps: DEFAULT_MARGIN_BPS,
            twap_enabled: true,
            twap_window_seconds: DEFAULT_TWAP_WINDOW_SECONDS,
            twap_max_observations: DEFAULT_TWAP_MAX_OBSERVATIONS,
            stable_pair: false,
            degraded_mode: DegradedModePolicy::disabled(),
        }
    }

    #[must_use]
    pub fn stable_default() -> Self {
        Self {
            twap_enabled: false,
            stable_pair: true,
            degraded_mode: DegradedModePolicy::disabled(),
            ..Self::volatile_default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairConfig {
    pub base: String,
    pub quote: String,
    pub chain_id: u64,
    pub chainlink: Option<ChainlinkFeedConfig>,
    pub pyth: Option<PythFeedConfig>,
    pub policy: PairPolicy,
}

impl PairConfig {
    #[must_use]
    pub fn pair(&self) -> String {
        pair_key(&self.base, &self.quote)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRuntimeOverride {
    pub base: String,
    pub quote: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_backend: Option<OracleBackendKind>,
    pub allow_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence_threshold_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_mode: Option<DegradedModePolicy>,
}

impl PairRuntimeOverride {
    #[must_use]
    pub fn pair(&self) -> String {
        pair_key(&self.base, &self.quote)
    }

    #[must_use]
    pub fn from_pair(pair: &PairConfig) -> Self {
        Self {
            base: pair.base.clone(),
            quote: pair.quote.clone(),
            enabled: true,
            force_backend: None,
            allow_fallback: true,
            divergence_threshold_bps: None,
            degraded_mode: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitoringConfig {
    pub alert_on_fallback: bool,
    pub alert_on_degraded: bool,
    pub alert_on_pause: bool,
    pub alert_on_sequencer: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            alert_on_fallback: true,
            alert_on_degraded: true,
            alert_on_pause: true,
            alert_on_sequencer: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    pub global_pause: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub chains: Vec<ChainlinkNetworkConfig>,
    pub pair_overrides: Vec<PairRuntimeOverride>,
    pub monitoring: MonitoringConfig,
}

impl OperatorConfig {
    #[must_use]
    pub fn pair_override(&self, base: &str, quote: &str) -> Option<&PairRuntimeOverride> {
        let wanted = pair_key(base, quote);
        self.pair_overrides
            .iter()
            .find(|pair| pair.pair() == wanted)
    }

    #[must_use]
    pub fn chain(&self, chain_id: u64) -> Option<&ChainlinkNetworkConfig> {
        self.chains.iter().find(|chain| chain.chain_id == chain_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceOracleConfig {
    pub primary: OracleBackendKind,
    pub fallback: Option<OracleBackendKind>,
    pub refresh_interval_seconds: u64,
    pub pyth: PythNetworkConfig,
    pub pairs: Vec<PairConfig>,
    pub operator: OperatorConfig,
}

impl PriceOracleConfig {
    #[must_use]
    pub fn base_mainnet_default(rpc_endpoint: impl Into<String>) -> Self {
        Self::base_arbitrum_default(
            rpc_endpoint.into(),
            "https://arbitrum-mainnet.example.invalid".to_string(),
        )
    }

    #[must_use]
    pub fn base_arbitrum_default(
        base_rpc_endpoint: impl Into<String>,
        arbitrum_rpc_endpoint: impl Into<String>,
    ) -> Self {
        let pairs = vec![
            PairConfig {
                base: "ETH".to_string(),
                quote: "USD".to_string(),
                chain_id: BASE_MAINNET_CHAIN_ID,
                chainlink: Some(ChainlinkFeedConfig {
                    address: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
                    decimals: 8,
                    heartbeat_seconds: 300,
                }),
                pyth: Some(PythFeedConfig {
                    id: "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
                        .to_string(),
                }),
                policy: PairPolicy::volatile_default(),
            },
            PairConfig {
                base: "BTC".to_string(),
                quote: "USD".to_string(),
                chain_id: BASE_MAINNET_CHAIN_ID,
                chainlink: Some(ChainlinkFeedConfig {
                    address: "0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F".to_string(),
                    decimals: 8,
                    heartbeat_seconds: 180,
                }),
                pyth: Some(PythFeedConfig {
                    id: "0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43"
                        .to_string(),
                }),
                policy: PairPolicy::volatile_default(),
            },
            PairConfig {
                base: "USDC".to_string(),
                quote: "USD".to_string(),
                chain_id: BASE_MAINNET_CHAIN_ID,
                chainlink: Some(ChainlinkFeedConfig {
                    address: "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B".to_string(),
                    decimals: 8,
                    heartbeat_seconds: 68_400,
                }),
                pyth: Some(PythFeedConfig {
                    id: "0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a"
                        .to_string(),
                }),
                policy: PairPolicy::stable_default(),
            },
            PairConfig {
                base: "LINK".to_string(),
                quote: "USD".to_string(),
                chain_id: BASE_MAINNET_CHAIN_ID,
                chainlink: Some(ChainlinkFeedConfig {
                    address: "0x17CAb8FE31E32f08326e5E27412894e49B0f9D65".to_string(),
                    decimals: 8,
                    heartbeat_seconds: 86_400,
                }),
                pyth: None,
                policy: PairPolicy::volatile_default(),
            },
        ];
        Self {
            primary: OracleBackendKind::Chainlink,
            fallback: Some(OracleBackendKind::Pyth),
            refresh_interval_seconds: DEFAULT_REFRESH_INTERVAL_SECONDS,
            pyth: PythNetworkConfig {
                hermes_url: "https://hermes.pyth.network".to_string(),
            },
            operator: OperatorConfig {
                global_pause: false,
                pause_reason: None,
                chains: vec![
                    ChainlinkNetworkConfig::base_mainnet(base_rpc_endpoint),
                    ChainlinkNetworkConfig::arbitrum_one(arbitrum_rpc_endpoint),
                ],
                pair_overrides: pairs.iter().map(PairRuntimeOverride::from_pair).collect(),
                monitoring: MonitoringConfig::default(),
            },
            pairs,
        }
    }

    pub fn validate(&self) -> Result<(), PriceOracleError> {
        if self.refresh_interval_seconds == 0 {
            return Err(PriceOracleError::InvalidConfiguration(
                "refresh_interval_seconds must be non-zero".to_string(),
            ));
        }
        if self.fallback == Some(self.primary) {
            return Err(PriceOracleError::InvalidConfiguration(
                "primary and fallback backends must be different".to_string(),
            ));
        }
        if self.pairs.is_empty() {
            return Err(PriceOracleError::InvalidConfiguration(
                "price oracle config must define at least one supported pair".to_string(),
            ));
        }
        if self.operator.chains.is_empty() {
            return Err(PriceOracleError::InvalidConfiguration(
                "operator config must define at least one chain".to_string(),
            ));
        }
        let mut seen_chains = BTreeSet::new();
        for chain in &self.operator.chains {
            if !seen_chains.insert(chain.chain_id) {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "duplicate chain_id {} in operator chain config",
                    chain.chain_id
                )));
            }
            if chain.label.trim().is_empty() || chain.caip2.trim().is_empty() {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "chain {} must define both label and caip2",
                    chain.chain_id
                )));
            }
            if chain.rpc_endpoint.trim().is_empty() {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "chain {} rpc_endpoint must be non-empty",
                    chain.chain_id
                )));
            }
            if chain.sequencer_uptime_feed.is_some() && chain.sequencer_grace_period_seconds == 0 {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "chain {} sequencer_grace_period_seconds must be non-zero",
                    chain.chain_id
                )));
            }
        }

        let mut seen_pairs = BTreeSet::new();
        for pair in &self.pairs {
            if pair.base.trim().is_empty() || pair.quote.trim().is_empty() {
                return Err(PriceOracleError::InvalidConfiguration(
                    "pair base/quote must be non-empty".to_string(),
                ));
            }
            if !seen_pairs.insert(pair.pair()) {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "duplicate pair configuration for {}",
                    pair.pair()
                )));
            }
            if self.operator.chain(pair.chain_id).is_none() {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "{} references unknown chain_id {}",
                    pair.pair(),
                    pair.chain_id
                )));
            }
            if pair.policy.max_age_seconds == 0 {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "{} max_age_seconds must be non-zero",
                    pair.pair()
                )));
            }
            if pair.policy.twap_enabled
                && (pair.policy.twap_window_seconds == 0 || pair.policy.twap_max_observations == 0)
            {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "{} TWAP settings must be non-zero when enabled",
                    pair.pair()
                )));
            }
            if pair.policy.degraded_mode.enabled
                && pair.policy.degraded_mode.max_stale_age_seconds == 0
            {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "{} degraded-mode max_stale_age_seconds must be non-zero when enabled",
                    pair.pair()
                )));
            }
            if matches!(self.primary, OracleBackendKind::Chainlink) && pair.chainlink.is_none() {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "{} requires a Chainlink feed for the configured primary backend",
                    pair.pair()
                )));
            }
        }

        for pair_override in &self.operator.pair_overrides {
            let pair = self
                .pair(&pair_override.base, &pair_override.quote)
                .ok_or_else(|| {
                    PriceOracleError::InvalidConfiguration(format!(
                        "operator override references unsupported pair {}",
                        pair_override.pair()
                    ))
                })?;
            if let Some(kind) = pair_override.force_backend {
                match kind {
                    OracleBackendKind::Chainlink if pair.chainlink.is_none() => {
                        return Err(PriceOracleError::InvalidConfiguration(format!(
                            "{} override forces Chainlink but no Chainlink feed is configured",
                            pair.pair()
                        )));
                    }
                    OracleBackendKind::Pyth if pair.pyth.is_none() => {
                        return Err(PriceOracleError::InvalidConfiguration(format!(
                            "{} override forces Pyth but no Pyth feed is configured",
                            pair.pair()
                        )));
                    }
                    _ => {}
                }
            }
            if let Some(degraded_mode) = pair_override.degraded_mode.as_ref() {
                if degraded_mode.enabled && degraded_mode.max_stale_age_seconds == 0 {
                    return Err(PriceOracleError::InvalidConfiguration(format!(
                        "{} override degraded-mode max_stale_age_seconds must be non-zero when enabled",
                        pair.pair()
                    )));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn pair(&self, base: &str, quote: &str) -> Option<&PairConfig> {
        let wanted = pair_key(base, quote);
        self.pairs.iter().find(|pair| pair.pair() == wanted)
    }

    #[must_use]
    pub fn supported_pairs(&self) -> Vec<String> {
        let mut pairs = self.pairs.iter().map(PairConfig::pair).collect::<Vec<_>>();
        pairs.sort();
        pairs
    }
}

#[must_use]
pub fn normalize_symbol(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

#[must_use]
pub fn pair_key(base: &str, quote: &str) -> String {
    format!("{}/{}", normalize_symbol(base), normalize_symbol(quote))
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestUnwrap;

    use super::{
        pair_key, PriceOracleConfig, ARBITRUM_ONE_CAIP2, ARBITRUM_ONE_CHAIN_ID, BASE_MAINNET_CAIP2,
        BASE_MAINNET_CHAIN_ID,
    };

    #[test]
    fn base_mainnet_default_exposes_supported_pairs() {
        let config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        let pairs = config.supported_pairs();
        assert_eq!(pairs, vec!["BTC/USD", "ETH/USD", "LINK/USD", "USDC/USD"]);
    }

    #[test]
    fn base_mainnet_default_includes_base_and_arbitrum_chain_inventory() {
        let config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        assert_eq!(config.operator.chains.len(), 2);
        assert_eq!(config.operator.chains[0].chain_id, BASE_MAINNET_CHAIN_ID);
        assert_eq!(config.operator.chains[0].caip2, BASE_MAINNET_CAIP2);
        assert_eq!(config.operator.chains[1].chain_id, ARBITRUM_ONE_CHAIN_ID);
        assert_eq!(config.operator.chains[1].caip2, ARBITRUM_ONE_CAIP2);
        assert!(!config.operator.chains[1].enabled);
    }

    #[test]
    fn operator_overrides_cover_each_supported_pair() {
        let config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        assert_eq!(config.operator.pair_overrides.len(), config.pairs.len());
        assert!(
            config
                .operator
                .pair_override("ETH", "USD")
                .test_unwrap("override")
                .allow_fallback
        );
    }

    #[test]
    fn pair_key_normalizes_symbols() {
        assert_eq!(pair_key(" eth ", "usd"), "ETH/USD");
    }
}
