use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use reqwest::Url;

use crate::config::{ChainlinkFeedConfig, ChainlinkNetworkConfig, PairConfig};
use crate::{ExchangeRate, OracleBackend, OracleBackendKind, OracleFuture, PriceOracleError};

sol! {
    #[sol(rpc)]
    contract AggregatorV3Interface {
        function latestRoundData() external view returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
        function decimals() external view returns (uint8 decimalsValue);
    }
}

pub struct ChainlinkFeedReader {
    networks: Vec<ChainlinkNetworkConfig>,
}

impl ChainlinkFeedReader {
    #[must_use]
    pub fn new(networks: Vec<ChainlinkNetworkConfig>) -> Self {
        Self { networks }
    }

    fn network_for_pair(
        &self,
        pair: &PairConfig,
    ) -> Result<&ChainlinkNetworkConfig, PriceOracleError> {
        self.networks
            .iter()
            .find(|network| network.chain_id == pair.chain_id)
            .ok_or_else(|| {
                PriceOracleError::InvalidConfiguration(format!(
                    "no Chainlink network is configured for {} chain_id {}",
                    pair.pair(),
                    pair.chain_id
                ))
            })
    }
}

impl OracleBackend for ChainlinkFeedReader {
    fn kind(&self) -> OracleBackendKind {
        OracleBackendKind::Chainlink
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, now: u64) -> OracleFuture<'a> {
        Box::pin(async move {
            let feed =
                pair.chainlink
                    .as_ref()
                    .ok_or_else(|| PriceOracleError::NoPairAvailable {
                        base: pair.base.clone(),
                        quote: pair.quote.clone(),
                    })?;
            let network = self.network_for_pair(pair)?;
            read_chainlink_rate(&network.rpc_endpoint, pair, feed, now).await
        })
    }
}

async fn read_chainlink_rate(
    rpc_endpoint: &str,
    pair: &PairConfig,
    feed: &ChainlinkFeedConfig,
    now: u64,
) -> Result<ExchangeRate, PriceOracleError> {
    let url = rpc_endpoint.parse::<Url>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid Chainlink RPC endpoint {rpc_endpoint}: {err}"
        ))
    })?;
    let address = feed.address.parse::<Address>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid Chainlink feed address {} for {}: {err}",
            feed.address,
            pair.pair()
        ))
    })?;
    let provider = ProviderBuilder::new().connect_http(url);
    let contract = AggregatorV3Interface::new(address, &provider);
    let latest = contract.latestRoundData().call().await.map_err(|err| {
        PriceOracleError::Unavailable(format!(
            "Chainlink latestRoundData failed for {} at {}: {err}",
            pair.pair(),
            feed.address
        ))
    })?;
    let decimals = contract.decimals().call().await.map_err(|err| {
        PriceOracleError::Unavailable(format!(
            "Chainlink decimals failed for {} at {}: {err}",
            pair.pair(),
            feed.address
        ))
    })?;
    if decimals != feed.decimals {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Chainlink decimals mismatch for {} at {}: configured {}, contract returned {}",
            pair.pair(),
            feed.address,
            feed.decimals,
            decimals
        )));
    }
    let answer = u128::try_from(latest.answer).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "Chainlink returned a negative or oversized answer for {} at {}",
            pair.pair(),
            feed.address
        ))
    })?;
    if answer == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Chainlink returned zero for {} at {}",
            pair.pair(),
            feed.address
        )));
    }
    let updated_at = u64::try_from(latest.updatedAt).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "Chainlink updatedAt overflowed u64 for {} at {}",
            pair.pair(),
            feed.address
        ))
    })?;
    if updated_at == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Chainlink updatedAt was zero for {} at {}",
            pair.pair(),
            feed.address
        )));
    }
    let denominator = 10_u128
        .checked_pow(u32::from(feed.decimals))
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "decimal normalization overflowed for {} at {}",
                pair.pair(),
                feed.address
            ))
        })?;
    let max_age_seconds = pair.policy.max_age_seconds.min(feed.heartbeat_seconds);
    let rate = ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator: answer,
        rate_denominator: denominator,
        updated_at,
        fetched_at: now,
        source: "chainlink".to_string(),
        feed_reference: feed.address.clone(),
        max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: None,
        confidence_denominator: None,
    };
    rate.ensure_fresh(now)?;
    Ok(rate)
}

#[cfg(test)]
mod tests {
    use crate::config::{
        ChainlinkFeedConfig, ChainlinkNetworkConfig, PairConfig, PairPolicy, BASE_MAINNET_CAIP2,
        BASE_MAINNET_CHAIN_ID,
    };
    use crate::test_support::{TestUnwrap, TestUnwrapErr};
    use crate::OracleBackend;

    use super::{read_chainlink_rate, ChainlinkFeedReader};

    fn pair_with_chainlink(address: &str) -> PairConfig {
        PairConfig {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            chain_id: BASE_MAINNET_CHAIN_ID,
            chainlink: Some(ChainlinkFeedConfig {
                address: address.to_string(),
                decimals: 8,
                heartbeat_seconds: 300,
            }),
            pyth: None,
            policy: PairPolicy::volatile_default(),
        }
    }

    fn base_network(rpc_endpoint: &str) -> ChainlinkNetworkConfig {
        ChainlinkNetworkConfig {
            chain_id: BASE_MAINNET_CHAIN_ID,
            label: "base-mainnet".to_string(),
            caip2: BASE_MAINNET_CAIP2.to_string(),
            rpc_endpoint: rpc_endpoint.to_string(),
            enabled: true,
            sequencer_uptime_feed: None,
            sequencer_grace_period_seconds: 300,
        }
    }

    #[tokio::test]
    async fn rejects_invalid_rpc_endpoints() {
        let pair = pair_with_chainlink("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70");
        let error = read_chainlink_rate(
            "not a url",
            &pair,
            pair.chainlink.as_ref().test_unwrap("feed"),
            1_743_292_780,
        )
        .await
        .test_unwrap_err("invalid endpoint");
        assert!(matches!(
            error,
            crate::PriceOracleError::InvalidConfiguration(_)
        ));
    }

    #[test]
    fn rejects_pairs_without_a_configured_network() {
        let reader = ChainlinkFeedReader::new(vec![base_network("https://rpc.example")]);
        let mut pair = pair_with_chainlink("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70");
        pair.chain_id = 1;

        let error = reader
            .network_for_pair(&pair)
            .test_unwrap_err("missing network");

        assert!(matches!(
            error,
            crate::PriceOracleError::InvalidConfiguration(_)
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_feed_addresses() {
        let pair = pair_with_chainlink("not-an-address");

        let error = read_chainlink_rate(
            "https://rpc.example",
            &pair,
            pair.chainlink.as_ref().test_unwrap("feed"),
            1_743_292_780,
        )
        .await
        .test_unwrap_err("invalid feed address");

        assert!(matches!(
            error,
            crate::PriceOracleError::InvalidConfiguration(_)
        ));
    }

    #[tokio::test]
    async fn backend_rejects_pairs_without_chainlink_feeds() {
        let reader = ChainlinkFeedReader::new(vec![base_network("https://rpc.example")]);
        let pair = PairConfig {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            chain_id: BASE_MAINNET_CHAIN_ID,
            chainlink: None,
            pyth: None,
            policy: PairPolicy::volatile_default(),
        };

        let error = reader
            .read_rate(&pair, 1_743_292_780)
            .await
            .test_unwrap_err("missing feed");

        assert!(matches!(
            error,
            crate::PriceOracleError::NoPairAvailable { .. }
        ));
    }
}
