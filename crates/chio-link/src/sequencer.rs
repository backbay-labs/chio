use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use reqwest::Url;

use crate::config::ChainlinkNetworkConfig;
use crate::PriceOracleError;

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
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencerAvailability {
    Up,
    Down,
    Recovering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerStatus {
    pub chain_id: u64,
    pub feed_address: String,
    pub checked_at: u64,
    pub status_started_at: u64,
    pub availability: SequencerAvailability,
}

pub async fn read_sequencer_status(
    chain: &ChainlinkNetworkConfig,
    now: u64,
) -> Result<Option<SequencerStatus>, PriceOracleError> {
    let Some(feed_address) = chain.sequencer_uptime_feed.as_ref() else {
        return Ok(None);
    };
    let url = chain.rpc_endpoint.parse::<Url>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid RPC endpoint {} for chain {}: {err}",
            chain.rpc_endpoint, chain.chain_id
        ))
    })?;
    let address = feed_address.parse::<Address>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid sequencer uptime feed {} for chain {}: {err}",
            feed_address, chain.chain_id
        ))
    })?;
    let provider = ProviderBuilder::new().connect_http(url);
    let contract = AggregatorV3Interface::new(address, &provider);
    let latest = contract.latestRoundData().call().await.map_err(|err| {
        PriceOracleError::Unavailable(format!(
            "sequencer uptime read failed for chain {} at {}: {err}",
            chain.chain_id, feed_address
        ))
    })?;
    let answer = u8::try_from(latest.answer).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "sequencer uptime answer was invalid for chain {} at {}",
            chain.chain_id, feed_address
        ))
    })?;
    if answer > 1 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "sequencer uptime answer {} was unsupported for chain {} at {}",
            answer, chain.chain_id, feed_address
        )));
    }
    let status_started_at = u64::try_from(latest.startedAt).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "sequencer startedAt overflowed for chain {} at {}",
            chain.chain_id, feed_address
        ))
    })?;
    let availability = if answer == 1 {
        SequencerAvailability::Down
    } else if status_started_at > 0
        && now.saturating_sub(status_started_at) < chain.sequencer_grace_period_seconds
    {
        SequencerAvailability::Recovering
    } else {
        SequencerAvailability::Up
    };
    Ok(Some(SequencerStatus {
        chain_id: chain.chain_id,
        feed_address: feed_address.clone(),
        checked_at: now,
        status_started_at,
        availability,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainlinkNetworkConfig, BASE_MAINNET_CAIP2, BASE_MAINNET_CHAIN_ID};
    use crate::test_support::{TestUnwrap, TestUnwrapErr};

    fn base_chain(rpc_endpoint: &str, feed: Option<&str>) -> ChainlinkNetworkConfig {
        ChainlinkNetworkConfig {
            chain_id: BASE_MAINNET_CHAIN_ID,
            label: "base-mainnet".to_string(),
            caip2: BASE_MAINNET_CAIP2.to_string(),
            rpc_endpoint: rpc_endpoint.to_string(),
            enabled: true,
            sequencer_uptime_feed: feed.map(ToString::to_string),
            sequencer_grace_period_seconds: 300,
        }
    }

    #[tokio::test]
    async fn returns_none_when_no_sequencer_feed_is_configured() {
        let result = read_sequencer_status(&base_chain("https://rpc.example", None), 1_743_292_780)
            .await
            .test_unwrap("no feed configured");

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn rejects_invalid_rpc_endpoints() {
        let error = read_sequencer_status(
            &base_chain(
                "not a url",
                Some("0xFdB631F5EE196F0ed6FAa767959853A9F217697D"),
            ),
            1_743_292_780,
        )
        .await
        .test_unwrap_err("invalid rpc endpoint");

        assert!(matches!(error, PriceOracleError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn rejects_invalid_feed_addresses() {
        let error = read_sequencer_status(
            &base_chain("https://rpc.example", Some("not-an-address")),
            1_743_292_780,
        )
        .await
        .test_unwrap_err("invalid sequencer feed");

        assert!(matches!(error, PriceOracleError::InvalidConfiguration(_)));
    }
}
