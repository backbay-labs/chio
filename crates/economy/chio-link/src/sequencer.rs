use alloy_primitives::Address;
use alloy_sol_types::sol;
use chio_egress_contract::HttpEgressContract;
use reqwest::Url;

use crate::chainlink::contract_backed_provider;
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

/// Read the L2 sequencer-uptime status while enforcing the supplied
/// [`HttpEgressContract`] on the chain RPC endpoint URL before any HTTP
/// connect. The contract is required: production paths must thread the
/// tenant-scoped contract through this entry point so SSRF gates apply
/// uniformly.
pub async fn read_sequencer_status(
    chain: &ChainlinkNetworkConfig,
    now: u64,
    egress_contract: &HttpEgressContract,
) -> Result<Option<SequencerStatus>, PriceOracleError> {
    let Some(feed_address) = chain.sequencer_uptime_feed.as_ref() else {
        return Ok(None);
    };
    // Policy check only; the pinned ContractDnsResolver (contract_backed_provider)
    // enforces hostname address-class at connect, so this does not resolve DNS
    // here (a config-time lookup would be redundant and offline-fragile).
    egress_contract
        .enforce_url(&chain.rpc_endpoint, 0)
        .map_err(|err| {
            PriceOracleError::InvalidConfiguration(format!(
                "HttpEgressContract rejects sequencer RPC endpoint: {err}"
            ))
        })?;
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
    let provider = contract_backed_provider(url, egress_contract)?;
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
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};

    fn authority(addr: SocketAddr) -> String {
        format!("{}:{}", addr.ip(), addr.port())
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .unwrap_or_else(|err| panic!("read request: {err}"));
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn spawn_single_response_server<F>(
        response_for_request: F,
    ) -> (SocketAddr, Receiver<String>, JoinHandle<()>)
    where
        F: FnOnce(String) -> String + Send + 'static,
    {
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|err| panic!("bind server: {err}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("read server addr: {err}"));
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|err| panic!("accept request: {err}"));
            let request = read_http_request(&mut stream);
            tx.send(request.clone())
                .unwrap_or_else(|err| panic!("send captured request: {err}"));
            let response = response_for_request(request);
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|err| panic!("write response: {err}"));
        });
        (addr, rx, handle)
    }

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

    fn permissive_contract() -> HttpEgressContract {
        HttpEgressContract::permissive_for_tests("rpc.example")
    }

    #[tokio::test]
    async fn returns_none_when_no_sequencer_feed_is_configured() {
        let result = read_sequencer_status(
            &base_chain("https://rpc.example", None),
            1_743_292_780,
            &permissive_contract(),
        )
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
            &permissive_contract(),
        )
        .await
        .test_unwrap_err("invalid rpc endpoint");

        assert!(matches!(error, PriceOracleError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn accepts_hostname_rpc_endpoints_for_contract_backed_dispatch() {
        let error = read_sequencer_status(
            &base_chain(
                "https://rpc.example",
                Some("0xFdB631F5EE196F0ed6FAa767959853A9F217697D"),
            ),
            1_743_292_780,
            &permissive_contract(),
        )
        .await
        .test_unwrap_err("unreachable hostname RPC endpoint should fail during dispatch");

        let message = error.to_string();
        assert!(
            message.contains("rpc.example") && message.contains("oracle backend unavailable"),
            "unexpected sequencer hostname dispatch error: {message}"
        );
    }

    #[tokio::test]
    async fn rpc_transport_rejects_redirects_outside_contract() {
        let denied_target = "http://127.0.0.1:9/final";
        let (addr, _rx, handle) = spawn_single_response_server({
            let denied_target = denied_target.to_string();
            move |_| {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {denied_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });
        let endpoint = format!("http://{}/rpc", authority(addr));
        let contract = HttpEgressContract::permissive_for_tests(&authority(addr));

        let error = read_sequencer_status(
            &base_chain(
                &endpoint,
                Some("0xFdB631F5EE196F0ed6FAa767959853A9F217697D"),
            ),
            1_743_292_780,
            &contract,
        )
        .await
        .test_unwrap_err("redirect target should be denied");
        let message = error.to_string();
        assert!(
            message.contains("sequencer uptime read failed")
                && message.contains("authority")
                && message.contains("not allowed"),
            "unexpected sequencer redirect denial: {message}"
        );
        handle
            .join()
            .unwrap_or_else(|_| panic!("join redirect server"));
    }

    #[tokio::test]
    async fn rpc_transport_rejects_oversized_responses() {
        let (addr, _rx, handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef".to_string()
        });
        let endpoint = format!("http://{}/rpc", authority(addr));
        let mut contract = HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = 5;

        let error = read_sequencer_status(
            &base_chain(
                &endpoint,
                Some("0xFdB631F5EE196F0ed6FAa767959853A9F217697D"),
            ),
            1_743_292_780,
            &contract,
        )
        .await
        .test_unwrap_err("oversized response should be denied");
        let message = error.to_string();
        assert!(
            message.contains("sequencer uptime read failed")
                && message.contains("response size 6 exceeds maximum 5"),
            "unexpected sequencer response-size denial: {message}"
        );
        handle.join().unwrap_or_else(|_| panic!("join body server"));
    }

    #[tokio::test]
    async fn rejects_invalid_feed_addresses() {
        let error = read_sequencer_status(
            &base_chain("http://203.0.113.10", Some("not-an-address")),
            1_743_292_780,
            &HttpEgressContract::permissive_for_tests("203.0.113.10"),
        )
        .await
        .test_unwrap_err("invalid sequencer feed");

        assert!(matches!(error, PriceOracleError::InvalidConfiguration(_)));
    }
}
