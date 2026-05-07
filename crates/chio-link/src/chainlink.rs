use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder as AlloyClientBuilder;
use alloy_sol_types::sol;
use alloy_transport::{TransportError, TransportErrorKind, TransportFut};
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use reqwest::{Client, Url};
use std::task;
use tower::Service;

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

#[derive(Clone, Debug)]
pub(crate) struct ContractJsonRpcTransport {
    url: Url,
    http_client: Client,
    egress_contract: HttpEgressContract,
}

impl ContractJsonRpcTransport {
    fn new(url: Url, egress_contract: &HttpEgressContract) -> Result<Self, PriceOracleError> {
        egress_contract
            .enforce_url_with_dns(url.as_str(), 0)
            .map_err(|err| {
                PriceOracleError::InvalidConfiguration(format!(
                    "HttpEgressContract rejects JSON-RPC endpoint: {err}"
                ))
            })?;
        let http_client = client_builder_with_contract(egress_contract)
            .build()
            .map_err(|err| {
                PriceOracleError::Unavailable(format!(
                    "building contract-backed JSON-RPC client failed: {err}"
                ))
            })?;
        Ok(Self {
            url,
            http_client,
            egress_contract: egress_contract.clone(),
        })
    }

    async fn send_json_rpc(self, req: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let request = self
            .http_client
            .post(self.url.clone())
            .json(&req)
            .headers(req.headers())
            .build()
            .map_err(TransportErrorKind::custom)?;
        let response = send_with_contract(&self.egress_contract, &self.http_client, request)
            .await
            .map_err(TransportErrorKind::custom)?;
        let status = response.status();
        let body = response.body();
        if !status.is_success() {
            return Err(TransportErrorKind::http_error(
                status.as_u16(),
                String::from_utf8_lossy(body).into_owned(),
            ));
        }
        serde_json::from_slice(body)
            .map_err(|err| TransportError::deser_err(err, String::from_utf8_lossy(body)))
    }
}

impl Service<RequestPacket> for ContractJsonRpcTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let transport = self.clone();
        Box::pin(async move { transport.send_json_rpc(req).await })
    }
}

pub(crate) fn contract_backed_provider(
    url: Url,
    egress_contract: &HttpEgressContract,
) -> Result<impl Provider, PriceOracleError> {
    let is_local = rpc_url_is_local(&url);
    let transport = ContractJsonRpcTransport::new(url, egress_contract)?;
    let client = AlloyClientBuilder::default().transport(transport, is_local);
    Ok(ProviderBuilder::new().connect_client(client))
}

fn rpc_url_is_local(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "localhost.localdomain" | "127.0.0.1" | "::1")
    )
}

#[derive(Debug)]
pub struct ChainlinkFeedReader {
    networks: Vec<ChainlinkNetworkConfig>,
    egress_contract: HttpEgressContract,
}

impl ChainlinkFeedReader {
    /// Construct a [`ChainlinkFeedReader`] that enforces the supplied
    /// [`HttpEgressContract`] on every RPC endpoint URL before any HTTP
    /// connect through `alloy`. The contract is required: the typed
    /// egress gate is the only thing standing between substrate
    /// dispatches and unconstrained RPC URLs.
    #[must_use]
    pub fn new(networks: Vec<ChainlinkNetworkConfig>, egress_contract: HttpEgressContract) -> Self {
        Self {
            networks,
            egress_contract,
        }
    }

    pub fn try_new(
        networks: Vec<ChainlinkNetworkConfig>,
        egress_contract: HttpEgressContract,
    ) -> Result<Self, PriceOracleError> {
        egress_contract
            .validate_dispatchable_with_pinned_dns()
            .map_err(|err| {
                PriceOracleError::InvalidConfiguration(format!(
                    "Chainlink HttpEgressContract is not dispatchable with pinned DNS: {err}"
                ))
            })?;
        Ok(Self::new(networks, egress_contract))
    }

    /// Backwards-compatible alias for [`ChainlinkFeedReader::new`].
    #[must_use]
    pub fn with_contract(
        networks: Vec<ChainlinkNetworkConfig>,
        egress_contract: HttpEgressContract,
    ) -> Self {
        Self::new(networks, egress_contract)
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
            // HttpEgressContract: validate the RPC endpoint URL through the
            // typed egress contract before alloy opens an HTTP connection.
            // The contract is non-optional in production paths; bypass is
            // not possible without recompiling.
            self.egress_contract
                .enforce_url_with_dns(&network.rpc_endpoint, 0)
                .map_err(|err| {
                    PriceOracleError::InvalidConfiguration(format!(
                        "HttpEgressContract rejects Chainlink RPC endpoint: {err}"
                    ))
                })?;
            read_chainlink_rate(
                &network.rpc_endpoint,
                pair,
                feed,
                now,
                &self.egress_contract,
            )
            .await
        })
    }
}

async fn read_chainlink_rate(
    rpc_endpoint: &str,
    pair: &PairConfig,
    feed: &ChainlinkFeedConfig,
    now: u64,
    egress_contract: &HttpEgressContract,
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
    let provider = contract_backed_provider(url, egress_contract)?;
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
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};

    use crate::config::{
        ChainlinkFeedConfig, ChainlinkNetworkConfig, PairConfig, PairPolicy, BASE_MAINNET_CAIP2,
        BASE_MAINNET_CHAIN_ID,
    };
    use crate::test_support::{TestUnwrap, TestUnwrapErr};
    use crate::OracleBackend;

    use super::{read_chainlink_rate, ChainlinkFeedReader};

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
            &chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
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
        let reader = ChainlinkFeedReader::new(
            vec![base_network("https://rpc.example")],
            chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
        );
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

    #[test]
    fn try_new_accepts_hostname_contract_with_pinned_dns() {
        let reader = ChainlinkFeedReader::try_new(
            vec![base_network("https://rpc.example")],
            chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
        )
        .test_unwrap("hostname contract is resolver-enforced at dispatch");
        assert_eq!(reader.networks.len(), 1);
    }

    #[tokio::test]
    async fn backend_accepts_hostname_rpc_for_contract_backed_dispatch() {
        let reader = ChainlinkFeedReader::new(
            vec![base_network("https://rpc.example")],
            chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
        );
        let pair = pair_with_chainlink("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70");

        let error = reader
            .read_rate(&pair, 1_743_292_780)
            .await
            .test_unwrap_err("unreachable hostname RPC should fail during dispatch");
        let message = error.to_string();
        assert!(
            message.contains("rpc.example") && message.contains("dispatch failed"),
            "unexpected Chainlink hostname dispatch error: {message}"
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
        let contract =
            chio_egress_contract::HttpEgressContract::permissive_for_tests(&authority(addr));
        let pair = pair_with_chainlink("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70");

        let error = read_chainlink_rate(
            &endpoint,
            &pair,
            pair.chainlink.as_ref().test_unwrap("feed"),
            1_743_292_780,
            &contract,
        )
        .await
        .test_unwrap_err("redirect target should be denied");
        let message = error.to_string();
        assert!(
            message.contains("Chainlink latestRoundData failed")
                && message.contains("authority")
                && message.contains("not allowed"),
            "unexpected Chainlink redirect denial: {message}"
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
        let mut contract =
            chio_egress_contract::HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = 5;
        let pair = pair_with_chainlink("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70");

        let error = read_chainlink_rate(
            &endpoint,
            &pair,
            pair.chainlink.as_ref().test_unwrap("feed"),
            1_743_292_780,
            &contract,
        )
        .await
        .test_unwrap_err("oversized response should be denied");
        let message = error.to_string();
        assert!(
            message.contains("Chainlink latestRoundData failed")
                && message.contains("response size 6 exceeds maximum 5"),
            "unexpected Chainlink response-size denial: {message}"
        );
        handle.join().unwrap_or_else(|_| panic!("join body server"));
    }

    #[tokio::test]
    async fn rejects_invalid_feed_addresses() {
        let pair = pair_with_chainlink("not-an-address");

        let error = read_chainlink_rate(
            "https://rpc.example",
            &pair,
            pair.chainlink.as_ref().test_unwrap("feed"),
            1_743_292_780,
            &chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
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
        let reader = ChainlinkFeedReader::new(
            vec![base_network("https://rpc.example")],
            chio_egress_contract::HttpEgressContract::permissive_for_tests("rpc.example"),
        );
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
