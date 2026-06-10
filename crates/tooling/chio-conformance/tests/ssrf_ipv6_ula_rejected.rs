//! SSRF negative-conformance test: IPv6 unique-local (`fc00::/7`) is rejected.
//!
//! Drives a real production caller (`chio-link` `PythHermesClient`)
//! configured with an `HttpEgressContract` whose authority allow-list does
//! not include `[fc00::1]`. The substrate must reject the URL through the
//! contract-backed `send_with_contract` path before reqwest attempts a TCP
//! connect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use chio_link::config::{PairConfig, PairPolicy, PythFeedConfig, BASE_MAINNET_CHAIN_ID};
use chio_link::pyth::PythHermesClient;
use chio_link::OracleBackend;

fn strict_contract_excluding_ula() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from(["127.0.0.1".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

fn pyth_pair() -> PairConfig {
    PairConfig {
        base: "ETH".to_string(),
        quote: "USD".to_string(),
        chain_id: BASE_MAINNET_CHAIN_ID,
        chainlink: None,
        pyth: Some(PythFeedConfig {
            id: "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace".to_string(),
        }),
        policy: PairPolicy::volatile_default(),
    }
}

#[tokio::test]
async fn pyth_contract_rejects_ipv6_ula_target_through_read() {
    let contract = strict_contract_excluding_ula();
    // Direct contract probe: the URL we expect a real PythHermesClient
    // would attempt is `http://[fc00::1]/api/latest_price_feeds?ids[]=...`.
    let probe = "http://[fc00::1]/api/latest_price_feeds";
    let err = contract
        .enforce_url(probe, 0)
        .expect_err("IPv6 ULA must be denied");
    let message = err.to_string();
    assert!(
        message.contains("IPv6 unique-local")
            || message.contains("Ipv6Ula")
            || message.contains("fc00"),
        "expected HttpEgressContract IPv6 ULA denial, got: {message}"
    );

    let client = PythHermesClient::with_contract(
        "http://[fc00::1]".to_string(),
        strict_contract_excluding_ula(),
    )
    .expect("hermes client builds even with disallowed base url");
    let pair = pyth_pair();
    let error = client
        .read_rate(&pair, 1_743_292_780)
        .await
        .expect_err("Hermes read should reject IPv6 ULA before connect");
    let message = error.to_string();
    assert!(
        message.contains("Hermes request rejected by HttpEgressContract")
            && message.contains("IPv6 unique-local")
            && message.contains("fc00"),
        "expected production Hermes read to reject IPv6 ULA, got: {message}"
    );
}
