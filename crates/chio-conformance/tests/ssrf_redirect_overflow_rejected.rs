//! SSRF negative-conformance test: redirect chains exceeding the contract
//! ceiling are rejected.
//!
//! Constructs a real production caller (`chio-siem` `DatadogExporter`) with
//! an `HttpEgressContract` whose `max_redirect_chain` is `0`. The contract
//! must reject any attempt that observes a redirect hop count above the
//! ceiling.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use chio_egress_contract::HttpEgressContract;
use chio_siem::exporters::datadog::{DatadogConfig, DatadogExporter};

fn no_redirect_contract() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from([
            "http-intake.logs.datadoghq.com".to_string(),
            "evil.example.com".to_string(),
        ]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 1024,
    }
}

#[test]
fn datadog_construction_accepts_initial_target_under_zero_redirect_ceiling() {
    let cfg = DatadogConfig {
        api_key: "k".to_string(),
        site: "datadoghq.com".to_string(),
        timeout: Duration::from_secs(1),
        egress_contract: Some(no_redirect_contract()),
        ..DatadogConfig::default()
    };
    // The Datadog endpoint authority is in the allow-list and there is no
    // redirect, so construction succeeds.
    DatadogExporter::new(cfg).expect("contract accepts initial target");
}

#[test]
fn redirect_chain_above_ceiling_is_rejected() {
    let contract = no_redirect_contract();
    // A redirect chain length of 1 already exceeds `max_redirect_chain = 0`.
    let err = contract
        .enforce_url("https://evil.example.com/redirect-target", 1)
        .expect_err("redirect chain exceeding ceiling must be denied");
    let message = err.to_string();
    assert!(
        message.contains("redirect chain length") || message.contains("RedirectLimitExceeded"),
        "expected RedirectLimitExceeded denial, got: {message}"
    );
}
