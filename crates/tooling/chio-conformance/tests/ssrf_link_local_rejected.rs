//! SSRF negative-conformance test: IPv4 link-local (cloud metadata) is rejected.
//!
//! Constructs a real production caller (`chio-siem` `SplunkHecExporter`)
//! configured with an `HttpEgressContract` whose authority allow-list does
//! not include `169.254.169.254`. The exporter must reject the dispatch
//! with `LinkLocalDenied` before any TCP connect attempt.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use chio_egress_contract::HttpEgressContract;
use chio_siem::exporters::splunk::{SplunkConfig, SplunkHecExporter};

fn strict_contract_excluding_link_local() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from(["splunk.example.com:8088".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

#[tokio::test]
async fn splunk_hec_construction_rejects_link_local_target() {
    let cfg = SplunkConfig {
        endpoint: "https://169.254.169.254".to_string(),
        hec_token: "dummy".to_string(),
        timeout: Duration::from_secs(1),
        egress_contract: Some(strict_contract_excluding_link_local()),
        ..SplunkConfig::default()
    };

    let result = SplunkHecExporter::new(cfg);
    let message = match result {
        Ok(_) => panic!("link-local target must be denied"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("HttpEgressContract")
            || message.contains("link-local")
            || message.contains("169.254"),
        "expected HttpEgressContract link-local denial, got: {message}"
    );
}
