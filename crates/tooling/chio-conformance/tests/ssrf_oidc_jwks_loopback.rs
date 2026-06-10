//! SSRF negative-conformance test: OIDC discovery and JWKS fetches are
//! gated by the typed `HttpEgressContract`.
//!
//! Constructs a contract whose authority allow-list permits only the
//! configured identity-provider host and asserts that loopback /
//! link-local discovery URLs are rejected through the same code path
//! the remote MCP runtime uses for OIDC discovery and JWKS resolution.
//! Pins the SSRF fix that gates `fetch_identity_provider_json` and its
//! callers (`resolve_jwks_key_set`, `resolve_discovered_identity_provider`)
//! through the typed contract before a TCP connect is attempted.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use chio_mcp_remote::enforce_oidc_egress_contract;
use url::Url;

fn idp_only_contract() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from(["hermetic-idp.test".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

fn hermetic_loopback_idp_contract() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from(["127.0.0.1:9443".to_string()]),
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

#[test]
fn oidc_discovery_loopback_target_is_denied() {
    let url = Url::parse("https://127.0.0.1:18080/.well-known/openid-configuration")
        .expect("loopback discovery url");
    let contract = idp_only_contract();
    let err = enforce_oidc_egress_contract(&url, &contract)
        .expect_err("loopback OIDC discovery must be denied");
    let message = err.to_string();
    assert!(
        message.contains("HttpEgressContract")
            && (message.contains("loopback") || message.contains("127.0.0.1")),
        "expected HttpEgressContract loopback denial for OIDC discovery, got: {message}"
    );
}

#[test]
fn jwks_link_local_target_is_denied() {
    let url = Url::parse("https://169.254.169.254/jwks.json").expect("link-local jwks url");
    let contract = idp_only_contract();
    let err = enforce_oidc_egress_contract(&url, &contract)
        .expect_err("link-local JWKS fetch must be denied");
    let message = err.to_string();
    assert!(
        message.contains("HttpEgressContract")
            && (message.contains("link-local") || message.contains("169.254")),
        "expected HttpEgressContract link-local denial for JWKS fetch, got: {message}"
    );
}

#[test]
fn allow_listed_idp_passes_contract() {
    let url = Url::parse("https://127.0.0.1:9443/.well-known/openid-configuration")
        .expect("allow-listed discovery url");
    let contract = hermetic_loopback_idp_contract();
    enforce_oidc_egress_contract(&url, &contract).expect("allow-listed OIDC discovery must pass");
}
