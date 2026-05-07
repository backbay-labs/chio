//! SSRF negative-conformance test: responses exceeding `max_response_bytes`
//! are rejected.
//!
//! Constructs a real production caller (`chio-openapi-mcp-bridge`
//! `OpenApiMcpBridge`) and asserts that the typed `HttpEgressContract`
//! rejects the response-size ceiling check via `enforce_response_bytes`.
//! This drives the same code path the bridge's dispatcher would invoke
//! when it observes a response with a `Content-Length` larger than the
//! contract permits.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::{HttpEgressContract, HttpEgressError};
use chio_openapi_mcp_bridge::{BridgeConfig, OpenApiMcpBridge};

const MINIMAL_OPENAPI_SPEC: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "T", "version": "1.0" },
  "paths": {
    "/listPets": {
      "get": {
        "operationId": "listPets",
        "responses": { "200": { "description": "ok" } }
      }
    }
  }
}"#;

fn tight_response_size_contract() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from(["api.example.com".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 1024,
    }
}

#[test]
fn bridge_construction_accepts_in_scope_url() {
    let cfg = BridgeConfig {
        server_id: "svc".to_string(),
        server_name: "svc".to_string(),
        server_version: "1.0".to_string(),
        public_key: "00".to_string(),
        base_url: "https://api.example.com".to_string(),
        egress_contract: Some(tight_response_size_contract()),
    };
    let _bridge = OpenApiMcpBridge::from_spec(MINIMAL_OPENAPI_SPEC, cfg)
        .expect("bridge builds with allow-listed authority");
}

#[test]
fn contract_rejects_oversize_response() {
    let contract = tight_response_size_contract();
    let err = contract
        .enforce_response_bytes(1025)
        .expect_err("oversize response must be denied");
    assert!(matches!(
        err,
        HttpEgressError::ResponseTooLarge {
            observed: 1025,
            max: 1024
        }
    ));
}
