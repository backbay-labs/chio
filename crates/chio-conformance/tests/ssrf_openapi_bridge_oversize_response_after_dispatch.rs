//! SSRF negative-conformance test: oversize bridge responses are rejected
//! after dispatch.
//!
//! Constructs a real production caller (`chio-openapi-mcp-bridge`
//! `OpenApiMcpBridge`) configured with a tight `max_response_bytes`
//! ceiling, wires a dispatcher that returns a body larger than the
//! ceiling, and asserts that the contract rejects the response through
//! the post-dispatch `enforce_attempt` call rather than letting the
//! oversize body reach the caller. This pins the SSRF fix to fail-closed
//! behavior on the response-size axis.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use chio_openapi_mcp_bridge::{BridgeConfig, BridgeError, BridgedResponse, OpenApiMcpBridge};
use serde_json::json;

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
        allowed_schemes: BTreeSet::from(["http".to_string()]),
        allowed_authority_set: BTreeSet::from(["127.0.0.1:18080".to_string()]),
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64,
    }
}

#[test]
fn bridge_rejects_oversize_dispatcher_response_via_enforce_attempt() {
    let cfg = BridgeConfig {
        server_id: "svc".to_string(),
        server_name: "svc".to_string(),
        server_version: "1.0".to_string(),
        public_key: "00".to_string(),
        base_url: "http://127.0.0.1:18080".to_string(),
        egress_contract: Some(tight_response_size_contract()),
    };
    let mut bridge = OpenApiMcpBridge::from_spec(MINIMAL_OPENAPI_SPEC, cfg)
        .expect("bridge builds with allow-listed authority");
    bridge.set_dispatcher(Box::new(|_method, _url, _args| {
        // Body larger than the contract's 64-byte ceiling once
        // serialised. A naive bridge would forward this to the caller.
        Ok(BridgedResponse {
            status: 200,
            body: json!({ "payload": "x".repeat(512) }),
            is_error: false,
        })
    }));

    let err = bridge
        .invoke_tool("listPets", json!({}))
        .expect_err("oversize bridge response must be denied post-dispatch");
    let message = match err {
        BridgeError::UpstreamError(message) => message,
        other => panic!("expected UpstreamError, got {other:?}"),
    };
    assert!(
        message.contains("HttpEgressContract")
            && (message.contains("response") || message.contains("ResponseTooLarge")),
        "expected post-dispatch HttpEgressContract response-size denial, got: {message}"
    );
}
