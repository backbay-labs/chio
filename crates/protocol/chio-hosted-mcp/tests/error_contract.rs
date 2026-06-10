#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use chio_core::crypto::Keypair;
use serde_json::{json, Value};

use support::{sign_jwt, start_http_server, start_jwt_http_server, unix_now};

fn initialize_request(include_id: bool) -> Value {
    if include_id {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        })
    }
}

#[test]
fn hosted_mcp_rejects_malformed_jsonrpc_body_with_structured_error() {
    let server = start_http_server("test-token");

    let response = server.post_bytes(
        Some("test-token"),
        None,
        "application/json, text/event-stream",
        "application/json",
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25""#,
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().expect("malformed body json");
    assert_eq!(body["error"]["code"], -32700);
    assert!(body["error"]["message"]
        .as_str()
        .expect("parse error message")
        .contains("invalid JSON"));

    let session = server.initialize_session();
    assert!(!session.id.is_empty());
}

#[test]
fn hosted_mcp_rejects_initialize_without_request_id() {
    let server = start_http_server("test-token");

    let response = server.post_raw(
        Some("test-token"),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(false),
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
    let body: Value = response.json().expect("missing id body json");
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("initialize must be a JSON-RPC request with an id")
    );

    let session = server.initialize_session();
    assert!(!session.id.is_empty());
}

#[test]
fn hosted_mcp_rejects_initialize_with_session_header_without_issuing_session() {
    let server = start_http_server("test-token");

    let response = server.post_raw(
        Some("test-token"),
        Some("bogus-session"),
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(true),
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
    let body: Value = response.json().expect("session header body json");
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("initialize request must not include MCP-Session-Id")
    );

    let session = server.initialize_session();
    assert!(!session.id.is_empty());
}

#[test]
fn hosted_mcp_rejects_invalid_content_negotiation_without_panicking() {
    let server = start_http_server("test-token");

    let bad_accept = server.post_raw(
        Some("test-token"),
        None,
        "application/json",
        "application/json",
        &initialize_request(true),
    );
    assert_eq!(bad_accept.status(), reqwest::StatusCode::NOT_ACCEPTABLE);

    let bad_content_type = server.post_raw(
        Some("test-token"),
        None,
        "application/json, text/event-stream",
        "text/plain",
        &initialize_request(true),
    );
    assert_eq!(
        bad_content_type.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let session = server.initialize_session();
    assert!(!session.id.is_empty());
}

#[test]
fn hosted_mcp_rejects_expired_or_mismatched_auth_during_session_reuse_without_panicking() {
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let signing_key = Keypair::generate();
    let server = start_jwt_http_server(
        &signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );

    let valid_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": unix_now() + 300,
        }),
    );
    let session = server.initialize_session_with_token(&valid_token);

    let expired_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": unix_now() - 10,
        }),
    );
    let expired = server.post_json_with_token(
        &expired_token,
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(expired.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(expired
        .headers()
        .get("WWW-Authenticate")
        .expect("www-authenticate header")
        .to_str()
        .expect("challenge string")
        .contains("Bearer"));

    let mismatched_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-456",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-other",
            "exp": unix_now() + 600,
        }),
    );
    let mismatched = server.post_json_with_token(
        &mismatched_token,
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(mismatched.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(mismatched
        .text()
        .expect("mismatched body")
        .contains("authenticated authorization context does not match session"));

    let tools = server.list_tools_with_token(&valid_token, &session);
    assert_eq!(
        tools["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
}
