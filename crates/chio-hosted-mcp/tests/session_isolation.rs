#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;

use chio_core::crypto::Keypair;
use serde_json::{json, Value};

use support::{sign_jwt, start_jwt_http_server, unix_now};

#[derive(Clone, Copy)]
struct JwtSessionClaims<'a> {
    subject: &'a str,
    client_id: &'a str,
    tenant_id: &'a str,
    scopes: &'a str,
    groups: &'a [&'a str],
}

fn jwt_for(
    signing_key: &Keypair,
    issuer: &str,
    audience: &str,
    subject: &str,
    client_id: &str,
    tenant_id: &str,
    exp_offset_secs: u64,
) -> String {
    jwt_for_claims(
        signing_key,
        issuer,
        audience,
        JwtSessionClaims {
            subject,
            client_id,
            tenant_id,
            scopes: "mcp:invoke tools.read",
            groups: &[],
        },
        exp_offset_secs,
    )
}

fn jwt_for_claims(
    signing_key: &Keypair,
    issuer: &str,
    audience: &str,
    claims: JwtSessionClaims<'_>,
    exp_offset_secs: u64,
) -> String {
    sign_jwt(
        signing_key,
        &json!({
            "iss": issuer,
            "sub": claims.subject,
            "aud": audience,
            "scope": claims.scopes,
            "client_id": claims.client_id,
            "tid": claims.tenant_id,
            "groups": claims.groups,
            "exp": unix_now() + exp_offset_secs,
        }),
    )
}

#[test]
fn hosted_mcp_rejects_cross_tenant_session_reuse() {
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

    let token_a = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-123",
        "client-a",
        "tenant-a",
        300,
    );
    let token_b = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-456",
        "client-b",
        "tenant-b",
        600,
    );

    let session_a = server.initialize_session_with_token(&token_a);
    let session_b = server.initialize_session_with_token(&token_b);

    let cross_a = server.post_json_with_token(
        &token_b,
        Some(&session_a.id),
        Some(&session_a.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(cross_a.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(cross_a
        .text()
        .expect("cross-session body")
        .contains("authenticated authorization context does not match session"));

    let cross_b = server.post_json_with_token(
        &token_a,
        Some(&session_b.id),
        Some(&session_b.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(cross_b.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(cross_b
        .text()
        .expect("cross-session body")
        .contains("authenticated authorization context does not match session"));

    let tools_a = server.list_tools_with_token(&token_a, &session_a);
    assert_eq!(
        tools_a["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
    let tools_b = server.list_tools_with_token(&token_b, &session_b);
    assert_eq!(
        tools_b["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
}

#[test]
fn hosted_mcp_isolates_receipt_and_trust_attribution_by_session() {
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

    let token_a = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-123",
        "client-a",
        "tenant-a",
        300,
    );
    let token_b = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-456",
        "client-b",
        "tenant-b",
        600,
    );

    let session_a = server.initialize_session_with_token(&token_a);
    let session_b = server.initialize_session_with_token(&token_b);

    let trust_a: Value = server
        .get_admin_session_trust(&session_a.id)
        .json()
        .expect("session A trust json");
    let trust_b: Value = server
        .get_admin_session_trust(&session_b.id)
        .json()
        .expect("session B trust json");

    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-a")
    );
    assert_eq!(
        trust_b["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-b")
    );

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_ne!(subject_a, subject_b);

    let echo_a = server.call_echo_json_with_token(&token_a, &session_a, 41, "tenant-a");
    assert_eq!(echo_a["result"]["structuredContent"]["echo"], "tenant-a");
    let echo_b = server.call_echo_json_with_token(&token_b, &session_b, 42, "tenant-b");
    assert_eq!(echo_b["result"]["structuredContent"]["echo"], "tenant-b");

    let receipts = server.get_admin_tool_receipts(&[("toolName", "echo_json"), ("limit", "10")]);
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("tool receipts json");
    let receipts = receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert_eq!(receipts.len(), 2);

    let mut subject_counts = BTreeMap::new();
    for receipt in receipts {
        assert_eq!(receipt["tool_name"].as_str(), Some("echo_json"));
        assert_eq!(receipt["decision"]["verdict"].as_str(), Some("allow"));
        let subject_key = receipt["metadata"]["attribution"]["subject_key"]
            .as_str()
            .expect("receipt subject key");
        *subject_counts
            .entry(subject_key.to_string())
            .or_insert(0usize) += 1;
    }

    assert_eq!(subject_counts.get(&subject_a), Some(&1));
    assert_eq!(subject_counts.get(&subject_b), Some(&1));
}

#[test]
fn hosted_mcp_rejects_session_reuse_when_authorization_context_drifts() {
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

    let baseline_groups = ["eng", "ops"];
    let reduced_groups = ["eng"];
    let baseline = JwtSessionClaims {
        subject: "user-123",
        client_id: "client-a",
        tenant_id: "tenant-a",
        scopes: "mcp:invoke tools.read",
        groups: &baseline_groups,
    };
    let session_token = jwt_for_claims(&signing_key, issuer, audience, baseline, 300);
    let session = server.initialize_session_with_token(&session_token);

    let scenarios = [
        (
            "privilege shrink",
            JwtSessionClaims {
                scopes: "mcp:invoke",
                ..baseline
            },
        ),
        (
            "client context drift",
            JwtSessionClaims {
                client_id: "client-b",
                ..baseline
            },
        ),
        (
            "tenant drift",
            JwtSessionClaims {
                tenant_id: "tenant-b",
                ..baseline
            },
        ),
        (
            "group drift",
            JwtSessionClaims {
                groups: &reduced_groups,
                ..baseline
            },
        ),
    ];

    for (index, (label, claims)) in scenarios.iter().enumerate() {
        let token = jwt_for_claims(&signing_key, issuer, audience, *claims, 600 + index as u64);
        let response = server.post_json_with_token(
            &token,
            Some(&session.id),
            Some(&session.protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 20 + index as i64,
                "method": "tools/list",
                "params": {}
            }),
        );
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{label} should block session reuse"
        );
        let body = response.text().expect("drift response body");
        assert!(
            body.contains("authenticated authorization context does not match session"),
            "{label} returned unexpected body: {body}"
        );
    }

    let tools = server.list_tools_with_token(&session_token, &session);
    assert_eq!(
        tools["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
}

#[test]
fn hosted_mcp_rejects_session_reuse_when_origin_drifts() {
    let server = support::start_http_server("test-token");
    let session = server
        .initialize_session_with_token_and_origin("test-token", Some("http://localhost:3000"));

    let response = server.post_json_with_token_and_origin(
        "test-token",
        Some(&session.id),
        Some(&session.protocol_version),
        Some("http://localhost:4000"),
        &json!({
            "jsonrpc": "2.0",
            "id": 88,
            "method": "tools/list",
            "params": {}
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(response
        .text()
        .expect("origin drift body")
        .contains("authenticated origin does not match session"));

    let tools = server.list_tools_with_token_and_origin(
        "test-token",
        &session,
        Some("http://localhost:3000"),
    );
    assert_eq!(
        tools["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
}

#[test]
fn hosted_mcp_dedicated_sessions_require_exact_oauth_bearer_continuity() {
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

    let claims = JwtSessionClaims {
        subject: "user-123",
        client_id: "client-a",
        tenant_id: "tenant-a",
        scopes: "mcp:invoke tools.read",
        groups: &[],
    };
    let session_token = jwt_for_claims(&signing_key, issuer, audience, claims, 300);
    let session = server.initialize_session_with_token(&session_token);
    let trust: Value = server
        .get_admin_session_trust(&session.id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );

    let refreshed_token = jwt_for_claims(&signing_key, issuer, audience, claims, 600);
    let response = server.post_json_with_token(
        &refreshed_token,
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(response
        .text()
        .expect("refreshed token body")
        .contains("authenticated authorization context does not match session"));
}
