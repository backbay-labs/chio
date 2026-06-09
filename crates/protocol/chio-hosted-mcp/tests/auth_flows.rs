#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::crypto::Keypair;
use reqwest::header::LOCATION;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use support::{
    sign_jwt, start_http_server, start_jwt_http_server, start_local_oauth_http_server, unix_now,
    TestServer,
};

fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
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

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn authorize_code(
    server: &TestServer,
    redirect_uri: &str,
    resource: &str,
    code_verifier: &str,
) -> String {
    let challenge = pkce_challenge(code_verifier);
    let authorize_page = server
        .client
        .get(format!("{}/oauth/authorize", server.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", "state-123"),
            ("resource", resource),
            ("scope", "mcp:invoke"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send authorize request")
        .error_for_status()
        .expect("authorize page ok")
        .text()
        .expect("authorize page text");
    assert!(authorize_page.contains("Approve"));

    let approval = server
        .client
        .post(format!("{}/oauth/authorize", server.base_url))
        .form(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", "state-123"),
            ("resource", resource),
            ("scope", "mcp:invoke"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("decision", "approve"),
        ])
        .send()
        .expect("submit approval");
    assert!(approval.status().is_redirection());

    let location = approval
        .headers()
        .get(LOCATION)
        .expect("approval redirect")
        .to_str()
        .expect("location string");
    Url::parse(location)
        .expect("parse redirect URL")
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.to_string())
        .expect("authorization code")
}

fn exchange_code(
    server: &TestServer,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    resource: &str,
) -> reqwest::blocking::Response {
    server
        .client
        .post(format!("{}/oauth/token", server.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", "https://client.example/app"),
            ("code_verifier", code_verifier),
            ("resource", resource),
        ])
        .send()
        .expect("exchange authorization code")
}

fn decode_jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload segment");
    let decoded = URL_SAFE_NO_PAD.decode(payload).expect("decode JWT payload");
    serde_json::from_slice(&decoded).expect("parse JWT payload")
}

#[test]
fn hosted_mcp_accepts_static_bearer_and_rejects_invalid_token() {
    let server = start_http_server("test-token");

    let session = server.initialize_session();
    assert!(!session.id.is_empty());

    let invalid = server.post_raw(
        Some("wrong-token"),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(9),
    );
    assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid
            .headers()
            .get("WWW-Authenticate")
            .expect("www-authenticate header")
            .to_str()
            .expect("challenge string"),
        "Bearer"
    );
}

#[test]
fn hosted_mcp_accepts_jwt_and_rejects_wrong_audience() {
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
    let trust: Value = server
        .get_admin_session_trust(&session.id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );

    let wrong_audience_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": "wrong-audience",
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": unix_now() + 300,
        }),
    );
    let response = server.post_raw(
        Some(&wrong_audience_token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(10),
    );
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get("WWW-Authenticate")
        .expect("www-authenticate header")
        .to_str()
        .expect("challenge string")
        .contains("Bearer"));
}

#[test]
fn hosted_mcp_accepts_local_oauth_pkce_and_rejects_invalid_verifier() {
    let server = start_local_oauth_http_server("admin-token");
    let metadata: Value = server
        .get_protected_resource_metadata()
        .json()
        .expect("protected resource metadata");
    let resource = metadata["resource"].as_str().expect("resource").to_string();
    let redirect_uri = "http://localhost:7777/callback";

    let invalid_code = authorize_code(&server, redirect_uri, &resource, "chio-auth-verifier");
    let invalid_exchange = exchange_code(
        &server,
        &invalid_code,
        redirect_uri,
        "wrong-verifier",
        &resource,
    );
    assert_eq!(invalid_exchange.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_exchange: Value = invalid_exchange.json().expect("invalid exchange json");
    assert_eq!(invalid_exchange["error"].as_str(), Some("invalid_grant"));
    assert_eq!(
        invalid_exchange["error_description"].as_str(),
        Some("PKCE verification failed")
    );

    let code = authorize_code(&server, redirect_uri, &resource, "chio-auth-verifier");
    let token_response = exchange_code(
        &server,
        &code,
        redirect_uri,
        "chio-auth-verifier",
        &resource,
    );
    assert_eq!(token_response.status(), reqwest::StatusCode::OK);
    let token_response: Value = token_response.json().expect("token response json");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let access_payload = decode_jwt_payload(&access_token);
    assert_eq!(access_payload["aud"].as_str(), Some(resource.as_str()));
    assert_eq!(access_payload["resource"].as_str(), Some(resource.as_str()));

    let session = server.initialize_session_with_token(&access_token);
    assert!(!session.id.is_empty());
}
