#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-cli-auth-server-{nonce}"))
}

fn auth_server_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import sys

def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

TOOLS = [{
    "name": "echo_json",
    "description": "Echo JSON",
    "inputSchema": {"type": "object"},
    "annotations": {"readOnlyHint": True}
}]

for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-http-upstream", "version": "0.1.0"}
            }
        })
        continue
    if method == "notifications/initialized":
        continue
    if method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        continue
    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_http_auth_server.py");
    fs::write(&path, script).expect("write mock server script");
    path
}

fn write_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
capabilities:
  default:
    tools:
      - server: wrapped-http-mock
        tool: echo_json
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("http-policy.yaml");
    fs::write(&path, policy).expect("write policy");
    path
}

fn spawn_http_server_with_local_auth(
    dir: &Path,
    listen: SocketAddr,
    admin_token: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let session_db_path = dir.join(format!("remote-session-{}.sqlite3", listen.port()));
    let authority_seed_path = dir.join("remote-authority.seed");
    let auth_server_seed_path = dir.join("auth-server.seed");
    let public_base_url = format!("http://{listen}");
    let audience = format!("{public_base_url}/mcp");

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--session-db",
            session_db_path.to_str().expect("session db path"),
            "--authority-seed-file",
            authority_seed_path.to_str().expect("authority seed path"),
            "mcp",
            "serve-http",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-http-mock",
            "--server-name",
            "Wrapped HTTP Mock",
            "--listen",
            &listen.to_string(),
            "--public-base-url",
            &public_base_url,
            "--auth-server-seed-file",
            auth_server_seed_path
                .to_str()
                .expect("auth server seed path"),
            "--auth-jwt-audience",
            &audience,
            "--auth-scope",
            "mcp:invoke",
            "--admin-token",
            admin_token,
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http");

    ServerGuard { child }
}

fn wait_for_http_server(client: &Client, base_url: &str, server: &mut ServerGuard) {
    for _ in 0..300 {
        match client
            .get(format!(
                "{base_url}/.well-known/oauth-protected-resource/mcp"
            ))
            .send()
        {
            Ok(response) if response.status().is_success() => return,
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    let mut stderr = String::new();
    if let Some(child_stderr) = server.child.stderr.as_mut() {
        let _ = child_stderr.read_to_string(&mut stderr);
    }
    panic!("remote MCP auth server did not become ready\nstderr:\n{stderr}");
}

fn post_mcp_json(client: &Client, base_url: &str, token: &str, body: &Value) -> Response {
    post_mcp_json_with_headers(client, base_url, token, &[], body)
}

fn post_mcp_json_with_headers(
    client: &Client,
    base_url: &str,
    token: &str,
    extra_headers: &[(&str, String)],
    body: &Value,
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json");
    for (name, value) in extra_headers {
        request = request.header(*name, value);
    }
    request
        .body(serde_json::to_vec(body).expect("serialize request body"))
        .send()
        .expect("send HTTP MCP request")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn encode_sender_dpop_header(
    keypair: &Keypair,
    binding_id: &str,
    target: &str,
    method: &str,
    nonce: &str,
) -> String {
    let proof = DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.to_string(),
            capability_id: binding_id.to_string(),
            tool_server: target.to_string(),
            tool_name: method.to_string(),
            action_hash: sha256_hex(b""),
            nonce: nonce.to_string(),
            issued_at: unix_now(),
            agent_key: keypair.public_key(),
        },
        keypair,
    )
    .expect("sign sender DPoP proof");
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&proof).expect("serialize DPoP proof"))
}

fn oauth_form_with_sender_constraint<'a>(
    redirect_uri: &'a str,
    resource: &'a str,
    challenge: &'a str,
    decision: &'a str,
    sender_fields: &[(&'a str, &'a str)],
    extra_fields: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![
        ("response_type", "code"),
        ("client_id", "https://client.example/app"),
        ("redirect_uri", redirect_uri),
        ("state", "state-123"),
        ("resource", resource),
        ("scope", "mcp:invoke"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("decision", decision),
    ];
    fields.extend_from_slice(extra_fields);
    fields.extend_from_slice(sender_fields);
    fields
}

fn authorize_sender_bound_code(
    client: &Client,
    base_url: &str,
    redirect_uri: &str,
    resource: &str,
    sender_query_fields: &[(&str, &str)],
    approval_extra_fields: &[(&str, &str)],
) -> String {
    let code_verifier = "chio-auth-verifier";
    let challenge = pkce_challenge(code_verifier);
    let mut authorize = client.get(format!("{base_url}/oauth/authorize")).query(&[
        ("response_type", "code"),
        ("client_id", "https://client.example/app"),
        ("redirect_uri", redirect_uri),
        ("state", "state-123"),
        ("resource", resource),
        ("scope", "mcp:invoke"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    for (name, value) in sender_query_fields {
        authorize = authorize.query(&[(*name, *value)]);
    }
    for (name, value) in approval_extra_fields {
        authorize = authorize.query(&[(*name, *value)]);
    }
    authorize
        .send()
        .expect("send authorize request")
        .error_for_status()
        .expect("authorize page ok");

    let approval_fields = oauth_form_with_sender_constraint(
        redirect_uri,
        resource,
        challenge.as_str(),
        "approve",
        sender_query_fields,
        approval_extra_fields,
    );
    let approval_response = client
        .post(format!("{base_url}/oauth/authorize"))
        .form(&approval_fields)
        .send()
        .expect("submit approval");
    assert!(approval_response.status().is_redirection());
    let location = approval_response
        .headers()
        .get(LOCATION)
        .expect("approval location")
        .to_str()
        .expect("location str");
    let redirect = Url::parse(location).expect("parse approval redirect");
    redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("authorization code")
}

fn token_exchange_with_headers(
    client: &Client,
    base_url: &str,
    form: &[(&str, &str)],
    extra_headers: &[(&str, String)],
) -> reqwest::blocking::Response {
    client
        .post(format!("{base_url}/oauth/token"))
        .headers({
            let mut headers = reqwest::header::HeaderMap::new();
            for (name, value) in extra_headers {
                headers.insert(
                    HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                    HeaderValue::from_str(value).expect("header value"),
                );
            }
            headers
        })
        .form(form)
        .send()
        .expect("send token request")
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn decode_jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload segment");
    let decoded = URL_SAFE_NO_PAD.decode(payload).expect("decode JWT payload");
    serde_json::from_slice(&decoded).expect("parse JWT payload")
}

#[test]
fn mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange() {
    if skip_when_loopback_bind_denied(
        "mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange",
    ) {
        return;
    }

    let _guard = auth_server_test_guard();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let mut server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url, &mut server);

    let protected_resource: Value = client
        .get(format!(
            "{base_url}/.well-known/oauth-protected-resource/mcp"
        ))
        .send()
        .expect("send protected resource request")
        .error_for_status()
        .expect("protected resource ok")
        .json()
        .expect("decode protected resource");
    assert_eq!(
        protected_resource["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        protected_resource["chio_authorization_profile"]["portableIdentityBinding"]
            ["chioProvenanceAnchor"]
            .as_str(),
        Some("did:chio")
    );
    assert_eq!(
        protected_resource["chio_authorization_profile"]["governedAuthBinding"]
            ["authoritativeSource"]
            .as_str(),
        Some("metadata.governed_transaction")
    );
    assert_eq!(
        protected_resource["chio_authorization_profile"]["requestTimeContract"]
            ["authorizationDetailsParameter"]
            .as_str(),
        Some("authorization_details")
    );
    assert_eq!(
        protected_resource["chio_authorization_profile"]["resourceBinding"]
            ["requestResourceMustMatchProtectedResource"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        protected_resource["chio_authorization_profile"]["artifactBoundary"]
            ["reviewerEvidenceRuntimeAdmissionSupported"]
            .as_bool(),
        Some(false)
    );
    let issuer = protected_resource["authorization_servers"][0]
        .as_str()
        .expect("issuer")
        .to_string();
    let auth_metadata_path = format!(
        "{base_url}/.well-known/oauth-authorization-server/{}",
        Url::parse(&issuer)
            .expect("parse issuer")
            .path()
            .trim_matches('/')
    );
    let auth_metadata: Value = client
        .get(&auth_metadata_path)
        .send()
        .expect("send auth metadata request")
        .error_for_status()
        .expect("auth metadata ok")
        .json()
        .expect("decode auth metadata");
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["portableIdentityBinding"]
            ["chioProvenanceAnchor"]
            .as_str(),
        Some("did:chio")
    );
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["governedAuthBinding"]["authoritativeSource"]
            .as_str(),
        Some("metadata.governed_transaction")
    );
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["requestTimeContract"]
            ["accessTokenTransactionContextClaim"]
            .as_str(),
        Some("chio_transaction_context")
    );
    assert_eq!(
        auth_metadata["grant_types_supported"],
        json!([
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ])
    );

    let code_verifier = "chio-auth-verifier";
    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let state = "state-123";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let authorization_details = json!([{
        "type": "chio_governed_tool",
        "locations": ["wrapped-http-mock"],
        "actions": ["echo_json"],
        "purpose": "request-time MCP invocation"
    }]);
    let transaction_context = json!({
        "intentId": "intent-live-auth-1",
        "intentHash": "intent-hash-live-auth-1",
        "identityAssertion": {
            "verifierId": "https://client.example/app",
            "subject": "alice@example.com",
            "continuityId": "session-live-auth-1",
            "issuedAt": now,
            "expiresAt": now + 300,
            "provider": "oidc",
            "sessionHint": "resume"
        }
    });
    let authorization_details_json = authorization_details.to_string();
    let transaction_context_json = transaction_context.to_string();
    let challenge = pkce_challenge(code_verifier);

    let invalid_target = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("resource", "https://wrong.example/mcp"),
            ("scope", "mcp:invoke"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send invalid target authorize request");
    assert_eq!(invalid_target.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_target_body: Value = invalid_target
        .json()
        .expect("decode invalid target authorize response");
    assert_eq!(
        invalid_target_body["error"].as_str(),
        Some("invalid_target")
    );

    let authorize_response = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            ("authorization_details", authorization_details_json.as_str()),
            (
                "chio_transaction_context",
                transaction_context_json.as_str(),
            ),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send authorize request")
        .error_for_status()
        .expect("authorize page ok")
        .text()
        .expect("read authorize page");
    assert!(authorize_response.contains("Approve"));
    assert!(authorize_response.contains("Chio Authorization Details: 1 detail(s)"));
    assert!(authorize_response
        .contains("Chio Transaction Context: intent-live-auth-1 / intent-hash-live-auth-1"));
    assert!(authorize_response.contains("alice@example.com / session-live-auth-1"));

    let approval_response = client
        .post(format!("{base_url}/oauth/authorize"))
        .form(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            ("authorization_details", authorization_details_json.as_str()),
            (
                "chio_transaction_context",
                transaction_context_json.as_str(),
            ),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("decision", "approve"),
        ])
        .send()
        .expect("submit approval");
    assert!(approval_response.status().is_redirection());
    let location = approval_response
        .headers()
        .get(LOCATION)
        .expect("approval location")
        .to_str()
        .expect("location str");
    let redirect = Url::parse(location).expect("parse approval redirect");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("authorization code");

    let code_replay = post_mcp_json(
        &client,
        &base_url,
        &code,
        &json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test-replay", "version": "0.1.0"}
            }
        }),
    );
    assert_eq!(code_replay.status(), reqwest::StatusCode::UNAUTHORIZED);

    let token_response: Value = client
        .post(format!("{base_url}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("client_id", "https://client.example/app"),
            ("code_verifier", code_verifier),
            ("resource", resource.as_str()),
        ])
        .send()
        .expect("exchange authorization code")
        .error_for_status()
        .expect("token exchange ok")
        .json()
        .expect("decode token response");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    assert_eq!(token_response["scope"].as_str(), Some("mcp:invoke"));
    let access_payload = decode_jwt_payload(&access_token);
    assert_eq!(access_payload["aud"].as_str(), Some(resource.as_str()));
    assert_eq!(access_payload["resource"].as_str(), Some(resource.as_str()));
    assert_eq!(
        access_payload["authorization_details"][0]["type"].as_str(),
        Some("chio_governed_tool")
    );
    assert_eq!(
        access_payload["chio_transaction_context"]["intentId"].as_str(),
        Some("intent-live-auth-1")
    );
    assert_eq!(
        access_payload["chio_transaction_context"]["identityAssertion"]["subject"].as_str(),
        Some("alice@example.com")
    );
    assert_eq!(
        access_payload["chio_transaction_context"]["identityAssertion"]["continuityId"].as_str(),
        Some("session-live-auth-1")
    );

    let initialize_response = post_mcp_json(
        &client,
        &base_url,
        &access_token,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test", "version": "0.1.0"}
            }
        }),
    );
    let initialize_status = initialize_response.status();
    let initialize_headers = initialize_response.headers().clone();
    let initialize_body = initialize_response.text().expect("initialize body");
    assert!(
        initialize_status.is_success(),
        "initialize failed: status={initialize_status} body={initialize_body}"
    );
    assert!(initialize_headers.get("MCP-Session-Id").is_some());

    let exchanged_response: Value = client
        .post(format!("{base_url}/oauth/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", access_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
        ])
        .send()
        .expect("exchange subject token")
        .error_for_status()
        .expect("token exchange ok")
        .json()
        .expect("decode exchanged token response");
    let exchanged_token = exchanged_response["access_token"]
        .as_str()
        .expect("exchanged access token");
    assert_ne!(exchanged_token, access_token);
    let exchanged_payload = decode_jwt_payload(exchanged_token);
    assert_eq!(
        exchanged_payload["authorization_details"][0]["actions"][0].as_str(),
        Some("echo_json")
    );
    assert_eq!(
        exchanged_payload["chio_transaction_context"]["intentHash"].as_str(),
        Some("intent-hash-live-auth-1")
    );
    assert_eq!(
        exchanged_payload["chio_transaction_context"]["identityAssertion"]["verifierId"].as_str(),
        Some("https://client.example/app")
    );

    let exchanged_initialize = post_mcp_json(
        &client,
        &base_url,
        exchanged_token,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test-2", "version": "0.1.0"}
            }
        }),
    );
    let exchanged_status = exchanged_initialize.status();
    let exchanged_body = exchanged_initialize
        .text()
        .expect("exchanged initialize body");
    assert!(
        exchanged_status.is_success(),
        "exchanged initialize failed: status={exchanged_status} body={exchanged_body}"
    );
}

#[test]
fn mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion() {
    if skip_when_loopback_bind_denied(
        "mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion",
    ) {
        return;
    }

    let _guard = auth_server_test_guard();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let mut server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url, &mut server);

    let code_verifier = "chio-auth-verifier";
    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let state = "state-123";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let challenge = pkce_challenge(code_verifier);
    let authorization_details = json!([{
        "type": "chio_governed_tool",
        "locations": ["wrapped-http-mock"],
        "actions": ["echo_json"]
    }])
    .to_string();
    let stale_context = json!({
        "intentId": "intent-live-auth-stale",
        "intentHash": "intent-hash-live-auth-stale",
        "identityAssertion": {
            "verifierId": "https://client.example/app",
            "subject": "alice@example.com",
            "continuityId": "session-stale",
            "issuedAt": now.saturating_sub(600),
            "expiresAt": now.saturating_sub(1)
        }
    })
    .to_string();
    let mismatch_context = json!({
        "intentId": "intent-live-auth-mismatch",
        "intentHash": "intent-hash-live-auth-mismatch",
        "identityAssertion": {
            "verifierId": "https://different.example/app",
            "subject": "alice@example.com",
            "continuityId": "session-mismatch",
            "issuedAt": now,
            "expiresAt": now + 300
        }
    })
    .to_string();

    let stale = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            ("authorization_details", authorization_details.as_str()),
            ("chio_transaction_context", stale_context.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send stale authorize request");
    assert_eq!(stale.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(stale
        .text()
        .expect("stale authorize body")
        .contains("identityAssertion is stale"));

    let mismatch = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            ("authorization_details", authorization_details.as_str()),
            ("chio_transaction_context", mismatch_context.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send mismatched authorize request");
    assert_eq!(mismatch.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(mismatch
        .text()
        .expect("mismatched authorize body")
        .contains("identityAssertion.verifierId must match client_id"));
}

#[test]
fn mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime() {
    if skip_when_loopback_bind_denied(
        "mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime",
    ) {
        return;
    }

    let _guard = auth_server_test_guard();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let mut server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url, &mut server);

    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let sender_keypair = Keypair::generate();
    let sender_key_hex = sender_keypair.public_key().to_hex();
    let code = authorize_sender_bound_code(
        &client,
        &base_url,
        redirect_uri,
        resource.as_str(),
        &[("chio_sender_dpop_public_key", sender_key_hex.as_str())],
        &[],
    );

    let code_dpop_header = encode_sender_dpop_header(
        &sender_keypair,
        code.as_str(),
        &format!("{base_url}/oauth/token"),
        "POST",
        "token-dpop-nonce-1",
    );
    let token_response: Value = token_exchange_with_headers(
        &client,
        &base_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("client_id", "https://client.example/app"),
            ("code_verifier", "chio-auth-verifier"),
            ("resource", resource.as_str()),
        ],
        &[("dpop", code_dpop_header)],
    )
    .error_for_status()
    .expect("sender-constrained token exchange ok")
    .json()
    .expect("decode sender-constrained token response");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let access_payload = decode_jwt_payload(&access_token);
    assert_eq!(
        access_payload["cnf"]["chioSenderKey"].as_str(),
        Some(sender_key_hex.as_str())
    );
    let access_token_jti = access_payload["jti"].as_str().expect("access token jti");

    let runtime_dpop_header = encode_sender_dpop_header(
        &sender_keypair,
        access_token_jti,
        resource.as_str(),
        "POST",
        "runtime-dpop-nonce-1",
    );
    let initialize_response = post_mcp_json_with_headers(
        &client,
        &base_url,
        &access_token,
        &[("dpop", runtime_dpop_header.clone())],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sender-dpop-test", "version": "0.1.0"}
            }
        }),
    );
    let initialize_status = initialize_response.status();
    let initialize_body = initialize_response.text().expect("initialize body");
    assert!(
        initialize_status.is_success(),
        "sender-constrained initialize failed: status={initialize_status} body={initialize_body}"
    );

    let replay_response = post_mcp_json_with_headers(
        &client,
        &base_url,
        &access_token,
        &[("dpop", runtime_dpop_header)],
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sender-dpop-replay", "version": "0.1.0"}
            }
        }),
    );
    assert_eq!(replay_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(replay_response
        .text()
        .expect("replay body")
        .contains("already used"));
}

#[test]
fn mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint() {
    if skip_when_loopback_bind_denied(
        "mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint",
    ) {
        return;
    }

    let _guard = auth_server_test_guard();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let mut server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url, &mut server);

    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let mtls_thumbprint = "thumb-live-1";
    let attestation_hash = "sha256-attestation-auth-1";
    let transaction_context = json!({
        "intentId": "intent-mtls-attestation-1",
        "intentHash": "intent-hash-mtls-attestation-1",
        "runtimeAssuranceTier": "verified",
        "runtimeAssuranceVerifier": "azure_maa",
        "runtimeAssuranceEvidenceSha256": attestation_hash
    })
    .to_string();
    let code = authorize_sender_bound_code(
        &client,
        &base_url,
        redirect_uri,
        resource.as_str(),
        &[
            ("chio_sender_mtls_thumbprint_sha256", mtls_thumbprint),
            ("chio_sender_attestation_sha256", attestation_hash),
        ],
        &[("chio_transaction_context", transaction_context.as_str())],
    );

    let token_response: Value = token_exchange_with_headers(
        &client,
        &base_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("client_id", "https://client.example/app"),
            ("code_verifier", "chio-auth-verifier"),
            ("resource", resource.as_str()),
        ],
        &[
            ("x-chio-mtls-thumbprint-sha256", mtls_thumbprint.to_string()),
            (
                "x-chio-runtime-attestation-sha256",
                attestation_hash.to_string(),
            ),
        ],
    )
    .error_for_status()
    .expect("mtls/attestation token exchange ok")
    .json()
    .expect("decode mtls/attestation token response");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let access_payload = decode_jwt_payload(&access_token);
    assert_eq!(
        access_payload["cnf"]["x5t#S256"].as_str(),
        Some(mtls_thumbprint)
    );
    assert_eq!(
        access_payload["cnf"]["chioAttestationSha256"].as_str(),
        Some(attestation_hash)
    );

    let initialize_response = post_mcp_json_with_headers(
        &client,
        &base_url,
        &access_token,
        &[
            ("x-chio-mtls-thumbprint-sha256", mtls_thumbprint.to_string()),
            (
                "x-chio-runtime-attestation-sha256",
                attestation_hash.to_string(),
            ),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sender-mtls-test", "version": "0.1.0"}
            }
        }),
    );
    let initialize_status = initialize_response.status();
    assert!(
        initialize_status.is_success(),
        "mtls/attestation initialize failed: {}",
        initialize_response.text().expect("initialize body")
    );
    drop(initialize_response);

    let missing_attestation = post_mcp_json_with_headers(
        &client,
        &base_url,
        &access_token,
        &[("x-chio-mtls-thumbprint-sha256", mtls_thumbprint.to_string())],
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sender-mtls-missing-attestation", "version": "0.1.0"}
            }
        }),
    );
    assert_eq!(
        missing_attestation.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(missing_attestation
        .text()
        .expect("missing attestation body")
        .contains("missing runtime attestation binding header"));
}

#[test]
fn mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls() {
    if skip_when_loopback_bind_denied(
        "mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls",
    ) {
        return;
    }

    let _guard = auth_server_test_guard();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let mut server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url, &mut server);

    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let challenge = pkce_challenge("chio-auth-verifier");
    let attestation_only_context = json!({
        "intentId": "intent-attestation-only-1",
        "intentHash": "intent-hash-attestation-only-1",
        "runtimeAssuranceTier": "verified",
        "runtimeAssuranceVerifier": "azure_maa",
        "runtimeAssuranceEvidenceSha256": "sha256-attestation-auth-1"
    })
    .to_string();
    let attestation_only = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", "state-123"),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            (
                "chio_transaction_context",
                attestation_only_context.as_str(),
            ),
            (
                "chio_sender_attestation_sha256",
                "sha256-attestation-auth-1",
            ),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send attestation-only authorize request");
    assert_eq!(attestation_only.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(attestation_only
        .text()
        .expect("attestation-only body")
        .contains(
            "require either chio_sender_dpop_public_key or chio_sender_mtls_thumbprint_sha256"
        ));

    let sender_keypair = Keypair::generate();
    let sender_key_hex = sender_keypair.public_key().to_hex();
    let mismatch_context = json!({
        "intentId": "intent-attestation-mismatch-1",
        "intentHash": "intent-hash-attestation-mismatch-1",
        "runtimeAssuranceTier": "verified",
        "runtimeAssuranceVerifier": "azure_maa",
        "runtimeAssuranceEvidenceSha256": "sha256-attestation-auth-expected"
    })
    .to_string();
    let mismatch = client
        .get(format!("{base_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", "state-123"),
            ("resource", resource.as_str()),
            ("scope", "mcp:invoke"),
            ("chio_transaction_context", mismatch_context.as_str()),
            ("chio_sender_dpop_public_key", sender_key_hex.as_str()),
            (
                "chio_sender_attestation_sha256",
                "sha256-attestation-auth-actual",
            ),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send mismatched attestation authorize request");
    assert_eq!(mismatch.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(mismatch
        .text()
        .expect("mismatched attestation body")
        .contains("must match chio_transaction_context.runtimeAssuranceEvidenceSha256"));
}
