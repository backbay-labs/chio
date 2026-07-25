#![allow(clippy::expect_used, clippy::unwrap_used, dead_code)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::crypto::Keypair;
use chio_hosted_mcp::RemoteServeHttpConfig;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN};
use serde_json::{json, Value};

const SESSION_IDLE_EXPIRY_ENV: &str = "CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS";
const SESSION_DRAIN_GRACE_ENV: &str = "CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS";
const SESSION_REAPER_INTERVAL_ENV: &str = "CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS";

static UNIQUE_TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static TEST_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Clone, Debug, Default)]
pub struct LifecycleTuning {
    pub session_db_path: Option<PathBuf>,
    pub idle_expiry_millis: Option<u64>,
    pub drain_grace_millis: Option<u64>,
    pub reaper_interval_millis: Option<u64>,
}

#[derive(Debug)]
pub struct SessionHandle {
    pub id: String,
    pub protocol_version: String,
}

pub struct TestServer {
    pub base_url: String,
    pub client: Client,
    pub token: String,
    pub receipt_db_path: PathBuf,
    _guard: ServerGuard,
}

struct ServerGuard {
    _thread: JoinHandle<()>,
    result_rx: Receiver<Result<(), String>>,
}

pub fn start_http_server(token: &str) -> TestServer {
    start_http_server_with_lifecycle_tuning(token, LifecycleTuning::default())
}

pub fn start_http_server_with_lifecycle_tuning(token: &str, tuning: LifecycleTuning) -> TestServer {
    let spawn_tuning = tuning.clone();
    start_server(token.to_string(), tuning, |dir, listen| {
        spawn_static_bearer_server_thread(dir, listen, token, spawn_tuning)
    })
}

pub fn start_jwt_http_server(
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> TestServer {
    start_server(
        admin_token.to_string(),
        LifecycleTuning::default(),
        |dir, listen| {
            spawn_jwt_http_server_thread(
                dir,
                listen,
                jwt_public_key_hex,
                issuer,
                audience,
                admin_token,
            )
        },
    )
}

pub fn start_local_oauth_http_server(admin_token: &str) -> TestServer {
    start_server(
        admin_token.to_string(),
        LifecycleTuning::default(),
        |dir, listen| spawn_local_oauth_http_server_thread(dir, listen, admin_token),
    )
}

pub fn sign_jwt(keypair: &Keypair, claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT"
        }))
        .expect("serialize JWT header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    format!("{signing_input}.{signature}")
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn start_server<F>(token: String, tuning: LifecycleTuning, spawn: F) -> TestServer
where
    F: FnOnce(&Path, SocketAddr) -> ServerGuard,
{
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let client = build_client();
    let base_url = format!("http://{listen}");
    let receipt_db_path = dir.join("remote-receipts.sqlite3");

    let guard = {
        let _env_lock = TEST_ENV_LOCK.lock().expect("lock test env");
        let env_snapshot = apply_session_lifecycle_env(&tuning);
        let guard = spawn(&dir, listen);
        let startup = wait_for_server_result(&client, &base_url, &guard);
        restore_env(env_snapshot);
        startup.expect("hosted MCP server to become ready");
        guard
    };

    // Sanity-check that the worker did not exit immediately after readiness.
    if let Some(error) = guard.try_get_result().expect("poll server result") {
        panic!("hosted MCP server exited after startup: {error}");
    }

    TestServer {
        base_url,
        client,
        token,
        receipt_db_path,
        _guard: guard,
    }
}

impl TestServer {
    pub fn initialize_session(&self) -> SessionHandle {
        self.initialize_session_with_token(&self.token)
    }

    pub fn initialize_session_with_token(&self, token: &str) -> SessionHandle {
        self.initialize_session_with_token_and_origin(token, None)
    }

    pub fn initialize_session_with_token_and_origin(
        &self,
        token: &str,
        origin: Option<&str>,
    ) -> SessionHandle {
        let response = self.post_json_with_token_and_origin(
            token,
            None,
            Some("2025-11-25"),
            origin,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "sampling": {
                            "context": {},
                            "tools": {}
                        }
                    },
                    "clientInfo": {
                        "name": "integration-test",
                        "version": "0.1.0"
                    }
                }
            }),
        );
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let session_id = response
            .headers()
            .get("MCP-Session-Id")
            .expect("session id header")
            .to_str()
            .expect("session id string")
            .to_string();
        let (initialize, init_messages) = read_sse_until_response(response, json!(1));
        assert!(init_messages.is_empty());

        let protocol_version = initialize["result"]["protocolVersion"]
            .as_str()
            .expect("protocol version")
            .to_string();

        let initialized = self.post_json_with_token_and_origin(
            token,
            Some(&session_id),
            Some(&protocol_version),
            origin,
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
        );
        assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);

        SessionHandle {
            id: session_id,
            protocol_version,
        }
    }

    pub fn list_tools(&self, session: &SessionHandle) -> Value {
        self.list_tools_with_token(&self.token, session)
    }

    pub fn list_tools_with_token(&self, token: &str, session: &SessionHandle) -> Value {
        self.list_tools_with_token_and_origin(token, session, None)
    }

    pub fn list_tools_with_token_and_origin(
        &self,
        token: &str,
        session: &SessionHandle,
        origin: Option<&str>,
    ) -> Value {
        let response = self.post_json_with_token_and_origin(
            token,
            Some(&session.id),
            Some(&session.protocol_version),
            origin,
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        );
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (message, side_effects) = read_sse_until_response(response, json!(2));
        assert!(side_effects.is_empty());
        message
    }

    pub fn call_echo_json_with_token(
        &self,
        token: &str,
        session: &SessionHandle,
        request_id: i64,
        message: &str,
    ) -> Value {
        let response = self.post_json_with_token(
            token,
            Some(&session.id),
            Some(&session.protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": "echo_json",
                    "arguments": {"message": message}
                }
            }),
        );
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (message, side_effects) = read_sse_until_response(response, json!(request_id));
        assert!(side_effects.is_empty());
        message
    }

    pub fn post_json(
        &self,
        session_id: Option<&str>,
        protocol_version: Option<&str>,
        body: &Value,
    ) -> Response {
        self.post_json_with_token(&self.token, session_id, protocol_version, body)
    }

    pub fn post_json_with_token(
        &self,
        token: &str,
        session_id: Option<&str>,
        protocol_version: Option<&str>,
        body: &Value,
    ) -> Response {
        self.post_json_with_token_and_origin(token, session_id, protocol_version, None, body)
    }

    pub fn post_json_with_token_and_origin(
        &self,
        token: &str,
        session_id: Option<&str>,
        protocol_version: Option<&str>,
        origin: Option<&str>,
        body: &Value,
    ) -> Response {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body).expect("serialize request body"));

        if let Some(session_id) = session_id {
            request = request.header("MCP-Session-Id", session_id);
        }
        if let Some(protocol_version) = protocol_version {
            request = request.header("MCP-Protocol-Version", protocol_version);
        }
        if let Some(origin) = origin {
            request = request.header(ORIGIN, origin);
        }

        request.send().expect("send HTTP MCP request")
    }

    pub fn post_raw(
        &self,
        token: Option<&str>,
        session_id: Option<&str>,
        accept: &str,
        content_type: &str,
        body: &Value,
    ) -> Response {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.base_url))
            .header(ACCEPT, accept)
            .header(CONTENT_TYPE, content_type)
            .body(serde_json::to_vec(body).expect("serialize request body"));

        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(session_id) = session_id {
            request = request.header("MCP-Session-Id", session_id);
        }

        request.send().expect("send raw HTTP MCP request")
    }

    pub fn post_bytes(
        &self,
        token: Option<&str>,
        session_id: Option<&str>,
        accept: &str,
        content_type: &str,
        body: &[u8],
    ) -> Response {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.base_url))
            .header(ACCEPT, accept)
            .header(CONTENT_TYPE, content_type)
            .body(body.to_vec());

        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(session_id) = session_id {
            request = request.header("MCP-Session-Id", session_id);
        }

        request.send().expect("send raw byte HTTP MCP request")
    }

    pub fn get_session_stream(
        &self,
        session_id: &str,
        protocol_version: Option<&str>,
        last_event_id: Option<&str>,
    ) -> Response {
        self.get_session_stream_with_token(&self.token, session_id, protocol_version, last_event_id)
    }

    pub fn get_session_stream_with_token(
        &self,
        token: &str,
        session_id: &str,
        protocol_version: Option<&str>,
        last_event_id: Option<&str>,
    ) -> Response {
        let mut request = self
            .client
            .get(format!("{}/mcp", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "text/event-stream")
            .header("MCP-Session-Id", session_id);

        if let Some(protocol_version) = protocol_version {
            request = request.header("MCP-Protocol-Version", protocol_version);
        }
        if let Some(last_event_id) = last_event_id {
            request = request.header("Last-Event-ID", last_event_id);
        }

        request.send().expect("send GET session stream request")
    }

    #[allow(dead_code)]
    pub fn delete_session(&self, session_id: &str) -> Response {
        self.client
            .delete(format!("{}/mcp", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header("MCP-Session-Id", session_id)
            .send()
            .expect("send session delete request")
    }

    pub fn get_admin_session_trust(&self, session_id: &str) -> Response {
        self.get_admin_session_trust_with_token(&self.token, session_id)
    }

    pub fn get_admin_session_trust_with_token(&self, token: &str, session_id: &str) -> Response {
        self.client
            .get(format!(
                "{}/admin/sessions/{session_id}/trust",
                self.base_url
            ))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .expect("send admin session trust request")
    }

    pub fn get_admin_tool_receipts(&self, query: &[(&str, &str)]) -> Response {
        self.client
            .get(format!("{}/admin/receipts/tools", self.base_url))
            .query(query)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .expect("send admin tool receipts request")
    }

    pub fn get_protected_resource_metadata(&self) -> Response {
        self.client
            .get(format!(
                "{}/.well-known/oauth-protected-resource/mcp",
                self.base_url
            ))
            .send()
            .expect("send protected resource metadata request")
    }

    #[allow(dead_code)]
    pub fn post_admin_session_drain(&self, session_id: &str) -> Response {
        self.client
            .post(format!(
                "{}/admin/sessions/{session_id}/drain",
                self.base_url
            ))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .expect("send admin session drain request")
    }

    #[allow(dead_code)]
    pub fn post_admin_session_shutdown(&self, session_id: &str) -> Response {
        self.client
            .post(format!(
                "{}/admin/sessions/{session_id}/shutdown",
                self.base_url
            ))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .expect("send admin session shutdown request")
    }

    pub fn wait_for_session_state(&self, session_id: &str, expected_state: &str) -> Value {
        for _ in 0..40 {
            let response = self.get_admin_session_trust(session_id);
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let payload: Value = response.json().expect("session trust json");
            if payload["lifecycle"]["state"].as_str() == Some(expected_state) {
                return payload;
            }
            thread::sleep(Duration::from_millis(75));
        }

        panic!("session {session_id} did not reach {expected_state}");
    }
}

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-hosted-mcp-tests-{}-{nonce}-{counter}",
        std::process::id()
    ))
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
}

fn build_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client")
}

pub fn base_remote_config(dir: &Path, listen: SocketAddr) -> RemoteServeHttpConfig {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    RemoteServeHttpConfig {
        listen,
        auth_token: None,
        auth_jwt_public_key: None,
        auth_jwt_discovery_url: None,
        auth_introspection_url: None,
        auth_introspection_client_id: None,
        auth_introspection_client_secret: None,
        auth_jwt_provider_profile: None,
        auth_server_seed_path: None,
        identity_federation_seed_path: None,
        enterprise_providers_file: None,
        auth_jwt_issuer: None,
        auth_jwt_audience: None,
        admin_token: None,
        control_url: None,
        control_token: None,
        public_base_url: None,
        auth_servers: vec![],
        auth_authorization_endpoint: None,
        auth_token_endpoint: None,
        auth_registration_endpoint: None,
        auth_jwks_uri: None,
        auth_scopes: vec![],
        auth_subject: "operator".to_string(),
        auth_code_ttl_secs: 300,
        auth_access_token_ttl_secs: 600,
        receipt_db_path: Some(dir.join("remote-receipts.sqlite3")),
        revocation_db_path: None,
        authority_seed_path: Some(dir.join("remote-authority.seed")),
        authority_db_path: None,
        budget_db_path: None,
        session_db_path: Some(dir.join("remote-session-tombstones.sqlite3")),
        policy_path,
        server_id: "wrapped-http-mock".to_string(),
        server_name: "Wrapped HTTP Mock".to_string(),
        server_version: "0.1.0".to_string(),
        manifest_public_key: None,
        page_size: 50,
        tools_list_changed: false,
        shared_hosted_owner: false,
        wrapped_command: "python3".to_string(),
        wrapped_args: vec![script_path.to_string_lossy().into_owned()],
        egress_contract: None,
    }
}

fn spawn_static_bearer_server_thread(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    tuning: LifecycleTuning,
) -> ServerGuard {
    let mut config = base_remote_config(dir, listen);
    let session_db_path = tuning
        .session_db_path
        .unwrap_or_else(|| dir.join("remote-session-tombstones.sqlite3"));
    config.auth_token = Some(token.to_string());
    config.session_db_path = Some(session_db_path);
    spawn_server_thread(config)
}

fn spawn_jwt_http_server_thread(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> ServerGuard {
    let mut config = base_remote_config(dir, listen);
    config.auth_jwt_public_key = Some(jwt_public_key_hex.to_string());
    config.auth_jwt_issuer = Some(issuer.to_string());
    config.auth_jwt_audience = Some(audience.to_string());
    config.admin_token = Some(admin_token.to_string());
    config.auth_scopes = vec!["mcp:invoke".to_string()];
    spawn_server_thread(config)
}

fn spawn_local_oauth_http_server_thread(
    dir: &Path,
    listen: SocketAddr,
    admin_token: &str,
) -> ServerGuard {
    let mut config = base_remote_config(dir, listen);
    let auth_server_seed_path = dir.join("auth-server.seed");
    let public_base_url = format!("http://{listen}");
    config.auth_server_seed_path = Some(auth_server_seed_path);
    config.auth_jwt_audience = Some(format!("{public_base_url}/mcp"));
    config.admin_token = Some(admin_token.to_string());
    config.public_base_url = Some(public_base_url);
    config.auth_scopes = vec!["mcp:invoke".to_string()];
    spawn_server_thread(config)
}

fn spawn_server_thread(config: RemoteServeHttpConfig) -> ServerGuard {
    let (result_tx, result_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        let result = std::panic::catch_unwind(|| chio_hosted_mcp::serve_http(config));
        let exit_result = match result {
            Ok(Ok(())) => Err("hosted MCP server exited unexpectedly".to_string()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("hosted MCP server panicked".to_string()),
        };
        let _ = result_tx.send(exit_result);
    });

    ServerGuard {
        _thread: thread,
        result_rx,
    }
}

fn wait_for_server_result(
    client: &Client,
    base_url: &str,
    guard: &ServerGuard,
) -> Result<(), String> {
    for _ in 0..100 {
        if let Some(error) = guard.try_get_result()? {
            return Err(error);
        }
        match client.get(format!("{base_url}/mcp")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }

    Err("hosted MCP server did not become ready".to_string())
}

impl ServerGuard {
    fn try_get_result(&self) -> Result<Option<String>, String> {
        match self.result_rx.try_recv() {
            Ok(Ok(())) => Ok(None),
            Ok(Err(error)) => Ok(Some(error)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err("hosted MCP server worker disconnected".to_string())
            }
        }
    }
}

fn apply_session_lifecycle_env(tuning: &LifecycleTuning) -> Vec<(String, Option<String>)> {
    let mut snapshot = Vec::new();
    apply_env_override(
        &mut snapshot,
        SESSION_IDLE_EXPIRY_ENV,
        tuning.idle_expiry_millis.map(|value| value.to_string()),
    );
    apply_env_override(
        &mut snapshot,
        SESSION_DRAIN_GRACE_ENV,
        tuning.drain_grace_millis.map(|value| value.to_string()),
    );
    apply_env_override(
        &mut snapshot,
        SESSION_REAPER_INTERVAL_ENV,
        tuning.reaper_interval_millis.map(|value| value.to_string()),
    );
    snapshot
}

fn apply_env_override(
    snapshot: &mut Vec<(String, Option<String>)>,
    name: &str,
    value: Option<String>,
) {
    snapshot.push((name.to_string(), std::env::var(name).ok()));
    if let Some(value) = value {
        // Safety: test startup serializes process-global env mutation under TEST_ENV_LOCK.
        unsafe { std::env::set_var(name, value) };
    } else {
        // Safety: test startup serializes process-global env mutation under TEST_ENV_LOCK.
        unsafe { std::env::remove_var(name) };
    }
}

fn restore_env(snapshot: Vec<(String, Option<String>)>) {
    for (name, value) in snapshot {
        if let Some(value) = value {
            // Safety: test startup serializes process-global env mutation under TEST_ENV_LOCK.
            unsafe { std::env::set_var(name, value) };
        } else {
            // Safety: test startup serializes process-global env mutation under TEST_ENV_LOCK.
            unsafe { std::env::remove_var(name) };
        }
    }
}

fn write_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_sampling: true
capabilities:
  default:
    tools:
      - server: wrapped-http-mock
        tool: echo_json
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("http-policy.yaml");
    fs::write(&path, policy).expect("write HTTP policy");
    path
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import sys

TOOLS = [{
    "name": "echo_json",
    "title": "Echo JSON",
    "description": "Return structured JSON",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message": {"type": "string"}
        }
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "echo": {"type": "string"}
        }
    },
    "annotations": {
        "readOnlyHint": True
    }
}]

def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

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
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mock-http-upstream",
                    "version": "0.1.0"
                }
            }
        })
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "tools": TOOLS
            }
        })
        continue

    if method == "tools/call":
        arguments = message.get("params", {}).get("arguments", {})
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": "echoed"}],
                "structuredContent": {"echo": arguments.get("message", "hello")},
                "isError": False
            }
        })
        continue

    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {
            "code": -32601,
            "message": f"unknown method: {method}"
        }
    })
"##;

    let path = dir.join("mock_http_mcp_server.py");
    fs::write(&path, script).expect("write mock server script");
    path
}

fn read_sse_until_response(response: Response, expected_id: Value) -> (Value, Vec<Value>) {
    let mut reader = BufReader::new(response);
    let mut messages = Vec::new();

    loop {
        let Some(message) = read_next_sse_message(&mut reader) else {
            panic!("expected terminal JSON-RPC response on SSE stream");
        };
        if message.get("id") == Some(&expected_id) && message.get("method").is_none() {
            return (message, messages);
        }
        messages.push(message);
    }
}

fn read_next_sse_message(reader: &mut impl BufRead) -> Option<Value> {
    loop {
        let event = read_next_sse_event(reader)?;
        if let Some(message) = event {
            return Some(message);
        }
    }
}

fn read_next_sse_event(reader: &mut impl BufRead) -> Option<Option<Value>> {
    let mut data = Vec::new();

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).expect("read SSE line");
        if bytes == 0 {
            return None;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if data.is_empty() {
                continue;
            }

            let payload = data.join("\n");
            return Some(Some(
                serde_json::from_str(&payload).expect("parse SSE JSON-RPC payload"),
            ));
        }

        if let Some(rest) = trimmed.strip_prefix("data:") {
            data.push(rest.trim_start().to_string());
        }
    }
}
