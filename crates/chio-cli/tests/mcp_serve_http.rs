#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chio_core::crypto::Keypair;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};

static UNIQUE_TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
const SERVER_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const SERVER_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-cli-mcp-http-{}-{nonce}-{counter}",
        std::process::id()
    ))
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
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

#[derive(Debug)]
enum StartupError {
    BindCollision(String),
    EarlyExit(String),
    Timeout(&'static str),
}

impl StartupError {
    fn from_child_exit(status: std::process::ExitStatus, stderr: String) -> Self {
        if is_bind_collision(&stderr) {
            Self::BindCollision(stderr)
        } else {
            Self::EarlyExit(format!(
                "process exited before readiness with status {status}: {}",
                stderr.trim()
            ))
        }
    }

    fn panic_context(&self, label: &str) -> String {
        match self {
            Self::BindCollision(stderr) => format!(
                "{label} failed to bind after retry budget was exhausted: {}",
                stderr.trim()
            ),
            Self::EarlyExit(message) => format!("{label} {message}"),
            Self::Timeout(message) => format!("{label} {message}"),
        }
    }
}

fn is_bind_collision(stderr: &str) -> bool {
    stderr.contains("Address already in use")
        || stderr.contains("os error 48")
        || stderr.contains("os error 98")
}

fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(stderr_pipe) = child.stderr.as_mut() {
        let _ = stderr_pipe.read_to_string(&mut stderr);
    }
    stderr
}

fn spawn_with_bind_retry<F, W>(
    client: &Client,
    label: &str,
    mut spawn: F,
    mut wait: W,
) -> (SocketAddr, ServerGuard)
where
    F: FnMut(SocketAddr) -> ServerGuard,
    W: FnMut(&Client, &str, &mut ServerGuard) -> Result<(), StartupError>,
{
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 1..=MAX_ATTEMPTS {
        let listen = reserve_listen_addr();
        let mut guard = spawn(listen);
        let base_url = format!("http://{listen}");
        match wait(client, &base_url, &mut guard) {
            Ok(()) => return (listen, guard),
            Err(StartupError::BindCollision(_)) if attempt < MAX_ATTEMPTS => {
                drop(guard);
                continue;
            }
            Err(error) => panic!("{}", error.panic_context(label)),
        }
    }

    unreachable!("bind retry loop must return or panic");
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import os
import sys
import threading
import time

CLIENT_CAPABILITIES = {}
STARTUP_MARKER_PATH = os.environ.get("CHIO_MCP_STARTUP_MARKER_PATH")
WRITE_LOCK = threading.Lock()

if STARTUP_MARKER_PATH:
    with open(STARTUP_MARKER_PATH, "a", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()}\n")

TOOLS = [
    {
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
    },
    {
        "name": "sampled_echo",
        "description": "Uses sampling/createMessage before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_echo",
        "description": "Sleeps briefly before responding",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_cancelable_echo",
        "description": "Sleeps longer before responding so cancellation stays in flight",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_fixture_notifications",
        "description": "Emits resource notifications before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_late_fixture_notifications",
        "description": "Responds first and emits resource notifications later",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "delayMs": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "drop_stream_mid_call",
        "description": "Closes the wrapped MCP process before completing the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    }
]

RESOURCES = [
    {
        "uri": "fixture://docs/0",
        "name": "Fixture Doc",
        "mimeType": "text/plain"
    }
]

def respond(payload):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()

for line in sys.stdin:
    if not line.strip():
        continue

    message = json.loads(line)
    method = message.get("method")

    if method == "initialize":
        CLIENT_CAPABILITIES = message.get("params", {}).get("capabilities", {})
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {},
                    "resources": {
                        "subscribe": True,
                        "listChanged": True
                    }
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
            "result": {"tools": TOOLS}
        })
        continue

    if method == "resources/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resources": RESOURCES}
        })
        continue

    if method == "resources/templates/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resourceTemplates": []}
        })
        continue

    if method == "resources/read":
        uri = message.get("params", {}).get("uri", "fixture://docs/0")
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": "fixture resource"
                    }
                ]
            }
        })
        continue

    if method == "resources/subscribe" or method == "resources/unsubscribe":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {}
        })
        continue

    if method == "tools/call":
        tool_name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})

        if tool_name == "echo_json":
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

        if tool_name == "slow_echo":
            time.sleep(1.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "slow_cancelable_echo":
            time.sleep(3.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow cancellation response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            for index in range(count):
                if index % 2 == 0:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/list_changed"
                    })
                else:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": {"uri": f"fixture://docs/{index}"}
                    })
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"emitted {count} notifications"}],
                    "structuredContent": {"count": count},
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_late_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            delay_ms = max(10, int(arguments.get("delayMs", 150)))

            def emit_late_notifications():
                time.sleep(delay_ms / 1000.0)
                for index in range(count):
                    if index % 2 == 0:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/list_changed"
                        })
                    else:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/updated",
                            "params": {"uri": f"fixture://docs/{index}"}
                        })

            threading.Thread(target=emit_late_notifications, daemon=True).start()
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"scheduled {count} late notifications"}],
                    "structuredContent": {"count": count, "delayMs": delay_ms},
                    "isError": False
                }
            })
            continue

        if tool_name == "drop_stream_mid_call":
            sys.stdout.flush()
            sys.exit(0)

        if tool_name == "sampled_echo":
            if "sampling" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128
                }
            })

            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = sample_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {"sampled": sampled},
                        "isError": False
                    }
                })
                break
            continue

    if method == "tasks/get":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {
                "code": -32602,
                "message": "unknown method: tasks/get"
            }
        })
        continue

    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_http_mcp_server.py");
    fs::write(&path, script).expect("write mock server script");
    path
}

fn write_policy_with_tools_and_ttl(dir: &Path, tools: &[&str], ttl: u64) -> PathBuf {
    let mut policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_sampling: true
capabilities:
  default:
    tools:
"#
    .to_string();
    for tool in tools {
        policy.push_str(&format!(
            "      - server: wrapped-http-mock\n        tool: {tool}\n        operations: [invoke]\n        ttl: {ttl}\n"
        ));
    }

    let path = dir.join("http-policy.yaml");
    fs::write(&path, policy).expect("write HTTP policy");
    path
}

fn write_policy_with_tools(dir: &Path, tools: &[&str]) -> PathBuf {
    write_policy_with_tools_and_ttl(dir, tools, 300)
}

fn write_policy(dir: &Path) -> PathBuf {
    write_policy_with_tools(
        dir,
        &[
            "echo_json",
            "sampled_echo",
            "slow_echo",
            "slow_cancelable_echo",
            "emit_fixture_notifications",
            "emit_late_fixture_notifications",
            "drop_stream_mid_call",
        ],
    )
}

fn spawn_http_server(dir: &Path, listen: SocketAddr, token: &str) -> ServerGuard {
    spawn_http_server_with_session_lifecycle_tuning(dir, listen, token, None, None, None, None)
}

fn spawn_http_server_with_session_lifecycle_tuning(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
) -> ServerGuard {
    spawn_http_server_with_session_lifecycle_env_prefix(
        dir,
        listen,
        token,
        session_db_path,
        idle_expiry_millis,
        drain_grace_millis,
        reaper_interval_millis,
        "CHIO",
    )
}

fn spawn_http_server_with_session_lifecycle_env_prefix(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
    env_prefix: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        dir,
        &policy_path,
        listen,
        token,
        session_db_path,
        idle_expiry_millis,
        drain_grace_millis,
        reaper_interval_millis,
        env_prefix,
    )
}

fn spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
    dir: &Path,
    policy_path: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
    env_prefix: &str,
) -> ServerGuard {
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
    ]);
    if let Some(path) = session_db_path {
        command.args(["--session-db", path.to_str().expect("session db path")]);
    }
    command.args([
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
        "--auth-token",
        token,
        "--",
        "python3",
        script_path.to_str().expect("script path"),
    ]);
    if let Some(value) = idle_expiry_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_IDLE_EXPIRY_MILLIS"),
            value.to_string(),
        );
    }
    if let Some(value) = drain_grace_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_DRAIN_GRACE_MILLIS"),
            value.to_string(),
        );
    }
    if let Some(value) = reaper_interval_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_REAPER_INTERVAL_MILLIS"),
            value.to_string(),
        );
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http");

    ServerGuard { child }
}

fn spawn_http_server_with_policy_path_and_jwt_auth(
    dir: &Path,
    policy_path: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    session_db_path: Option<&Path>,
) -> ServerGuard {
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
    ]);
    if let Some(path) = session_db_path {
        command.args(["--session-db", path.to_str().expect("session db path")]);
    }
    let child = command
        .args([
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
            "--auth-jwt-public-key",
            jwt_public_key_hex,
            "--auth-jwt-issuer",
            issuer,
            "--auth-jwt-audience",
            audience,
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
        .expect("spawn chio mcp serve-http with jwt auth");

    ServerGuard { child }
}

fn spawn_http_server_with_shared_owner(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    startup_marker_path: &Path,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .env(
            "CHIO_MCP_STARTUP_MARKER_PATH",
            startup_marker_path.to_str().expect("startup marker path"),
        )
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
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
            "--auth-token",
            token,
            "--shared-hosted-owner",
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

fn spawn_http_server_with_authority_db(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    authority_db_path: &Path,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
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
            "--auth-token",
            token,
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

fn spawn_http_server_with_jwt_auth(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> ServerGuard {
    spawn_http_server_with_jwt_auth_and_identity_federation(
        dir,
        listen,
        jwt_public_key_hex,
        issuer,
        audience,
        admin_token,
        None,
    )
}

fn spawn_http_server_with_shared_owner_and_jwt_auth(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
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
            "--auth-jwt-public-key",
            jwt_public_key_hex,
            "--auth-jwt-issuer",
            issuer,
            "--auth-jwt-audience",
            audience,
            "--auth-scope",
            "mcp:invoke",
            "--admin-token",
            admin_token,
            "--shared-hosted-owner",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http with shared-owner jwt auth");

    ServerGuard { child }
}

fn spawn_http_server_with_jwt_auth_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
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
        "--auth-jwt-public-key",
        jwt_public_key_hex,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    let child = command
        .args(["--", "python3", script_path.to_str().expect("script path")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http");

    ServerGuard { child }
}

fn spawn_http_server_with_jwt_auth_and_local_discovery(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    authorization_endpoint: &str,
    token_endpoint: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");
    let public_base_url = format!("http://{listen}");

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
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
            "--auth-jwt-public-key",
            jwt_public_key_hex,
            "--auth-jwt-issuer",
            issuer,
            "--auth-jwt-audience",
            audience,
            "--admin-token",
            admin_token,
            "--public-base-url",
            &public_base_url,
            "--auth-server",
            issuer,
            "--auth-authorization-endpoint",
            authorization_endpoint,
            "--auth-token-endpoint",
            token_endpoint,
            "--auth-scope",
            "mcp:invoke",
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

fn write_oidc_discovery_fixture_with_jwks(
    dir: &Path,
    idp_listen: SocketAddr,
    issuer_path: &str,
    jwks: Value,
) -> (PathBuf, String, String) {
    let root = dir.join("oidc-idp");
    fs::create_dir_all(&root).expect("create oidc root");
    let issuer_path = issuer_path.trim_start_matches('/');
    let issuer = format!("http://127.0.0.1:{}/{}", idp_listen.port(), issuer_path);
    let issuer_dir = root.join(issuer_path);
    let discovery_dir = issuer_dir.join(".well-known");
    fs::create_dir_all(&discovery_dir).expect("create oidc discovery dir");
    let discovery_path = discovery_dir.join("openid-configuration");
    let jwks_path = root.join("jwks.json");
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let jwks_uri = format!("http://127.0.0.1:{}/jwks.json", idp_listen.port());

    fs::write(
        &discovery_path,
        serde_json::to_vec_pretty(&json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "registration_endpoint": format!("{issuer}/oauth2/register"),
            "jwks_uri": jwks_uri,
        }))
        .expect("serialize oidc discovery document"),
    )
    .expect("write oidc discovery document");
    fs::write(
        &jwks_path,
        serde_json::to_vec_pretty(&jwks).expect("serialize oidc jwks"),
    )
    .expect("write oidc jwks");

    (root, issuer, discovery_url)
}

fn write_oidc_discovery_fixture(
    dir: &Path,
    idp_listen: SocketAddr,
    issuer_path: &str,
    signing_key: &Keypair,
) -> (PathBuf, String, String) {
    write_oidc_discovery_fixture_with_jwks(
        dir,
        idp_listen,
        issuer_path,
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(signing_key.public_key().as_bytes()),
            }]
        }),
    )
}

fn write_introspection_server_script(dir: &Path) -> PathBuf {
    let script = r#"
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

RESPONSES_PATH = os.environ["CHIO_INTROSPECTION_RESPONSES_PATH"]
EXPECTED_AUTH = os.environ.get("CHIO_INTROSPECTION_EXPECTED_AUTH")

with open(RESPONSES_PATH, "r", encoding="utf-8") as handle:
    RESPONSES = json.load(handle)

class Handler(BaseHTTPRequestHandler):
    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/introspect":
            self._write_json(404, {"error": "not_found"})
            return
        if EXPECTED_AUTH is not None and self.headers.get("Authorization") != EXPECTED_AUTH:
            self._write_json(401, {"error": "invalid_client"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)
        token = params.get("token", [""])[0]
        self._write_json(200, RESPONSES.get(token, {"active": False}))

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
"#;
    let script_path = dir.join("introspection_server.py");
    fs::write(&script_path, script).expect("write introspection server script");
    script_path
}

fn spawn_introspection_server(
    script_path: &Path,
    listen: SocketAddr,
    responses_path: &Path,
    expected_auth: Option<&str>,
) -> ServerGuard {
    let mut command = Command::new("python3");
    command
        .env(
            "CHIO_INTROSPECTION_RESPONSES_PATH",
            responses_path
                .to_str()
                .expect("introspection responses path"),
        )
        .args([
            script_path.to_str().expect("introspection script path"),
            &listen.port().to_string(),
        ]);
    if let Some(expected_auth) = expected_auth {
        command.env("CHIO_INTROSPECTION_EXPECTED_AUTH", expected_auth);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn introspection server");
    ServerGuard { child }
}

fn spawn_static_http_fixture_server(root: &Path, listen: SocketAddr) -> ServerGuard {
    let child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &listen.port().to_string(),
            "--bind",
            "127.0.0.1",
            "--directory",
            root.to_str().expect("fixture root path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn static fixture server");
    ServerGuard { child }
}

fn wait_for_http_fixture_url(client: &Client, url: &str, guard: &mut ServerGuard) {
    for _ in 0..100 {
        if let Some(status) = guard.child.try_wait().expect("poll fixture child") {
            panic!(
                "{}",
                StartupError::from_child_exit(status, read_child_stderr(&mut guard.child))
                    .panic_context("fixture server")
            );
        }
        match client.get(url).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("fixture server did not become ready");
}

fn spawn_http_server_with_oidc_discovery_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    discovery_url: &str,
    provider_profile: Option<&str>,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
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
        "--auth-jwt-discovery-url",
        discovery_url,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(profile) = provider_profile {
        command.args(["--auth-jwt-provider-profile", profile]);
    }
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    let child = command
        .args(["--", "python3", script_path.to_str().expect("script path")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http with oidc discovery");

    ServerGuard { child }
}

fn spawn_http_server_with_token_introspection_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    introspection_url: &str,
    introspection_client_id: &str,
    introspection_client_secret: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
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
        "--auth-introspection-url",
        introspection_url,
        "--auth-introspection-client-id",
        introspection_client_id,
        "--auth-introspection-client-secret",
        introspection_client_secret,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    let child = command
        .args(["--", "python3", script_path.to_str().expect("script path")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve-http with token introspection");

    ServerGuard { child }
}

fn spawn_trust_control_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio trust control service");

    ServerGuard { child }
}

fn spawn_http_server_with_control_plane(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    control_url: &str,
    control_token: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--control-url",
            control_url,
            "--control-token",
            control_token,
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
            "--auth-token",
            token,
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn control-backed chio mcp serve-http");

    ServerGuard { child }
}

fn wait_for_server_result(
    client: &Client,
    base_url: &str,
    guard: &mut ServerGuard,
) -> Result<(), StartupError> {
    let deadline = Instant::now() + SERVER_STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(status) = guard.child.try_wait().expect("poll remote MCP child") {
            return Err(StartupError::from_child_exit(
                status,
                read_child_stderr(&mut guard.child),
            ));
        }
        match client.get(format!("{base_url}/mcp")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(SERVER_STARTUP_POLL_INTERVAL),
        }
    }
    Err(StartupError::Timeout(
        "remote MCP server did not become ready",
    ))
}

fn wait_for_server(client: &Client, base_url: &str) {
    let deadline = Instant::now() + SERVER_STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        match client.get(format!("{base_url}/mcp")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => return,
            Ok(_) | Err(_) => thread::sleep(SERVER_STARTUP_POLL_INTERVAL),
        }
    }
    panic!("remote MCP server did not become ready");
}

fn wait_for_control_service_result(
    client: &Client,
    base_url: &str,
    guard: &mut ServerGuard,
) -> Result<(), StartupError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(status) = guard.child.try_wait().expect("poll trust control child") {
            return Err(StartupError::from_child_exit(
                status,
                read_child_stderr(&mut guard.child),
            ));
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
    Err(StartupError::Timeout(
        "trust control service did not become ready",
    ))
}

fn post_json(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: Option<&str>,
    protocol_version: Option<&str>,
    body: &Value,
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
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

    request.send().expect("send HTTP MCP request")
}

fn post_json_no_auth(client: &Client, base_url: &str, body: &Value) -> Response {
    client
        .post(format!("{base_url}/mcp"))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).expect("serialize request body"))
        .send()
        .expect("send unauthenticated HTTP MCP request")
}

fn post_raw(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    session_id: Option<&str>,
    accept: &str,
    content_type: &str,
    body: &Value,
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
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

fn post_bytes(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    session_id: Option<&str>,
    accept: &str,
    content_type: &str,
    body: &[u8],
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
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

fn post_notification(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    protocol_version: Option<&str>,
    body: &Value,
) -> Response {
    post_json(
        client,
        base_url,
        token,
        Some(session_id),
        protocol_version,
        body,
    )
}

fn get_session_stream(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    protocol_version: Option<&str>,
    last_event_id: Option<&str>,
) -> Response {
    let mut request = client
        .get(format!("{base_url}/mcp"))
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

fn delete_session(client: &Client, base_url: &str, token: &str, session_id: &str) -> Response {
    client
        .delete(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("MCP-Session-Id", session_id)
        .send()
        .expect("send session delete request")
}

fn get_admin_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin authority get request")
}

fn get_control_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control authority get request")
}

fn get_protected_resource_metadata(client: &Client, base_url: &str) -> Response {
    client
        .get(format!(
            "{base_url}/.well-known/oauth-protected-resource/mcp"
        ))
        .send()
        .expect("send protected resource metadata request")
}

fn get_oauth_authorization_server_metadata(
    client: &Client,
    base_url: &str,
    issuer_path: &str,
) -> Response {
    client
        .get(format!(
            "{base_url}/.well-known/oauth-authorization-server/{}",
            issuer_path.trim_start_matches('/')
        ))
        .send()
        .expect("send oauth authorization server metadata request")
}

fn post_admin_rotate_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .post(format!("{base_url}/admin/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin authority rotate request")
}

fn post_control_rotate_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .post(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .expect("send control authority rotate request")
}

fn get_admin_session_trust(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .get(format!("{base_url}/admin/sessions/{session_id}/trust"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin trust get request")
}

fn get_admin_sessions(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/sessions"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin sessions get request")
}

fn get_admin_health(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/health"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin health request")
}

fn post_admin_session_revoke(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/trust"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin trust revoke request")
}

fn post_admin_session_drain(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/drain"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin session drain request")
}

fn post_admin_session_shutdown(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/shutdown"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin session shutdown request")
}

fn get_admin_tool_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/receipts/tools"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin tool receipts request")
}

fn get_control_tool_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/v1/receipts/tools"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control tool receipts request")
}

fn get_admin_child_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/receipts/children"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin child receipts request")
}

fn get_admin_revocations(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/revocations"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin revocations request")
}

fn get_control_revocations(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/v1/revocations"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control revocations request")
}

fn post_admin_capability_revoke(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/revocations"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({ "capability_id": capability_id }))
        .send()
        .expect("send admin capability revoke request")
}

fn read_sse_until_response<F>(
    response: Response,
    expected_id: Value,
    mut on_message: F,
) -> (Value, Vec<Value>)
where
    F: FnMut(&Value),
{
    let mut reader = BufReader::new(response);
    let mut messages = Vec::new();

    loop {
        let Some(message) = read_next_sse_message(&mut reader) else {
            panic!("expected terminal JSON-RPC response on SSE stream");
        };
        if message.get("id") == Some(&expected_id) && message.get("method").is_none() {
            return (message, messages);
        }
        on_message(&message);
        messages.push(message);
    }
}

fn read_sse_events_until_response(
    response: Response,
    expected_id: Value,
) -> (Value, Vec<SseEvent>) {
    let mut reader = BufReader::new(response);
    let mut events = Vec::new();

    loop {
        let Some(event) = read_next_sse_event(&mut reader) else {
            panic!("expected terminal JSON-RPC response on SSE stream");
        };
        let Some(message) = event.message.as_ref() else {
            continue;
        };
        if message.get("id") == Some(&expected_id) && message.get("method").is_none() {
            return (message.clone(), events);
        }
        events.push(event);
    }
}

#[derive(Debug)]
struct SseEvent {
    id: Option<String>,
    message: Option<Value>,
}

fn read_next_sse_event(reader: &mut impl BufRead) -> Option<SseEvent> {
    let mut id = None;
    let mut data = Vec::new();

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).expect("read SSE line");
        if bytes == 0 {
            return None;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if id.is_none() && data.is_empty() {
                continue;
            }

            let message = if data.is_empty() {
                None
            } else {
                let payload = data.join("\n");
                Some(serde_json::from_str(&payload).expect("parse SSE JSON-RPC payload"))
            };
            return Some(SseEvent { id, message });
        }

        if let Some(rest) = trimmed.strip_prefix("id:") {
            id = Some(rest.trim_start().to_string());
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("data:") {
            data.push(rest.trim_start().to_string());
        }
    }
}

fn read_next_sse_message(reader: &mut impl BufRead) -> Option<Value> {
    loop {
        let event = read_next_sse_event(reader)?;
        if let Some(message) = event.message {
            return Some(message);
        }
    }
}

fn sign_jwt(keypair: &Keypair, claims: &Value) -> String {
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

fn sign_jwt_with_header(header: Value, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

fn sign_jwt_rs256(private_key: &rsa::RsaPrivateKey, claims: &Value, kid: &str) -> String {
    use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    let signing_key = RsaPkcs1v15SigningKey::<sha2::Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign(message).to_vec(),
    )
}

fn sign_jwt_es256(signing_key: &p256::ecdsa::SigningKey, claims: &Value, kid: &str) -> String {
    use p256::ecdsa::signature::Signer as _;

    sign_jwt_with_header(
        json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p256::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn initialize_session(client: &Client, base_url: &str, token: &str) -> (String, String) {
    initialize_session_with_capabilities(
        client,
        base_url,
        token,
        json!({
            "sampling": {
                "context": {},
                "tools": {}
            }
        }),
    )
}

fn initialize_session_with_capabilities(
    client: &Client,
    base_url: &str,
    token: &str,
    capabilities: Value,
) -> (String, String) {
    let response = post_json(
        client,
        base_url,
        token,
        None,
        Some("2025-11-25"),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": capabilities,
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
    let (initialize, init_messages) = read_sse_until_response(response, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        client,
        base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);

    (session_id, protocol_version)
}

#[test]
fn mcp_serve_http_streams_roots_request_after_initialized_when_client_supports_roots() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_json(
        &client,
        &base_url,
        token,
        None,
        Some("2025-11-25"),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "roots": {
                        "listChanged": true
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
    let (initialize, init_messages) = read_sse_until_response(response, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::OK);

    let mut reader = BufReader::new(initialized);
    let roots_request = read_next_sse_message(&mut reader).expect("roots/list request");
    assert_eq!(roots_request["method"], "roots/list");
    let roots_request_id = roots_request["id"]
        .as_str()
        .expect("roots request id")
        .to_string();

    let roots_response = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": roots_request_id,
            "result": {
                "roots": [{
                    "uri": "file:///workspace/project",
                    "name": "Project"
                }]
            }
        }),
    );
    assert!(matches!(
        roots_response.status(),
        reqwest::StatusCode::OK | reqwest::StatusCode::ACCEPTED
    ));
}

#[test]
fn mcp_serve_http_requires_auth_reuses_sessions_and_supports_delete() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let unauthenticated = post_json_no_auth(
        &client,
        &base_url,
        &json!({
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
        }),
    );
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (tools_list, notifications) = read_sse_until_response(response, json!(2), |_| {});
    assert!(notifications.is_empty());
    let tool_names = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert!(tool_names.contains(&"echo_json"));
    assert!(tool_names.contains(&"sampled_echo"));
    assert!(tool_names.contains(&"slow_echo"));

    let deleted = delete_session(&client, &base_url, token, &session_id);
    assert_eq!(deleted.status(), reqwest::StatusCode::NO_CONTENT);

    let deleted_trust = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
    let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
    assert_eq!(
        deleted_trust["lifecycle"]["state"].as_str(),
        Some("deleted")
    );
    assert_eq!(
        deleted_trust["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );

    let missing_session = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(missing_session.status(), reqwest::StatusCode::GONE);

    let missing_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(missing_stream.status(), reqwest::StatusCode::GONE);
}

#[test]
fn mcp_serve_http_session_trust_reports_lifecycle_and_reconnect_contract() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["sessionId"].as_str(),
        Some(session_id.as_str())
    );
    assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));
    assert_eq!(
        trust_status["lifecycle"]["protocolVersion"].as_str(),
        Some(protocol_version.as_str())
    );
    assert!(trust_status["lifecycle"]["createdAt"].as_u64().is_some());
    assert!(trust_status["lifecycle"]["lastSeenAt"].as_u64().is_some());
    assert_eq!(
        trust_status["ownership"]["requestStreamOwner"].as_str(),
        Some("exclusive_request_stream")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["resultStreamOwner"].as_str(),
        Some("request_stream")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["terminalStateOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamOwner"].as_str(),
        Some("session_notification_stream")
    );
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("post_response_fallback")
    );
    assert_eq!(
        trust_status["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust_status["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["mode"].as_str(),
        Some("post-session-reuse-only")
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["requiresAuthContinuity"].as_bool(),
        Some(true)
    );
    let terminal_states = trust_status["lifecycle"]["reconnect"]["terminalStates"]
        .as_array()
        .expect("terminal states");
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("deleted")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("expired")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("draining")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("closed")));
}

#[test]
fn mcp_serve_http_session_trust_reports_request_stream_lease_while_post_stream_is_open() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let call = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "lease-check" }
            }
        }),
    );

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["terminalStateOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("post_response_fallback")
    );

    let (response, events) = read_sse_until_response(call, json!(22), |_| {});
    assert!(events.is_empty());
    assert_eq!(response["result"]["content"][0]["text"], "slow response");

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
}

#[test]
fn mcp_serve_http_idle_expiry_reaps_sessions_and_blocks_reuse() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        None,
        Some(250),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let mut expired = None;
    for _ in 0..40 {
        let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("session trust json");
        if trust_status["lifecycle"]["state"].as_str() == Some("expired") {
            expired = Some(trust_status);
            break;
        }
        thread::sleep(Duration::from_millis(75));
    }
    let expired = expired.expect("session to expire");
    assert_eq!(
        expired["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );
    assert_eq!(
        expired["lifecycle"]["reconnect"]["terminalStates"]
            .as_array()
            .expect("terminal states")
            .iter()
            .any(|value| value.as_str() == Some("expired")),
        true
    );

    let resumed_post = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::GONE);

    let resumed_get = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(resumed_get.status(), reqwest::StatusCode::GONE);
}

#[test]
fn mcp_serve_http_admin_drain_shutdown_and_delete_have_distinct_terminal_states() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        None,
        Some(5_000),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (draining_session, draining_protocol) = initialize_session(&client, &base_url, token);
    let drain = post_admin_session_drain(&client, &base_url, token, &draining_session);
    assert_eq!(drain.status(), reqwest::StatusCode::OK);
    let drain: Value = drain.json().expect("drain json");
    assert_eq!(drain["lifecycle"]["state"].as_str(), Some("draining"));

    let draining_post = post_json(
        &client,
        &base_url,
        token,
        Some(&draining_session),
        Some(&draining_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(draining_post.status(), reqwest::StatusCode::CONFLICT);

    let mut deleted = None;
    for _ in 0..40 {
        let trust_status = get_admin_session_trust(&client, &base_url, token, &draining_session);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("draining trust json");
        if trust_status["lifecycle"]["state"].as_str() == Some("deleted") {
            deleted = Some(trust_status);
            break;
        }
        thread::sleep(Duration::from_millis(75));
    }
    let deleted = deleted.expect("draining session to settle as deleted");
    assert_eq!(
        deleted["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );

    let deleted_post = post_json(
        &client,
        &base_url,
        token,
        Some(&draining_session),
        Some(&draining_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(deleted_post.status(), reqwest::StatusCode::GONE);

    let (deleted_session, deleted_protocol) = initialize_session(&client, &base_url, token);
    let deleted_direct = delete_session(&client, &base_url, token, &deleted_session);
    assert_eq!(deleted_direct.status(), reqwest::StatusCode::NO_CONTENT);
    let deleted_trust = get_admin_session_trust(&client, &base_url, token, &deleted_session);
    assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
    let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
    assert_eq!(
        deleted_trust["lifecycle"]["state"].as_str(),
        Some("deleted")
    );

    let deleted_post = post_json(
        &client,
        &base_url,
        token,
        Some(&deleted_session),
        Some(&deleted_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(deleted_post.status(), reqwest::StatusCode::GONE);

    let (shutdown_session, shutdown_protocol) = initialize_session(&client, &base_url, token);
    let shutdown = post_admin_session_shutdown(&client, &base_url, token, &shutdown_session);
    assert_eq!(shutdown.status(), reqwest::StatusCode::OK);
    let shutdown: Value = shutdown.json().expect("shutdown json");
    assert_eq!(shutdown["lifecycle"]["state"].as_str(), Some("closed"));

    let shutdown_post = post_json(
        &client,
        &base_url,
        token,
        Some(&shutdown_session),
        Some(&shutdown_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(shutdown_post.status(), reqwest::StatusCode::GONE);

    let sessions = get_admin_sessions(&client, &base_url, token);
    assert_eq!(sessions.status(), reqwest::StatusCode::OK);
    let sessions: Value = sessions.json().expect("admin sessions json");
    assert!(sessions["terminalCount"].as_u64().unwrap_or(0) >= 3);
}

#[test]
fn mcp_serve_http_terminal_tombstones_survive_restart_and_block_reuse() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-tombstones.sqlite3");

    let (
        deleted_session,
        deleted_protocol,
        expired_session,
        expired_protocol,
        shutdown_session,
        shutdown_protocol,
    ) = {
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(250),
            Some(250),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (deleted_session, deleted_protocol) = initialize_session(&client, &base_url, token);
        let deleted = delete_session(&client, &base_url, token, &deleted_session);
        assert_eq!(deleted.status(), reqwest::StatusCode::NO_CONTENT);
        let deleted_trust = get_admin_session_trust(&client, &base_url, token, &deleted_session);
        assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
        let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
        assert_eq!(
            deleted_trust["lifecycle"]["state"].as_str(),
            Some("deleted")
        );

        let (expired_session, expired_protocol) = initialize_session(&client, &base_url, token);
        let mut expired = None;
        for _ in 0..40 {
            let trust_status = get_admin_session_trust(&client, &base_url, token, &expired_session);
            assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
            let trust_status: Value = trust_status.json().expect("expired trust json");
            if trust_status["lifecycle"]["state"].as_str() == Some("expired") {
                expired = Some(trust_status);
                break;
            }
            thread::sleep(Duration::from_millis(75));
        }
        let expired = expired.expect("session to expire before restart");
        assert_eq!(expired["sessionId"], expired_session);

        let (shutdown_session, shutdown_protocol) = initialize_session(&client, &base_url, token);
        let shutdown = post_admin_session_shutdown(&client, &base_url, token, &shutdown_session);
        assert_eq!(shutdown.status(), reqwest::StatusCode::OK);
        let shutdown: Value = shutdown.json().expect("shutdown json");
        assert_eq!(shutdown["lifecycle"]["state"].as_str(), Some("closed"));

        (
            deleted_session,
            deleted_protocol,
            expired_session,
            expired_protocol,
            shutdown_session,
            shutdown_protocol,
        )
    };

    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        Some(&session_db_path),
        Some(250),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let sessions = get_admin_sessions(&client, &base_url, token);
    assert_eq!(sessions.status(), reqwest::StatusCode::OK);
    let sessions: Value = sessions.json().expect("admin sessions json");
    assert!(sessions["terminalCount"].as_u64().unwrap_or(0) >= 3);

    for (session_id, protocol_version, expected_state) in [
        (&deleted_session, &deleted_protocol, "deleted"),
        (&expired_session, &expired_protocol, "expired"),
        (&shutdown_session, &shutdown_protocol, "closed"),
    ] {
        let trust_status = get_admin_session_trust(&client, &base_url, token, session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("terminal trust json");
        assert_eq!(
            trust_status["lifecycle"]["state"].as_str(),
            Some(expected_state)
        );

        let reuse_post = post_json(
            &client,
            &base_url,
            token,
            Some(session_id),
            Some(protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/list",
                "params": {}
            }),
        );
        assert_eq!(reuse_post.status(), reqwest::StatusCode::GONE);
    }
}

#[test]
fn mcp_serve_http_ready_sessions_survive_restart_and_resume_authenticated_calls() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
        let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("ready trust json");
        assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));
        (session_id, protocol_version)
    };

    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("restored trust json");
    assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));

    let resumed_post = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::OK);
    let (resumed_tools, notifications) = read_sse_until_response(resumed_post, json!(12), |_| {});
    assert!(notifications.is_empty());
    assert!(resumed_tools["result"]["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty()));

    let resumed_get = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(resumed_get.status(), reqwest::StatusCode::OK);
}

#[test]
fn mcp_serve_http_ready_sessions_reissue_capabilities_after_policy_tightening() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy_with_tools(&dir, &["echo_json", "sampled_echo"]);

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        initialize_session(&client, &base_url, token)
    };

    let policy_path = write_policy_with_tools(&dir, &["sampled_echo"]);
    let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        &dir,
        &policy_path,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
        "Chio",
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);

    let denied_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(77), |_| {});
    assert_eq!(denied_notifications.len(), 1);
    assert_eq!(
        denied_notifications[0]["method"].as_str(),
        Some("notifications/message")
    );
    assert_eq!(
        denied_notifications[0]["params"]["data"]["event"].as_str(),
        Some("tool_denied")
    );
    assert_eq!(
        denied_notifications[0]["params"]["data"]["tool"].as_str(),
        Some("echo_json")
    );
    assert_eq!(denied_tool_call["result"]["isError"], true);
}

#[test]
#[ignore = "flaky on CI: TTL-bounded session restore race; passes locally"]
fn mcp_serve_http_restores_sessions_with_fresh_capabilities_after_ttl_expiry() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy_with_tools_and_ttl(&dir, &["echo_json"], 1);

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        initialize_session(&client, &base_url, token)
    };

    thread::sleep(Duration::from_secs(2));

    let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        &dir,
        &policy_path,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
        "Chio",
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let restored_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 88,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "restored session should refresh capabilities"}
            }
        }),
    );
    assert_eq!(restored_response.status(), reqwest::StatusCode::OK);
    let (tool_call, notifications) = read_sse_until_response(restored_response, json!(88), |_| {});
    assert!(notifications.is_empty());
    assert_ne!(tool_call["result"]["isError"], true);
}

#[test]
fn mcp_serve_http_drops_restored_sessions_when_auth_mode_changes() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy(&dir);

    let session_id = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        let (session_id, _) = initialize_session(&client, &base_url, token);
        session_id
    };

    let auth_kp = Keypair::generate();
    let issuer = "https://issuer.example/restore-auth-mode";
    let audience = "chio-restore-auth-mode";
    let admin_token = "admin-token";
    let _server = spawn_http_server_with_policy_path_and_jwt_auth(
        &dir,
        &policy_path,
        listen,
        &auth_kp.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&session_db_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn mcp_serve_http_isolates_multiple_sessions() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let shared_owner_capabilities = json!({
        "sampling": {
            "context": {},
            "tools": {}
        },
        "resources": {
            "subscribe": true,
            "listChanged": true
        }
    });
    let (session_a, protocol_a) = initialize_session_with_capabilities(
        &client,
        &base_url,
        token,
        shared_owner_capabilities.clone(),
    );
    let (session_b, protocol_b) =
        initialize_session_with_capabilities(&client, &base_url, token, shared_owner_capabilities);
    assert_ne!(session_a, session_b);

    let session_a_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": {},
                "task": {}
            }
        }),
    );
    let (task_created, task_messages) = read_sse_until_response(session_a_task, json!(2), |_| {});
    assert!(task_messages.is_empty());
    let task_id = task_created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let session_b_task_get = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_messages) =
        read_sse_until_response(session_b_task_get, json!(3), |_| {});
    assert!(task_get_messages.is_empty());
    assert_eq!(task_get["error"]["code"], -32602);
    assert!(task_get["error"]["message"]
        .as_str()
        .expect("task get error")
        .contains("task not found"));
}

#[test]
fn mcp_serve_http_get_stream_owns_session_notifications_when_attached() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
    let mut get_reader = BufReader::new(get_stream);
    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("get_sse")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(true)
    );

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "stream to GET" },
                "task": {}
            }
        }),
    );
    let (created, create_messages) = read_sse_until_response(create_task, json!(30), |_| {});
    assert!(create_messages.is_empty());
    assert_eq!(created["result"]["task"]["ownership"]["workOwner"], "task");
    assert_eq!(
        created["result"]["task"]["ownership"]["resultStreamOwner"],
        "request_stream"
    );
    assert_eq!(
        created["result"]["task"]["ownership"]["statusNotificationOwner"],
        "session_notification_stream"
    );
    assert_eq!(
        created["result"]["task"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(created["result"]["task"]["ownerSessionId"]
        .as_str()
        .expect("owner session id")
        .starts_with("sess-"));
    assert!(created["result"]["task"]["ownerRequestId"]
        .as_str()
        .expect("owner request id")
        .starts_with("mcp-edge-req-"));
    assert!(created["result"]["task"]["parentRequestId"].is_null());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cancel_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cancelled, cancel_messages) = read_sse_until_response(cancel_task, json!(31), |_| {});
    assert_eq!(cancelled["result"]["status"], "cancelled");
    assert!(
        cancel_messages.is_empty(),
        "POST stream should not duplicate session notifications while GET is attached"
    );

    let first = read_next_sse_event(&mut get_reader).expect("GET task notification event");
    assert!(first.id.is_some());
    assert_eq!(
        first.message.as_ref().expect("GET notification message")["method"],
        "notifications/tasks/status"
    );
    assert_eq!(
        first
            .message
            .as_ref()
            .expect("GET task notification message")["params"]["taskId"],
        task_id
    );
}

#[test]
fn mcp_serve_http_get_stream_replays_retained_notifications_and_rejects_stale_cursor() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let create_task_a = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "task-a" },
                "task": {}
            }
        }),
    );
    let (created_a, created_a_messages) = read_sse_until_response(create_task_a, json!(31), |_| {});
    assert!(created_a_messages.is_empty());
    let task_id_a = created_a["result"]["task"]["taskId"]
        .as_str()
        .expect("task a id")
        .to_string();

    let cancel_a = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tasks/cancel",
            "params": { "taskId": task_id_a }
        }),
    );
    let (_cancelled_a, cancel_a_events) = read_sse_events_until_response(cancel_a, json!(32));
    let first_id = cancel_a_events
        .iter()
        .find_map(|event| event.id.clone())
        .expect("first notification id");

    let create_task_b = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "task-b" },
                "task": {}
            }
        }),
    );
    let (created_b, created_b_messages) = read_sse_until_response(create_task_b, json!(33), |_| {});
    assert!(created_b_messages.is_empty());
    let task_id_b = created_b["result"]["task"]["taskId"]
        .as_str()
        .expect("task b id")
        .to_string();

    let cancel_b = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tasks/cancel",
            "params": { "taskId": task_id_b }
        }),
    );
    let (_cancelled_b, cancel_b_events) = read_sse_events_until_response(cancel_b, json!(34));
    assert!(
        cancel_b_events.iter().any(|event| {
            event.message.as_ref().is_some_and(|message| {
                message["method"] == "notifications/tasks/status"
                    && message["params"]["taskId"].as_str() == Some(task_id_b.as_str())
            })
        }),
        "expected a later retained task status notification"
    );

    let replay = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        Some(&first_id),
    );
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    let mut replay_reader = BufReader::new(replay);
    let replayed = read_next_sse_event(&mut replay_reader).expect("replayed notification");
    let replayed_message = replayed.message.as_ref().expect("replayed message");
    let replayed_method = replayed_message["method"]
        .as_str()
        .expect("replayed method");
    assert_eq!(replayed_method, "notifications/tasks/status");
    assert_eq!(
        replayed_message["params"]["taskId"].as_str(),
        Some(task_id_b.as_str())
    );
    drop(replay_reader);

    for index in 0..70 {
        let overflow = post_json(
            &client,
            &base_url,
            token,
            Some(&session_id),
            Some(&protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 1000 + index,
                "method": "tools/call",
                "params": {
                    "name": "emit_fixture_notifications",
                    "arguments": { "count": 1 }
                }
            }),
        );
        let (_overflow_terminal, _overflow_events) =
            read_sse_events_until_response(overflow, json!(1000 + index));
    }

    let stale_replay = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        Some(&first_id),
    );
    assert_eq!(stale_replay.status(), reqwest::StatusCode::CONFLICT);
}

#[test]
fn mcp_serve_http_get_stream_receives_late_wrapped_notifications_after_post_finishes() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
    let mut get_reader = BufReader::new(get_stream);

    let invoke = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 35,
            "method": "tools/call",
            "params": {
                "name": "emit_late_fixture_notifications",
                "arguments": {
                    "count": 1,
                    "delayMs": 150
                }
            }
        }),
    );
    let (terminal, post_messages) = read_sse_until_response(invoke, json!(35), |_| {});
    assert!(post_messages.is_empty());
    assert!(terminal.get("error").is_none());

    let mut saw_late_resource_event = false;
    for _ in 0..5 {
        let late_event = read_next_sse_event(&mut get_reader).expect("late wrapped notification");
        let Some(late_message) = late_event.message.as_ref() else {
            continue;
        };
        if late_message["method"] == "notifications/resources/list_changed" {
            saw_late_resource_event = true;
            break;
        }
    }
    assert!(
        saw_late_resource_event,
        "expected a late wrapped resources/list_changed notification"
    );
}

#[test]
fn mcp_serve_http_returns_error_when_wrapped_stream_ends_mid_call() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let invoke = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 36,
            "method": "tools/call",
            "params": {
                "name": "drop_stream_mid_call",
                "arguments": {}
            }
        }),
    );
    let (terminal, notifications) = read_sse_until_response(invoke, json!(36), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(terminal["result"]["isError"], true);
    let message = terminal["result"]["content"][0]["text"]
        .as_str()
        .expect("interrupted stream text");
    assert!(
        message.contains("closed stdout") || message.contains("upstream stream interrupted"),
        "unexpected interrupted stream error: {message}"
    );
}

#[test]
fn mcp_serve_http_cancels_same_session_tasks_and_blocks_cross_session_cancel() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "cancel me" },
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(40), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cross_cancel = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cross_cancel, cross_messages) = read_sse_until_response(cross_cancel, json!(41), |_| {});
    assert!(cross_messages.is_empty());
    assert_eq!(cross_cancel["error"]["code"], -32602);
    assert!(cross_cancel["error"]["message"]
        .as_str()
        .expect("cross-session cancel error")
        .contains("task not found"));

    let cancel_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cancelled, cancel_messages) = read_sse_until_response(cancel_task, json!(42), |_| {});
    assert_eq!(cancelled["result"]["status"], "cancelled");
    assert!(cancel_messages.iter().any(|message| {
        message["method"] == "notifications/tasks/status"
            && message["params"]["taskId"].as_str() == Some(task_id.as_str())
    }));

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tasks/result",
            "params": { "taskId": task_id }
        }),
    );
    let (task_result, task_result_messages) =
        read_sse_until_response(task_result, json!(43), |_| {});
    assert!(task_result_messages.is_empty());
    assert_eq!(task_result["result"]["isError"], true);
}

#[test]
fn mcp_serve_http_shared_hosted_owner_reuses_one_upstream_subprocess_and_keeps_sessions_isolated() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let startup_marker_path = dir.join("upstream-startups.log");
    let _server = spawn_http_server_with_shared_owner(&dir, listen, token, &startup_marker_path);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);
    let trust_a: Value = get_admin_session_trust(&client, &base_url, token, &session_a)
        .json()
        .expect("session A trust json");
    assert_eq!(
        trust_a["ownership"]["hostedIsolation"].as_str(),
        Some("shared_hosted_owner_compatibility")
    );
    assert_eq!(
        trust_a["ownership"]["hostedIdentityProfile"].as_str(),
        Some("weak_shared_hosted_owner_compatibility")
    );

    let startup_markers =
        fs::read_to_string(&startup_marker_path).expect("read shared owner startup markers");
    let startup_pids = startup_markers
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        startup_pids.len(),
        1,
        "shared hosted owner should reuse one upstream subprocess across sessions"
    );

    let client_a = client.clone();
    let base_url_a = base_url.clone();
    let session_a_for_thread = session_a.clone();
    let protocol_a_for_thread = protocol_a.clone();
    let token_a = token.to_string();
    let slow_a = thread::spawn(move || {
        let response = post_json(
            &client_a,
            &base_url_a,
            &token_a,
            Some(&session_a_for_thread),
            Some(&protocol_a_for_thread),
            &json!({
                "jsonrpc": "2.0",
                "id": 48,
                "method": "tools/call",
                "params": {
                    "name": "slow_echo",
                    "arguments": { "message": "session-a" }
                }
            }),
        );
        read_sse_until_response(response, json!(48), |_| {})
    });

    let client_b = client.clone();
    let base_url_b = base_url.clone();
    let session_b_for_thread = session_b.clone();
    let protocol_b_for_thread = protocol_b.clone();
    let token_b = token.to_string();
    let slow_b = thread::spawn(move || {
        let response = post_json(
            &client_b,
            &base_url_b,
            &token_b,
            Some(&session_b_for_thread),
            Some(&protocol_b_for_thread),
            &json!({
                "jsonrpc": "2.0",
                "id": 49,
                "method": "tools/call",
                "params": {
                    "name": "slow_echo",
                    "arguments": { "message": "session-b" }
                }
            }),
        );
        read_sse_until_response(response, json!(49), |_| {})
    });

    let (slow_a_result, slow_a_events) = slow_a.join().expect("shared owner slow call A");
    let (slow_b_result, slow_b_events) = slow_b.join().expect("shared owner slow call B");
    assert!(slow_a_events.is_empty());
    assert!(slow_b_events.is_empty());
    assert_eq!(slow_a_result["result"]["isError"], false);
    assert_eq!(slow_b_result["result"]["isError"], false);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "slow_cancelable_echo",
                "arguments": { "message": "shared owner" },
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(50), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cross_cancel = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cross_cancel, cross_messages) = read_sse_until_response(cross_cancel, json!(51), |_| {});
    assert!(cross_messages.is_empty());
    assert_eq!(cross_cancel["error"]["code"], -32602);
    assert!(cross_cancel["error"]["message"]
        .as_str()
        .expect("cross-session cancel error")
        .contains("task not found"));

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "tasks/result",
            "params": { "taskId": task_id }
        }),
    );
    let (task_result, task_result_messages) =
        read_sse_until_response(task_result, json!(52), |_| {});
    assert!(task_result_messages.iter().any(|message| {
        message["method"] == "notifications/tasks/status"
            && message["params"]["taskId"].as_str() == Some(task_id.as_str())
            && message["params"]["status"].as_str() == Some("completed")
    }));
    assert!(task_result.get("error").is_none());
}

#[test]
fn mcp_serve_http_shared_hosted_owner_broadcasts_global_notifications() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let startup_marker_path = dir.join("upstream-startups.log");
    let _server = spawn_http_server_with_shared_owner(&dir, listen, token, &startup_marker_path);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, protocol_a) = initialize_session(&client, &base_url, token);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, token);
    let get_stream_a = get_session_stream(
        &client,
        &base_url,
        token,
        &session_a,
        Some(&protocol_a),
        None,
    );
    assert_eq!(get_stream_a.status(), reqwest::StatusCode::OK);
    let mut get_reader_a = BufReader::new(get_stream_a);
    let get_stream_b = get_session_stream(
        &client,
        &base_url,
        token,
        &session_b,
        Some(&protocol_b),
        None,
    );
    assert_eq!(get_stream_b.status(), reqwest::StatusCode::OK);
    let mut get_reader_b = BufReader::new(get_stream_b);

    let emit_late = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "emit_late_fixture_notifications",
                "arguments": {
                    "count": 1,
                    "delayMs": 150
                }
            }
        }),
    );
    let (terminal, post_messages) = read_sse_until_response(emit_late, json!(60), |_| {});
    assert!(post_messages.is_empty());
    assert!(terminal.get("error").is_none());

    let mut saw_a_notification = false;
    let mut saw_b_notification = false;
    for _ in 0..5 {
        let event_a = read_next_sse_event(&mut get_reader_a).expect("shared owner stream A event");
        if let Some(message) = event_a.message.as_ref() {
            if message["method"] == "notifications/resources/list_changed" {
                saw_a_notification = true;
                break;
            }
        }
    }
    for _ in 0..5 {
        let event_b = read_next_sse_event(&mut get_reader_b).expect("shared owner stream B event");
        if let Some(message) = event_b.message.as_ref() {
            if message["method"] == "notifications/resources/list_changed" {
                saw_b_notification = true;
                break;
            }
        }
    }

    assert!(
        saw_a_notification,
        "expected the originating shared-owner session to receive the late global resources/list_changed notification"
    );
    assert!(
        saw_b_notification,
        "expected every shared-owner session stream to receive the late global resources/list_changed notification"
    );
}

#[test]
fn mcp_serve_http_supports_nested_sampling_over_sse() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let sampled_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this over HTTP"}
            }
        }),
    );

    let (tool_result, stream_messages) =
        read_sse_until_response(sampled_response, json!(2), |message| {
            if message["method"] == "sampling/createMessage" {
                let follow_up = post_notification(
                    &client,
                    &base_url,
                    token,
                    &session_id,
                    Some(&protocol_version),
                    &json!({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "role": "assistant",
                            "content": {
                                "type": "text",
                                "text": "sampled by http client"
                            },
                            "model": "gpt-test",
                            "stopReason": "end_turn"
                        }
                    }),
                );
                assert_eq!(follow_up.status(), reqwest::StatusCode::ACCEPTED);
            }
        });

    let nested_requests = stream_messages
        .iter()
        .filter(|message| message["method"] == "sampling/createMessage")
        .collect::<Vec<_>>();
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(tool_result["result"]["isError"], false);
    assert_eq!(
        tool_result["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by http client"
    );
}

#[test]
fn mcp_serve_http_parent_cancellation_during_tasks_result_marks_task_cancelled() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "cancel this task over HTTP"},
                "task": {}
            }
        }),
    );
    let (created, created_messages) = read_sse_until_response(create_task, json!(60), |_| {});
    assert!(created_messages.is_empty());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let task_result = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_result, task_messages) = read_sse_until_response(task_result, json!(61), |message| {
        if message["method"] == "sampling/createMessage" {
            let cancel = post_notification(
                &client,
                &base_url,
                token,
                &session_id,
                Some(&protocol_version),
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": message["id"],
                        "reason": "user aborted sample"
                    }
                }),
            );
            assert_eq!(cancel.status(), reqwest::StatusCode::ACCEPTED);
        }
    });

    assert_eq!(task_result["result"]["isError"], true);
    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["ownerSessionId"]
            .as_str()
            .expect("owner session id")
            .starts_with("sess-")
    );
    assert!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["ownerRequestId"]
            .as_str()
            .expect("owner request id")
            .starts_with("mcp-edge-req-")
    );
    assert!(task_result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("cancelled by client: user aborted sample"));
    assert!(
        task_messages.iter().any(|message| {
            message["method"] == "notifications/tasks/status"
                && message["params"]["taskId"].as_str() == Some(task_id.as_str())
                && message["params"]["status"].as_str() == Some("cancelled")
        }),
        "missing cancelled task status notification: {task_messages:?}"
    );

    let task_get = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 62,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_messages) = read_sse_until_response(task_get, json!(62), |_| {});
    assert!(task_get_messages.is_empty());
    assert_eq!(task_get["result"]["status"], "cancelled");
    assert_eq!(
        task_get["result"]["ownership"]["terminalStateOwner"],
        "task"
    );
}

#[test]
fn mcp_serve_http_admin_receipt_queries_return_tool_and_child_receipts() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let echo_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "receipts please"}
            }
        }),
    );
    assert_eq!(echo_response.status(), reqwest::StatusCode::OK);
    let (echo_result, echo_messages) = read_sse_until_response(echo_response, json!(20), |_| {});
    assert!(echo_messages.is_empty());
    assert_eq!(echo_result["result"]["isError"], false);

    let sampled_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "receipt child flow"}
            }
        }),
    );
    let (_sampled_result, _messages) =
        read_sse_until_response(sampled_response, json!(21), |message| {
            if message["method"] == "sampling/createMessage" {
                let follow_up = post_notification(
                    &client,
                    &base_url,
                    token,
                    &session_id,
                    Some(&protocol_version),
                    &json!({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "role": "assistant",
                            "content": {
                                "type": "text",
                                "text": "sample receipt"
                            },
                            "model": "gpt-test",
                            "stopReason": "end_turn"
                        }
                    }),
                );
                assert_eq!(follow_up.status(), reqwest::StatusCode::ACCEPTED);
            }
        });

    let tool_receipts = get_admin_tool_receipts(
        &client,
        &base_url,
        token,
        &[("tool_name", "echo_json"), ("limit", "10")],
    );
    assert_eq!(tool_receipts.status(), reqwest::StatusCode::OK);
    let tool_receipts: Value = tool_receipts.json().expect("tool receipts json");
    assert_eq!(tool_receipts["backend"], "sqlite");
    let tool_receipts = tool_receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert_eq!(tool_receipts.len(), 1);
    assert_eq!(tool_receipts[0]["tool_name"], "echo_json");
    assert_eq!(tool_receipts[0]["decision"]["verdict"], "allow");

    let child_receipts = get_admin_child_receipts(
        &client,
        &base_url,
        token,
        &[("operation_kind", "create_message"), ("limit", "10")],
    );
    assert_eq!(child_receipts.status(), reqwest::StatusCode::OK);
    let child_receipts: Value = child_receipts.json().expect("child receipts json");
    assert_eq!(child_receipts["backend"], "sqlite");
    let child_receipts = child_receipts["receipts"]
        .as_array()
        .expect("child receipts array");
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts[0]["operation_kind"], "create_message");
    assert!(child_receipts[0]["parent_request_id"].is_string());
}

#[test]
fn mcp_serve_http_admin_revocation_queries_and_direct_revoke_work() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server admin revocation query",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, _protocol_version) = initialize_session(&client, &base_url, token);
    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("trust status json");
    let capability_id = trust_status["capabilities"]
        .as_array()
        .expect("capabilities array")
        .first()
        .and_then(|capability| capability["capabilityId"].as_str())
        .expect("capability id")
        .to_string();

    let before = get_admin_revocations(
        &client,
        &base_url,
        token,
        &[("capability_id", &capability_id), ("limit", "10")],
    );
    assert_eq!(before.status(), reqwest::StatusCode::OK);
    let before: Value = before.json().expect("revocations json");
    assert_eq!(before["capabilityId"], capability_id);
    assert_eq!(before["revoked"], false);
    assert_eq!(before["count"], 0);

    let revoked = post_admin_capability_revoke(&client, &base_url, token, &capability_id);
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);
    let revoked: Value = revoked.json().expect("revoke json");
    assert_eq!(revoked["capabilityId"], capability_id);
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["newlyRevoked"], true);

    let after = get_admin_revocations(
        &client,
        &base_url,
        token,
        &[("capability_id", &capability_id), ("limit", "10")],
    );
    assert_eq!(after.status(), reqwest::StatusCode::OK);
    let after: Value = after.json().expect("revocations json");
    assert_eq!(after["revoked"], true);
    assert_eq!(after["count"], 1);
    let entries = after["revocations"].as_array().expect("revocations array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["capabilityId"], capability_id);

    let all = get_admin_revocations(&client, &base_url, token, &[("limit", "10")]);
    assert_eq!(all.status(), reqwest::StatusCode::OK);
    let all: Value = all.json().expect("all revocations json");
    let entries = all["revocations"].as_array().expect("revocations array");
    assert!(entries
        .iter()
        .any(|entry| entry["capabilityId"] == capability_id));
}

#[test]
fn mcp_serve_http_admin_revocation_denies_future_calls_for_session() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server admin revocation deny",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let trust_status_before = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status_before.status(), reqwest::StatusCode::OK);
    let trust_status_before: Value = trust_status_before.json().expect("trust status json");
    let capabilities_before = trust_status_before["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert!(!capabilities_before.is_empty());
    assert!(capabilities_before
        .iter()
        .all(|capability| capability["revoked"] == false));

    let revoke = post_admin_session_revoke(&client, &base_url, token, &session_id);
    assert_eq!(revoke.status(), reqwest::StatusCode::OK);
    let revoke_body: Value = revoke.json().expect("revoke json");
    assert_eq!(revoke_body["revoked"], true);
    assert!(
        revoke_body["newlyRevokedCount"]
            .as_u64()
            .expect("newly revoked count")
            >= 1
    );

    let trust_status_after = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status_after.status(), reqwest::StatusCode::OK);
    let trust_status_after: Value = trust_status_after.json().expect("trust status json");
    let capabilities_after = trust_status_after["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert_eq!(capabilities_after.len(), capabilities_before.len());
    assert!(capabilities_after
        .iter()
        .all(|capability| capability["revoked"] == true));

    let denied_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(99), |_| {});
    assert!(denied_notifications.is_empty());
    assert_eq!(denied_tool_call["result"]["isError"], true);
    assert!(denied_tool_call["result"]["content"][0]["text"]
        .as_str()
        .expect("denied text")
        .contains("revoked"));
}

#[test]
fn mcp_serve_http_admin_authority_rotation_only_affects_future_sessions() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_a, _protocol_a) = initialize_session(&client, &base_url, token);

    let authority_before = get_admin_authority(&client, &base_url, token);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("authority json");
    assert_eq!(authority_before["configured"], true);
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();

    let trust_a_before = get_admin_session_trust(&client, &base_url, token, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let rotated = post_admin_rotate_authority(&client, &base_url, token);
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    assert_eq!(rotated["rotated"], true);
    assert_eq!(rotated["appliesToFutureSessionsOnly"], true);
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    assert_ne!(old_public_key, new_public_key);

    let authority_after = get_admin_authority(&client, &base_url, token);
    assert_eq!(authority_after.status(), reqwest::StatusCode::OK);
    let authority_after: Value = authority_after.json().expect("authority json");
    assert_eq!(
        authority_after["publicKey"].as_str(),
        Some(new_public_key.as_str())
    );

    let (session_b, _protocol_b) = initialize_session(&client, &base_url, token);
    let trust_b = get_admin_session_trust(&client, &base_url, token, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let trust_a_after = get_admin_session_trust(&client, &base_url, token, &session_a);
    assert_eq!(trust_a_after.status(), reqwest::StatusCode::OK);
    let trust_a_after: Value = trust_a_after.json().expect("session trust json");
    let caps_a_after = trust_a_after["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert_eq!(caps_a_after.len(), caps_a_before.len());
    assert!(caps_a_after.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));
}

#[test]
fn mcp_serve_http_shared_authority_rotation_propagates_across_nodes() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let authority_db_path = dir.join("shared-authority.sqlite3");
    let listen_a = reserve_listen_addr();
    let listen_b = reserve_listen_addr();
    let token = "test-token";
    let _server_a = spawn_http_server_with_authority_db(&dir, listen_a, token, &authority_db_path);
    let _server_b = spawn_http_server_with_authority_db(&dir, listen_b, token, &authority_db_path);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");
    wait_for_server(&client, &base_url_a);
    wait_for_server(&client, &base_url_b);

    let authority_before = get_admin_authority(&client, &base_url_a, token);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("authority json");
    assert_eq!(authority_before["backend"], "sqlite");
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();
    let old_generation = authority_before["generation"]
        .as_u64()
        .expect("old authority generation");

    let (session_a, _protocol_a) = initialize_session(&client, &base_url_a, token);
    let trust_a_before = get_admin_session_trust(&client, &base_url_a, token, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let rotated = post_admin_rotate_authority(&client, &base_url_a, token);
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    assert_eq!(rotated["backend"], "sqlite");
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    let new_generation = rotated["generation"]
        .as_u64()
        .expect("new authority generation");
    assert_ne!(old_public_key, new_public_key);
    assert_eq!(new_generation, old_generation + 1);

    let authority_seen_from_b = get_admin_authority(&client, &base_url_b, token);
    assert_eq!(authority_seen_from_b.status(), reqwest::StatusCode::OK);
    let authority_seen_from_b: Value = authority_seen_from_b.json().expect("authority json");
    assert_eq!(
        authority_seen_from_b["publicKey"].as_str(),
        Some(new_public_key.as_str())
    );
    assert_eq!(
        authority_seen_from_b["generation"].as_u64(),
        Some(new_generation)
    );

    let (session_b, _protocol_b) = initialize_session(&client, &base_url_b, token);
    let trust_b = get_admin_session_trust(&client, &base_url_b, token, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let trust_a_after = get_admin_session_trust(&client, &base_url_a, token, &session_a);
    assert_eq!(trust_a_after.status(), reqwest::StatusCode::OK);
    let trust_a_after: Value = trust_a_after.json().expect("session trust json");
    let caps_a_after = trust_a_after["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert_eq!(caps_a_after.len(), caps_a_before.len());
    assert!(caps_a_after.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));
}

#[test]
fn mcp_serve_http_control_service_centralizes_receipts_revocations_and_authority() {
    let dir = unique_test_dir();
    let node_a_dir = dir.join("node-a");
    let node_b_dir = dir.join("node-b");
    fs::create_dir_all(&node_a_dir).expect("create node A dir");
    fs::create_dir_all(&node_b_dir).expect("create node B dir");

    let receipt_db_path = dir.join("control-receipts.sqlite3");
    let revocation_db_path = dir.join("control-revocations.sqlite3");
    let authority_db_path = dir.join("control-authority.sqlite3");
    let budget_db_path = dir.join("control-budgets.sqlite3");
    let auth_token = "edge-token";
    let control_token = "control-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");

    let (control_listen, _control) = spawn_with_bind_retry(
        &client,
        "trust control service",
        |listen| {
            spawn_trust_control_service(
                listen,
                control_token,
                &receipt_db_path,
                &revocation_db_path,
                &authority_db_path,
                &budget_db_path,
            )
        },
        wait_for_control_service_result,
    );
    let control_base_url = format!("http://{control_listen}");

    let (listen_a, _server_a) = spawn_with_bind_retry(
        &client,
        "control-backed MCP server A",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_a_dir,
                listen,
                auth_token,
                &control_base_url,
                control_token,
            )
        },
        wait_for_server_result,
    );
    let (listen_b, _server_b) = spawn_with_bind_retry(
        &client,
        "control-backed MCP server B",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_b_dir,
                listen,
                auth_token,
                &control_base_url,
                control_token,
            )
        },
        wait_for_server_result,
    );
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");

    let authority_before = get_control_authority(&client, &control_base_url, control_token);
    assert_eq!(authority_before.status(), reqwest::StatusCode::OK);
    let authority_before: Value = authority_before.json().expect("control authority json");
    assert_eq!(authority_before["configured"], true);
    assert_eq!(authority_before["backend"], "sqlite");
    let old_public_key = authority_before["publicKey"]
        .as_str()
        .expect("old authority public key")
        .to_string();

    let (session_a, protocol_a) = initialize_session(&client, &base_url_a, auth_token);
    let trust_a_before = get_admin_session_trust(&client, &base_url_a, auth_token, &session_a);
    assert_eq!(trust_a_before.status(), reqwest::StatusCode::OK);
    let trust_a_before: Value = trust_a_before.json().expect("session trust json");
    let caps_a_before = trust_a_before["capabilities"]
        .as_array()
        .expect("session A capabilities");
    assert!(!caps_a_before.is_empty());
    let capability_id = caps_a_before[0]["capabilityId"]
        .as_str()
        .expect("capability id")
        .to_string();
    assert!(caps_a_before.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(old_public_key.as_str())
    }));

    let tool_call = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "distributed hello"}
            }
        }),
    );
    assert_eq!(tool_call.status(), reqwest::StatusCode::OK);
    let (tool_call, notifications) = read_sse_until_response(tool_call, json!(41), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(
        tool_call["result"]["structuredContent"]["echo"],
        "distributed hello"
    );

    let control_receipts = get_control_tool_receipts(
        &client,
        &control_base_url,
        control_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(control_receipts.status(), reqwest::StatusCode::OK);
    let control_receipts: Value = control_receipts.json().expect("control receipts json");
    assert_eq!(control_receipts["configured"], true);
    assert_eq!(control_receipts["kind"], "tool");
    assert_eq!(control_receipts["count"], 1);

    let proxied_receipts = get_admin_tool_receipts(
        &client,
        &base_url_b,
        auth_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(proxied_receipts.status(), reqwest::StatusCode::OK);
    let proxied_receipts: Value = proxied_receipts.json().expect("proxied receipts json");
    assert_eq!(proxied_receipts["count"], control_receipts["count"]);
    assert_eq!(
        proxied_receipts["receipts"][0]["tool_name"],
        control_receipts["receipts"][0]["tool_name"]
    );

    let rotated = post_control_rotate_authority(&client, &control_base_url, control_token);
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: Value = rotated.json().expect("rotated authority json");
    let new_public_key = rotated["publicKey"]
        .as_str()
        .expect("new authority public key")
        .to_string();
    assert_ne!(new_public_key, old_public_key);
    let trusted_keys = rotated["trustedPublicKeys"]
        .as_array()
        .expect("trusted authority keys");
    assert!(trusted_keys
        .iter()
        .any(|value| value.as_str() == Some(old_public_key.as_str())));
    assert!(trusted_keys
        .iter()
        .any(|value| value.as_str() == Some(new_public_key.as_str())));

    let authority_seen_from_b = get_admin_authority(&client, &base_url_b, auth_token);
    assert_eq!(authority_seen_from_b.status(), reqwest::StatusCode::OK);
    let authority_seen_from_b: Value = authority_seen_from_b.json().expect("authority json");
    assert_eq!(
        authority_seen_from_b["publicKey"].as_str(),
        Some(new_public_key.as_str())
    );

    let tool_call_after_rotation = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "old session still valid"}
            }
        }),
    );
    assert_eq!(tool_call_after_rotation.status(), reqwest::StatusCode::OK);
    let (tool_call_after_rotation, notifications) =
        read_sse_until_response(tool_call_after_rotation, json!(42), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(
        tool_call_after_rotation["result"]["structuredContent"]["echo"],
        "old session still valid"
    );

    let (session_b, _protocol_b) = initialize_session(&client, &base_url_b, auth_token);
    let trust_b = get_admin_session_trust(&client, &base_url_b, auth_token, &session_b);
    assert_eq!(trust_b.status(), reqwest::StatusCode::OK);
    let trust_b: Value = trust_b.json().expect("session trust json");
    let caps_b = trust_b["capabilities"]
        .as_array()
        .expect("session B capabilities");
    assert!(!caps_b.is_empty());
    assert!(caps_b.iter().all(|capability| {
        capability["issuerPublicKey"].as_str() == Some(new_public_key.as_str())
    }));

    let revoke = post_admin_capability_revoke(&client, &base_url_b, auth_token, &capability_id);
    assert_eq!(revoke.status(), reqwest::StatusCode::OK);
    let revoke: Value = revoke.json().expect("revoke capability json");
    assert_eq!(revoke["capabilityId"], capability_id);
    assert_eq!(revoke["revoked"], true);
    assert_eq!(revoke["newlyRevoked"], true);

    let control_revocations = get_control_revocations(
        &client,
        &control_base_url,
        control_token,
        &[("capabilityId", capability_id.as_str()), ("limit", "1")],
    );
    assert_eq!(control_revocations.status(), reqwest::StatusCode::OK);
    let control_revocations: Value = control_revocations
        .json()
        .expect("control revocations json");
    assert_eq!(control_revocations["revoked"], true);
    assert_eq!(control_revocations["count"], 1);

    let denied_response = post_json(
        &client,
        &base_url_a,
        auth_token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(43), |_| {});
    assert!(denied_notifications.is_empty());
    assert_eq!(denied_tool_call["result"]["isError"], true);
    assert!(denied_tool_call["result"]["content"][0]["text"]
        .as_str()
        .expect("denied text")
        .contains("revoked"));
}

#[test]
fn mcp_serve_http_dedicated_jwt_sessions_require_exact_bearer_continuity_and_separate_admin_token()
{
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);
    let trust = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: Value = trust.json().expect("session trust json");
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let tools_list = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(tools_list.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(tools_list
        .text()
        .expect("dedicated continuity body")
        .contains("authenticated authorization context does not match session"));

    let admin_unauthorized = get_admin_authority(&client, &base_url, &token_b);
    assert_eq!(
        admin_unauthorized.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let admin_authorized = get_admin_authority(&client, &base_url, admin_token);
    assert_eq!(admin_authorized.status(), reqwest::StatusCode::OK);
    let admin_authorized: Value = admin_authorized.json().expect("authority json");
    assert_eq!(admin_authorized["configured"], true);
}

#[test]
fn mcp_serve_http_shared_owner_jwt_sessions_keep_weak_compatibility_continuity() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_shared_owner_and_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);
    let trust = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: Value = trust.json().expect("session trust json");
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("shared_hosted_owner_compatibility")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("weak_shared_hosted_owner_compatibility")
    );

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let tools_list = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(tools_list.status(), reqwest::StatusCode::OK);
    let (tools_list, notifications) = read_sse_until_response(tools_list, json!(2), |_| {});
    assert!(notifications.is_empty());
    assert!(
        tools_list["result"]["tools"]
            .as_array()
            .expect("tools array")
            .len()
            >= 1
    );
}

#[test]
fn mcp_serve_http_identity_federation_derives_stable_subjects_from_jwt_principals() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_identity_federation(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&federation_seed_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_for = |subject: &str, exp_offset: u64| {
        sign_jwt(
            &jwt_signing_key,
            &json!({
                "iss": issuer,
                "sub": subject,
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": format!("client-{subject}"),
                "tid": "tenant-123",
                "org_id": "org-789",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + exp_offset,
            }),
        )
    };

    let token_a = token_for("user-123", 300);
    let (session_a, protocol_a) = initialize_session(&client, &base_url, &token_a);
    let token_b = token_for("user-123", 600);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, &token_b);
    let token_c = token_for("user-456", 900);
    let (session_c, protocol_c) = initialize_session(&client, &base_url, &token_c);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");
    let trust_c: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_c)
        .json()
        .expect("session C trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    let subject_c = trust_c["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session C subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    assert_ne!(subject_a, subject_c);
    let enterprise_subject_a = trust_a["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session A enterprise subject key")
        .to_string();
    let enterprise_subject_b = trust_b["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session B enterprise subject key")
        .to_string();
    let enterprise_subject_c = trust_c["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session C enterprise subject key")
        .to_string();
    assert_eq!(enterprise_subject_a, enterprise_subject_b);
    assert_ne!(enterprise_subject_a, enterprise_subject_c);
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["tenantId"].as_str(),
        Some("tenant-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["organizationId"].as_str(),
        Some("org-789")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["roles"],
        json!(["operator"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("sub")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["groups"]
            .as_str(),
        Some("groups")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["roles"]
            .as_str(),
        Some("roles")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("client-user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["organizationId"].as_str(),
        Some("org-789")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );
    assert_eq!(
        trust_c["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-456")
    );

    for (session_id, protocol_version, token, message) in [
        (&session_a, &protocol_a, &token_a, "same-subject-a"),
        (&session_b, &protocol_b, &token_b, "same-subject-b"),
        (&session_c, &protocol_c, &token_c, "different-subject"),
    ] {
        let tool_call = post_json(
            &client,
            &base_url,
            token,
            Some(session_id),
            Some(protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "echo_json",
                    "arguments": {"message": message}
                }
            }),
        );
        assert_eq!(tool_call.status(), reqwest::StatusCode::OK);
        let (tool_call, notifications) = read_sse_until_response(tool_call, json!(41), |_| {});
        assert!(notifications.is_empty());
        assert_eq!(tool_call["result"]["structuredContent"]["echo"], message);
    }

    let receipts = get_admin_tool_receipts(
        &client,
        &base_url,
        admin_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("receipt list json");
    let subject_keys = receipts["receipts"]
        .as_array()
        .expect("receipt array")
        .iter()
        .map(|receipt| {
            receipt["metadata"]["attribution"]["subject_key"]
                .as_str()
                .expect("receipt attribution subject")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        subject_keys
            .iter()
            .filter(|subject| *subject == &subject_a)
            .count(),
        2
    );
    assert_eq!(
        subject_keys
            .iter()
            .filter(|subject| *subject == &subject_c)
            .count(),
        1
    );
}

#[test]
fn mcp_serve_http_admin_health_reports_runtime_state() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_identity_federation(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&federation_seed_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-health",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let _ = initialize_session(&client, &base_url, &token);

    let health = get_admin_health(&client, &base_url, admin_token);
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health: Value = health.json().expect("admin health json");
    assert_eq!(health["ok"], true);
    assert_eq!(health["server"]["serverId"], "wrapped-http-mock");
    assert_eq!(health["auth"]["mode"], "jwt_bearer");
    assert_eq!(health["stores"]["receiptsConfigured"], true);
    assert_eq!(health["stores"]["revocationsConfigured"], true);
    assert_eq!(health["federation"]["identityFederationConfigured"], true);
    assert_eq!(health["server"]["sharedHostedOwner"], false);
    assert!(
        health["sessions"]["activeCount"].as_u64().unwrap_or(0) >= 1,
        "expected at least one active session in admin health"
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_jwt_and_uses_azure_ad_profile_mapping() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let oidc_signing_key = Keypair::generate();
    let (idp_root, issuer, discovery_url) =
        write_oidc_discovery_fixture(&dir, idp_listen, "tenant/v2.0", &oidc_signing_key);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                Some("azure-ad"),
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let token_for = |exp_offset: u64| {
        sign_jwt(
            &oidc_signing_key,
            &json!({
                "iss": issuer,
                "sub": "opaque-subject",
                "oid": "object-123",
                "appid": "client-abc",
                "tid": "tenant-azure",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "groups": ["ops", "eng"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + exp_offset,
            }),
        )
    };

    let token_a = token_for(300);
    let (session_a, _) = initialize_session(&client, &base_url, &token_a);
    let token_b = token_for(600);
    let (session_b, _) = initialize_session(&client, &base_url, &token_b);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    let expected_principal = format!("oidc:{issuer}#oid:object-123");
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some(expected_principal.as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some(expected_principal.as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("oid")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["clientId"]
            .as_str(),
        Some("appid")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["objectId"].as_str(),
        Some("object-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("client-abc")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-azure")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );

    let metadata = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(metadata.status(), reqwest::StatusCode::OK);
    let metadata: Value = metadata.json().expect("protected metadata json");
    assert_eq!(
        metadata["authorization_servers"][0].as_str(),
        Some(issuer.as_str())
    );
    assert_eq!(
        metadata["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        metadata["chio_authorization_profile"]["senderConstraints"]["subjectBinding"].as_str(),
        Some("capability_subject")
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_rs256_tokens() {
    use rsa::traits::PublicKeyParts as _;

    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let rsa_private_key =
        rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate rsa key");
    let rsa_public_key = rsa_private_key.to_public_key();
    let (idp_root, issuer, discovery_url) = write_oidc_discovery_fixture_with_jwks(
        &dir,
        idp_listen,
        "rsa",
        json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "rsa-key-1",
                "n": URL_SAFE_NO_PAD.encode(rsa_public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(rsa_public_key.e().to_bytes_be()),
            }]
        }),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery RS256",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                None,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    let token = sign_jwt_rs256(
        &rsa_private_key,
        &json!({
            "iss": issuer,
            "sub": "rsa-user",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
        "rsa-key-1",
    );
    let (session_id, _) = initialize_session(&client, &base_url, &token);
    let trust: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:rsa-user").as_str())
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_es256_tokens() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded.x().expect("p256 x coordinate");
    let y = encoded.y().expect("p256 y coordinate");
    let (idp_root, issuer, discovery_url) = write_oidc_discovery_fixture_with_jwks(
        &dir,
        idp_listen,
        "ec",
        json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": "ec-key-1",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            }]
        }),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery ES256",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                None,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    let token = sign_jwt_es256(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "ec-user",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
        "ec-key-1",
    );
    let (session_id, _) = initialize_session(&client, &base_url, &token);
    let trust: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:ec-user").as_str())
    );
}

#[test]
fn mcp_serve_http_token_introspection_verifies_opaque_tokens_and_derives_stable_subjects() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let introspection_listen = reserve_listen_addr();
    let introspection_script = write_introspection_server_script(&dir);
    let introspection_responses_path = dir.join("introspection-responses.json");
    let issuer = "https://issuer.example/introspection";
    let audience = "chio-mcp";
    let token_a = "opaque-token-a";
    let token_b = "opaque-token-b";
    fs::write(
        &introspection_responses_path,
        serde_json::to_vec_pretty(&json!({
            token_a: {
                "active": true,
                "token_type": "Bearer",
                "iss": issuer,
                "sub": "opaque-user",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": "confidential-client",
                "tid": "tenant-opaque",
                "org_id": "org-opaque",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + 300,
            },
            token_b: {
                "active": true,
                "token_type": "Bearer",
                "iss": issuer,
                "sub": "opaque-user",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": "confidential-client",
                "tid": "tenant-opaque",
                "org_id": "org-opaque",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + 600,
            }
        }))
        .expect("serialize introspection responses"),
    )
    .expect("write introspection responses");
    let client_id = "chio-edge";
    let client_secret = "top-secret";
    let expected_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{client_id}:{client_secret}"))
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut introspection_server = spawn_introspection_server(
        &introspection_script,
        introspection_listen,
        &introspection_responses_path,
        Some(&expected_auth),
    );
    wait_for_http_fixture_url(
        &client,
        &format!("http://{}/health", introspection_listen),
        &mut introspection_server,
    );

    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let introspection_url = format!("http://{}/introspect", introspection_listen);
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with token introspection",
        |listen| {
            spawn_http_server_with_token_introspection_and_identity_federation(
                &dir,
                listen,
                &introspection_url,
                client_id,
                client_secret,
                issuer,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_a, _) = initialize_session(&client, &base_url, token_a);
    let (session_b, _) = initialize_session(&client, &base_url, token_b);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:opaque-user").as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:opaque-user").as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["providerKind"].as_str(),
        Some("oauth_introspection")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("sub")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("confidential-client")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-opaque")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["organizationId"].as_str(),
        Some("org-opaque")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );
}

#[test]
fn mcp_serve_http_rejects_session_reuse_when_authenticated_principal_changes() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-456",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-other",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let response = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[test]
fn mcp_serve_http_rejects_jwt_with_wrong_audience() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let wrong_audience_token = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": "wrong-audience",
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let response = post_raw(
        &client,
        &base_url,
        Some(&wrong_audience_token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
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
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("www-authenticate header")
        .to_str()
        .expect("www-authenticate string");
    assert!(challenge.contains("resource_metadata="));
    assert!(challenge.contains("scope=\"mcp:invoke\""));

    let metadata = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(metadata.status(), reqwest::StatusCode::OK);
    let metadata: Value = metadata.json().expect("metadata json");
    assert_eq!(metadata["resource"].as_str(), Some(audience));
    assert_eq!(metadata["authorization_servers"][0].as_str(), Some(issuer));
    assert!(metadata["scopes_supported"]
        .as_array()
        .expect("scopes array")
        .iter()
        .any(|scope| scope.as_str() == Some("mcp:invoke")));
    assert_eq!(
        metadata["chio_authorization_profile"]["senderConstraints"]["proofTypesSupported"][0]
            .as_str(),
        Some("chio_dpop_v1")
    );
}

#[test]
fn mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let issuer = format!("{base_url}/oauth");
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let authorization_endpoint = "https://auth.example.com/oauth2/authorize";
    let token_endpoint = "https://auth.example.com/oauth2/token";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_local_discovery(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        &issuer,
        audience,
        admin_token,
        authorization_endpoint,
        token_endpoint,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    wait_for_server(&client, &base_url);

    let protected = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(protected.status(), reqwest::StatusCode::OK);
    let protected: Value = protected.json().expect("protected metadata json");
    assert_eq!(
        protected["authorization_servers"][0].as_str(),
        Some(issuer.as_str())
    );
    assert_eq!(
        protected["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let auth_metadata = get_oauth_authorization_server_metadata(&client, &base_url, "/oauth");
    assert_eq!(auth_metadata.status(), reqwest::StatusCode::OK);
    let auth_metadata: Value = auth_metadata.json().expect("auth metadata json");
    assert_eq!(auth_metadata["issuer"].as_str(), Some(issuer.as_str()));
    assert_eq!(
        auth_metadata["authorization_endpoint"].as_str(),
        Some(authorization_endpoint)
    );
    assert_eq!(
        auth_metadata["token_endpoint"].as_str(),
        Some(token_endpoint)
    );
    assert!(auth_metadata["response_types_supported"]
        .as_array()
        .expect("response types")
        .iter()
        .any(|value| value.as_str() == Some("code")));
    assert!(auth_metadata["code_challenge_methods_supported"]
        .as_array()
        .expect("code challenge methods")
        .iter()
        .any(|value| value.as_str() == Some("S256")));
    assert!(auth_metadata["scopes_supported"]
        .as_array()
        .expect("scopes supported")
        .iter()
        .any(|value| value.as_str() == Some("mcp:invoke")));
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["senderConstraints"]["proofTypesSupported"][0]
            .as_str(),
        Some("chio_dpop_v1")
    );
}

#[test]
fn mcp_serve_http_requires_both_accept_types_and_json_content_type() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let init_body = json!({
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
    });

    let bad_accept = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json",
        "application/json",
        &init_body,
    );
    assert_eq!(bad_accept.status(), reqwest::StatusCode::NOT_ACCEPTABLE);

    let bad_content_type = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "text/plain",
        &init_body,
    );
    assert_eq!(
        bad_content_type.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[test]
fn mcp_serve_http_sets_explicit_response_mode_headers() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let initialize = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
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
        }),
    );
    assert_eq!(
        initialize
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("initialize_sse")
    );
    let session_id = initialize
        .headers()
        .get("MCP-Session-Id")
        .expect("session id header")
        .to_str()
        .expect("session id string")
        .to_string();
    let (initialize, init_messages) = read_sse_until_response(initialize, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(
        initialized
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("post_notification_accepted")
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);

    let tools_list = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(
        tools_list
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("post_request_sse")
    );
    let (tools_list, notifications) = read_sse_until_response(tools_list, json!(2), |_| {});
    assert!(notifications.is_empty());
    assert!(tools_list["result"]["tools"].is_array());

    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(
        get_stream
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("get_sse_live")
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
}

#[test]
fn mcp_serve_http_rejects_initialize_with_session_header_without_issuing_session() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        Some("bogus-session"),
        "application/json, text/event-stream",
        "application/json",
        &json!({
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
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_initialize_without_request_id() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
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
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_malformed_jsonrpc_body() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_bytes(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25""#,
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().expect("parse malformed request response");
    assert_eq!(body["error"]["code"], -32700);
    assert!(body["error"]["message"]
        .as_str()
        .expect("parse error message")
        .contains("invalid JSON"));
}
