//! Ollama `/api/chat` replay coverage.
//!
//! Two lanes share the same adapter entry point ([`OllamaAdapter::chat`]):
//!
//! - A hermetic lane (always runs) scripts the shared
//!   [`MockTransport`](chio_ollama_tools_adapter::transport::MockTransport) with
//!   the recorded `ollama_localhost_replay` fixture response and asserts the
//!   lifted tool call. No sockets and no network are involved, so it is
//!   deterministic in CI.
//! - An opt-in live lane drives the real reqwest-backed transport against a
//!   running daemon. It is gated on the `OLLAMA_HOST` environment variable, so
//!   PR jobs that do not have a model on every machine skip it. The lane uses
//!   the shared transport (no hand-rolled HTTP), exactly the path production
//!   code takes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chio_ollama_tools_adapter::transport::{self, MockTransport};
use chio_ollama_tools_adapter::{OllamaAdapter, OllamaAdapterConfig};
use chio_provider_adapter_core::http::HttpResponse;
use chio_tool_call_fabric::{ProviderId, ToolInvocation};
use serde_json::Value;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../chio-provider-conformance/fixtures/ollama/ollama_localhost_replay.ndjson")
}

/// Pull the recorded `upstream_response` payload out of the capture fixture.
fn read_response_payload(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path).map_err(|error| format!("read {path:?}: {error}"))?;
    for (idx, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("parse {path:?} line {}: {error}", idx + 1))?;
        if value.get("direction").and_then(Value::as_str) == Some("upstream_response") {
            return value
                .get("payload")
                .cloned()
                .ok_or_else(|| format!("upstream_response payload missing at line {}", idx + 1));
        }
    }
    Err(format!("no upstream_response in {path:?}"))
}

fn adapter(transport: Arc<dyn transport::Transport>) -> OllamaAdapter {
    OllamaAdapter::new(
        OllamaAdapterConfig::new(
            "ollama-1",
            "Ollama Chat",
            "0.1.0",
            "deadbeef",
            "local_chio_demo",
        ),
        transport,
    )
}

fn assert_replay_invocation(invocations: &[ToolInvocation]) {
    assert_eq!(invocations.len(), 1, "expected one tool invocation");
    let invocation = &invocations[0];
    assert_eq!(invocation.provider, ProviderId::Ollama);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(invocation.provenance.api_version, "2025-04");
}

fn response_has_chat_shape(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => value
            .as_object()
            .is_some_and(|object| object.get("message").is_some() || object.get("done").is_some()),
        Err(_) => false,
    }
}

#[test]
fn response_has_chat_shape_rejects_unrelated_json() {
    assert!(!response_has_chat_shape(br#"{"status":"ok"}"#));
    assert!(!response_has_chat_shape(
        br#"[{"message":{"role":"assistant"}}]"#
    ));
    assert!(response_has_chat_shape(
        br#"{"message":{"role":"assistant","content":"OK"},"done":true}"#
    ));
}

/// Hermetic lane: the adapter posts `/api/chat` through the shared mock
/// transport scripted with the recorded fixture, and lifts the tool call. This
/// exercises the same `chat` path as production without any network.
#[tokio::test]
async fn fixture_replay_through_mock_transport() {
    let payload = match read_response_payload(&fixture_path()) {
        Ok(payload) => payload,
        Err(error) => panic!("{error}"),
    };
    assert!(
        response_has_chat_shape(&serde_json::to_vec(&payload).expect("encode fixture payload")),
        "recorded fixture must be a chat-shaped response",
    );

    let mock = Arc::new(MockTransport::new("mock://ollama"));
    mock.push_response(HttpResponse::new(
        200,
        serde_json::to_vec(&payload).expect("encode fixture payload"),
        Some("application/json".to_string()),
    ));
    let adapter = adapter(mock.clone());

    let request = serde_json::to_vec(&serde_json::json!({
        "model": "llama3.2:1b",
        "stream": false,
        "messages": [{"role": "user", "content": "Localhost integration test"}]
    }))
    .expect("encode request");

    let invocations = match adapter.chat(&request).await {
        Ok(invocations) => invocations,
        Err(error) => panic!("chat failed: {error}"),
    };
    assert_replay_invocation(&invocations);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1, "exactly one /api/chat call expected");
    assert_eq!(calls[0].path, transport::OLLAMA_CHAT_PATH);
    assert_eq!(calls[0].body, request);
}

/// Opt-in live lane: drive the real reqwest transport against `OLLAMA_HOST`.
///
/// Skipped (not failed) when `OLLAMA_HOST` is unset so default CI stays offline.
/// When set, it posts a real `/api/chat` request through the shared transport
/// and asserts the daemon returns a chat-shaped response.
#[tokio::test]
async fn live_ollama_host_chat_probe() {
    let Ok(host) = std::env::var("OLLAMA_HOST") else {
        eprintln!("OLLAMA_HOST not set; skipping live Ollama chat probe");
        return;
    };
    if host.trim().is_empty() {
        eprintln!("OLLAMA_HOST is empty; skipping live Ollama chat probe");
        return;
    }
    let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.2:1b".to_string());

    let transport = match transport::live_transport_with_timeout(Duration::from_secs(30)) {
        Ok(transport) => transport,
        Err(error) => panic!("build live Ollama transport: {error}"),
    };
    assert_eq!(
        transport.base_url(),
        host,
        "live transport must target the configured OLLAMA_HOST",
    );

    let request = serde_json::to_vec(&serde_json::json!({
        "model": model,
        "stream": false,
        "messages": [{"role": "user", "content": "Return exactly OK."}]
    }))
    .expect("encode request");

    let response = match transport
        .post_json(transport::OLLAMA_CHAT_PATH, &request)
        .await
    {
        Ok(response) => response,
        Err(error) => panic!("live /api/chat call to OLLAMA_HOST `{host}` failed: {error}"),
    };
    assert!(
        response_has_chat_shape(&response.body),
        "Ollama /api/chat returned a non-chat response: {}",
        String::from_utf8_lossy(&response.body)
    );
}
