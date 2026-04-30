//! Ollama localhost deterministic-replay gate.
//!
//! This is intentionally a deterministic offline replay, not a live HTTP
//! integration test. It runs the captured `ollama_localhost_replay` NDJSON
//! fixture through the adapter's `lift_batch` path so the lane stays
//! reproducible on hermetic CI runners and developer machines without a
//! local daemon.
//!
//! `OLLAMA_HOST` is treated purely as an opt-in switch: when unset the
//! lane is skipped so PR jobs do not require a model on every machine, and
//! when set the captured fixture bytes are still replayed through the
//! `MockTransport` to keep the gate offline-deterministic. Live wire-level
//! validation of `/api/chat` is the responsibility of the M07 P4 nightly
//! lane and the broader provider-conformance harness, not this test.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_ollama_tools_adapter::transport::MockTransport;
use chio_ollama_tools_adapter::{OllamaAdapter, OllamaAdapterConfig};
use chio_tool_call_fabric::{ProviderId, ProviderRequest};
use serde_json::Value;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../chio-provider-conformance/fixtures/ollama/ollama_localhost_replay.ndjson")
}

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

#[test]
fn deterministic_localhost_fixture_replays_through_mock_transport() {
    let Some(host) = env::var("OLLAMA_HOST").ok() else {
        eprintln!("OLLAMA_HOST not set; skipping localhost integration replay");
        return;
    };

    let path = fixture_path();
    let payload = match read_response_payload(&path) {
        Ok(payload) => payload,
        Err(error) => panic!("{error}"),
    };

    let bytes = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(error) => panic!("encode replay payload: {error}"),
    };

    // Even with a real daemon configured we replay the deterministic
    // fixture through the adapter so the lane stays offline-deterministic.
    // The OLLAMA_HOST variable only gates execution, not the bytes.
    let adapter = OllamaAdapter::new(
        OllamaAdapterConfig::new(
            "ollama-1",
            "Ollama Chat",
            "0.1.0",
            "deadbeef",
            "local_chio_demo",
        ),
        Arc::new(MockTransport::new()),
    );
    assert_eq!(
        adapter.transport().endpoint(),
        "mock://ollama",
        "localhost replay must drive the mock transport, not {host}",
    );

    let invocations = match adapter.lift_batch(ProviderRequest(bytes)) {
        Ok(invocations) => invocations,
        Err(error) => panic!("lift_batch failed: {error}"),
    };
    assert_eq!(invocations.len(), 1, "expected one tool invocation");
    let invocation = &invocations[0];
    assert_eq!(invocation.provider, ProviderId::Ollama);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(invocation.provenance.api_version, "2025-04");
}
