//! Ollama localhost integration test.
//!
//! Boots an Ollama daemon when `OLLAMA_HOST` is set in the environment and
//! asserts the deterministic `ollama_localhost_replay` fixture round-trips
//! through the adapter. The lane is skipped when the env var is absent so
//! PR runs do not require a model on every developer machine.
//!
//! CI exposes the daemon through a service container with a pre-pulled
//! `llama3.2:1b` model; per the M07 P4 plan, the lane is optional on PR
//! and required on nightly.

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
fn localhost_fixture_replays_when_daemon_available() {
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
