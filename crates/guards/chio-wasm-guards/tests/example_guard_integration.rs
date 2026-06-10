//! Integration tests for SDK-compiled example guards.
//!
//! Loads the compiled `.wasm` binaries for `tool-gate` and `enriched-inspector`
//! into the `WasmtimeBackend` host runtime and verifies correct Allow/Deny
//! verdicts for various request scenarios.
//!
//! Proves the full SDK-to-host round trip: proc macro code generation, WASM
//! compilation, host loading, request serialization, guest evaluation, and
//! verdict deserialization.

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/wasm_examples.rs"]
mod wasm_examples;

use std::collections::HashMap;

use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load an example guard WASM binary by crate artifact name.
fn load_example_wasm(name: &str) -> Vec<u8> {
    let package = match name {
        "chio_example_tool_gate" => "chio-example-tool-gate",
        "chio_example_enriched_inspector" => "chio-example-enriched-inspector",
        other => panic!("unknown Rust example guard artifact: {other}"),
    };
    wasm_examples::load_rust_example_wasm(package, name)
}

/// Create a minimal guard request with only a tool name set.
fn make_request(tool_name: &str) -> GuardRequest {
    GuardRequest {
        tool_name: tool_name.to_string(),
        server_id: "test-server".to_string(),
        agent_id: "test-agent".to_string(),
        arguments: serde_json::json!({}),
        scopes: vec![],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: vec![],
        matched_grant_index: None,
    }
}

/// Create a guard request with enriched fields set.
fn make_enriched_request(
    tool_name: &str,
    action_type: Option<&str>,
    extracted_path: Option<&str>,
) -> GuardRequest {
    GuardRequest {
        tool_name: tool_name.to_string(),
        server_id: "test-server".to_string(),
        agent_id: "test-agent".to_string(),
        arguments: serde_json::json!({}),
        scopes: vec![],
        action_type: action_type.map(String::from),
        extracted_path: extracted_path.map(String::from),
        extracted_target: None,
        filesystem_roots: vec![],
        matched_grant_index: None,
    }
}

// ---------------------------------------------------------------------------
// tool-gate tests
// ---------------------------------------------------------------------------

#[test]
fn tool_gate_allows_safe_tool() {
    let wasm_bytes = load_example_wasm("chio_example_tool_gate");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request("read_file")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for safe tool, got {verdict:?}"
    );
}

#[test]
fn tool_gate_denies_dangerous_tool() {
    let wasm_bytes = load_example_wasm("chio_example_tool_gate");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request("dangerous_tool")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for dangerous_tool, got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("blocked by policy"),
                "expected reason to contain 'blocked by policy', got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }
}

#[test]
fn tool_gate_denies_padded_tool_name() {
    let wasm_bytes = load_example_wasm("chio_example_tool_gate");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request(" dangerous_tool ")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for padded dangerous_tool, got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("not canonical"),
                "expected reason to mention canonical tool names, got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }
}

#[test]
fn tool_gate_denies_rm_rf() {
    let wasm_bytes = load_example_wasm("chio_example_tool_gate");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request("rm_rf")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for rm_rf, got {verdict:?}"
    );
}

#[test]
fn tool_gate_denies_drop_database() {
    let wasm_bytes = load_example_wasm("chio_example_tool_gate");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request("drop_database")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for drop_database, got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// enriched-inspector tests
// ---------------------------------------------------------------------------

#[test]
fn enriched_inspector_allows_non_file_write() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend.evaluate(&make_request("any_tool")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for non-file-write action, got {verdict:?}"
    );
}

#[test]
fn enriched_inspector_allows_file_read() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "read_file",
            Some("file_access"),
            Some("/etc/passwd"),
        ))
        .unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for file_access (not file_write), got {verdict:?}"
    );
}

#[test]
fn enriched_inspector_denies_write_to_etc() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            Some("/etc/passwd"),
        ))
        .unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for file_write to /etc, got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("write to /etc blocked"),
                "expected reason to contain 'write to /etc blocked', got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }
}

#[test]
fn enriched_inspector_denies_file_write_without_path_evidence() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            None,
        ))
        .unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for file_write without path evidence, got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("missing normalized path evidence"),
                "expected reason to mention missing path evidence, got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }
}

#[test]
fn enriched_inspector_allows_write_to_tmp() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            Some("/tmp/data.txt"),
        ))
        .unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for file_write to /tmp, got {verdict:?}"
    );
}

#[test]
fn enriched_inspector_allows_write_to_etcetera_sibling() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            Some("/etcetera/passwd"),
        ))
        .unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for file_write to /etcetera sibling, got {verdict:?}"
    );
}

#[test]
fn enriched_inspector_denies_write_to_configured_path() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let config = HashMap::from([("blocked_path".to_string(), "/var/secret".to_string())]);
    let mut backend = WasmtimeBackend::with_engine_and_config(engine, config);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            Some("/var/secret/key.pem"),
        ))
        .unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for file_write to configured blocked path, got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("protected path"),
                "expected reason to contain 'protected path', got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }
}

#[test]
fn enriched_inspector_allows_configured_path_sibling() {
    let wasm_bytes = load_example_wasm("chio_example_enriched_inspector");
    let engine = create_shared_engine().unwrap();
    let config = HashMap::from([("blocked_path".to_string(), "/var/secret".to_string())]);
    let mut backend = WasmtimeBackend::with_engine_and_config(engine, config);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let verdict = backend
        .evaluate(&make_enriched_request(
            "write_file",
            Some("file_write"),
            Some("/var/secrets/key.pem"),
        ))
        .unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for configured blocked-path sibling, got {verdict:?}"
    );
}
