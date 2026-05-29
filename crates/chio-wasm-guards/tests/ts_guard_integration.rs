//! Integration tests for the TypeScript guard SDK round trip.
//!
//! Loads the TypeScript-compiled `tool-gate.wasm` (built by `jco componentize`)
//! into the Chio host dual-mode WASM runtime and verifies correct Allow/Deny
//! verdicts.
//!
//! Proves the full SDK-to-host round trip: WIT type generation via `jco types`,
//! TypeScript guard compiled via `esbuild` + `jco componentize`, host
//! auto-detection of Component Model format, and correct verdict evaluation
//! through `ComponentBackend`.
//!
//! The TypeScript guard mirrors the Rust `tool-gate` example: it allows any
//! tool not on the deny list (`dangerous_tool`, `rm_rf`, `drop_database`) and
//! returns a deny reason containing "blocked by policy" for blocked tools.
//!
//! # Prerequisites
//!
//! Build the TypeScript guard before running these tests:
//!
//! ```bash
//! cd sdks/guard/chio-guard-ts && npm install && npm run build:example
//! ```

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::{create_backend, detect_wasm_format, ComponentBackend, WasmFormat};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum module size for TypeScript-compiled WASM components.
///
/// The `jco componentize` output includes the SpiderMonkey JS engine, which
/// produces binaries around 11 MiB. This exceeds the default 10 MiB
/// `max_module_size` on `ComponentBackend`, so we raise the limit to 15 MiB.
const TS_MAX_MODULE_SIZE: usize = 15 * 1024 * 1024;

/// Maximum memory for the TypeScript component runtime (16 MiB, same as default).
const TS_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// Load the TypeScript-compiled tool-gate guard WASM binary.
fn load_ts_guard_wasm() -> Vec<u8> {
    let path = format!(
        "{}/../../sdks/guard/chio-guard-ts/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Missing .wasm at {path}: {e}. Build with: \
             cd sdks/guard/chio-guard-ts && npm run build:example"
        )
    })
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

/// Load the TS guard into a `ComponentBackend` with raised module-size limits.
///
/// The 11 MiB jco output exceeds the default 10 MiB limit on `ComponentBackend`,
/// so we use `with_limits()` to raise `max_module_size` to 15 MiB. This is the
/// expected path for any Component Model guard that embeds a JS runtime.
fn load_ts_backend() -> Box<dyn WasmGuardAbi> {
    let wasm_bytes = load_ts_guard_wasm();
    let engine = create_shared_engine().unwrap();
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(TS_MAX_MEMORY, TS_MAX_MODULE_SIZE);
    backend.load_module(&wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_detected_as_component() {
    let bytes = load_ts_guard_wasm();
    let format = detect_wasm_format(&bytes).unwrap();
    assert!(
        matches!(format, WasmFormat::Component),
        "expected Component format, got {format:?}"
    );
}

// ---------------------------------------------------------------------------
// Loading via create_backend (dual-mode auto-detection)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_loads_via_create_backend() {
    let wasm_bytes = load_ts_guard_wasm();
    let engine = create_shared_engine().unwrap();

    // The default create_backend() has a 10 MiB module limit, but the TS guard
    // is ~11 MiB due to the embedded SpiderMonkey engine. Verify that
    // create_backend() rejects it with ModuleTooLarge, then load via
    // ComponentBackend with raised limits.
    let result = create_backend(engine.clone(), &wasm_bytes, 1_000_000_000, HashMap::new());
    assert!(
        result.is_err(),
        "expected create_backend() to reject 11 MiB module with default 10 MiB limit"
    );

    // Load with raised limits instead
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(TS_MAX_MEMORY, TS_MAX_MODULE_SIZE);
    backend.load_module(&wasm_bytes, 1_000_000_000).unwrap();
    assert_eq!(
        backend.backend_name(),
        "wasmtime-component",
        "expected wasmtime-component backend"
    );
}

// ---------------------------------------------------------------------------
// Verdict evaluation
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_allows_safe_tool() {
    let mut backend = load_ts_backend();
    let verdict = backend.evaluate(&make_request("read_file")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for safe tool 'read_file', got {verdict:?}"
    );
}

#[test]
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_denies_dangerous_tool() {
    let mut backend = load_ts_backend();
    let verdict = backend.evaluate(&make_request("dangerous_tool")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'dangerous_tool', got {verdict:?}"
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
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_denies_rm_rf() {
    let mut backend = load_ts_backend();
    let verdict = backend.evaluate(&make_request("rm_rf")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'rm_rf', got {verdict:?}"
    );
}

#[test]
#[ignore = "requires built TS guard wasm: cd sdks/guard/chio-guard-ts && npm run build:example"]
fn ts_guard_denies_drop_database() {
    let mut backend = load_ts_backend();
    let verdict = backend.evaluate(&make_request("drop_database")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'drop_database', got {verdict:?}"
    );
}
