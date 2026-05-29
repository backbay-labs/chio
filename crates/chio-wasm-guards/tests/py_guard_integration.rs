//! Integration tests for the Python guard SDK round trip.
//!
//! Loads the Python-compiled `tool-gate.wasm` (built by `componentize-py`)
//! into the Chio host dual-mode WASM runtime and verifies correct Allow/Deny
//! verdicts.
//!
//! Proves the full SDK-to-host round trip: WIT type generation,
//! Python guard compiled via `componentize-py` with `--stub-wasi`, host
//! auto-detection of Component Model format, and correct verdict evaluation
//! through `ComponentBackend`.
//!
//! The Python guard mirrors the Rust `tool-gate` example: it allows any
//! tool not on the deny list (`dangerous_tool`, `rm_rf`, `drop_database`) and
//! returns a deny reason containing "blocked by policy" for blocked tools.
//!
//! # Prerequisites
//!
//! Build the Python guard before running these tests:
//!
//! ```bash
//! cd sdks/guard/chio-guard-py && ./scripts/build-guard.sh
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

/// Maximum module size for Python-compiled WASM components.
///
/// The `componentize-py` output embeds the CPython interpreter, which
/// produces binaries around 10-35 MiB. The current build produces ~18 MiB.
/// This exceeds the default 10 MiB `max_module_size` on `ComponentBackend`,
/// so we raise the limit to 40 MiB for safety margin.
const PY_MAX_MODULE_SIZE: usize = 40 * 1024 * 1024;

/// Maximum memory for the Python component runtime (64 MiB).
///
/// CPython needs more memory than SpiderMonkey for interpreter
/// initialization, so we raise the default 16 MiB limit.
const PY_MAX_MEMORY: usize = 64 * 1024 * 1024;

/// Load the Python-compiled tool-gate guard WASM binary.
fn load_py_guard_wasm() -> Vec<u8> {
    let path = format!(
        "{}/../../sdks/guard/chio-guard-py/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Missing .wasm at {path}: {e}. Build with: \
             cd sdks/guard/chio-guard-py && ./scripts/build-guard.sh"
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

/// Load the Python guard into a `ComponentBackend` with raised limits.
///
/// The ~18 MiB componentize-py output exceeds the default 10 MiB limit on
/// `ComponentBackend`, so we use `with_limits()` to raise `max_module_size`
/// to 40 MiB and memory to 64 MiB (CPython needs more memory than
/// SpiderMonkey for interpreter initialization).
fn load_py_backend() -> Box<dyn WasmGuardAbi> {
    let wasm_bytes = load_py_guard_wasm();
    let engine = create_shared_engine().unwrap();
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(PY_MAX_MEMORY, PY_MAX_MODULE_SIZE);
    backend.load_module(&wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

#[test]
fn py_guard_detected_as_component() {
    let bytes = load_py_guard_wasm();
    let format = detect_wasm_format(&bytes).unwrap();
    assert!(
        matches!(format, WasmFormat::Component),
        "expected Component format, got {format:?}"
    );
}

// ---------------------------------------------------------------------------
// Loading via ComponentBackend with raised limits
// ---------------------------------------------------------------------------

#[test]
fn py_guard_loads_via_component_backend() {
    let wasm_bytes = load_py_guard_wasm();
    let engine = create_shared_engine().unwrap();

    // The default create_backend() has a 10 MiB module limit, but the Python
    // guard is ~18 MiB due to the embedded CPython interpreter. Verify that
    // create_backend() rejects it, then load via ComponentBackend with raised
    // limits.
    let result = create_backend(engine.clone(), &wasm_bytes, 1_000_000_000, HashMap::new());
    assert!(
        result.is_err(),
        "expected create_backend() to reject ~18 MiB module with default 10 MiB limit"
    );

    // Load with raised limits instead
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(PY_MAX_MEMORY, PY_MAX_MODULE_SIZE);
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
fn py_guard_allows_safe_tool() {
    let mut backend = load_py_backend();
    let verdict = backend.evaluate(&make_request("read_file")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for safe tool 'read_file', got {verdict:?}"
    );
}

#[test]
fn py_guard_denies_dangerous_tool() {
    let mut backend = load_py_backend();
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
fn py_guard_denies_rm_rf() {
    let mut backend = load_py_backend();
    let verdict = backend.evaluate(&make_request("rm_rf")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'rm_rf', got {verdict:?}"
    );
}

#[test]
fn py_guard_denies_drop_database() {
    let mut backend = load_py_backend();
    let verdict = backend.evaluate(&make_request("drop_database")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'drop_database', got {verdict:?}"
    );
}
