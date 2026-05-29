//! Integration tests for the Go guard SDK round trip.
//!
//! Loads the Go-compiled `tool-gate.wasm` (built by TinyGo wasip2 + wasi-virt)
//! into the Chio host dual-mode WASM runtime and verifies correct Allow/Deny
//! verdicts.
//!
//! Proves the full SDK-to-host round trip: WIT type generation via
//! `wit-bindgen-go`, Go guard compiled via `tinygo build` (wasip2 target) with
//! `wasi-virt` stripping WASI imports, host auto-detection of Component Model
//! format, and correct verdict evaluation through `ComponentBackend`.
//!
//! The Go guard mirrors the Rust `tool-gate` example: it allows any tool not
//! on the deny list (`dangerous_tool`, `rm_rf`, `drop_database`) and returns a
//! deny reason containing "blocked by policy" for blocked tools.
//!
//! Go/TinyGo guards are much smaller than TypeScript or Python guards
//! (typically 500 KiB - 2 MiB after wasi-virt stripping), so they fit within
//! the default 10 MiB `max_module_size` on `ComponentBackend` and can be
//! loaded via `create_backend()` without raised limits.
//!
//! # Prerequisites
//!
//! Build the Go guard before running these tests. Requires TinyGo, wasi-virt,
//! wasm-tools, and wkg:
//!
//! ```bash
//! cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh
//! ```
//!
//! Install toolchain prerequisites:
//! - TinyGo: `brew install tinygo`
//! - wasi-virt: `cargo install --git https://github.com/bytecodealliance/wasi-virt`
//! - wasm-tools: `cargo install --locked wasm-tools@1.225.0`
//! - wkg: `cargo install wkg`

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::{create_backend, detect_wasm_format, ComponentBackend, WasmFormat};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum module size for Go-compiled WASM components.
///
/// TinyGo wasip2 + wasi-virt produces binaries around 500 KiB - 2 MiB,
/// well within the default 10 MiB limit. We set 10 MiB for consistency.
const GO_MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum memory for the Go component runtime (16 MiB, same as default).
const GO_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// Path to the Go-compiled tool-gate guard WASM binary.
fn go_guard_wasm_path() -> String {
    format!(
        "{}/../../sdks/guard/chio-guard-go/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    )
}

/// Returns true if the Go guard WASM binary exists on disk.
///
/// The TinyGo + wasi-virt build pipeline requires external toolchains that
/// may not be installed. Tests that need the binary are skipped when it is
/// absent.
fn go_guard_wasm_exists() -> bool {
    std::path::Path::new(&go_guard_wasm_path()).exists()
}

/// Load the Go-compiled tool-gate guard WASM binary.
///
/// Panics if the binary is not found. Call `go_guard_wasm_exists()` first
/// to check availability, or use the `skip_if_no_go_wasm!` macro.
fn load_go_guard_wasm() -> Vec<u8> {
    let path = go_guard_wasm_path();
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Missing .wasm at {path}: {e}. Build with: \
             cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh"
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

/// Load the Go guard into a `ComponentBackend` with default limits.
///
/// Unlike TS/Python guards, Go/TinyGo guards are small enough to fit within
/// the default 10 MiB module-size limit, so they can use standard limits.
fn load_go_backend() -> Box<dyn WasmGuardAbi> {
    let wasm_bytes = load_go_guard_wasm();
    let engine = create_shared_engine().unwrap();
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(GO_MAX_MEMORY, GO_MAX_MODULE_SIZE);
    backend.load_module(&wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

#[test]
fn go_guard_detected_as_component() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let bytes = load_go_guard_wasm();
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
fn go_guard_loads_via_create_backend() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let wasm_bytes = load_go_guard_wasm();
    let engine = create_shared_engine().unwrap();

    // Unlike TS/Python guards, Go guards are small (<10 MiB), so
    // create_backend() with default limits should succeed.
    let backend = create_backend(engine, &wasm_bytes, 1_000_000_000, HashMap::new());
    assert!(
        backend.is_ok(),
        "expected create_backend() to succeed for small Go guard, got: {:?}",
        backend.err()
    );
    let backend = backend.unwrap();
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
fn go_guard_allows_safe_tool() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let mut backend = load_go_backend();
    let verdict = backend.evaluate(&make_request("read_file")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for safe tool 'read_file', got {verdict:?}"
    );
}

#[test]
fn go_guard_denies_dangerous_tool() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let mut backend = load_go_backend();
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
fn go_guard_denies_rm_rf() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let mut backend = load_go_backend();
    let verdict = backend.evaluate(&make_request("rm_rf")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'rm_rf', got {verdict:?}"
    );
}

#[test]
fn go_guard_denies_drop_database() {
    if !go_guard_wasm_exists() {
        eprintln!(
            "SKIPPED: Go guard WASM not found at {}. \
             Build with: cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh",
            go_guard_wasm_path()
        );
        return;
    }
    let mut backend = load_go_backend();
    let verdict = backend.evaluate(&make_request("drop_database")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'drop_database', got {verdict:?}"
    );
}
