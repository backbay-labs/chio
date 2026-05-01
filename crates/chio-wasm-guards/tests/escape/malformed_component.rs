//! Escape class: malformed component-model encoding.
//!
//! Threat: a `.wasm` blob that carries the component-model magic
//! preamble but follows it with a structurally-broken section header
//! (unknown section id, truncated payload, unsupported layer/version).
//! The host's Component Model parser must reject it without panicking,
//! reading uninitialised memory, or escaping the process sandbox.
//!
//! Defense: `ComponentBackend::load_module` defers to
//! `wasmtime::component::Component::new`, which surfaces parse errors
//! as wasmtime errors that the host wraps as
//! `WasmGuardError::Compilation`.
//!
//! Fixtures live at `tests/escape/fixtures/`; see that directory's
//! README for the byte-by-byte breakdown.

use std::path::PathBuf;
use std::sync::Arc;

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::component::ComponentBackend;
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::host::create_shared_engine;

use super::common::load_frozen_config;

fn read_fixture(name: &str) -> Vec<u8> {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set under cargo test");
    let path = PathBuf::from(&manifest_dir)
        .join("tests/escape/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()))
}

fn fresh_component_backend() -> ComponentBackend {
    let engine = create_shared_engine().expect("create_shared_engine");
    ComponentBackend::with_engine(Arc::clone(&engine))
}

/// Component preamble + invalid section id 0xff + 4 bytes of garbage.
/// `wasmtime::component::Component::new` rejects this with a parse
/// error; the host wraps as `Compilation`.
#[test]
fn truncated_section_yields_compilation_error() {
    let cfg = load_frozen_config();
    let bytes = read_fixture("malformed_component_truncated.wasm");
    let mut backend = fresh_component_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("malformed component must be rejected");

    match err {
        WasmGuardError::Compilation(_) => {}
        other => panic!("expected Compilation, got {other:?}"),
    }
}

/// Layer/version byte pattern that does not match any wasmtime-supported
/// component-model encoding. Surfaces as Compilation.
#[test]
fn wrong_version_yields_compilation_error() {
    let cfg = load_frozen_config();
    let bytes = read_fixture("malformed_component_wrong_version.wasm");
    let mut backend = fresh_component_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("unknown component version must be rejected");

    match err {
        WasmGuardError::Compilation(_) => {}
        other => panic!("expected Compilation, got {other:?}"),
    }
}

/// A blob whose layer field looks core-module-like but whose body is
/// component-shaped. Either parse path rejects it.
#[test]
fn zero_layer_with_component_body_is_rejected() {
    let cfg = load_frozen_config();
    let bytes = read_fixture("malformed_component_zero_layer.wasm");
    let mut backend = fresh_component_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("layer-mismatched module must be rejected");

    match err {
        WasmGuardError::Compilation(_) => {}
        other => panic!("expected Compilation, got {other:?}"),
    }
}

/// Empty input. The component parser reports a structural error rather
/// than reading past the end of the buffer.
#[test]
fn empty_input_yields_compilation_error() {
    let cfg = load_frozen_config();
    let bytes: Vec<u8> = Vec::new();
    let mut backend = fresh_component_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("empty input must be rejected");

    match err {
        WasmGuardError::Compilation(_) => {}
        other => panic!("expected Compilation, got {other:?}"),
    }
}
