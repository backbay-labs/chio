// Threat test for threat ID `tool_server_escape`.
//
// Threat: tool_server_escape (Tool server escape).
// Surfaces: kernel_to_tool.
//
// Coverage strategy: import the production
// `chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend`
// directly. The threat row's stable production defense is the
// runtime sandbox enforced by chio-wasm-guards: a malicious tool
// module signed by an attacker-controlled key still trips a typed
// `WasmGuardError` because the runtime layer rejects undeclared host
// imports, oversize declared memory, and fuel-budget overrun
// independently of the signing layer (the signing layer only
// certifies provenance, never content).
//
// The actual sandbox-escape containment lives in chio-wasm-guards, not
// in the signing or kernel dispatch layer. This conformance test
// pins the production runtime deny path that catches a malicious
// tool module at module-load and at evaluate-time. Three sub-vectors:
//
//   1. Undeclared host import. The module imports a host function
//      that is NOT in the chio.* allowed surface (`wasi_snapshot_preview1.fd_write`).
//      Production `load_module` MUST reject with
//      `WasmGuardError::ImportViolation` before any guest code runs.
//   2. Fuel-budget escape attempt. The module spins in a tight loop
//      to exhaust the host process's CPU budget. Production
//      `evaluate` MUST trap and return `WasmGuardError::FuelExhausted`
//      (or `Trap`) before the loop completes.
//   3. Round-trip sanity. A trivially benign module that exports
//      `evaluate` and returns `Allow` MUST verify successfully,
//      guarding against an over-rejecting deny path that would
//      silently classify all tool modules as escapes.
//
// Production call sites:
//   `crates/chio-wasm-guards/src/runtime.rs:1167`
//     (`WasmtimeBackend::load_module`).
//   `crates/chio-wasm-guards/src/runtime.rs:1202`
//     (`WasmtimeBackend::evaluate`).
//
// Cross-link: the chio-wasm-guards crate ships its own escape harness
// at `crates/chio-wasm-guards/tests/escape/` (8 named escape classes,
// all yielding typed `WasmGuardError`). This conformance test replays
// two of those escape classes through the same production backend so
// the threat row carries both file-existence and runtime evidence.
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-wasm-guards/src/runtime.rs`, locate the
// `validate_imports` (or equivalently named) helper used by
// `WasmtimeBackend::load_module` to reject non-`chio.*` imports.
// Replace its body with `Ok(())`. Re-run
// `cargo test -p chio-conformance --test threats -- tool_server_escape`
// and the
// `assert!(matches!(err, WasmGuardError::ImportViolation { .. }))`
// arm in `undeclared_host_import_rejected_at_load` MUST then fail
// because production now admits modules with arbitrary host imports.

use chio_wasm_guards::abi::{GuardRequest, WasmGuardAbi};
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

const ESCAPE_FUEL_LIMIT: u64 = 5_000_000;

fn minimal_request() -> GuardRequest {
    GuardRequest {
        tool_name: String::new(),
        server_id: String::new(),
        agent_id: "tool-server-escape-test".to_string(),
        arguments: serde_json::Value::Null,
        scopes: Vec::new(),
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

#[test]
fn threat_tool_server_escape_undeclared_host_import_rejected_at_load() {
    // covers: tool_server_escape
    //
    // Attacker scenario: an attacker controlling a "tool module"
    // imports the wasi `fd_write` host function in an attempt to
    // escape into raw stdout/stderr file descriptors via the
    // wasi-libc shim. Production MUST reject this at module-load
    // before any guest code runs.
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };

    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    let err = match backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        Ok(()) => panic!(
            "WasmtimeBackend::load_module MUST reject undeclared host \
             imports (escape via wasi_snapshot_preview1.fd_write); got Ok"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::ImportViolation { module, name } => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("expected WasmGuardError::ImportViolation on wasi import, got {other:?}"),
    }
}

#[test]
fn threat_tool_server_escape_fuel_exhaustion_attack_traps() {
    // covers: tool_server_escape
    //
    // Attacker scenario: the tool module loads cleanly but its
    // `evaluate` body spins in an infinite loop to denial-of-service
    // the host. Production fuel metering MUST trap with
    // `WasmGuardError::FuelExhausted` (or a fuel-related `Trap`)
    // before the host loses liveness.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (loop $forever (br $forever))
            (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };

    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    if let Err(err) = backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        panic!(
            "infinite-loop module MUST load (the trap fires at evaluate), \
             got load-time error {err:?}"
        );
    }
    let err = match backend.evaluate(&minimal_request()) {
        Ok(verdict) => panic!(
            "WasmtimeBackend::evaluate MUST trap on a fuel-escape module; \
             got verdict {verdict:?}"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or fuel-related Trap, got {other:?}"),
    }
}

#[test]
fn threat_tool_server_escape_benign_module_round_trips() {
    // covers: tool_server_escape (sanity)
    //
    // Sanity arm: a benign module that exports `evaluate` and
    // returns `0` (Allow) MUST load and run without error. This
    // guards against an over-rejecting deny path that would silently
    // classify all tool modules as escapes.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };
    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    if let Err(err) = backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        panic!("benign module MUST load (over-rejecting); got {err:?}");
    }
    if let Err(err) = backend.evaluate(&minimal_request()) {
        panic!(
            "benign module MUST evaluate without error (over-rejecting); \
             got {err:?}"
        );
    }
}
