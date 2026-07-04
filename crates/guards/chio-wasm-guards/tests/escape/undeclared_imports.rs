//! Escape class: undeclared host imports.
//!
//! Threat: a malicious module declares an import outside the `chio.*`
//! namespace (e.g. `wasi_snapshot_preview1.fd_write`) in an attempt to
//! reach syscalls the host runtime never exposes.
//!
//! Defense: import-namespace check inside
//! `WasmtimeBackend::load_module` rejects any import whose module name
//! is not exactly `"chio"`. The check is fail-closed.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config};

/// Reject a module that imports `wasi_snapshot_preview1.fd_write`.
#[test]
fn rejects_wasi_fd_write_import() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("undeclared import must be rejected");

    match err {
        WasmGuardError::ImportViolation { module, name } => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("expected ImportViolation, got {other:?}"),
    }
}

/// Reject a module that imports an env-style host fn.
#[test]
fn rejects_env_namespace_import() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "env" "abort" (func $abort))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("env import must be rejected");

    match err {
        WasmGuardError::ImportViolation { module, name } => {
            assert_eq!(module, "env");
            assert_eq!(name, "abort");
        }
        other => panic!("expected ImportViolation, got {other:?}"),
    }
}

/// Reject a module that grafts a near-namespace ("chio_evil") in an
/// attempt to bypass an exact-match check that does prefix matching by
/// mistake. The import-namespace check does exact-string equality on the import module
/// name, so this must still trip ImportViolation.
#[test]
fn rejects_namespace_substring_attack() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "chio_evil" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("near-namespace import must be rejected");

    match err {
        WasmGuardError::ImportViolation { module, name } => {
            assert_eq!(module, "chio_evil");
            assert_eq!(name, "log");
        }
        other => panic!("expected ImportViolation, got {other:?}"),
    }
}
