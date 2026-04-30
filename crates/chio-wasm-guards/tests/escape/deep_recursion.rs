//! Escape class: stack overflow via deep recursion.
//!
//! Threat: a module whose `evaluate` body recurses without a base
//! case, attempting to overflow the native stack and either crash the
//! host process or escape to undefined behavior.
//!
//! Defense: wasmtime guards the guest stack via a configured stack
//! limit; recursion past that limit traps with a stack-overflow trap.
//! The host wraps it as `WasmGuardError::Trap`. Fuel metering is the
//! second layer: even unbounded recursion costs fuel per call, so
//! fuel-exhaustion may fire first.
//!
//! Owner: M05.P3.T3.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config, minimal_request};

/// Self-recursive `evaluate` with no base case. Either
/// stack-overflow trap (via the guest stack guard) or fuel-exhaustion
/// trap fires first; both surface as a typed error.
#[test]
fn unbounded_self_recursion_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func $rec (export "evaluate") (param i32 i32) (result i32)
            (drop (call $rec (local.get 0) (local.get 1)))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("recursion module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("unbounded recursion must trap");

    match err {
        WasmGuardError::Trap(_) | WasmGuardError::FuelExhausted { .. } => {}
        other => panic!("expected Trap or FuelExhausted, got {other:?}"),
    }
}

/// Mutually-recursive call chain (`a -> b -> a`). Same expected
/// outcome as the self-recursion case; this fixture exists to confirm
/// the trap path covers indirect recursion as well.
#[test]
fn mutual_recursion_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func $a (param i32 i32) (result i32)
            (drop (call $b (local.get 0) (local.get 1)))
            (i32.const 0))
          (func $b (param i32 i32) (result i32)
            (drop (call $a (local.get 0) (local.get 1)))
            (i32.const 0))
          (func (export "evaluate") (param i32 i32) (result i32)
            (call $a (local.get 0) (local.get 1))))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("mutual-recursion module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("mutual recursion must trap");

    match err {
        WasmGuardError::Trap(_) | WasmGuardError::FuelExhausted { .. } => {}
        other => panic!("expected Trap or FuelExhausted, got {other:?}"),
    }
}

/// Recursion with large per-frame locals. The combination of frame
/// size and unbounded depth may stress the guest stack faster than a
/// minimal-frame recursion; the typed-error post-condition is the
/// same.
#[test]
fn fat_frame_recursion_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func $rec (export "evaluate") (param i32 i32) (result i32)
            (local $a i64) (local $b i64) (local $c i64) (local $d i64)
            (local $e i64) (local $f i64) (local $g i64) (local $h i64)
            (drop (call $rec (local.get 0) (local.get 1)))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("fat-frame recursion module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("fat-frame recursion must trap");

    match err {
        WasmGuardError::Trap(_) | WasmGuardError::FuelExhausted { .. } => {}
        other => panic!("expected Trap or FuelExhausted, got {other:?}"),
    }
}
