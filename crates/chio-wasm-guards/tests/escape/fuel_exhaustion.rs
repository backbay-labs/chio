//! Escape class: fuel-budget exhaustion mid-call.
//!
//! Threat: a module whose `evaluate` body either spins in a tight loop
//! or executes more guest instructions than the configured fuel
//! ceiling. Without metering this would be a one-line denial-of-service
//! against the host.
//!
//! Defense: `wasmtime::Config::consume_fuel(true)` plus the
//! `set_fuel(fuel_limit)` call at evaluate-time. When fuel reaches zero
//! wasmtime traps; the host wraps the trap as
//! `WasmGuardError::FuelExhausted` (or a fall-through `Trap`).
//!
//! Owner: M05.P3.T2.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config, minimal_request};

/// A tight infinite loop must trip fuel-exhaustion within the bounded
/// fuel budget. The host surfaces this as either `FuelExhausted` (when
/// the wasmtime fuel-trap reaches the runtime's typed translator) or a
/// `Trap` with a fuel-related message; both are typed errors and both
/// keep the host process intact.
#[test]
fn infinite_loop_traps_with_typed_error() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (loop $forever (br $forever))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("infinite-loop module loads (the trap fires at evaluate)");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("infinite loop must exhaust fuel");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}

/// A counted loop running more iterations than the fuel ceiling can
/// service. Mirrors the more realistic "do too much work" attack vector.
#[test]
fn counted_loop_above_fuel_ceiling_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (local $i i32)
            (loop $L
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $L (i32.lt_s (local.get $i) (i32.const 100000000))))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("counted-loop module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("oversized counted loop must exhaust fuel");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}

/// A zero-fuel ceiling must trip the fuel trap on the very first guest
/// instruction. The host short-circuits this through the same typed
/// error path as a long-running module.
#[test]
fn zero_fuel_ceiling_traps_on_first_instruction() {
    let cfg = load_frozen_config();
    // Sanity: the frozen ceiling is non-zero -- this test deliberately
    // sets a separate ceiling of zero to drive the boundary case.
    assert!(cfg.escape_fuel_limit > 0);

    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, 0)
        .expect("zero-fuel module loads (fuel limit applies at evaluate)");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("zero fuel must trap immediately");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}
