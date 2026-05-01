//! Escape class: host re-entry abuse.
//!
//! Threat: a module that imports a permitted `chio.*` host function
//! (e.g. `chio.log`) and calls it in a tight loop, attempting to spin
//! the host's tracing / metrics path or starve the runtime through
//! cross-boundary churn. Distinct from the undeclared-imports class:
//! the imports themselves are legitimate; the abuse vector is call
//! frequency.
//!
//! Defense: every host call is fuel-metered, so a million `chio.log`
//! calls inside `evaluate` exhaust fuel before the host's log buffer
//! grows unbounded (the buffer also has its own MAX_LOG_ENTRIES cap).
//! The `chio.log` payload-pointer interpretation is bounds-checked at
//! the host side; out-of-bounds pointers are silently dropped (level
//! out of range causes the log call to return without recording).

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config, minimal_request};

/// Tight `chio.log`-call loop: 1M iterations exhaust fuel within the
/// frozen ceiling.
#[test]
fn chio_log_call_storm_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "chio" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (local $i i32)
            (loop $L
              (call $log (i32.const 0) (i32.const 0) (i32.const 0))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $L (i32.lt_s (local.get $i) (i32.const 1000000))))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("host-reentry module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("host-call storm must trap");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}

/// `chio.get_time_unix_secs` storm. This host fn returns immediately
/// without copying anything into guest memory; its abuse vector is
/// purely call-frequency.
#[test]
fn chio_get_time_call_storm_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "chio" "get_time_unix_secs" (func $time (result i64)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (local $i i32)
            (loop $L
              (drop (call $time))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $L (i32.lt_s (local.get $i) (i32.const 1000000))))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("get-time storm module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("get-time storm must trap");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}

/// `chio.log` with deliberately out-of-bounds pointer parameters. The
/// host slices guest memory; out-of-bounds reads must surface as a
/// typed error rather than reading host process memory or panicking.
#[test]
fn chio_log_out_of_bounds_pointers_does_not_panic() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "chio" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (call $log (i32.const 0) (i32.const 999999999) (i32.const 999999999))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("oob-log module loads");

    let request = minimal_request();
    // Either the host slice silently truncates (Allow verdict from the
    // implicit i32.const 0 return) or surfaces a typed Trap. Anything
    // other than a panic is acceptable; the post-condition is "host
    // process intact".
    let _ = backend.evaluate(&request);
}
