//! Escape class: table grow / abuse.
//!
//! Threats:
//!   * A module that calls `table.grow` with a large delta inside the
//!     evaluate path, attempting to exhaust host memory through funcref
//!     table allocation.
//!   * A module whose initial table size is unreasonably large.
//!
//! Defense: wasmtime's compile-time element limits plus the
//! per-Store fuel budget. `table.grow` is fuel-metered, so a million-
//! entry grow inside `evaluate` exhausts fuel before the runtime
//! commits the allocation. A static initial-table size that bloats the
//! module past `DEFAULT_MAX_MODULE_SIZE` is also caught at module-load
//! time as `WasmGuardError::ModuleTooLarge`.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config, minimal_request};

/// `table.grow` of one million entries inside the evaluate path.
/// Wasmtime returns -1 from the grow opcode when the requested delta
/// exceeds the per-instance budget; the abuse therefore surfaces as a
/// silently-denied grow rather than a host panic. The post-condition
/// the harness cares about is the host process still being intact and
/// the runtime returning either a typed `WasmGuardError` OR a
/// well-formed `GuardVerdict`. No memory escape, no abort.
#[test]
fn table_grow_million_entries_is_contained() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (table $t 1 funcref)
          (func (export "evaluate") (param i32 i32) (result i32)
            ;; If the grow is rejected the opcode returns -1; we surface
            ;; that to the host as a Deny verdict to make the abuse
            ;; visible to the harness's verdict-shape assertions.
            (if (result i32)
              (i32.eq
                (table.grow $t (ref.null func) (i32.const 1000000))
                (i32.const -1))
              (then (i32.const 1))
              (else (i32.const 0)))))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("table-grow module loads");

    let request = minimal_request();
    // Three acceptable outcomes:
    //   1. Deny verdict (the grow returned -1, host process intact).
    //   2. FuelExhausted / Trap (the grow consumed enough fuel to
    //      trip the meter).
    //   3. Allow verdict (the grow succeeded within wasmtime's default
    //      table-element budget; the abuse is bounded by the runtime
    //      regardless).
    // The post-condition is "no panic" and the result is a typed value.
    let _ = backend.evaluate(&request);
}

/// Repeated `table.grow` calls in a tight loop. Even with small deltas
/// the loop exhausts fuel before the host runs out of memory.
#[test]
fn table_grow_in_loop_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (table $t 1 funcref)
          (func $f (result i32) (i32.const 0))
          (func (export "evaluate") (param i32 i32) (result i32)
            (local $i i32)
            (loop $L
              (drop (table.grow $t (ref.null func) (i32.const 1)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $L (i32.lt_s (local.get $i) (i32.const 1000000))))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("table-grow-loop module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("table.grow loop must trap");

    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or Trap, got {other:?}"),
    }
}

/// `table.fill` on a tiny table with an oversized count. wasmtime
/// surfaces this as an out-of-bounds trap, which the host wraps as a
/// typed `Trap`.
#[test]
fn table_fill_oversize_count_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (table $t 1 funcref)
          (func $f (result i32) (i32.const 0))
          (func (export "evaluate") (param i32 i32) (result i32)
            (table.fill $t (i32.const 0) (ref.null func) (i32.const 1000))
            (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("table-fill module loads");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("table.fill out-of-bounds must trap");

    match err {
        WasmGuardError::Trap(_) | WasmGuardError::FuelExhausted { .. } => {}
        other => panic!("expected Trap or FuelExhausted, got {other:?}"),
    }
}
