//! Escape class: oversized linear memory (and oversized module blob).
//!
//! Threats:
//!   * A module whose `.wasm` blob exceeds `DEFAULT_MAX_MODULE_SIZE`.
//!     Defense: `WasmtimeBackend::load_module` rejects with
//!     `WasmGuardError::ModuleTooLarge` BEFORE compilation, so attacker
//!     payload size cannot amplify into wasmtime parse work.
//!   * A module that compiles fine but declares an initial linear-memory
//!     of more pages than the host's 16 MiB cap. Defense: per-Store
//!     `StoreLimits` with `trap_on_grow_failure(true)` traps at
//!     instantiate; the host wraps this as `WasmGuardError::Trap`.
//!
//! Owner: M05.P3.T2.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;

use super::common::{fresh_wasmtime_backend, load_frozen_config, minimal_request};

/// Reject a `.wasm` blob whose size exceeds `DEFAULT_MAX_MODULE_SIZE`.
#[test]
fn rejects_oversized_module_blob() {
    let cfg = load_frozen_config();
    // One byte over the cap. The first four bytes are still the WASM
    // magic so the rejection path runs after the size check (which is
    // the path under test), not before.
    let mut bytes = b"\0asm".to_vec();
    bytes.resize(cfg.max_module_size + 1, 0);

    let (_engine, mut backend) = fresh_wasmtime_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("oversized module must be rejected");

    match err {
        WasmGuardError::ModuleTooLarge { size, limit } => {
            assert_eq!(size, cfg.max_module_size + 1);
            assert_eq!(limit, cfg.max_module_size);
        }
        other => panic!("expected ModuleTooLarge, got {other:?}"),
    }
}

/// A module that declares 1024 initial linear-memory pages (~64 MiB),
/// well above the 16 MiB MAX_MEMORY_BYTES cap. Load succeeds (the cap
/// is a per-Store ResourceLimiter, not a Module-time check); `evaluate`
/// must trap at instantiation time and surface a typed `Trap`.
#[test]
fn declared_memory_above_cap_traps_at_instantiate() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1024)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("oversize-memory module loads -- the cap is enforced at instantiate");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("instantiation must fail when declared memory exceeds the host cap");

    match err {
        WasmGuardError::Trap(_) => {}
        other => panic!("expected Trap, got {other:?}"),
    }
}

/// 16 MiB = 16777216 bytes = 256 wasm pages. A module that declares
/// exactly 257 pages should still trap (one page above the cap).
#[test]
fn declared_memory_one_page_above_cap_traps() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 257)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("declared 257 pages loads at module level");

    let request = minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("declared-memory just-above-cap must trap");

    match err {
        WasmGuardError::Trap(_) => {}
        other => panic!("expected Trap, got {other:?}"),
    }
}
