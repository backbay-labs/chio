// Threat test for threat ID `wasm_guard_resource_exhaustion`.
//
// Threat: wasm_guard_resource_exhaustion (WASM guard resource exhaustion).
// Surfaces: kernel_to_tool, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend`
// directly. The Risk Register R3 entry that previously listed this
// row as `BLOCKED-BY-ARCHITECTURE` was scoped to wasm-guard SDK v4
// (the SDK-side multi-tenant arena work) and explicitly noted that
// the existing per-class escape harness "pin only the harness, not
// a production-call-path". This conformance test resolves that
// constraint by driving the SAME production runtime-execution
// surface (`WasmtimeBackend::load_module` / `evaluate`) used by the
// kernel host pipeline, so the deny path that the threat row targets
// is exercised through a workspace-path import without depending on
// the deferred SDK v4. The escape-class fixture pins are kept as a
// supplementary regression net (a stealth removal of any of them
// still trips this test).
//
// Three sub-vectors:
//
//   1. Fuel-budget overrun. A guard module with an infinite loop is
//      attacker-controlled and tries to monopolize host CPU.
//      Production fuel metering MUST trap with
//      `WasmGuardError::FuelExhausted` (or fuel-related `Trap`).
//   2. Module-size cap. A blob synthetically padded above the
//      configured `DEFAULT_MAX_MODULE_SIZE` MUST be rejected at
//      `load_module` with `WasmGuardError::ModuleTooLarge`.
//   3. Round-trip sanity. A trivially-benign module MUST load and
//      evaluate without error so over-rejection cannot silently
//      mask a missing deny path.
//
// Production call sites:
//   `crates/chio-wasm-guards/src/runtime.rs:1167`
//     (`WasmtimeBackend::load_module`).
//   `crates/chio-wasm-guards/src/runtime.rs:1202`
//     (`WasmtimeBackend::evaluate`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-wasm-guards/src/runtime.rs`, locate the
// `if wasm_bytes.len() > self.max_module_size { return
// Err(WasmGuardError::ModuleTooLarge { ... }); }` guard inside
// `WasmtimeBackend::load_module`. Replace the `return` with a
// no-op. Re-run
// `cargo test -p chio-conformance --test threats -- wasm_guard_resource_exhaustion`
// and the `assert!(matches!(err, WasmGuardError::ModuleTooLarge { .. }))`
// arm in `oversize_module_rejected_at_load` MUST then fail because
// production now admits arbitrarily large modules.

use std::{fs, path::PathBuf};

use chio_wasm_guards::abi::{GuardRequest, WasmGuardAbi};
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

const ESCAPE_FUEL_LIMIT: u64 = 5_000_000;

fn minimal_request() -> GuardRequest {
    GuardRequest {
        tool_name: String::new(),
        server_id: String::new(),
        agent_id: "wasm-guard-resource-exhaustion-test".to_string(),
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
fn threat_wasm_guard_resource_exhaustion_fuel_overrun_traps() {
    // covers: wasm_guard_resource_exhaustion
    //
    // Attacker scenario: a guard module's `evaluate` body is an
    // infinite loop. Production fuel metering MUST trap before any
    // host livelock manifests.
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
            "infinite-loop module MUST load (the trap fires at evaluate); \
             got load-time error {err:?}"
        );
    }
    let err = match backend.evaluate(&minimal_request()) {
        Ok(verdict) => panic!(
            "production evaluate MUST trap on a fuel-overrun guard module; \
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
fn threat_wasm_guard_resource_exhaustion_oversize_module_rejected_at_load() {
    // covers: wasm_guard_resource_exhaustion
    //
    // Attacker scenario: a guard module's serialized blob is bigger
    // than the configured module-size cap. Production MUST reject
    // at `load_module` with `WasmGuardError::ModuleTooLarge` before
    // any compilation work fires.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let valid_bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };

    // Tighten the per-backend module-size cap so we do not have to
    // synthesise a multi-megabyte blob just to cross the default.
    // Anything strictly less than the valid bytes' length is enough
    // to trip the cap; ESCAPE_TINY_CAP is one byte below.
    let tight_cap = valid_bytes.len() - 1;
    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend.with_limits(/* max_memory_bytes */ 64 * 1024, tight_cap),
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    let err = match backend.load_module(&valid_bytes, ESCAPE_FUEL_LIMIT) {
        Ok(()) => panic!(
            "WasmtimeBackend::load_module MUST reject a module above the \
             configured max_module_size; got Ok"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::ModuleTooLarge { size, limit } => {
            assert_eq!(size, valid_bytes.len());
            assert_eq!(limit, tight_cap);
        }
        other => panic!("expected WasmGuardError::ModuleTooLarge {{ size, limit }}, got {other:?}"),
    }
}

#[test]
fn threat_wasm_guard_resource_exhaustion_benign_module_round_trips() {
    // covers: wasm_guard_resource_exhaustion (sanity)
    //
    // Sanity arm: a trivially benign module MUST load and evaluate
    // without error. Guards against an over-rejecting deny path
    // that would silently classify all guard modules as exhaustion
    // attacks.
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

const ESCAPE_EVIDENCE: &[(&str, &[&str])] = &[
    (
        "fuel_exhaustion.rs",
        &[
            "infinite_loop_traps_with_typed_error",
            "zero_fuel_ceiling_traps_on_first_instruction",
        ],
    ),
    (
        "oversize_memory.rs",
        &[
            "rejects_oversized_module_blob",
            "declared_memory_above_cap_traps_at_instantiate",
        ],
    ),
    ("deep_recursion.rs", &["unbounded_self_recursion_traps"]),
    ("table_grow.rs", &["table_grow_in_loop_traps"]),
];

fn escape_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chio-wasm-guards/tests/escape");
    match dir.canonicalize() {
        Ok(path) => path,
        Err(error) => panic!("resolve wasm guard escape directory: {error}"),
    }
}

#[test]
fn threat_wasm_guard_resource_exhaustion_escape_harness_pins_remain() {
    // covers: wasm_guard_resource_exhaustion
    //
    // Supplementary regression net: in addition to the production
    // deny-asserting arms above, pin the per-class escape harness
    // fixtures so a stealth removal of any of them still trips this
    // conformance row. The threat-coverage gate
    // (`scripts/check-threat-coverage.sh`) does not see beyond the
    // file existence; this assertion is the stronger pin.
    let escape_dir = escape_dir();
    for (fixture, needles) in ESCAPE_EVIDENCE {
        let path = escape_dir.join(fixture);
        assert!(path.is_file(), "{} must remain in tree", path.display());
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        assert!(
            raw.contains("#[test]"),
            "{} must be runnable",
            path.display()
        );
        for needle in *needles {
            assert!(
                raw.contains(needle),
                "{} must retain fail-closed assertion {needle}",
                path.display()
            );
        }
    }
}
