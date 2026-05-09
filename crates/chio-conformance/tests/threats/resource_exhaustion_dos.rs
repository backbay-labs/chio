// Threat test for threat ID `resource_exhaustion_dos`.
//
// Threat: resource_exhaustion_dos (Resource exhaustion denial of service).
// Surfaces: native_chio, hosted_mcp, trust_control, kernel_to_tool.
//
// Coverage strategy: import the production
// `chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend`
// directly and drive the production fuel-budget enforcement surface
// with attacker inputs that ATTEMPT to consume more CPU than the
// fuel ceiling allows. The fuel-budget admit path (set during
// `WasmtimeBackend::load_module(bytes, fuel_limit)` and consumed by
// `evaluate`) is the production decision the threat row targets:
// without it, a single tool-or-guard module could starve every other
// tenant on the shared host. Production traps with
// `WasmGuardError::FuelExhausted` (or a fuel-related `Trap`) before
// the host loses liveness.
//
// This test also retains the file-existence + named-fixture pins
// against `crates/chio-wasm-guards/tests/escape/` so a regression in
// the per-class escape harness still trips this conformance row.
// Both kinds of evidence are needed: the production deny-asserting
// arms below catch a regression in the runtime enforcement, and the
// fixture pins catch a stealth removal of the escape harness that
// the threat-coverage gate (`bash scripts/check-threat-coverage.sh`)
// otherwise has no way to detect.
//
// Production call sites:
//   `crates/chio-wasm-guards/src/runtime.rs:1167`
//     (`WasmtimeBackend::load_module`).
//   `crates/chio-wasm-guards/src/runtime.rs:1202`
//     (`WasmtimeBackend::evaluate`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-wasm-guards/src/runtime.rs`, locate the fuel-set
// call inside `WasmtimeBackend::evaluate` (the
// `store.set_fuel(self.fuel_limit)` line in the wasmtime backend
// path). Replace the stored fuel limit with `u64::MAX` (effectively
// uncapped). Re-run
// `cargo test -p chio-conformance --test threats -- resource_exhaustion_dos`
// and the `assert!(matches!(err, WasmGuardError::FuelExhausted { .. }
// | WasmGuardError::Trap(_)))` arm in
// `infinite_loop_attack_traps_under_fuel_cap` MUST then deadlock or
// fail because production no longer enforces the fuel cap.

use std::{fs, path::PathBuf};

use chio_wasm_guards::abi::{GuardRequest, WasmGuardAbi};
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

const ESCAPE_FUEL_LIMIT: u64 = 5_000_000;

fn minimal_request() -> GuardRequest {
    GuardRequest {
        tool_name: String::new(),
        server_id: String::new(),
        agent_id: "resource-exhaustion-test".to_string(),
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
fn threat_resource_exhaustion_dos_infinite_loop_attack_traps_under_fuel_cap() {
    // covers: resource_exhaustion_dos
    //
    // Attacker scenario: a tool-or-guard module loaded into the
    // shared runtime spins in a tight infinite loop to deny CPU to
    // every other tenant. Production fuel metering MUST trap before
    // the host loses liveness.
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
            "production evaluate MUST trap on a CPU-exhaustion module; \
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
fn threat_resource_exhaustion_dos_zero_fuel_ceiling_traps_immediately() {
    // covers: resource_exhaustion_dos
    //
    // Attacker scenario boundary case: the host operator dials the
    // fuel ceiling to zero (an admin operating under attack pressure
    // who wants to fail-closed on every guest call). Production MUST
    // trap on the very first guest instruction; any guest progress
    // would mean the fuel ceiling was silently relaxed.
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
    if let Err(err) = backend.load_module(&bytes, 0) {
        panic!(
            "minimal module MUST load even with zero fuel ceiling; \
             got load-time error {err:?}"
        );
    }
    let err = match backend.evaluate(&minimal_request()) {
        Ok(verdict) => panic!(
            "production evaluate MUST trap with zero fuel ceiling; \
             got verdict {verdict:?}"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!(
            "expected FuelExhausted or fuel-related Trap with zero fuel \
             ceiling, got {other:?}"
        ),
    }
}

/// Pairs of (escape-class fixture filename, evidence needles) that the
/// runtime exhaustion harness must keep in-tree. The needles are stable
/// test-function names that must remain inside the fixture; a missing
/// needle means the fixture has been gutted into a no-op stub and the
/// threat ID has lost its supplementary harness coverage.
const ESCAPE_CLASS_EVIDENCE: &[(&str, &[&str])] = &[
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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("../chio-wasm-guards/tests/escape");
    match dir.canonicalize() {
        Ok(resolved) => resolved,
        Err(err) => panic!("resolve wasm-guard escape directory: {err}"),
    }
}

#[test]
fn threat_resource_exhaustion_dos_escape_class_fixtures_remain_in_tree() {
    // covers: resource_exhaustion_dos
    //
    // The chio-wasm-guards escape harness is the supplementary
    // runtime evidence for this threat row: each cited fixture
    // exercises a different vector (CPU, declared memory, stack,
    // table growth) of resource exhaustion. The deny-asserting arms
    // above pin the CPU/fuel side directly; this assertion catches a
    // stealth removal of the named harness fixtures so the threat-
    // coverage gate does not silently report green when only the
    // CPU vector remains.
    let escape_dir = escape_dir();
    for (fixture, needles) in ESCAPE_CLASS_EVIDENCE {
        let path = escape_dir.join(fixture);
        assert!(
            path.is_file(),
            "expected wasm-guard escape fixture {} to exist; \
             resource_exhaustion_dos is covered by the runtime exhaustion harness",
            path.display()
        );
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(err) => panic!("read {}: {err}", path.display()),
        };
        assert!(
            raw.contains("#[test]"),
            "wasm-guard escape fixture {} must declare at least one #[test] \
             so resource_exhaustion_dos retains a runnable exercise",
            path.display()
        );
        for needle in *needles {
            assert!(
                raw.contains(needle),
                "wasm-guard escape fixture {} must mention test {needle:?} \
                 so resource_exhaustion_dos does not silently regress",
                path.display()
            );
        }
    }
}

#[test]
fn threat_resource_exhaustion_dos_class_set_is_pinned() {
    // covers: resource_exhaustion_dos
    //
    // Pin the cited escape-class set so a future shrink of the
    // runtime evidence list fails this test rather than silently
    // reducing coverage.
    let fixtures: std::collections::BTreeSet<&str> = ESCAPE_CLASS_EVIDENCE
        .iter()
        .map(|(fixture, _)| *fixture)
        .collect();
    let expected: std::collections::BTreeSet<&str> = [
        "fuel_exhaustion.rs",
        "oversize_memory.rs",
        "deep_recursion.rs",
        "table_grow.rs",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        fixtures, expected,
        "resource_exhaustion_dos must cite exactly the four pinned wasm-guard escape fixtures"
    );
}
