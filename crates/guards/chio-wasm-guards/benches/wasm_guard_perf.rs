#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Performance benchmarks for the chio-wasm-guards WASM guard runtime.
//!
//! Run with:
//!   cargo bench --bench wasm_guard_perf --features wasmtime-runtime
//!
//! Benchmark groups:
//! - wasm_guards/compilation: Module::new() compilation time for 50 KiB and 5 MiB WAT modules
//! - wasm_guards/instantiation: Linker::instantiate() per-call overhead with pre-compiled module
//! - wasm_guards/evaluate_latency: Full production hot-path latency (trivial Allow + realistic Deny)
//! - wasm_guards/fuel_overhead: Fuel metering enabled vs disabled overhead comparison
//! - wasm_guards/resource_limiter: ResourceLimiter trap validation under adversarial allocation

use std::collections::HashMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wasmtime::{Engine, Linker, Module, Store};

use chio_wasm_guards::abi::GuardRequest;
use chio_wasm_guards::host::{create_shared_engine, register_host_functions, WasmHostState};

// ---------------------------------------------------------------------------
// WAT module builder helpers
// ---------------------------------------------------------------------------

/// Returns a minimal WAT module that imports all three chio.* host functions,
/// exports memory (1 page) and `evaluate` returning VERDICT_ALLOW (0).
/// Approximately 200 bytes compiled. Used for instantiation benchmarks.
fn build_trivial_guard_wat() -> &'static str {
    r#"(module
    (import "chio" "log" (func $log (param i32 i32 i32)))
    (import "chio" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "chio" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 1)
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0)
    )
)"#
}

/// Builds a WAT module with a `(data ...)` segment padded with null bytes to
/// approximate the target compiled binary size.
///
/// The data segment uses `\00` bytes repeated to reach the target size minus
/// approximate WAT overhead for imports/exports/header (~300 bytes). Memory
/// pages are sized to fit the data segment.
///
/// Note: WAT data segments produce roughly 1:1 binary size for the data
/// payload. Accept approximate sizes within ~10% of target.
fn build_sized_wat(target_binary_bytes: usize) -> String {
    let padding_size = target_binary_bytes.saturating_sub(300);
    let padding = "\\00".repeat(padding_size);
    let pages = (target_binary_bytes / 65536) + 1;
    format!(
        r#"(module
    (import "chio" "log" (func $log (param i32 i32 i32)))
    (import "chio" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "chio" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") {pages})
    (data (i32.const 0) "{padding}")
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0)
    )
)"#
    )
}

// ---------------------------------------------------------------------------
// Benchmark group 1: Module compilation (WGBENCH-01)
// ---------------------------------------------------------------------------

/// Benchmarks Module::new() compilation time for representative guard sizes.
///
/// - 50 KiB module: validates against the 50ms compilation threshold from
///   docs/guards/05-V1-DECISION.md.
/// - 5 MiB module: documents large-module compilation time (may exceed 50ms;
///   that is expected for very large modules).
fn bench_module_compilation(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();

    let small_wat = build_sized_wat(50 * 1024); // ~50 KiB target
    let large_wat = build_sized_wat(5 * 1024 * 1024); // ~5 MiB target

    let mut group = c.benchmark_group("wasm_guards/compilation");

    group.bench_function("50kib_module", |b| {
        b.iter(|| {
            let _ = black_box(Module::new(
                black_box(&engine),
                black_box(small_wat.as_bytes()),
            ));
        });
    });

    // Reduce sample size for the slow 5 MiB compilation
    group.sample_size(10);
    group.bench_function("5mib_module", |b| {
        b.iter(|| {
            let _ = black_box(Module::new(
                black_box(&engine),
                black_box(large_wat.as_bytes()),
            ));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 2: Instantiation overhead (WGBENCH-02)
// ---------------------------------------------------------------------------

/// Benchmarks pure `linker.instantiate()` per-call overhead with a
/// pre-compiled trivial guard module.
///
/// The setup closure creates a fresh Store + Linker each iteration (matching
/// production behavior where each evaluate() gets a fresh Store), but the
/// module compilation is excluded from measurement.
fn bench_instantiation(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();
    let trivial_wat = build_trivial_guard_wat();
    let module = Module::new(&engine, trivial_wat).unwrap();

    let mut group = c.benchmark_group("wasm_guards/instantiation");

    group.bench_function("trivial_guard", |b| {
        b.iter_batched(
            || {
                // Setup: pre-build linker with host functions (isolates
                // instantiation cost from linker setup)
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(10_000_000).unwrap();
                let mut linker = Linker::new(&engine);
                register_host_functions(&mut linker).unwrap();
                (store, linker)
            },
            |(mut store, linker)| {
                // Measured: instantiation only
                let _instance = black_box(linker.instantiate(&mut store, &module).unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Evaluate helpers
// ---------------------------------------------------------------------------

/// Returns a WAT module that simulates a realistic guard: scans input bytes
/// looking for `0x7B` ('{' character, proxy for JSON parsing), and returns
/// VERDICT_DENY (1) if found, VERDICT_ALLOW (0) otherwise.
fn build_realistic_guard_wat() -> &'static str {
    r#"(module
    (import "chio" "log" (func $log (param i32 i32 i32)))
    (import "chio" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "chio" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 2)
    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
        (local $i i32)
        (local $found i32)
        (local.set $i (local.get $ptr))
        (block $done
            (loop $scan
                (br_if $done (i32.ge_u (local.get $i)
                    (i32.add (local.get $ptr) (local.get $len))))
                (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 0x7B))
                    (then (local.set $found (i32.const 1)))
                )
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)
            )
        )
        (local.get $found)
    )
)"#
}

/// Creates a representative GuardRequest for evaluate benchmarks.
fn make_bench_request() -> GuardRequest {
    GuardRequest {
        tool_name: "read_file".to_string(),
        server_id: "srv-fs".to_string(),
        agent_id: "agent-bench-001".to_string(),
        arguments: serde_json::json!({"path": "/etc/passwd", "encoding": "utf-8"}),
        scopes: vec!["file_access".to_string()],
        action_type: Some("file_access".to_string()),
        extracted_path: Some("/etc/passwd".to_string()),
        extracted_target: None,
        filesystem_roots: vec!["/home".to_string(), "/tmp".to_string()],
        matched_grant_index: Some(0),
    }
}

/// Creates an Engine with `consume_fuel(false)` (wasmtime default) for
/// WGBENCH-04 fuel overhead comparison.
fn create_no_fuel_engine() -> Arc<Engine> {
    let config = wasmtime::Config::new(); // consume_fuel defaults to false
    Arc::new(Engine::new(&config).unwrap())
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Evaluate latency (WGBENCH-03)
// ---------------------------------------------------------------------------

/// Benchmarks the FULL production hot path per-call: Store creation, Linker
/// setup, host function registration, instantiation, request serialization,
/// memory write, and evaluate call.
///
/// Two sub-benchmarks:
/// - `trivial_allow`: uses `build_trivial_guard_wat()`, measures immediate Allow
/// - `realistic_deny`: uses `build_realistic_guard_wat()`, measures byte-scanning Deny
fn bench_evaluate_latency(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();
    let trivial_wat = build_trivial_guard_wat();
    let realistic_wat = build_realistic_guard_wat();

    let trivial_module = Module::new(&engine, trivial_wat).unwrap();
    let realistic_module = Module::new(&engine, realistic_wat).unwrap();

    let request = make_bench_request();

    let mut group = c.benchmark_group("wasm_guards/evaluate_latency");

    // Trivial guard: immediate Allow (no input scanning)
    group.bench_function("trivial_allow", |b| {
        let request = request.clone();
        b.iter_batched(
            || request.clone(),
            |req| {
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(10_000_000).unwrap();
                let mut linker = Linker::new(&engine);
                register_host_functions(&mut linker).unwrap();
                let instance = linker.instantiate(&mut store, &trivial_module).unwrap();
                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let request_json = serde_json::to_vec(&req).unwrap();
                memory.write(&mut store, 0, &request_json).unwrap();
                let evaluate_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                    .unwrap();
                let _result = black_box(
                    evaluate_fn
                        .call(&mut store, (0, request_json.len() as i32))
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Realistic guard: byte-scanning Deny (scans JSON for '{')
    group.bench_function("realistic_deny", |b| {
        let request = request.clone();
        b.iter_batched(
            || request.clone(),
            |req| {
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(10_000_000).unwrap();
                let mut linker = Linker::new(&engine);
                register_host_functions(&mut linker).unwrap();
                let instance = linker.instantiate(&mut store, &realistic_module).unwrap();
                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let request_json = serde_json::to_vec(&req).unwrap();
                memory.write(&mut store, 0, &request_json).unwrap();
                let evaluate_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                    .unwrap();
                let _result = black_box(
                    evaluate_fn
                        .call(&mut store, (0, request_json.len() as i32))
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 4: Fuel metering overhead (WGBENCH-04)
// ---------------------------------------------------------------------------

/// Compares full evaluate latency with fuel metering enabled vs disabled.
///
/// Both sub-benchmarks use the same realistic guard WAT and full evaluate path.
/// The percentage overhead can be computed from Criterion output:
/// `overhead% = ((fuel_time - no_fuel_time) / no_fuel_time) * 100`
fn bench_fuel_overhead(c: &mut Criterion) {
    let fuel_engine = create_shared_engine().unwrap(); // consume_fuel(true)
    let no_fuel_engine = create_no_fuel_engine(); // consume_fuel(false)

    let realistic_wat = build_realistic_guard_wat();
    let fuel_module = Module::new(&fuel_engine, realistic_wat).unwrap();
    let no_fuel_module = Module::new(&no_fuel_engine, realistic_wat).unwrap();

    let request = make_bench_request();

    let mut group = c.benchmark_group("wasm_guards/fuel_overhead");

    // Fuel enabled: standard production path
    group.bench_function("fuel_enabled", |b| {
        let request = request.clone();
        b.iter_batched(
            || request.clone(),
            |req| {
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&fuel_engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(10_000_000).unwrap();
                let mut linker = Linker::new(&fuel_engine);
                register_host_functions(&mut linker).unwrap();
                let instance = linker.instantiate(&mut store, &fuel_module).unwrap();
                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let request_json = serde_json::to_vec(&req).unwrap();
                memory.write(&mut store, 0, &request_json).unwrap();
                let evaluate_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                    .unwrap();
                let _result = black_box(
                    evaluate_fn
                        .call(&mut store, (0, request_json.len() as i32))
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Fuel disabled: no fuel metering overhead
    group.bench_function("fuel_disabled", |b| {
        let request = request.clone();
        b.iter_batched(
            || request.clone(),
            |req| {
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&no_fuel_engine, host_state);
                store.limiter(|s| &mut s.limits);
                // NOTE: Do NOT call store.set_fuel() -- fuel is not enabled on this engine
                let mut linker = Linker::new(&no_fuel_engine);
                register_host_functions(&mut linker).unwrap();
                let instance = linker.instantiate(&mut store, &no_fuel_module).unwrap();
                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let request_json = serde_json::to_vec(&req).unwrap();
                memory.write(&mut store, 0, &request_json).unwrap();
                let evaluate_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                    .unwrap();
                let _result = black_box(
                    evaluate_fn
                        .call(&mut store, (0, request_json.len() as i32))
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ResourceLimiter helpers
// ---------------------------------------------------------------------------

/// Returns a WAT module that loops calling `memory.grow` with large page counts
/// to exceed the 16 MiB ceiling. With `trap_on_grow_failure(true)`, the first
/// grow that exceeds the limit traps.
///
/// Each `memory.grow(1024)` attempts to add 64 MiB (1024 pages * 64 KiB).
/// With the default 16 MiB ResourceLimiter, the first call should trap.
fn build_adversarial_memory_wat() -> &'static str {
    r#"(module
    (import "chio" "log" (func $log (param i32 i32 i32)))
    (import "chio" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "chio" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 1)
    (func (export "evaluate") (param i32 i32) (result i32)
        (local $i i32)
        (block $done
            (loop $grow
                (br_if $done (i32.ge_u (local.get $i) (i32.const 100)))
                (drop (memory.grow (i32.const 1024)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $grow)
            )
        )
        (i32.const 0)
    )
)"#
}

// ---------------------------------------------------------------------------
// Benchmark group 5: ResourceLimiter validation (WGBENCH-05)
// ---------------------------------------------------------------------------

/// Validates that the ResourceLimiter actually traps adversarial memory.grow
/// attempts that exceed the 16 MiB ceiling.
///
/// This is a correctness assertion disguised as a benchmark: it measures how
/// fast the ResourceLimiter detects and traps adversarial allocation, but the
/// key requirement is that the trap ACTUALLY occurs.
fn bench_resource_limiter(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();
    let adversarial_wat = build_adversarial_memory_wat();
    let module = Module::new(&engine, adversarial_wat).unwrap();

    let mut group = c.benchmark_group("wasm_guards/resource_limiter");

    group.bench_function("adversarial_grow_trapped", |b| {
        b.iter_batched(
            || {
                // Use default MAX_MEMORY_BYTES (16 MiB) limit
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(100_000_000).unwrap(); // high fuel so we hit memory limit first
                let mut linker = Linker::new(&engine);
                register_host_functions(&mut linker).unwrap();
                (store, linker)
            },
            |(mut store, linker)| {
                let instance = linker.instantiate(&mut store, &module).unwrap();
                let evaluate_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                    .unwrap();
                // The call MUST fail -- adversarial grow should trap
                let result = evaluate_fn.call(&mut store, (0, 0));
                assert!(
                    result.is_err(),
                    "ResourceLimiter must trap adversarial memory.grow"
                );
                let _ = black_box(result);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion entry point
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_module_compilation,
    bench_instantiation,
    bench_evaluate_latency,
    bench_fuel_overhead,
    bench_resource_limiter,
);
criterion_main!(benches);
