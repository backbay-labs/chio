//! M06 guard-pool checkout p99 bench.
//!
//! The measurement keeps module compilation and InstancePre creation outside
//! the timed loop. Each iteration exercises a warmed tenant ring checkout via
//! `WasmtimeBackend::evaluate`, which is the production path that records
//! guard-pool checkout metrics.

use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use chio_wasm_guards::{GuardRequest, GuardVerdict, WasmGuardAbi};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const FUEL_LIMIT: u64 = 10_000_000;
const TENANT_ID: &str = "bench-agent-p99";

fn allow_guard_wat() -> &'static str {
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

fn bench_request() -> GuardRequest {
    GuardRequest {
        tool_name: "read_file".to_string(),
        server_id: "bench-server".to_string(),
        agent_id: TENANT_ID.to_string(),
        arguments: serde_json::json!({
            "path": "/tmp/chio-bench-input.txt",
            "encoding": "utf-8"
        }),
        scopes: vec!["file_access".to_string()],
        action_type: Some("file_access".to_string()),
        extracted_path: Some("/tmp/chio-bench-input.txt".to_string()),
        extracted_target: None,
        filesystem_roots: vec!["/tmp".to_string()],
        matched_grant_index: Some(0),
    }
}

fn load_backend() -> WasmtimeBackend {
    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend.with_warm_instance_capacity(4),
        Err(error) => fail_bench(&format!("create Wasmtime backend: {error}")),
    };
    if let Err(error) = backend.load_module(allow_guard_wat().as_bytes(), FUEL_LIMIT) {
        fail_bench(&format!("load guard module: {error}"));
    }
    backend
}

fn assert_allow(verdict: GuardVerdict) {
    if !verdict.is_allow() {
        fail_bench("bench guard returned deny");
    }
}

fn warm_pool(backend: &mut WasmtimeBackend, request: &GuardRequest) {
    for _ in 0..8 {
        match backend.evaluate(request) {
            Ok(verdict) => assert_allow(verdict),
            Err(error) => fail_bench(&format!("warm guard pool: {error}")),
        }
    }

    let snapshot = match backend.pool_metrics_snapshot(TENANT_ID) {
        Some(snapshot) => snapshot,
        None => fail_bench("guard pool metrics were not recorded for bench tenant"),
    };
    if snapshot.warm_size == 0 {
        fail_bench("guard pool did not retain a warm InstancePre entry");
    }
}

fn bench_guard_pool_checkout_p99(c: &mut Criterion) {
    let mut backend = load_backend();
    let request = bench_request();
    warm_pool(&mut backend, &request);

    c.bench_function("guard_pool_checkout_p99/warm_tenant_checkout", |b| {
        b.iter(|| match backend.evaluate(black_box(&request)) {
            Ok(verdict) => assert_allow(black_box(verdict)),
            Err(error) => fail_bench(&format!("evaluate warmed guard: {error}")),
        });
    });
}

fn fail_bench(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_guard_pool_checkout_p99
}
criterion_main!(benches);
