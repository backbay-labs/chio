use super::*;
use crate::abi::GuardRequest;
use chio_kernel::Guard;

fn make_guard_request() -> GuardRequest {
    GuardRequest {
        tool_name: "test_tool".to_string(),
        server_id: "test_server".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({"key": "value"}),
        scopes: vec!["test_server:test_tool".to_string()],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

fn make_guard_request_for_agent(agent_id: &str) -> GuardRequest {
    let mut request = make_guard_request();
    request.agent_id = agent_id.to_string();
    request
}

// -------------------------------------------------------------------
// chio_alloc tests
// -------------------------------------------------------------------

#[test]
fn chio_alloc_used_when_exported() {
    // WAT module with chio_alloc that returns 1024.
    // evaluate checks that ptr == 1024 and returns ALLOW only if so.
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "chio_alloc") (param $size i32) (result i32)
                    ;; Always allocate at offset 1024
                    (i32.const 1024)
                )
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return ALLOW (0) only if ptr == 1024, else DENY (1)
                    (if (result i32) (i32.eq (local.get $ptr) (i32.const 1024))
                        (then (i32.const 0))
                        (else (i32.const 1))
                    )
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    assert!(
        result.is_allow(),
        "expected ALLOW (chio_alloc should have been used), got: {result:?}"
    );
}

#[test]
fn no_chio_alloc_uses_offset_zero() {
    // WAT module WITHOUT chio_alloc.
    // evaluate checks that ptr == 0 and returns ALLOW only if so.
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return ALLOW (0) only if ptr == 0, else DENY (1)
                    (if (result i32) (i32.eqz (local.get $ptr))
                        (then (i32.const 0))
                        (else (i32.const 1))
                    )
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    assert!(
        result.is_allow(),
        "expected ALLOW (offset 0 fallback should be used without chio_alloc), got: {result:?}"
    );
}

#[test]
fn get_config_reports_full_length_for_truncated_buffer() {
    let wat = r#"
            (module
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 8192) "secret")
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (local $copied i32)
                    (local.set $copied
                        (call $get_config
                            (i32.const 8192)
                            (i32.const 6)
                            (i32.const 32)
                            (i32.const 4)))
                    (if (result i32) (i32.eq (local.get $copied) (i32.const 6))
                        (then (i32.const 0))
                        (else (i32.const 1))
                    )
                )
            )
        "#;

    let mut config = std::collections::HashMap::new();
    config.insert("secret".to_string(), "abcdef".to_string());
    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine_and_config(engine, config);
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    assert!(
        result.is_allow(),
        "expected ALLOW when get_config returned the full value byte count, got: {result:?}"
    );
}

#[test]
fn chio_alloc_oob_fails_closed() {
    // WAT module with chio_alloc that returns 999_999_999 (out-of-bounds).
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "chio_alloc") (param $size i32) (result i32)
                    ;; Return absurdly large pointer
                    (i32.const 999999999)
                )
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let error = backend.evaluate(&req).unwrap_err();
    assert!(error.to_string().contains("out-of-bounds pointer"));
}

#[test]
fn chio_alloc_negative_fails_closed() {
    // WAT module with chio_alloc that returns -1 (negative pointer).
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "chio_alloc") (param $size i32) (result i32)
                    ;; Return negative pointer
                    (i32.const -1)
                )
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let error = backend.evaluate(&req).unwrap_err();
    assert!(error.to_string().contains("out-of-bounds pointer"));
}

#[test]
fn chio_alloc_trap_fails_closed() {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "chio_alloc") (param $size i32) (result i32)
                    unreachable
                )
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let error = backend.evaluate(&req).unwrap_err();
    assert!(error.to_string().contains("chio_alloc call failed"));
}

// -------------------------------------------------------------------
// chio_deny_reason tests
// -------------------------------------------------------------------

#[test]
fn chio_deny_reason_structured() {
    // WAT module with chio_deny_reason that writes a JSON GuestDenyResponse
    // into the provided buffer and returns the byte count.
    //
    // The JSON {"reason":"blocked by policy"} is stored using escaped
    // quotes in the WAT data segment at offset 512.
    // chio_deny_reason copies it to buf_ptr using memory.copy.
    let json_bytes = br#"{"reason":"blocked by policy"}"#;
    let json_len = json_bytes.len(); // 30

    // Build WAT data segment using \xx hex escapes to avoid quote issues
    let hex_data: String = json_bytes.iter().map(|b| format!("\\{b:02x}")).collect();

    let wat = format!(
        r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                ;; Store the JSON response at offset 512 using hex escapes
                (data (i32.const 512) "{hex_data}")
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return DENY (1)
                    (i32.const 1)
                )
                (func (export "chio_deny_reason") (param $buf_ptr i32) (param $buf_len i32) (result i32)
                    ;; Copy JSON from offset 512 to buf_ptr using memory.copy
                    (memory.copy
                        (local.get $buf_ptr)  ;; dest
                        (i32.const 512)       ;; src
                        (i32.const {json_len})  ;; len
                    )
                    ;; Return number of bytes written
                    (i32.const {json_len})
                )
            )
        "#
    );

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    match &result {
        GuardVerdict::Deny { reason } => {
            assert_eq!(
                reason.as_deref(),
                Some("blocked by policy"),
                "expected structured deny reason from chio_deny_reason"
            );
        }
        _ => panic!("expected Deny verdict, got: {result:?}"),
    }
}

#[test]
fn chio_deny_reason_fallback_core_module() {
    // WAT module WITHOUT chio_deny_reason export.
    // Has a NUL-terminated string at offset 65536 (core-module deny-reason ABI: "core-module reason\0").
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (data (i32.const 65536) "core-module reason\00")
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return DENY (1)
                    (i32.const 1)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    match &result {
        GuardVerdict::Deny { reason } => {
            assert_eq!(
                reason.as_deref(),
                Some("core-module reason"),
                "expected core-module deny reason from offset 64K"
            );
        }
        _ => panic!("expected Deny verdict, got: {result:?}"),
    }
}

#[test]
fn chio_deny_reason_invalid_returns_none() {
    // WAT module with chio_deny_reason that returns -1 (error).
    // The host should fall back to None reason.
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return DENY (1)
                    (i32.const 1)
                )
                (func (export "chio_deny_reason") (param $buf_ptr i32) (param $buf_len i32) (result i32)
                    ;; Return -1 (error)
                    (i32.const -1)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    match &result {
        GuardVerdict::Deny { reason } => {
            assert_eq!(
                reason, &None,
                "expected None reason when chio_deny_reason returns -1"
            );
        }
        _ => panic!("expected Deny verdict, got: {result:?}"),
    }
}

// -------------------------------------------------------------------
// Security enforcement tests
// -------------------------------------------------------------------

#[test]
fn module_too_large_rejected() {
    // Set a very small max_module_size and provide bytes exceeding it
    let mut backend = WasmtimeBackend::new()
        .unwrap()
        .with_limits(16 * 1024 * 1024, 100);
    let big_bytes = vec![0u8; 200];
    let result = backend.load_module(&big_bytes, 1_000_000);
    match result {
        Err(WasmGuardError::ModuleTooLarge { size, limit }) => {
            assert_eq!(size, 200);
            assert_eq!(limit, 100);
        }
        other => panic!("expected ModuleTooLarge, got: {other:?}"),
    }
}

#[test]
fn module_within_size_accepted() {
    // Use a small valid WAT module with default limits (10 MiB)
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;
    let mut backend = WasmtimeBackend::new().unwrap();
    let result = backend.load_module(wat.as_bytes(), 1_000_000);
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}

#[test]
fn import_validation_rejects_wasi() {
    // WAT module that imports from wasi_snapshot_preview1 (forbidden)
    let wat = r#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;
    let mut backend = WasmtimeBackend::new().unwrap();
    let result = backend.load_module(wat.as_bytes(), 1_000_000);
    match result {
        Err(WasmGuardError::ImportViolation { module, name }) => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("expected ImportViolation, got: {other:?}"),
    }
}

#[test]
fn import_validation_accepts_chio_only() {
    // WAT module that imports only from "chio" namespace
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;
    let mut backend = WasmtimeBackend::new().unwrap();
    let result = backend.load_module(wat.as_bytes(), 1_000_000);
    assert!(
        result.is_ok(),
        "expected Ok for chio-only imports, got: {result:?}"
    );
}

#[test]
fn memory_growth_beyond_limit_traps() {
    // WAT module that tries to grow memory by 1000 pages (64 MB)
    // with a very small limit (2 pages = 128 KiB)
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Try to grow memory by 1000 pages -- should trap
                    (drop (memory.grow (i32.const 1000)))
                    (i32.const 0)
                )
            )
        "#;
    let mut backend = WasmtimeBackend::new()
        .unwrap()
        .with_limits(2 * 64 * 1024, 10 * 1024 * 1024);
    backend.load_module(wat.as_bytes(), 10_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req);
    assert!(
        result.is_err(),
        "expected error (trap) when memory.grow exceeds limit, got: {result:?}"
    );
}

#[test]
fn memory_growth_within_limit_works() {
    // WAT module that grows memory by 1 page with default 16 MiB limit
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Grow memory by 1 page (64 KiB) -- should succeed
                    (drop (memory.grow (i32.const 1)))
                    (i32.const 0)
                )
            )
        "#;
    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 10_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req);
    assert!(
        result.is_ok(),
        "expected Ok when memory.grow is within limit, got: {result:?}"
    );
}

#[test]
fn deny_no_reason_at_all() {
    // WAT module without chio_deny_reason and no string at offset 64K.
    // Memory is zeroed so read_deny_reason will find a NUL at position 0.
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    ;; Return DENY (1)
                    (i32.const 1)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let req = make_guard_request();
    let result = backend.evaluate(&req).unwrap();
    match &result {
        GuardVerdict::Deny { reason } => {
            assert_eq!(
                reason, &None,
                "expected None reason when no deny reason mechanism is available"
            );
        }
        _ => panic!("expected Deny verdict, got: {result:?}"),
    }
}

// -------------------------------------------------------------------
// Fuel tracking tests
// -------------------------------------------------------------------

#[test]
fn wasmtime_fuel_consumed_after_evaluate() {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    assert!(
        backend.last_fuel_consumed().is_none(),
        "fuel should be None before any evaluation"
    );

    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();
    let req = make_guard_request();
    let _ = backend.evaluate(&req).unwrap();

    let fuel = backend.last_fuel_consumed();
    assert!(fuel.is_some(), "fuel should be Some after evaluation");
    assert!(fuel.unwrap() > 0, "fuel consumed should be > 0");
}

#[test]
fn wasmtime_instance_pre_cache_tracks_pool_checkout_metrics() -> Result<(), WasmGuardError> {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new()?.with_warm_instance_capacity(1);
    backend.load_module(wat.as_bytes(), 1_000_000)?;
    let cache_hash = match backend.instance_pre_cache_module_hash() {
        Some(hash) => hash.to_string(),
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    let req = make_guard_request();

    let first = backend.evaluate(&req)?;
    assert!(first.is_allow());
    let first_snapshot = match backend.pool_metrics_snapshot("agent-1") {
        Some(snapshot) => snapshot,
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    assert_eq!(first_snapshot.checkout_total, 1);
    assert_eq!(first_snapshot.warm_size, 1);
    assert_eq!(first_snapshot.evict_total, 0);

    let second = backend.evaluate(&req)?;
    assert!(second.is_allow());
    let second_snapshot = match backend.pool_metrics_snapshot("agent-1") {
        Some(snapshot) => snapshot,
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    assert_eq!(second_snapshot.checkout_total, 2);
    assert_eq!(second_snapshot.warm_size, 1);
    assert_eq!(second_snapshot.evict_total, 0);
    assert_eq!(
        backend.instance_pre_cache_module_hash(),
        Some(cache_hash.as_str())
    );
    assert_eq!(backend.pool_registered_tenant_count(), 1);
    Ok(())
}

#[test]
fn wasmtime_pool_capacity_zero_records_evicts() -> Result<(), WasmGuardError> {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new()?.with_warm_instance_capacity(0);
    backend.load_module(wat.as_bytes(), 1_000_000)?;
    let req = make_guard_request();
    let verdict = backend.evaluate(&req)?;
    assert!(verdict.is_allow());

    let snapshot = match backend.pool_metrics_snapshot("agent-1") {
        Some(snapshot) => snapshot,
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    assert_eq!(snapshot.checkout_total, 1);
    assert_eq!(snapshot.warm_size, 0);
    assert_eq!(snapshot.evict_total, 1);
    assert_eq!(backend.pool_registered_tenant_count(), 0);
    Ok(())
}

#[test]
fn wasmtime_pool_limits_tenant_ring_count_and_evicts_oldest() -> Result<(), WasmGuardError> {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new()?;
    backend.instance_pre_pool = InstancePrePool::with_limits(1, 2);
    backend.load_module(wat.as_bytes(), 1_000_000)?;

    let first = backend.evaluate(&make_guard_request_for_agent("agent-a"))?;
    assert!(first.is_allow());
    let second = backend.evaluate(&make_guard_request_for_agent("agent-b"))?;
    assert!(second.is_allow());
    assert_eq!(backend.pool_registered_tenant_count(), 2);

    let refreshed = backend.evaluate(&make_guard_request_for_agent("agent-a"))?;
    assert!(refreshed.is_allow());
    let third = backend.evaluate(&make_guard_request_for_agent("agent-c"))?;
    assert!(third.is_allow());

    assert_eq!(backend.pool_registered_tenant_count(), 2);
    assert_eq!(backend.instance_pre_pool.tenant_warm_size("agent-a"), 1);
    assert_eq!(backend.instance_pre_pool.tenant_warm_size("agent-b"), 0);
    assert_eq!(backend.instance_pre_pool.tenant_warm_size("agent-c"), 1);

    let evicted_snapshot = match backend.pool_metrics_snapshot("agent-b") {
        Some(snapshot) => snapshot,
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    assert_eq!(evicted_snapshot.warm_size, 0);
    assert_eq!(evicted_snapshot.evict_total, 1);
    Ok(())
}

#[test]
fn wasmtime_pool_records_hash_mismatch_discards_as_evicts() -> Result<(), WasmGuardError> {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new()?;
    backend.load_module(wat.as_bytes(), 1_000_000)?;
    let instance_pre = match backend.instance_pre_pool.cache.as_ref() {
        Some(cache) => cache.instance_pre.clone(),
        None => return Err(WasmGuardError::BackendUnavailable),
    };

    backend.instance_pre_pool.force_tenant_ring_entry(
        "agent-1",
        "stale-module-a".to_string(),
        instance_pre.clone(),
    );
    backend.instance_pre_pool.force_tenant_ring_entry(
        "agent-1",
        "stale-module-b".to_string(),
        instance_pre,
    );
    assert_eq!(backend.instance_pre_pool.tenant_warm_size("agent-1"), 2);

    let verdict = backend.evaluate(&make_guard_request())?;
    assert!(verdict.is_allow());
    let snapshot = match backend.pool_metrics_snapshot("agent-1") {
        Some(snapshot) => snapshot,
        None => return Err(WasmGuardError::BackendUnavailable),
    };
    assert_eq!(snapshot.checkout_total, 1);
    assert_eq!(snapshot.warm_size, 1);
    assert_eq!(snapshot.evict_total, 2);
    Ok(())
}

#[test]
fn wasmtime_fuel_consumed_tracked_on_wasm_guard() {
    let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#;

    let mut backend = WasmtimeBackend::new().unwrap();
    backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

    let guard = WasmGuard::new(
        "fuel-test".to_string(),
        Box::new(backend),
        false,
        Some("deadbeef".to_string()),
    );

    // Before evaluation
    assert!(guard.last_fuel_consumed().is_none());
    assert_eq!(guard.manifest_sha256().as_deref(), Some("deadbeef"));

    // After evaluation, metadata is captured from the evaluated epoch.
    let req = make_guard_request();
    let issuer = chio_core::crypto::Keypair::generate();
    let subject = chio_core::crypto::Keypair::generate();
    let capability = chio_core::capability::token::CapabilityToken::sign(
        chio_core::capability::token::CapabilityTokenBody {
            id: "cap-fuel-test".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: chio_core::capability::scope::ChioScope::default(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        },
        &issuer,
    )
    .unwrap();
    let scope = chio_core::capability::scope::ChioScope::default();
    let tool_request = chio_kernel::ToolCallRequest {
        request_id: "req-fuel-test".to_string(),
        capability,
        tool_name: req.tool_name.clone(),
        server_id: req.server_id.clone(),
        agent_id: req.agent_id.clone(),
        arguments: req.arguments.clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let ctx = chio_kernel::GuardContext {
        request: &tool_request,
        scope: &scope,
        agent_id: &req.agent_id,
        server_id: &req.server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    let _ = guard.evaluate(&ctx).unwrap();

    assert!(guard.last_fuel_consumed().is_some());
    assert!(guard.last_fuel_consumed().unwrap() > 0);

    // manifest_sha256 unchanged after evaluate
    assert_eq!(guard.manifest_sha256().as_deref(), Some("deadbeef"));

    // guard_evidence_metadata returns both values
    let evidence = guard.guard_evidence_metadata();
    assert!(evidence["fuel_consumed"].as_u64().unwrap() > 0);
    assert_eq!(evidence["manifest_sha256"], "deadbeef");
}

// -------------------------------------------------------------------
// Format detection tests
// -------------------------------------------------------------------

#[test]
fn detect_core_module_magic_bytes() {
    // Core WASM magic: \0asm followed by version 1
    let core_bytes = b"\x00asm\x01\x00\x00\x00";
    let format = detect_wasm_format(core_bytes);
    assert!(format.is_ok());
    assert_eq!(format.unwrap(), WasmFormat::CoreModule);
}

#[test]
fn detect_component_magic_bytes() {
    // Component magic: \0asm followed by component layer encoding
    let component_bytes = b"\x00asm\x0d\x00\x01\x00";
    let format = detect_wasm_format(component_bytes);
    assert!(format.is_ok());
    assert_eq!(format.unwrap(), WasmFormat::Component);
}

#[test]
fn detect_invalid_bytes() {
    let garbage = b"not wasm at all";
    let format = detect_wasm_format(garbage);
    assert!(format.is_err());
}
