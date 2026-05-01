//! Shared helpers for the WASM guard escape harness.
//!
//! Every escape companion fixture loads the frozen runtime-limit
//! snapshot via [`load_frozen_config`] and asserts the live
//! `chio-wasm-guards` constants still match. If they drift, the
//! fixture fails fast and a CODEOWNERS-gated update to
//! `tests/escape/config.frozen.toml` is required (matches the
//! threat-model risk-register entry on runtime config drift).

use std::path::PathBuf;
use std::sync::Arc;

use chio_wasm_guards::abi::GuardRequest;
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use serde::Deserialize;
use wasmtime::Engine;

/// Path to the frozen-config snapshot relative to the crate root.
pub const FROZEN_CONFIG_PATH: &str = "tests/escape/config.frozen.toml";

/// Frozen runtime-limit snapshot. Mirrors the `chio-wasm-guards`
/// constants enforced at module-load and store-creation time.
#[derive(Debug, Deserialize)]
pub struct FrozenConfig {
    pub schema_version: u32,
    pub max_memory_bytes: usize,
    pub max_module_size: usize,
    pub escape_fuel_limit: u64,
}

/// Read the frozen snapshot from disk and assert the live `chio-wasm-guards`
/// constants still agree. Panics (i.e. fails the test) on drift.
pub fn load_frozen_config() -> FrozenConfig {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set under cargo test");
    let path = PathBuf::from(&manifest_dir).join(FROZEN_CONFIG_PATH);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let cfg: FrozenConfig =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("parse frozen config failed: {e}"));

    assert_eq!(cfg.schema_version, 1, "frozen config schema must be 1");

    // Drift checks against the live constants. If any of these fire, do
    // NOT silently bump the snapshot; route the change through CODEOWNERS.
    assert_eq!(
        cfg.max_memory_bytes,
        chio_wasm_guards::host::MAX_MEMORY_BYTES,
        "max_memory_bytes drifted from chio_wasm_guards::host::MAX_MEMORY_BYTES; \
         update tests/escape/config.frozen.toml under CODEOWNERS review"
    );

    cfg
}

/// Tiny tenant-id used by every escape fixture's evaluate call.
pub const ESCAPE_TENANT_ID: &str = "escape-test";

/// Build a minimal `GuardRequest` to drive the runtime-execution surface.
/// All escape classes care about the host runtime's reaction to the
/// loaded module, not about request semantics.
pub fn minimal_request() -> GuardRequest {
    GuardRequest {
        tool_name: String::new(),
        server_id: String::new(),
        agent_id: ESCAPE_TENANT_ID.to_string(),
        arguments: serde_json::Value::Null,
        scopes: Vec::new(),
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

/// Build a fresh `WasmtimeBackend` against a shared engine. The engine
/// is rebuilt per fixture so fuel/memory state from a previous escape
/// attempt cannot leak into the next.
pub fn fresh_wasmtime_backend() -> (Arc<Engine>, WasmtimeBackend) {
    let engine = create_shared_engine().expect("create_shared_engine");
    let backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
    (engine, backend)
}
