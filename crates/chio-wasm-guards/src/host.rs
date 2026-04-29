//! Host state and WIT-generated host import wiring for WASM guards.
//!
//! Core-module guards still use [`WasmHostState`] for per-invocation limits and
//! configuration. Component-model guards use the same state through bindings
//! generated from `wit/chio-guard/world.wit`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use wasmtime::component::{
    Linker as ComponentLinker, Resource as ComponentResource, ResourceTable, ResourceTableError,
};
use wasmtime::{
    Caller, Engine, FuncType, Linker as CoreLinker, StoreLimits, StoreLimitsBuilder, Val, ValType,
};

use crate::bundle_store::{parse_sha256_digest, BundleStore, InMemoryBundleStore};
use crate::error::WasmGuardError;
use crate::observability::{
    guard_fetch_blob_span, guard_host_call_span, HOST_FETCH_BLOB, HOST_GET_CONFIG,
    HOST_GET_TIME_UNIX_SECS, HOST_LOG,
};

// ---------------------------------------------------------------------------
// bindgen-generated component bindings
// ---------------------------------------------------------------------------

/// Host-side representation for the `policy-context` bundle resource.
#[derive(Debug, Clone)]
pub struct BundleHandle {
    sha256: [u8; 32],
}

impl BundleHandle {
    #[must_use]
    pub fn id_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/chio-guard",
        world: "guard",
        imports: { default: async | trappable },
        exports: { default: async },
        with: {
            "chio:guard/policy-context.bundle-handle": super::BundleHandle,
        },
    });
}

pub use self::bindings::{Guard, GuardRequest, Verdict};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of log entries buffered per guard invocation.
pub const MAX_LOG_ENTRIES: usize = 256;

/// Maximum guest memory size in bytes (16 MiB).
pub const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// Maximum length of a single log message in bytes.
pub const MAX_LOG_MESSAGE_LEN: usize = 4096;

/// Maximum length of a config key in bytes.
pub const MAX_CONFIG_KEY_LEN: usize = 1024;

// ---------------------------------------------------------------------------
// WasmHostState
// ---------------------------------------------------------------------------

/// Per-invocation host state stored in the wasmtime `Store`.
pub struct WasmHostState {
    /// Guard-specific configuration key-value pairs from the manifest.
    pub config: HashMap<String, String>,
    /// Captured log entries from `host.log` calls: `(level, message)`.
    pub logs: Vec<(i32, String)>,
    /// Maximum log entries per invocation, bounded at [`MAX_LOG_ENTRIES`].
    pub max_log_entries: usize,
    /// Resource limits for memory and table growth.
    pub limits: StoreLimits,
    /// Content-addressed policy bundle storage.
    pub bundle_store: Arc<dyn BundleStore>,
    /// Host-owned component resource table.
    pub resources: ResourceTable,
}

impl WasmHostState {
    /// Create a new host state with the given config and default limits.
    pub fn new(config: HashMap<String, String>) -> Self {
        Self::with_memory_limit(config, MAX_MEMORY_BYTES)
    }

    /// Create a new host state with a custom memory limit.
    ///
    /// `trap_on_grow_failure(true)` causes `memory.grow` beyond the configured
    /// cap to trap, preserving fail-closed behavior.
    pub fn with_memory_limit(config: HashMap<String, String>, max_memory: usize) -> Self {
        Self::with_memory_limit_and_bundle_store(
            config,
            max_memory,
            Arc::new(InMemoryBundleStore::new()),
        )
    }

    /// Create host state with a custom in-process content bundle store.
    pub fn with_bundle_store(
        config: HashMap<String, String>,
        bundle_store: Arc<dyn BundleStore>,
    ) -> Self {
        Self::with_memory_limit_and_bundle_store(config, MAX_MEMORY_BYTES, bundle_store)
    }

    /// Create host state with custom memory and content bundle limits.
    pub fn with_memory_limit_and_bundle_store(
        config: HashMap<String, String>,
        max_memory: usize,
        bundle_store: Arc<dyn BundleStore>,
    ) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_memory)
            .trap_on_grow_failure(true)
            .build();
        Self {
            config,
            logs: Vec::new(),
            max_log_entries: MAX_LOG_ENTRIES,
            limits,
            bundle_store,
            resources: ResourceTable::new(),
        }
    }

    fn record_log(&mut self, level: u32, msg: String) {
        let span = guard_host_call_span(HOST_LOG);
        let _span_guard = span.enter();
        if level > 4 || msg.len() > MAX_LOG_MESSAGE_LEN {
            return;
        }

        match level {
            0 => tracing::trace!(target: "wasm_guard", "{msg}"),
            1 => tracing::debug!(target: "wasm_guard", "{msg}"),
            2 => tracing::info!(target: "wasm_guard", "{msg}"),
            3 => tracing::warn!(target: "wasm_guard", "{msg}"),
            4 => tracing::error!(target: "wasm_guard", "{msg}"),
            _ => {}
        }

        if self.logs.len() < self.max_log_entries {
            self.logs.push((level as i32, msg));
        }
    }

    fn read_bundle_blob(
        &self,
        handle: &BundleHandle,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, String> {
        let blob = self
            .bundle_store
            .fetch_blob(&handle.sha256)
            .map_err(|e| e.to_string())?;
        slice_blob(&blob, offset, len)
    }

    fn read_bundle_blob_with_spans(
        &self,
        handle: &BundleHandle,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, String> {
        let host_span = guard_host_call_span(HOST_FETCH_BLOB);
        let _host_guard = host_span.enter();
        let bundle_id = handle.id_hex();
        let fetch_span = guard_fetch_blob_span(&bundle_id, 0);
        let _fetch_guard = fetch_span.enter();
        let result = self.read_bundle_blob(handle, offset, len);
        let bytes = result.as_ref().map_or(0, Vec::len) as u64;
        fetch_span.record("bytes", bytes);
        result
    }
}

fn slice_blob(blob: &[u8], offset: u64, len: u32) -> Result<Vec<u8>, String> {
    let start =
        usize::try_from(offset).map_err(|_| "bundle blob offset exceeds host usize".to_string())?;
    let length =
        usize::try_from(len).map_err(|_| "bundle blob length exceeds host usize".to_string())?;
    if start > blob.len() {
        return Err(format!(
            "bundle blob offset {offset} is beyond blob length {}",
            blob.len()
        ));
    }

    let end = start.saturating_add(length).min(blob.len());
    Ok(blob[start..end].to_vec())
}

fn resource_table_error(err: ResourceTableError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("bundle handle resource table error: {err}"))
}

fn resource_table_error_string(err: ResourceTableError) -> String {
    format!("bundle handle resource table error: {err}")
}

// ---------------------------------------------------------------------------
// Shared Engine constructor
// ---------------------------------------------------------------------------

/// Create a shared wasmtime [`Engine`] with fuel and async component support.
pub fn create_shared_engine() -> Result<Arc<Engine>, WasmGuardError> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config).map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
    Ok(Arc::new(engine))
}

// ---------------------------------------------------------------------------
// Component host import wiring
// ---------------------------------------------------------------------------

/// Register WIT-generated `chio:guard/guard@0.2.0` host imports.
pub fn register_component_host_functions<T>(
    linker: &mut ComponentLinker<T>,
    get: fn(&mut T) -> &mut WasmHostState,
) -> Result<(), WasmGuardError>
where
    T: Send,
{
    Guard::add_to_linker::<T, wasmtime::component::HasSelf<WasmHostState>>(linker, get)
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))
}

/// Register legacy raw-ABI core-module imports.
///
/// Component guards use [`register_component_host_functions`]. This path remains
/// for older core modules and is implemented without the old linker shortcut.
pub fn register_host_functions(
    linker: &mut CoreLinker<WasmHostState>,
) -> Result<(), WasmGuardError> {
    let engine = linker.engine().clone();

    linker
        .func_new(
            "chio",
            "log",
            FuncType::new(&engine, [ValType::I32, ValType::I32, ValType::I32], []),
            legacy_log,
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    linker
        .func_new(
            "chio",
            "get_config",
            FuncType::new(
                &engine,
                [ValType::I32, ValType::I32, ValType::I32, ValType::I32],
                [ValType::I32],
            ),
            legacy_get_config,
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    linker
        .func_new(
            "chio",
            "get_time_unix_secs",
            FuncType::new(&engine, [], [ValType::I64]),
            legacy_get_time_unix_secs,
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    Ok(())
}

fn i32_param(params: &[Val], index: usize) -> Option<i32> {
    match params.get(index) {
        Some(Val::I32(value)) => Some(*value),
        _ => None,
    }
}

fn set_i32_result(results: &mut [Val], value: i32) -> wasmtime::Result<()> {
    match results.get_mut(0) {
        Some(slot) => {
            *slot = Val::I32(value);
            Ok(())
        }
        None => Err(wasmtime::Error::msg("missing i32 result slot")),
    }
}

fn set_i64_result(results: &mut [Val], value: i64) -> wasmtime::Result<()> {
    match results.get_mut(0) {
        Some(slot) => {
            *slot = Val::I64(value);
            Ok(())
        }
        None => Err(wasmtime::Error::msg("missing i64 result slot")),
    }
}

fn legacy_log(
    mut caller: Caller<'_, WasmHostState>,
    params: &[Val],
    _results: &mut [Val],
) -> wasmtime::Result<()> {
    let level = match i32_param(params, 0) {
        Some(value) if (0..=4).contains(&value) => value as u32,
        _ => return Ok(()),
    };
    let ptr = match i32_param(params, 1) {
        Some(value) if value >= 0 => value as usize,
        _ => return Ok(()),
    };
    let len = match i32_param(params, 2) {
        Some(value) if value >= 0 => value as usize,
        _ => return Ok(()),
    };
    if len > MAX_LOG_MESSAGE_LEN {
        return Ok(());
    }

    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(memory) => memory,
        None => return Ok(()),
    };

    let mut buf = vec![0u8; len];
    if memory.read(&caller, ptr, &mut buf).is_err() {
        return Ok(());
    }

    let msg = String::from_utf8_lossy(&buf).to_string();
    caller.data_mut().record_log(level, msg);
    Ok(())
}

fn legacy_get_config(
    mut caller: Caller<'_, WasmHostState>,
    params: &[Val],
    results: &mut [Val],
) -> wasmtime::Result<()> {
    let span = guard_host_call_span(HOST_GET_CONFIG);
    let _span_guard = span.enter();
    let key_ptr = match i32_param(params, 0) {
        Some(value) if value >= 0 => value as usize,
        _ => return set_i32_result(results, -1),
    };
    let key_len = match i32_param(params, 1) {
        Some(value) if value >= 0 && value as usize <= MAX_CONFIG_KEY_LEN => value as usize,
        _ => return set_i32_result(results, -1),
    };
    let val_out_ptr = match i32_param(params, 2) {
        Some(value) if value >= 0 => value as usize,
        _ => return set_i32_result(results, -1),
    };
    let val_out_len = match i32_param(params, 3) {
        Some(value) if value >= 0 => value as usize,
        _ => return set_i32_result(results, -1),
    };

    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(memory) => memory,
        None => return set_i32_result(results, -1),
    };

    let mut key_buf = vec![0u8; key_len];
    if memory.read(&caller, key_ptr, &mut key_buf).is_err() {
        return set_i32_result(results, -1);
    }

    let key = match std::str::from_utf8(&key_buf) {
        Ok(value) => value,
        Err(_) => return set_i32_result(results, -1),
    };

    let value = match caller.data().config.get(key) {
        Some(value) => value.clone(),
        None => return set_i32_result(results, -1),
    };
    let value_bytes = value.as_bytes();
    let copy_len = value_bytes.len().min(val_out_len);
    let mem_data = memory.data_mut(&mut caller);
    if val_out_ptr.saturating_add(copy_len) <= mem_data.len() {
        mem_data[val_out_ptr..val_out_ptr + copy_len].copy_from_slice(&value_bytes[..copy_len]);
    }

    let actual_len = i32::try_from(value_bytes.len()).unwrap_or(i32::MAX);
    set_i32_result(results, actual_len)
}

fn legacy_get_time_unix_secs(
    _caller: Caller<'_, WasmHostState>,
    _params: &[Val],
    results: &mut [Val],
) -> wasmtime::Result<()> {
    let span = guard_host_call_span(HOST_GET_TIME_UNIX_SECS);
    let _span_guard = span.enter();
    let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    set_i64_result(results, secs)
}

impl bindings::chio::guard::host::Host for WasmHostState {
    async fn log(&mut self, level: u32, msg: String) -> wasmtime::Result<()> {
        self.record_log(level, msg);
        Ok(())
    }

    async fn get_config(&mut self, key: String) -> wasmtime::Result<Option<String>> {
        let span = guard_host_call_span(HOST_GET_CONFIG);
        let _span_guard = span.enter();
        if key.len() > MAX_CONFIG_KEY_LEN {
            return Ok(None);
        }
        Ok(self.config.get(&key).cloned())
    }

    async fn get_time_unix_secs(&mut self) -> wasmtime::Result<u64> {
        let span = guard_host_call_span(HOST_GET_TIME_UNIX_SECS);
        let _span_guard = span.enter();
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => 0,
        };
        Ok(secs)
    }

    async fn fetch_blob(
        &mut self,
        handle: u32,
        offset: u64,
        len: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, String>> {
        let resource = ComponentResource::<BundleHandle>::new_borrow(handle);
        let handle = match self.resources.get(&resource) {
            Ok(handle) => handle,
            Err(err) => return Ok(Err(resource_table_error_string(err))),
        };
        Ok(self.read_bundle_blob_with_spans(handle, offset, len))
    }
}

impl bindings::chio::guard::types::Host for WasmHostState {}

impl bindings::chio::guard::policy_context::Host for WasmHostState {}

impl bindings::chio::guard::policy_context::HostBundleHandle for WasmHostState {
    async fn new(&mut self, id: String) -> wasmtime::Result<ComponentResource<BundleHandle>> {
        let sha256 = parse_sha256_digest(&id).map_err(|e| wasmtime::Error::msg(e.to_string()))?;
        self.resources
            .push(BundleHandle { sha256 })
            .map_err(resource_table_error)
    }

    async fn read(
        &mut self,
        self_: ComponentResource<BundleHandle>,
        offset: u64,
        len: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, String>> {
        let handle = match self.resources.get(&self_) {
            Ok(handle) => handle,
            Err(err) => return Ok(Err(resource_table_error_string(err))),
        };
        Ok(self.read_bundle_blob_with_spans(handle, offset, len))
    }

    async fn close(&mut self, self_: ComponentResource<BundleHandle>) -> wasmtime::Result<()> {
        let owned = ComponentResource::<BundleHandle>::new_own(self_.rep());
        self.resources
            .delete(owned)
            .map(|_| ())
            .map_err(resource_table_error)
    }

    async fn drop(&mut self, rep: ComponentResource<BundleHandle>) -> wasmtime::Result<()> {
        let owned = ComponentResource::<BundleHandle>::new_own(rep.rep());
        match self.resources.delete(owned) {
            Ok(_) | Err(ResourceTableError::NotPresent) => Ok(()),
            Err(err) => Err(resource_table_error(err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);

        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("host future should complete without suspension"),
        }
    }

    #[test]
    fn host_state_new_creates_empty_logs_with_config() {
        let mut config = HashMap::new();
        config.insert("key".to_string(), "value".to_string());
        let state = WasmHostState::new(config.clone());
        assert!(state.logs.is_empty());
        assert_eq!(state.max_log_entries, MAX_LOG_ENTRIES);
        assert_eq!(state.config.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn host_state_with_memory_limit_uses_custom_limit() {
        let config = HashMap::new();
        let custom_limit = 4 * 1024 * 1024;
        let state = WasmHostState::with_memory_limit(config, custom_limit);
        assert!(state.logs.is_empty());
        assert_eq!(state.max_log_entries, MAX_LOG_ENTRIES);
    }

    #[test]
    fn host_create_shared_engine_returns_arc() {
        let engine = create_shared_engine();
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        let _clone = engine.clone();
    }

    #[test]
    fn host_log_captures_message() {
        let mut state = WasmHostState::new(HashMap::new());
        block_on_ready(bindings::chio::guard::host::Host::log(
            &mut state,
            2,
            "hello".to_string(),
        ))
        .expect("log");

        assert_eq!(state.logs, vec![(2, "hello".to_string())]);
    }

    #[test]
    fn host_log_buffer_respects_max_entries() {
        let mut state = WasmHostState::new(HashMap::new());

        for _ in 0..=MAX_LOG_ENTRIES {
            block_on_ready(bindings::chio::guard::host::Host::log(
                &mut state,
                2,
                "x".to_string(),
            ))
            .expect("log");
        }

        assert_eq!(state.logs.len(), MAX_LOG_ENTRIES);
    }

    #[test]
    fn host_log_invalid_level_is_silently_ignored() {
        let mut state = WasmHostState::new(HashMap::new());
        block_on_ready(bindings::chio::guard::host::Host::log(
            &mut state,
            99,
            "bad".to_string(),
        ))
        .expect("log");

        assert!(state.logs.is_empty());
    }

    #[test]
    fn host_log_oversized_message_is_silently_ignored() {
        let mut state = WasmHostState::new(HashMap::new());
        block_on_ready(bindings::chio::guard::host::Host::log(
            &mut state,
            2,
            "x".repeat(MAX_LOG_MESSAGE_LEN + 1),
        ))
        .expect("log");

        assert!(state.logs.is_empty());
    }

    #[test]
    fn host_get_config_reads_value() {
        let mut config = HashMap::new();
        config.insert("timeout".to_string(), "30".to_string());
        let mut state = WasmHostState::new(config);

        let value = block_on_ready(bindings::chio::guard::host::Host::get_config(
            &mut state,
            "timeout".to_string(),
        ))
        .expect("get config");

        assert_eq!(value, Some("30".to_string()));
    }

    #[test]
    fn host_get_config_missing_key_returns_none() {
        let mut state = WasmHostState::new(HashMap::new());

        let value = block_on_ready(bindings::chio::guard::host::Host::get_config(
            &mut state,
            "missing".to_string(),
        ))
        .expect("get config");

        assert_eq!(value, None);
    }

    #[test]
    fn host_get_time_returns_positive_value() {
        let mut state = WasmHostState::new(HashMap::new());

        let time_val = block_on_ready(bindings::chio::guard::host::Host::get_time_unix_secs(
            &mut state,
        ))
        .expect("get time");

        assert!(time_val > 0, "expected positive timestamp, got {time_val}");
    }
}
