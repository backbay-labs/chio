//! Wasmtime-based WASM guard backend.
//!
//! Requires the `wasmtime-runtime` feature.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::guard::WasmGuard;
use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::error::WasmGuardError;
use crate::host::{create_shared_engine, register_host_functions, WasmHostState};
use crate::metrics::{
    tenant_id_label, GuardPoolMetrics, GuardPoolMetricsSnapshot, MAX_GUARD_METRIC_CARDINALITY,
};
use sha2::Digest;
use wasmtime::{Engine, InstancePre, Linker, Memory, Module, Store};

use crate::host::MAX_MEMORY_BYTES;

/// Default maximum module size in bytes (10 MiB).
pub const DEFAULT_MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_TENANT_WARM_INSTANCE_CAPACITY: usize = 4;
const DEFAULT_TENANT_WARM_RING_LIMIT: usize = MAX_GUARD_METRIC_CARDINALITY;

// -------------------------------------------------------------------
// Dual-mode format detection
// -------------------------------------------------------------------

/// Detected format of a .wasm binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmFormat {
    /// Traditional core WASM module (raw evaluate ABI).
    CoreModule,
    /// Component Model component (WIT-based ABI).
    Component,
}

/// Inspect the first bytes of a WASM binary to determine its format.
///
/// Uses `wasmparser::Parser` for authoritative detection. Returns `Err` if
/// the bytes are neither a valid core module nor a component.
pub fn detect_wasm_format(bytes: &[u8]) -> Result<WasmFormat, WasmGuardError> {
    if wasmparser::Parser::is_component(bytes) {
        Ok(WasmFormat::Component)
    } else if wasmparser::Parser::is_core_wasm(bytes) {
        Ok(WasmFormat::CoreModule)
    } else {
        Err(WasmGuardError::UnrecognizedFormat)
    }
}

/// Create the appropriate WASM guard backend based on binary format detection.
///
/// Inspects `wasm_bytes` to determine whether it is a core module or Component
/// Model component, then returns a loaded backend ready for `evaluate()` calls.
///
/// - Core modules route to `WasmtimeBackend` (raw ABI with host functions).
/// - Components route to `ComponentBackend` (WIT-based, type-safe bindings).
pub fn create_backend(
    engine: Arc<Engine>,
    wasm_bytes: &[u8],
    fuel_limit: u64,
    config: HashMap<String, String>,
) -> Result<Box<dyn crate::abi::WasmGuardAbi>, WasmGuardError> {
    let format = detect_wasm_format(wasm_bytes)?;

    match format {
        WasmFormat::CoreModule => {
            let mut backend = WasmtimeBackend::with_engine_and_config(engine, config);
            backend.load_module(wasm_bytes, fuel_limit)?;
            Ok(Box::new(backend))
        }
        WasmFormat::Component => {
            let mut backend =
                crate::component::ComponentBackend::with_engine_and_config(engine, config);
            backend.load_module(wasm_bytes, fuel_limit)?;
            Ok(Box::new(backend))
        }
    }
}

/// Load a WASM guard enforcing the signing policy.
///
/// Reads `wasm_path` from disk, verifies that the signature sidecar
/// (`wasm_path + ".sig"`) is present and valid per
/// [`crate::manifest::verify_guard_signature`], then checks the SHA-256
/// hash against the manifest declaration before instantiating the
/// backend via [`create_backend`].
///
/// Errors are fail-closed: any signature, hash, or format problem
/// rejects the guard before any guest code runs. Operators may set
/// `manifest.allow_unsigned = true` (with `signer_public_key = None`)
/// to permit unsigned modules, in which case a WARN is logged.
pub fn load_signed_guard(
    engine: Arc<Engine>,
    wasm_path: &str,
    fuel_limit: u64,
    manifest: &crate::manifest::GuardManifest,
) -> Result<Box<dyn crate::abi::WasmGuardAbi>, WasmGuardError> {
    let wasm_bytes = std::fs::read(wasm_path).map_err(|e| WasmGuardError::ModuleLoad {
        path: wasm_path.to_string(),
        reason: e.to_string(),
    })?;

    let verify_span =
        crate::observability::guard_verify_span(crate::observability::VERIFY_MODE_ED25519, None);
    let verification = (|| {
        let _verify_guard = verify_span.enter();
        crate::manifest::verify_wit_world(manifest.wit_world.as_deref())?;
        crate::manifest::verify_guard_signature(wasm_path, &wasm_bytes, manifest)?;
        crate::manifest::verify_wasm_hash(&wasm_bytes, &manifest.wasm_sha256)
    })();
    match verification {
        Ok(()) => {
            verify_span.record("result", crate::observability::VERIFY_RESULT_OK);
        }
        Err(err) => {
            verify_span.record("result", crate::observability::VERIFY_RESULT_FAIL);
            return Err(err);
        }
    }

    create_backend(engine, &wasm_bytes, fuel_limit, manifest.config.clone())
}

// -------------------------------------------------------------------
// WasmtimeBackend
// -------------------------------------------------------------------

#[derive(Clone)]
struct CachedInstancePre {
    module_hash: String,
    instance_pre: InstancePre<WasmHostState>,
}

struct WarmInstancePre {
    module_hash: String,
    instance_pre: InstancePre<WasmHostState>,
}

struct TenantWarmRing {
    capacity: usize,
    entries: VecDeque<WarmInstancePre>,
}

impl TenantWarmRing {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    fn checkout(&mut self, module_hash: &str) -> (Option<InstancePre<WasmHostState>>, usize) {
        let mut evicted = 0;
        while let Some(entry) = self.entries.pop_front() {
            if entry.module_hash == module_hash {
                return (Some(entry.instance_pre), evicted);
            }
            evicted += 1;
        }
        (None, evicted)
    }

    fn push(&mut self, entry: WarmInstancePre) -> bool {
        if self.capacity == 0 {
            return true;
        }
        let evicted = if self.entries.len() >= self.capacity {
            self.entries.pop_front();
            true
        } else {
            false
        };
        self.entries.push_back(entry);
        evicted
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

struct InstancePrePool {
    cache: Option<CachedInstancePre>,
    tenant_rings: HashMap<String, TenantWarmRing>,
    tenant_lru: VecDeque<String>,
    tenant_capacity: usize,
    tenant_limit: usize,
    metrics: GuardPoolMetrics,
}

impl InstancePrePool {
    fn new(tenant_capacity: usize) -> Self {
        Self::with_limits(tenant_capacity, DEFAULT_TENANT_WARM_RING_LIMIT)
    }

    fn with_limits(tenant_capacity: usize, tenant_limit: usize) -> Self {
        Self {
            cache: None,
            tenant_rings: HashMap::new(),
            tenant_lru: VecDeque::new(),
            tenant_capacity,
            tenant_limit,
            metrics: GuardPoolMetrics::new(),
        }
    }

    fn checkout(
        &mut self,
        tenant_id: &str,
        module_hash: &str,
    ) -> Result<InstancePre<WasmHostState>, WasmGuardError> {
        let tenant_id = tenant_id_label(tenant_id);
        self.metrics.record_checkout(&tenant_id);

        if let Some(ring) = self.tenant_rings.get_mut(&tenant_id) {
            let (instance_pre, evicted) = ring.checkout(module_hash);
            let warm_size = ring.len();
            self.record_evicts(&tenant_id, evicted);
            self.metrics.set_warm_size(&tenant_id, warm_size);
            self.touch_tenant(&tenant_id);
            if let Some(instance_pre) = instance_pre {
                return Ok(instance_pre);
            }
        }

        match self.cache.as_ref() {
            Some(cache) if cache.module_hash == module_hash => Ok(cache.instance_pre.clone()),
            _ => Err(WasmGuardError::BackendUnavailable),
        }
    }

    fn install(&mut self, module_hash: String, instance_pre: InstancePre<WasmHostState>) {
        self.cache = Some(CachedInstancePre {
            module_hash,
            instance_pre,
        });
        self.tenant_rings.clear();
        self.tenant_lru.clear();
        self.metrics.reset_warm_sizes();
    }

    fn return_instance_pre(
        &mut self,
        tenant_id: &str,
        module_hash: &str,
        instance_pre: InstancePre<WasmHostState>,
    ) {
        let tenant_id = tenant_id_label(tenant_id);
        if self.tenant_capacity == 0 {
            self.metrics.record_evict(&tenant_id);
            self.metrics.set_warm_size(&tenant_id, 0);
            return;
        }
        if !self.ensure_tenant_ring(&tenant_id) {
            self.metrics.record_evict(&tenant_id);
            self.metrics.set_warm_size(&tenant_id, 0);
            return;
        }
        let evicted = match self.tenant_rings.get_mut(&tenant_id) {
            Some(ring) => ring.push(WarmInstancePre {
                module_hash: module_hash.to_string(),
                instance_pre,
            }),
            None => {
                self.metrics.record_evict(&tenant_id);
                self.metrics.set_warm_size(&tenant_id, 0);
                return;
            }
        };
        let warm_size = match self.tenant_rings.get(&tenant_id) {
            Some(ring) => ring.len(),
            None => 0,
        };
        if evicted {
            self.metrics.record_evict(&tenant_id);
        }
        self.metrics.set_warm_size(&tenant_id, warm_size);
        self.touch_tenant(&tenant_id);
    }

    fn ensure_tenant_ring(&mut self, tenant_id: &str) -> bool {
        if self.tenant_rings.contains_key(tenant_id) {
            return true;
        }
        if self.tenant_limit == 0 {
            return false;
        }
        while self.tenant_rings.len() >= self.tenant_limit {
            if !self.evict_lru_tenant() {
                break;
            }
        }
        if self.tenant_rings.len() >= self.tenant_limit {
            return false;
        }
        self.tenant_rings.insert(
            tenant_id.to_string(),
            TenantWarmRing::new(self.tenant_capacity),
        );
        self.touch_tenant(tenant_id);
        true
    }

    fn evict_lru_tenant(&mut self) -> bool {
        while let Some(evicted_tenant_id) = self.tenant_lru.pop_front() {
            if let Some(ring) = self.tenant_rings.remove(&evicted_tenant_id) {
                self.record_evicts(&evicted_tenant_id, ring.len());
                self.metrics.set_warm_size(&evicted_tenant_id, 0);
                return true;
            }
        }
        let evicted_tenant_id = match self.tenant_rings.keys().min() {
            Some(tenant_id) => tenant_id.clone(),
            None => return false,
        };
        match self.tenant_rings.remove(&evicted_tenant_id) {
            Some(ring) => {
                self.record_evicts(&evicted_tenant_id, ring.len());
                self.metrics.set_warm_size(&evicted_tenant_id, 0);
                true
            }
            None => false,
        }
    }

    fn touch_tenant(&mut self, tenant_id: &str) {
        if let Some(position) = self.tenant_lru.iter().position(|entry| entry == tenant_id) {
            self.tenant_lru.remove(position);
        }
        self.tenant_lru.push_back(tenant_id.to_string());
    }

    fn record_evicts(&mut self, tenant_id: &str, evicted: usize) {
        for _ in 0..evicted {
            self.metrics.record_evict(tenant_id);
        }
    }

    #[cfg(test)]
    fn tenant_warm_size(&self, tenant_id: &str) -> usize {
        self.tenant_rings
            .get(&tenant_id_label(tenant_id))
            .map(TenantWarmRing::len)
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn force_tenant_ring_entry(
        &mut self,
        tenant_id: &str,
        module_hash: String,
        instance_pre: InstancePre<WasmHostState>,
    ) {
        let tenant_id = tenant_id_label(tenant_id);
        if !self.ensure_tenant_ring(&tenant_id) {
            self.metrics.record_evict(&tenant_id);
            self.metrics.set_warm_size(&tenant_id, 0);
            return;
        }
        let warm_size = match self.tenant_rings.get_mut(&tenant_id) {
            Some(ring) => {
                let evicted = ring.push(WarmInstancePre {
                    module_hash: module_hash.to_string(),
                    instance_pre,
                });
                if evicted {
                    self.metrics.record_evict(&tenant_id);
                }
                ring.len()
            }
            None => 0,
        };
        self.metrics.set_warm_size(&tenant_id, warm_size);
        self.touch_tenant(&tenant_id);
    }

    fn clear(&mut self) {
        self.cache = None;
        self.tenant_rings.clear();
        self.tenant_lru.clear();
        self.metrics.reset_warm_sizes();
    }

    fn cached_module_hash(&self) -> Option<&str> {
        self.cache.as_ref().map(|cache| cache.module_hash.as_str())
    }

    fn metrics_snapshot(&self, tenant_id: &str) -> Option<GuardPoolMetricsSnapshot> {
        self.metrics.snapshot(tenant_id)
    }

    fn registered_tenant_count(&self) -> usize {
        self.tenant_rings.len()
    }
}

fn build_instance_pre(
    engine: &Engine,
    module: &Module,
) -> Result<InstancePre<WasmHostState>, WasmGuardError> {
    let mut linker: Linker<WasmHostState> = Linker::new(engine);
    register_host_functions(&mut linker)?;
    linker
        .instantiate_pre(module)
        .map_err(|e| WasmGuardError::Compilation(e.to_string()))
}

/// WASM guard backend powered by Wasmtime.
///
/// Uses a shared [`Arc<Engine>`] and creates a fresh
/// [`Store<WasmHostState>`] per `evaluate()` call. Host functions
/// (`chio.log`, `chio.get_config`, `chio.get_time_unix_secs`) are registered
/// on the Linker before module instantiation.
pub struct WasmtimeBackend {
    engine: Arc<Engine>,
    module: Option<Module>,
    fuel_limit: u64,
    config: HashMap<String, String>,
    max_memory_bytes: usize,
    max_module_size: usize,
    last_fuel_consumed: Option<u64>,
    module_hash: Option<String>,
    instance_pre_pool: InstancePrePool,
}

impl WasmtimeBackend {
    /// Create a new Wasmtime backend with its own shared engine.
    ///
    /// Convenience constructor that creates its own engine; callers sharing
    /// an engine across guards should use [`with_engine`] instead.
    pub fn new() -> Result<Self, WasmGuardError> {
        let engine = create_shared_engine()?;
        Ok(Self {
            engine,
            module: None,
            fuel_limit: 0,
            config: HashMap::new(),
            max_memory_bytes: MAX_MEMORY_BYTES,
            max_module_size: DEFAULT_MAX_MODULE_SIZE,
            last_fuel_consumed: None,
            module_hash: None,
            instance_pre_pool: InstancePrePool::new(DEFAULT_TENANT_WARM_INSTANCE_CAPACITY),
        })
    }

    /// Create a Wasmtime backend with a pre-existing shared engine.
    ///
    /// This is the recommended constructor when loading multiple guards:
    /// create one `Arc<Engine>` via [`create_shared_engine()`] and pass it
    /// to each backend.
    pub fn with_engine(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            module: None,
            fuel_limit: 0,
            config: HashMap::new(),
            max_memory_bytes: MAX_MEMORY_BYTES,
            max_module_size: DEFAULT_MAX_MODULE_SIZE,
            last_fuel_consumed: None,
            module_hash: None,
            instance_pre_pool: InstancePrePool::new(DEFAULT_TENANT_WARM_INSTANCE_CAPACITY),
        }
    }

    /// Create a Wasmtime backend with a shared engine and guard-specific
    /// config that will be accessible to guests via `chio.get_config`.
    pub fn with_engine_and_config(engine: Arc<Engine>, config: HashMap<String, String>) -> Self {
        Self {
            engine,
            module: None,
            fuel_limit: 0,
            config,
            max_memory_bytes: MAX_MEMORY_BYTES,
            max_module_size: DEFAULT_MAX_MODULE_SIZE,
            last_fuel_consumed: None,
            module_hash: None,
            instance_pre_pool: InstancePrePool::new(DEFAULT_TENANT_WARM_INSTANCE_CAPACITY),
        }
    }

    /// Set custom resource limits for module size and memory.
    ///
    /// Builder-style method for configuring security boundaries.
    #[must_use]
    pub fn with_limits(mut self, max_memory_bytes: usize, max_module_size: usize) -> Self {
        self.max_memory_bytes = max_memory_bytes;
        self.max_module_size = max_module_size;
        self
    }

    /// Set the per-tenant warm InstancePre ring capacity.
    #[must_use]
    pub fn with_warm_instance_capacity(mut self, capacity: usize) -> Self {
        self.instance_pre_pool = InstancePrePool::new(capacity);
        self
    }

    #[must_use]
    pub fn instance_pre_cache_module_hash(&self) -> Option<&str> {
        self.instance_pre_pool.cached_module_hash()
    }

    #[must_use]
    pub fn pool_metrics_snapshot(&self, tenant_id: &str) -> Option<GuardPoolMetricsSnapshot> {
        self.instance_pre_pool.metrics_snapshot(tenant_id)
    }

    #[must_use]
    pub fn pool_registered_tenant_count(&self) -> usize {
        self.instance_pre_pool.registered_tenant_count()
    }
}

impl Default for WasmtimeBackend {
    fn default() -> Self {
        match Self::new() {
            Ok(b) => b,
            Err(_) => Self {
                engine: Arc::new(Engine::default()),
                module: None,
                fuel_limit: 0,
                config: HashMap::new(),
                max_memory_bytes: MAX_MEMORY_BYTES,
                max_module_size: DEFAULT_MAX_MODULE_SIZE,
                last_fuel_consumed: None,
                module_hash: None,
                instance_pre_pool: InstancePrePool::new(DEFAULT_TENANT_WARM_INSTANCE_CAPACITY),
            },
        }
    }
}

impl WasmGuardAbi for WasmtimeBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64) -> Result<(), WasmGuardError> {
        // Reject oversized modules before compilation
        if wasm_bytes.len() > self.max_module_size {
            return Err(WasmGuardError::ModuleTooLarge {
                size: wasm_bytes.len(),
                limit: self.max_module_size,
            });
        }

        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;

        // Validate that all imports come from the "chio" namespace
        for import in module.imports() {
            if import.module() != "chio" {
                return Err(WasmGuardError::ImportViolation {
                    module: import.module().to_string(),
                    name: import.name().to_string(),
                });
            }
        }

        let module_hash = hex::encode(sha2::Sha256::digest(wasm_bytes));
        let instance_pre = build_instance_pre(&self.engine, &module)?;
        self.module = Some(module);
        self.fuel_limit = fuel_limit;
        self.module_hash = Some(module_hash.clone());
        self.instance_pre_pool.install(module_hash, instance_pre);
        Ok(())
    }

    fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        let module = self
            .module
            .as_ref()
            .ok_or(WasmGuardError::BackendUnavailable)?;
        let module_hash = self
            .module_hash
            .as_deref()
            .ok_or(WasmGuardError::BackendUnavailable)?;
        let tenant_id = request.agent_id.as_str();

        // Create a fresh Store with configurable memory limit
        let host_state =
            WasmHostState::with_memory_limit(self.config.clone(), self.max_memory_bytes);
        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.fuel_limit)
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

        let instance_pre = match self.instance_pre_pool.checkout(tenant_id, module_hash) {
            Ok(instance_pre) => instance_pre,
            Err(_) => {
                let instance_pre = build_instance_pre(&self.engine, module)?;
                self.instance_pre_pool
                    .install(module_hash.to_string(), instance_pre.clone());
                instance_pre
            }
        };

        let instance = pollster::block_on(instance_pre.instantiate_async(&mut store))
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;
        self.instance_pre_pool
            .return_instance_pre(tenant_id, module_hash, instance_pre);

        // Serialize request to JSON
        let request_json = serde_json::to_vec(request)
            .map_err(|e| WasmGuardError::Serialization(e.to_string()))?;

        // Get guest memory
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmGuardError::MissingExport("memory".to_string()))?;

        // Probe for optional chio_alloc guest export
        let chio_alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "chio_alloc")
            .ok();

        let request_len: i32 = request_json.len() as i32;

        let request_ptr: i32 = if let Some(ref alloc_fn) = chio_alloc_fn {
            match pollster::block_on(alloc_fn.call_async(&mut store, request_len)) {
                Ok(ptr) => {
                    // Validate returned pointer is in bounds
                    let mem_size = memory.data_size(&store);
                    if ptr >= 0 && (ptr as usize).saturating_add(request_len as usize) <= mem_size {
                        ptr
                    } else {
                        return Err(WasmGuardError::Memory(format!(
                            "chio_alloc returned out-of-bounds pointer {ptr} for request length {request_len} and memory size {mem_size}"
                        )));
                    }
                }
                Err(e) => {
                    return Err(WasmGuardError::Trap(format!("chio_alloc call failed: {e}")));
                }
            }
        } else {
            // No chio_alloc export -- use offset-0 placement (core-module ABI)
            0
        };

        // Write request into guest memory at the resolved offset
        memory
            .write(&mut store, request_ptr as usize, &request_json)
            .map_err(|e| WasmGuardError::Memory(e.to_string()))?;

        // Call the evaluate function
        let evaluate_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .map_err(|e| WasmGuardError::MissingExport(format!("evaluate: {e}")))?;

        let result =
            pollster::block_on(evaluate_fn.call_async(&mut store, (request_ptr, request_len)))
                .map_err(|e| {
                    // Check if this was a fuel exhaustion
                    let msg = e.to_string();
                    if msg.contains("fuel") {
                        let consumed = self
                            .fuel_limit
                            .saturating_sub(store.get_fuel().unwrap_or(0));
                        // Record fuel even on exhaustion
                        self.last_fuel_consumed = Some(consumed);
                        WasmGuardError::FuelExhausted {
                            consumed,
                            limit: self.fuel_limit,
                        }
                    } else {
                        WasmGuardError::Trap(msg)
                    }
                })?;

        // Track fuel consumed for receipt metadata
        let remaining = store.get_fuel().unwrap_or(0);
        let consumed = self.fuel_limit.saturating_sub(remaining);
        self.last_fuel_consumed = Some(consumed);

        let verdict = match result {
            crate::abi::VERDICT_ALLOW => Ok(GuardVerdict::Allow),
            crate::abi::VERDICT_DENY => {
                // Probe for structured chio_deny_reason export
                let deny_reason_fn = instance
                    .get_typed_func::<(i32, i32), i32>(&mut store, "chio_deny_reason")
                    .ok();

                let reason = if let Some(ref reason_fn) = deny_reason_fn {
                    read_structured_deny_reason(reason_fn, &memory, &mut store)
                } else {
                    // Fallback to core-module offset-64K NUL-terminated deny string (no chio_deny_reason export)
                    read_deny_reason(&memory, &store)
                };

                Ok(GuardVerdict::Deny { reason })
            }
            _ => {
                // Unexpected return value -- fail closed
                Err(WasmGuardError::Trap(format!(
                    "unexpected return value from evaluate: {result}"
                )))
            }
        };

        // Drain the log buffer and emit via tracing for host-side visibility
        for (level, msg) in &store.data().logs {
            match level {
                0 => tracing::trace!(target: "wasm_guard", "{msg}"),
                1 => tracing::debug!(target: "wasm_guard", "{msg}"),
                2 => tracing::info!(target: "wasm_guard", "{msg}"),
                3 => tracing::warn!(target: "wasm_guard", "{msg}"),
                4 => tracing::error!(target: "wasm_guard", "{msg}"),
                _ => {}
            }
        }

        verdict
    }

    fn backend_name(&self) -> &str {
        "wasmtime"
    }

    fn last_fuel_consumed(&self) -> Option<u64> {
        self.last_fuel_consumed
    }

    fn clear_instance_pre_cache(&mut self) {
        self.instance_pre_pool.clear();
    }
}

/// Read a structured deny reason from the guest via the `chio_deny_reason`
/// export. The host calls `chio_deny_reason(buf_ptr, buf_len)` with a
/// buffer region in guest memory. The guest writes a JSON-encoded
/// [`GuestDenyResponse`](crate::abi::GuestDenyResponse) into the buffer
/// and returns the number of bytes written (or a negative/zero value on
/// error).
///
/// All error paths return `None` (fail closed with no reason rather than
/// crashing).
fn read_structured_deny_reason(
    reason_fn: &wasmtime::TypedFunc<(i32, i32), i32>,
    memory: &Memory,
    store: &mut Store<WasmHostState>,
) -> Option<String> {
    const DENY_BUF_OFFSET: i32 = 65536;
    const DENY_BUF_LEN: i32 = 4096;

    // Call the guest's chio_deny_reason function
    let bytes_written = match pollster::block_on(
        reason_fn.call_async(&mut *store, (DENY_BUF_OFFSET, DENY_BUF_LEN)),
    ) {
        Ok(n) if n > 0 && n <= DENY_BUF_LEN => n,
        Ok(_) => return None,  // 0 or negative or too large
        Err(_) => return None, // call failed, no reason
    };

    // Read the response from guest memory
    let mut buf = vec![0u8; bytes_written as usize];
    if memory
        .read(store, DENY_BUF_OFFSET as usize, &mut buf)
        .is_err()
    {
        return None;
    }

    // Try to parse as JSON GuestDenyResponse
    match serde_json::from_slice::<crate::abi::GuestDenyResponse>(&buf) {
        Ok(resp) => Some(resp.reason),
        Err(_) => {
            // Not valid JSON -- try as plain UTF-8 string
            std::str::from_utf8(&buf)
                .ok()
                .map(|s| s.trim_end_matches('\0').to_string())
                .filter(|s| !s.is_empty())
        }
    }
}

/// Try to read a deny reason string from the guest memory region after
/// the request data. The guest may write a NUL-terminated UTF-8 string
/// starting at a well-known offset (64 KiB).
fn read_deny_reason(memory: &Memory, store: &Store<WasmHostState>) -> Option<String> {
    const DENY_REASON_OFFSET: usize = 65536;
    const MAX_REASON_LEN: usize = 4096;

    let data = memory.data(store);
    if data.len() <= DENY_REASON_OFFSET {
        return None;
    }

    let region = &data[DENY_REASON_OFFSET..];
    let end = region
        .iter()
        .take(MAX_REASON_LEN)
        .position(|&b| b == 0)
        .unwrap_or(region.len().min(MAX_REASON_LEN));

    if end == 0 {
        return None;
    }

    std::str::from_utf8(&region[..end]).ok().map(String::from)
}

// -------------------------------------------------------------------
// Policy-driven loading with placeholders and capability
// intersection.
// -------------------------------------------------------------------

use crate::manifest::GuardManifest;
use crate::placeholders::{resolve_placeholders_in_json, PlaceholderEnv, PlaceholderError};
/// Names of `chio.*` host functions Chio currently exposes to guests.
///
/// Operators can pass a subset of this list as `policy_allowed_host_fns`
/// to [`load_guards_from_policy`] to restrict which capabilities any
/// custom guard may request.
pub const KNOWN_HOST_FUNCTIONS: &[&str] =
    &["chio.log", "chio.get_config", "chio.get_time_unix_secs"];

/// A single WASM guard declared in the policy YAML.
///
/// A custom-guard plugin entry: it names the module, points at its `.wasm`
/// bytes (either on disk or inline), declares the host-function
/// capabilities the guard needs, and carries a JSON config blob that may
/// contain `${ENV_VAR}` placeholders.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyCustomGuard {
    /// Human-readable guard name. Used for logs, receipts, and to identify
    /// the guard in the pipeline.
    pub name: String,

    /// Semantic version of the guard. Must match the signature sidecar's
    /// `version` field when signing is enabled.
    #[serde(default = "default_guard_version")]
    pub version: String,

    /// Source of the `.wasm` bytes. Either a filesystem path or inline
    /// bytes.
    #[serde(flatten)]
    pub module: PolicyModuleSource,

    /// Host functions this guard requests access to (e.g. `chio.log`).
    /// Capabilities not present in the policy-allowed allowlist cause
    /// loading to fail closed.
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Guard configuration. String leaves may contain `${VAR}` or
    /// `${VAR:-default}` placeholders that are resolved at load time
    /// against the injected [`PlaceholderEnv`].
    #[serde(default)]
    pub config: serde_json::Value,

    /// Fuel budget per `evaluate()` call.
    #[serde(default = "default_policy_fuel_limit")]
    pub fuel_limit: u64,

    /// Guard priority (lower values run first).
    #[serde(default = "default_policy_priority")]
    pub priority: u32,

    /// If true, denials are downgraded to `Verdict::Allow` and merely
    /// logged (consistent with [`WasmGuard::is_advisory`]).
    #[serde(default)]
    pub advisory: bool,

    /// Hex-encoded Ed25519 public key of the trusted signer. Enforced via
    /// the signing path ([`crate::manifest::verify_guard_signature`]).
    /// When set the `.wasm.sig` sidecar MUST exist.
    #[serde(default)]
    pub signer_public_key: Option<String>,

    /// Explicit opt-out for unsigned modules. Matches the field of the
    /// same name on [`GuardManifest`]. Ignored when `signer_public_key`
    /// is set.
    #[serde(default)]
    pub allow_unsigned: bool,
}

/// Source of the `.wasm` bytes for a [`PolicyCustomGuard`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PolicyModuleSource {
    /// Load the module from disk. The signature sidecar (if any) lives
    /// at `module_path + ".sig"`.
    Path {
        /// Filesystem path to the `.wasm` file.
        module_path: String,
    },
    /// Inline raw WASM bytes. Useful for tests and for embedding small
    /// modules in a policy file.
    Inline {
        /// Raw WASM bytes.
        module_bytes: Vec<u8>,
    },
}

impl PolicyModuleSource {
    /// Borrow the module path, if this source is backed by a file.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Path { module_path } => Some(module_path.as_str()),
            Self::Inline { .. } => None,
        }
    }
}

fn default_guard_version() -> String {
    "0.0.0".to_string()
}

fn default_policy_fuel_limit() -> u64 {
    crate::config::DEFAULT_FUEL_LIMIT
}

fn default_policy_priority() -> u32 {
    1000
}

/// Top-level `custom_guards:` section of a policy document.
///
/// Consumed by [`load_guards_from_policy`]. Deliberately defined here in
/// `chio-wasm-guards` so that chio-policy can hand this struct off without
/// taking a dependency on the reverse direction.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PolicyCustomGuards {
    /// Ordered list of guard declarations.
    #[serde(default)]
    pub modules: Vec<PolicyCustomGuard>,
}

/// Errors returned by [`load_guards_from_policy`].
///
/// Kept distinct from [`WasmGuardError`] so callers can tell a policy
/// wiring problem (missing capability, unresolved placeholder, bad
/// signature) apart from a pure runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The guard requested a host function that is not in the policy's
    /// allowed allowlist. Fail-closed.
    #[error(
        "guard {guard:?} requested capability {capability:?} which is not permitted by policy"
    )]
    CapabilityDenied {
        /// The guard name for which the check failed.
        guard: String,
        /// The offending capability string.
        capability: String,
    },

    /// The guard's WASM module imports a host function from the `chio`
    /// namespace that was not declared in its `capabilities` list.
    #[error("guard {guard:?} module imports {import:?} which is not declared in capabilities")]
    UndeclaredHostImport {
        /// The guard name.
        guard: String,
        /// The import the module requires (e.g. `chio.log`).
        import: String,
    },

    /// A placeholder in the guard config could not be resolved.
    #[error("placeholder resolution failed for guard {guard:?}: {source}")]
    Placeholder {
        /// The guard name.
        guard: String,
        /// Underlying placeholder error.
        #[source]
        source: PlaceholderError,
    },

    /// The guard config was not a JSON object (the backend expects a map
    /// of string keys to string values after placeholder expansion).
    #[error("guard {guard:?} config must be a JSON object, got {kind}")]
    ConfigShape {
        /// The guard name.
        guard: String,
        /// Describes the actual JSON kind that was found.
        kind: &'static str,
    },

    /// A resolved config value at key `key` was not a string after
    /// placeholder expansion; the current host ABI only accepts strings.
    #[error("guard {guard:?} config value at {key:?} must resolve to a string")]
    ConfigNotString {
        /// The guard name.
        guard: String,
        /// The config key that produced the non-string value.
        key: String,
    },

    /// Underlying WASM guard runtime error.
    #[error(transparent)]
    Runtime(#[from] WasmGuardError),
}

/// Handle returned by [`load_guards_from_policy`].
///
/// Wraps a fully loaded [`WasmGuard`] alongside metadata describing the
/// capabilities that were ultimately granted to the module. Callers can
/// feed `into_guard()` (or `into_guards()` on a collection) directly into
/// [`crate::build_guard_pipeline`] or register with `WasmGuardRuntime`.
#[derive(Debug)]
pub struct WasmGuardHandle {
    guard: WasmGuard,
    granted_capabilities: Vec<String>,
    priority: u32,
}

impl WasmGuardHandle {
    /// Consume the handle and return the inner [`WasmGuard`].
    pub fn into_guard(self) -> WasmGuard {
        self.guard
    }

    /// Borrow the inner guard.
    pub fn guard(&self) -> &WasmGuard {
        &self.guard
    }

    /// Capabilities that were granted to the guard (the intersection of
    /// requested and policy-allowed host functions).
    pub fn granted_capabilities(&self) -> &[String] {
        &self.granted_capabilities
    }

    /// Guard priority (lower runs first).
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

/// Load every guard declared in `policy` and return a vector of handles.
///
/// Steps for each entry, in order:
///
/// 1. **Capability intersection.** Every entry in `guard.capabilities`
///    must also appear in `policy_allowed_host_fns`. If any requested
///    capability is missing, loading fails with
///    [`LoadError::CapabilityDenied`]. An empty `capabilities` list is
///    allowed and means the guard opts into no host functions.
///
/// 2. **Placeholder resolution.** String leaves in `guard.config` are
///    rewritten via [`resolve_placeholders_in_json`] against `env`.
///    Undefined placeholders without a `:-default` fail closed.
///
/// 3. **Signature verification.** If the guard declares
///    `signer_public_key` (or `allow_unsigned = false` with no key), the
///    signing path ([`crate::manifest::verify_guard_signature`])
///    is invoked. For on-disk modules the `.wasm.sig` sidecar is
///    consulted; for inline modules only `allow_unsigned = true` is
///    accepted (there is no sidecar to check).
///
/// 4. **Import check.** The module is compiled and its imports are
///    inspected: any `chio.*` import not in the guard's `capabilities`
///    list is rejected ([`LoadError::UndeclaredHostImport`]). This
///    enforces capability intersection at the module boundary, not just
///    at the policy layer.
///
/// 5. **Backend construction.** A [`WasmtimeBackend`] is instantiated
///    with the resolved config map and the supplied `engine`.
///
/// Returned handles are sorted by priority (lower first), matching the
/// ordering used by [`crate::load_wasm_guards`].
pub fn load_guards_from_policy(
    policy: &PolicyCustomGuards,
    env: &dyn PlaceholderEnv,
    policy_allowed_host_fns: &[String],
    engine: Arc<Engine>,
) -> Result<Vec<WasmGuardHandle>, LoadError> {
    let mut handles: Vec<WasmGuardHandle> = Vec::with_capacity(policy.modules.len());

    // Sort a copy of the entries so lower priority runs first, non-advisory
    // before advisory at the same priority. Priority is the primary key;
    // advisory is only a tie-breaker. Matches `load_wasm_guards` in
    // `wiring.rs` so policy-driven and config-driven loading produce the
    // same evaluation order.
    let mut sorted: Vec<PolicyCustomGuard> = policy.modules.clone();
    sorted.sort_by_key(|g| (g.priority, g.advisory as u8));

    for guard_spec in &sorted {
        // 1. Capability intersection (fail closed on any un-allowed capability).
        for requested in &guard_spec.capabilities {
            if !policy_allowed_host_fns.iter().any(|a| a == requested) {
                return Err(LoadError::CapabilityDenied {
                    guard: guard_spec.name.clone(),
                    capability: requested.clone(),
                });
            }
        }
        let granted: Vec<String> = guard_spec.capabilities.clone();

        // 2. Placeholder resolution on the config JSON.
        let resolved_config =
            resolve_placeholders_in_json(&guard_spec.config, env).map_err(|source| {
                LoadError::Placeholder {
                    guard: guard_spec.name.clone(),
                    source,
                }
            })?;
        let config_map = json_object_to_string_map(&resolved_config, &guard_spec.name)?;

        // 3. Obtain bytes and enforce the signing policy.
        let wasm_bytes = match &guard_spec.module {
            PolicyModuleSource::Path { module_path } => {
                let bytes = std::fs::read(module_path).map_err(|e| {
                    LoadError::Runtime(WasmGuardError::ModuleLoad {
                        path: module_path.clone(),
                        reason: e.to_string(),
                    })
                })?;

                // Build a transient GuardManifest describing just the
                // identity + signer, so we can reuse the signing
                // sidecar verification path.
                let transient_manifest = GuardManifest {
                    name: guard_spec.name.clone(),
                    version: guard_spec.version.clone(),
                    abi_version: "1".to_string(),
                    wit_world: Some(crate::manifest::REQUIRED_WIT_WORLD.to_string()),
                    wasm_path: module_path.clone(),
                    wasm_sha256: hex::encode(sha2::Sha256::digest(&bytes)),
                    config: std::collections::HashMap::new(),
                    signer_public_key: guard_spec.signer_public_key.clone(),
                    allow_unsigned: guard_spec.allow_unsigned,
                };
                crate::manifest::verify_guard_signature(module_path, &bytes, &transient_manifest)
                    .map_err(LoadError::Runtime)?;

                bytes
            }
            PolicyModuleSource::Inline { module_bytes } => {
                // Inline modules have no sidecar. Require allow_unsigned.
                if guard_spec.signer_public_key.is_some() {
                    return Err(LoadError::Runtime(WasmGuardError::SignatureVerification(
                        format!(
                            "guard {:?} has signer_public_key but inline module_bytes have no sidecar",
                            guard_spec.name
                        ),
                    )));
                }
                if !guard_spec.allow_unsigned {
                    return Err(LoadError::Runtime(WasmGuardError::SignatureVerification(
                        format!(
                            "guard {:?} inline module_bytes require allow_unsigned=true",
                            guard_spec.name
                        ),
                    )));
                }
                module_bytes.clone()
            }
        };

        // 4. Compile and check imports against the granted capability set.
        verify_module_imports_within_capabilities(&engine, &wasm_bytes, guard_spec, &granted)?;

        // 5. Construct the backend + guard.
        let mut backend =
            WasmtimeBackend::with_engine_and_config(engine.clone(), config_map.clone());
        backend
            .load_module(&wasm_bytes, guard_spec.fuel_limit)
            .map_err(LoadError::Runtime)?;

        let manifest_sha = hex::encode(sha2::Sha256::digest(&wasm_bytes));
        let guard = WasmGuard::new_with_metadata(
            guard_spec.name.clone(),
            guard_spec.version.clone(),
            Box::new(backend),
            guard_spec.advisory,
            Some(manifest_sha),
        );

        handles.push(WasmGuardHandle {
            guard,
            granted_capabilities: granted,
            priority: guard_spec.priority,
        });
    }

    Ok(handles)
}

/// Coerce a resolved JSON config into the string-to-string map the host
/// ABI exposes via `chio.get_config`.
///
/// Only the top-level object's string values are preserved; nested
/// objects / arrays cause `ConfigNotString` because the `chio.get_config`
/// host function returns UTF-8 bytes by key.
fn json_object_to_string_map(
    value: &serde_json::Value,
    guard_name: &str,
) -> Result<std::collections::HashMap<String, String>, LoadError> {
    use serde_json::Value;

    let mut out = std::collections::HashMap::new();
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::String(s) => {
                        out.insert(k.clone(), s.clone());
                    }
                    Value::Null => {
                        // Skip nulls -- treat as "unset".
                    }
                    Value::Bool(b) => {
                        out.insert(k.clone(), b.to_string());
                    }
                    Value::Number(n) => {
                        out.insert(k.clone(), n.to_string());
                    }
                    _ => {
                        return Err(LoadError::ConfigNotString {
                            guard: guard_name.to_string(),
                            key: k.clone(),
                        });
                    }
                }
            }
            Ok(out)
        }
        Value::Null => Ok(out),
        Value::Array(_) => Err(LoadError::ConfigShape {
            guard: guard_name.to_string(),
            kind: "array",
        }),
        Value::Bool(_) => Err(LoadError::ConfigShape {
            guard: guard_name.to_string(),
            kind: "bool",
        }),
        Value::Number(_) => Err(LoadError::ConfigShape {
            guard: guard_name.to_string(),
            kind: "number",
        }),
        Value::String(_) => Err(LoadError::ConfigShape {
            guard: guard_name.to_string(),
            kind: "string",
        }),
    }
}

/// Compile the module and ensure every `chio.*` import is in the granted
/// capabilities list.
///
/// Modules loaded as components (WIT) are exempt from this check because
/// they do not declare core imports the same way.
fn verify_module_imports_within_capabilities(
    engine: &Engine,
    wasm_bytes: &[u8],
    guard_spec: &PolicyCustomGuard,
    granted: &[String],
) -> Result<(), LoadError> {
    // Only core modules expose the `chio.*` imports; skip components.
    if detect_wasm_format(wasm_bytes).unwrap_or(WasmFormat::CoreModule) != WasmFormat::CoreModule {
        return Ok(());
    }

    let module = Module::new(engine, wasm_bytes)
        .map_err(|e| LoadError::Runtime(WasmGuardError::Compilation(e.to_string())))?;
    for import in module.imports() {
        if import.module() == "chio" {
            let qualified = format!("chio.{}", import.name());
            if !granted.iter().any(|g| g == &qualified) {
                return Err(LoadError::UndeclaredHostImport {
                    guard: guard_spec.name.clone(),
                    import: qualified,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "wasmtime_backend_tests.rs"]
mod tests;
