//! Component Model backend for WASM guard evaluation.
//!
//! The [`ComponentBackend`] evaluates Component Model guards through bindings
//! generated in [`crate::host`] from `wit/chio-guard/world.wit`. Host imports
//! are registered with the same generated bindings, including async host calls.

use std::collections::HashMap;
use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use crate::abi::{GuardVerdict, WasmGuardAbi};
use crate::bundle_store::{BundleStore, InMemoryBundleStore};
use crate::error::WasmGuardError;
use crate::host::{
    register_component_host_functions, Guard, GuardRequest, Verdict, WasmHostState,
    MAX_MEMORY_BYTES,
};

// ---------------------------------------------------------------------------
// ComponentBackend
// ---------------------------------------------------------------------------

/// Component Model backend that evaluates WIT-based guard components.
///
/// Uses the `wasmtime::component::bindgen!` generated `Guard` bindings to
/// instantiate and call `evaluate` on Component Model `.wasm` files.
pub struct ComponentBackend {
    engine: Arc<Engine>,
    component: Option<Component>,
    fuel_limit: u64,
    config: HashMap<String, String>,
    bundle_store: Arc<dyn BundleStore>,
    max_memory_bytes: usize,
    max_module_size: usize,
    last_fuel_consumed: Option<u64>,
}

impl ComponentBackend {
    /// Create a new `ComponentBackend` using the given shared engine.
    ///
    /// Uses default limits: 16 MiB memory, 10 MiB module size, 1M fuel.
    pub fn with_engine(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            component: None,
            fuel_limit: 1_000_000,
            config: HashMap::new(),
            bundle_store: Arc::new(InMemoryBundleStore::new()),
            max_memory_bytes: MAX_MEMORY_BYTES,
            max_module_size: 10 * 1024 * 1024,
            last_fuel_consumed: None,
        }
    }

    /// Create a new `ComponentBackend` with guard-specific host config.
    pub fn with_engine_and_config(engine: Arc<Engine>, config: HashMap<String, String>) -> Self {
        Self {
            engine,
            component: None,
            fuel_limit: 1_000_000,
            config,
            bundle_store: Arc::new(InMemoryBundleStore::new()),
            max_memory_bytes: MAX_MEMORY_BYTES,
            max_module_size: 10 * 1024 * 1024,
            last_fuel_consumed: None,
        }
    }

    /// Builder method to set the content bundle store used by host calls.
    #[must_use]
    pub fn with_bundle_store(mut self, bundle_store: Arc<dyn BundleStore>) -> Self {
        self.bundle_store = bundle_store;
        self
    }

    /// Builder method to set custom memory and module size limits.
    #[must_use]
    pub fn with_limits(mut self, max_memory_bytes: usize, max_module_size: usize) -> Self {
        self.max_memory_bytes = max_memory_bytes;
        self.max_module_size = max_module_size;
        self
    }
}

impl WasmGuardAbi for ComponentBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64) -> Result<(), WasmGuardError> {
        // WGSEC-03: reject oversized modules before compilation
        if wasm_bytes.len() > self.max_module_size {
            return Err(WasmGuardError::ModuleTooLarge {
                size: wasm_bytes.len(),
                limit: self.max_module_size,
            });
        }

        let component = Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
        self.component = Some(component);
        self.fuel_limit = fuel_limit;
        Ok(())
    }

    fn evaluate(
        &mut self,
        request: &crate::abi::GuardRequest,
    ) -> Result<GuardVerdict, WasmGuardError> {
        let component = self
            .component
            .as_ref()
            .ok_or(WasmGuardError::BackendUnavailable)?;

        let host_state = WasmHostState::with_memory_limit_and_bundle_store(
            self.config.clone(),
            self.max_memory_bytes,
            Arc::clone(&self.bundle_store),
        );
        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.fuel_limit)
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

        let mut linker = Linker::<WasmHostState>::new(&self.engine);
        register_component_host_functions(&mut linker, |state| state)?;

        let bindings = pollster::block_on(Guard::instantiate_async(&mut store, component, &linker))
            .map_err(|e: wasmtime::Error| WasmGuardError::Trap(e.to_string()))?;

        // Convert request to WIT-generated type
        let wit_request = to_wit_request(request);

        // Call the exported evaluate function
        let wit_verdict = pollster::block_on(bindings.call_evaluate(&mut store, &wit_request))
            .map_err(|e: wasmtime::Error| WasmGuardError::Trap(e.to_string()))?;

        // Track fuel consumed
        let remaining = store.get_fuel().unwrap_or(0);
        self.last_fuel_consumed = Some(self.fuel_limit.saturating_sub(remaining));

        Ok(from_wit_verdict(wit_verdict))
    }

    fn backend_name(&self) -> &str {
        "wasmtime-component"
    }

    fn last_fuel_consumed(&self) -> Option<u64> {
        self.last_fuel_consumed
    }
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert the crate's [`crate::abi::GuardRequest`] to the bindgen-generated
/// [`GuardRequest`] for passing across the WIT boundary.
fn to_wit_request(req: &crate::abi::GuardRequest) -> GuardRequest {
    GuardRequest {
        tool_name: req.tool_name.clone(),
        server_id: req.server_id.clone(),
        agent_id: req.agent_id.clone(),
        arguments: serde_json::to_string(&req.arguments).unwrap_or_default(),
        scopes: req.scopes.clone(),
        action_type: req.action_type.clone(),
        extracted_path: req.extracted_path.clone(),
        extracted_target: req.extracted_target.clone(),
        filesystem_roots: req.filesystem_roots.clone(),
        matched_grant_index: req.matched_grant_index.map(|i| i as u32),
    }
}

/// Convert the bindgen-generated [`Verdict`] to the crate's
/// [`GuardVerdict`].
fn from_wit_verdict(v: Verdict) -> GuardVerdict {
    match v {
        Verdict::Allow => GuardVerdict::Allow,
        Verdict::Deny(reason) => GuardVerdict::Deny {
            reason: Some(reason),
        },
    }
}
