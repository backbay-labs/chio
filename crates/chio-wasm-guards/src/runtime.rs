//! WASM guard runtime and kernel integration.
//!
//! This module provides `WasmGuard` which implements `chio_kernel::Guard` and
//! `WasmGuardRuntime` which manages a collection of loaded WASM guards.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chio_kernel::{Guard, GuardContext, KernelError, Verdict};
use tracing::{debug, warn};

use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::config::WasmGuardConfig;
use crate::epoch::EpochId;
use crate::error::WasmGuardError;
use crate::observability::{
    guard_digest_or_unknown, guard_evaluate_span, DEFAULT_GUARD_VERSION, VERDICT_ALLOW,
    VERDICT_DENY, VERDICT_ERROR,
};

// ---------------------------------------------------------------------------
// WasmGuard -- single WASM guard implementing chio_kernel::Guard
// ---------------------------------------------------------------------------

/// Loaded WASM module state for one guard epoch.
///
/// The runtime publishes new module epochs by swapping an `Arc<LoadedModule>`.
/// Evaluations take a single `load_full()` snapshot and keep using that module
/// even if a later reload publishes a newer epoch.
pub struct LoadedModule {
    /// Monotonic epoch identifier for this loaded module.
    epoch_id: EpochId,
    /// The loaded WASM backend, behind a Mutex for interior mutability.
    backend: Mutex<Box<dyn WasmGuardAbi>>,
    /// SHA-256 hex digest of the guard manifest, if loaded from a manifest.
    manifest_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct LastEvaluationEvidence {
    epoch_id: EpochId,
    manifest_sha256: Option<String>,
    fuel_consumed: Option<u64>,
}

impl LoadedModule {
    /// Create a loaded module epoch from an initialized backend.
    #[must_use]
    pub fn new(
        backend: Box<dyn WasmGuardAbi>,
        epoch_id: EpochId,
        manifest_sha256: Option<String>,
    ) -> Self {
        Self {
            epoch_id,
            backend: Mutex::new(backend),
            manifest_sha256,
        }
    }

    /// Return this module's epoch identifier.
    #[must_use]
    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    /// Returns the SHA-256 hex digest of the guard manifest, if set.
    #[must_use]
    pub fn manifest_sha256(&self) -> Option<&str> {
        self.manifest_sha256.as_deref()
    }

    fn evaluate(
        &self,
        request: &GuardRequest,
    ) -> Result<(Result<GuardVerdict, WasmGuardError>, Option<u64>), KernelError> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|e| KernelError::Internal(format!("WASM guard mutex poisoned: {e}")))?;

        let result = backend.evaluate(request);
        let fuel = backend.last_fuel_consumed();
        Ok((result, fuel))
    }
}

impl std::fmt::Debug for LoadedModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedModule")
            .field("epoch_id", &self.epoch_id)
            .field("manifest_sha256", &self.manifest_sha256.as_deref())
            .finish()
    }
}

/// A single WASM guard module loaded into the runtime.
///
/// Wraps a swappable `LoadedModule` and adapts it to the kernel's `Guard`
/// trait. On any error (fuel exhaustion, traps, serialization failures) the
/// guard fails closed and returns `Verdict::Deny`.
///
/// Carries optional receipt metadata: `manifest_sha256` (set at construction
/// from the guard manifest) plus the module epoch used by the most recent
/// `evaluate()` call.
pub struct WasmGuard {
    /// Guard name (from config).
    name: String,
    /// Guard semantic version from policy or manifest metadata.
    version: String,
    /// Current loaded module epoch.
    loaded: ArcSwap<LoadedModule>,
    /// Serializes module swaps with rollback baseline capture.
    reload_lock: Mutex<()>,
    /// Next epoch identifier reserved for future module swaps.
    next_epoch_id: AtomicU64,
    /// Latest reload sequence observed for this guard.
    reload_seq: AtomicU64,
    /// Whether this guard is advisory-only (non-blocking).
    advisory: bool,
    /// Evidence metadata captured from the most recent `evaluate()` call.
    last_evaluation_evidence: Mutex<Option<LastEvaluationEvidence>>,
}

impl WasmGuard {
    /// Create a new WASM guard from a loaded backend.
    ///
    /// `manifest_sha256` is the hex-encoded SHA-256 digest of the guard's
    /// manifest file, used for receipt metadata. Pass `None` when loading
    /// without a manifest (e.g. in tests).
    pub fn new(
        name: String,
        backend: Box<dyn WasmGuardAbi>,
        advisory: bool,
        manifest_sha256: Option<String>,
    ) -> Self {
        Self::new_with_metadata(
            name,
            DEFAULT_GUARD_VERSION.to_string(),
            backend,
            advisory,
            manifest_sha256,
        )
    }

    /// Create a new WASM guard with explicit guard metadata.
    pub fn new_with_metadata(
        name: String,
        version: String,
        backend: Box<dyn WasmGuardAbi>,
        advisory: bool,
        manifest_sha256: Option<String>,
    ) -> Self {
        Self {
            name,
            version,
            loaded: ArcSwap::from_pointee(LoadedModule::new(
                backend,
                EpochId::INITIAL,
                manifest_sha256,
            )),
            reload_lock: Mutex::new(()),
            next_epoch_id: AtomicU64::new(1),
            reload_seq: AtomicU64::new(0),
            advisory,
            last_evaluation_evidence: Mutex::new(None),
        }
    }

    /// Returns `true` if this guard is advisory-only.
    #[must_use]
    pub fn is_advisory(&self) -> bool {
        self.advisory
    }

    /// Returns the guard semantic version attached to tracing metadata.
    #[must_use]
    pub fn guard_version(&self) -> &str {
        &self.version
    }

    /// Returns the SHA-256 hex digest of the guard manifest, if set.
    #[must_use]
    pub fn manifest_sha256(&self) -> Option<String> {
        self.loaded
            .load()
            .manifest_sha256()
            .map(ToString::to_string)
    }

    /// Return a snapshot of the currently loaded module.
    #[must_use]
    pub fn loaded_module(&self) -> Arc<LoadedModule> {
        self.loaded.load_full()
    }

    /// Return the epoch identifier of the currently loaded module.
    #[must_use]
    pub fn current_epoch_id(&self) -> EpochId {
        self.loaded.load().epoch_id()
    }

    /// Return the latest observed reload sequence for this guard.
    #[must_use]
    pub fn current_reload_seq(&self) -> u64 {
        self.reload_seq.load(Ordering::SeqCst)
    }

    /// Record the latest reload sequence for evaluation spans.
    pub fn record_reload_seq(&self, reload_seq: u64) {
        self.reload_seq.store(reload_seq, Ordering::SeqCst);
    }

    /// Reserve and return the next monotonic epoch identifier.
    ///
    /// Returns `None` if the counter is already exhausted.
    pub fn reserve_next_epoch_id(&self) -> Option<EpochId> {
        let next = self
            .next_epoch_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .ok()?;
        Some(EpochId::new(next))
    }

    /// Replace the current loaded module with a new backend and return its
    /// assigned epoch identifier.
    pub fn replace_loaded_module(
        &self,
        backend: Box<dyn WasmGuardAbi>,
        manifest_sha256: Option<String>,
    ) -> Option<EpochId> {
        self.replace_loaded_module_with_previous(backend, manifest_sha256)
            .map(|(_, epoch_id)| epoch_id)
    }

    /// Replace the loaded module and return the previous module snapshot.
    pub fn replace_loaded_module_with_previous(
        &self,
        backend: Box<dyn WasmGuardAbi>,
        manifest_sha256: Option<String>,
    ) -> Option<(Arc<LoadedModule>, EpochId)> {
        let _reload_guard = match self.reload_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous = self.loaded.load_full();
        let epoch_id = self.reserve_next_epoch_id()?;
        self.loaded.store(Arc::new(LoadedModule::new(
            backend,
            epoch_id,
            manifest_sha256,
        )));
        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = None;
        }
        Some((previous, epoch_id))
    }

    /// Restore a previously loaded module snapshot.
    ///
    /// Used by the hot-reload watchdog to roll back a published epoch without
    /// recompiling the prior module.
    pub fn restore_loaded_module(&self, module: Arc<LoadedModule>) {
        let _reload_guard = match self.reload_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.loaded.store(module);
        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = None;
        }
    }

    /// Returns the fuel consumed during the most recent `evaluate()` call,
    /// or `None` if no evaluation has occurred or the backend does not track
    /// fuel.
    #[must_use]
    pub fn last_fuel_consumed(&self) -> Option<u64> {
        self.last_evaluation_evidence
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|evidence| evidence.fuel_consumed))
    }

    /// Returns a JSON object containing receipt metadata from the most
    /// recent evaluation: `fuel_consumed` and `manifest_sha256`.
    #[must_use]
    pub fn guard_evidence_metadata(&self) -> serde_json::Value {
        if let Ok(evidence) = self.last_evaluation_evidence.lock() {
            if let Some(evidence) = evidence.as_ref() {
                return serde_json::json!({
                    "epoch_id": evidence.epoch_id.get(),
                    "fuel_consumed": evidence.fuel_consumed,
                    "manifest_sha256": evidence.manifest_sha256,
                });
            }
        }
        let loaded = self.loaded.load();
        serde_json::json!({
            "epoch_id": loaded.epoch_id().get(),
            "fuel_consumed": null,
            "manifest_sha256": loaded.manifest_sha256(),
        })
    }

    pub(crate) fn build_request(ctx: &GuardContext<'_>) -> GuardRequest {
        use chio_guards::ToolAction;

        let scopes = ctx
            .scope
            .grants
            .iter()
            .map(|g| format!("{}:{}", g.server_id, g.tool_name))
            .collect();

        let action = chio_guards::extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let (action_type, extracted_path, extracted_target) = match &action {
            ToolAction::FileAccess(path) => (Some("file_access".into()), Some(path.clone()), None),
            ToolAction::FileWrite(path, _) => (Some("file_write".into()), Some(path.clone()), None),
            ToolAction::NetworkEgress(host, _) => {
                (Some("network_egress".into()), None, Some(host.clone()))
            }
            ToolAction::ShellCommand(_) => (Some("shell_command".into()), None, None),
            ToolAction::McpTool(_, _) => (Some("mcp_tool".into()), None, None),
            ToolAction::Patch(path, _) => (Some("patch".into()), Some(path.clone()), None),
            ToolAction::CodeExecution { language, .. } => {
                (Some("code_execution".into()), None, Some(language.clone()))
            }
            ToolAction::BrowserAction { verb, target } => (
                Some("browser_action".into()),
                None,
                target.clone().or_else(|| Some(verb.clone())),
            ),
            ToolAction::DatabaseQuery { database, .. } => {
                (Some("database_query".into()), None, Some(database.clone()))
            }
            ToolAction::ExternalApiCall { service, endpoint } => (
                Some("external_api_call".into()),
                None,
                Some(format!("{service}:{endpoint}")),
            ),
            ToolAction::MemoryWrite { store, key } => (
                Some("memory_write".into()),
                None,
                Some(format!("{store}/{key}")),
            ),
            ToolAction::MemoryRead { store, key } => (
                Some("memory_read".into()),
                None,
                Some(match key {
                    Some(k) => format!("{store}/{k}"),
                    None => store.clone(),
                }),
            ),
            ToolAction::Unknown => (Some("unknown".into()), None, None),
        };

        let filesystem_roots = ctx
            .session_filesystem_roots
            .map(|roots| roots.to_vec())
            .unwrap_or_default();

        GuardRequest {
            tool_name: ctx.request.tool_name.clone(),
            server_id: ctx.server_id.clone(),
            agent_id: ctx.agent_id.clone(),
            arguments: ctx.request.arguments.clone(),
            scopes,
            action_type,
            extracted_path,
            extracted_target,
            filesystem_roots,
            matched_grant_index: ctx.matched_grant_index,
        }
    }
}

impl std::fmt::Debug for WasmGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmGuard")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("advisory", &self.advisory)
            .finish()
    }
}

impl Guard for WasmGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let request = Self::build_request(ctx);
        let loaded = self.loaded.load_full();
        let span = guard_evaluate_span(
            &self.name,
            &self.version,
            guard_digest_or_unknown(loaded.manifest_sha256()),
            loaded.epoch_id().get(),
            self.current_reload_seq(),
            None,
        );
        let _span_guard = span.enter();

        let (result, fuel) = match loaded.evaluate(&request) {
            Ok(value) => value,
            Err(err) => {
                span.record("verdict", VERDICT_ERROR);
                return Err(err);
            }
        };

        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = Some(LastEvaluationEvidence {
                epoch_id: loaded.epoch_id(),
                manifest_sha256: loaded.manifest_sha256().map(ToString::to_string),
                fuel_consumed: fuel,
            });
        }

        match result {
            Ok(GuardVerdict::Allow) => {
                span.record("verdict", VERDICT_ALLOW);
                debug!(
                    guard = %self.name,
                    epoch_id = loaded.epoch_id().get(),
                    "WASM guard allowed request"
                );
                Ok(Verdict::Allow)
            }
            Ok(GuardVerdict::Deny { reason }) => {
                let reason_str = reason.as_deref().unwrap_or("denied by WASM guard");
                span.record("verdict", VERDICT_DENY);
                if self.advisory {
                    debug!(
                        guard = %self.name,
                        epoch_id = loaded.epoch_id().get(),
                        reason = %reason_str,
                        "WASM advisory guard denied (non-blocking)"
                    );
                    Ok(Verdict::Allow)
                } else {
                    warn!(
                        guard = %self.name,
                        epoch_id = loaded.epoch_id().get(),
                        reason = %reason_str,
                        "WASM guard denied request"
                    );
                    Ok(Verdict::Deny)
                }
            }
            Err(e) => {
                // Fail closed: any error during WASM execution denies.
                span.record("verdict", VERDICT_ERROR);
                warn!(
                    guard = %self.name,
                    epoch_id = loaded.epoch_id().get(),
                    error = %e,
                    "WASM guard error, failing closed"
                );
                if self.advisory {
                    Ok(Verdict::Allow)
                } else {
                    Ok(Verdict::Deny)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WasmGuardRuntime -- manages multiple WASM guards
// ---------------------------------------------------------------------------

/// Runtime that manages a collection of loaded WASM guard modules.
///
/// Guards are sorted by priority (lower = earlier) before evaluation.
pub struct WasmGuardRuntime {
    guards: Vec<WasmGuard>,
}

impl WasmGuardRuntime {
    /// Create a new empty runtime.
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    /// Register a pre-loaded WASM guard.
    pub fn add_guard(&mut self, guard: WasmGuard) {
        self.guards.push(guard);
    }

    /// Load a WASM guard from a configuration entry and a backend factory.
    ///
    /// The `factory` closure receives the raw WASM bytes and fuel limit,
    /// and must return a loaded `WasmGuardAbi` implementation.
    pub fn load_guard<F>(
        &mut self,
        config: &WasmGuardConfig,
        factory: F,
    ) -> Result<(), WasmGuardError>
    where
        F: FnOnce(&[u8], u64) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError>,
    {
        let wasm_bytes = std::fs::read(&config.path).map_err(|e| WasmGuardError::ModuleLoad {
            path: config.path.clone(),
            reason: e.to_string(),
        })?;

        // WGSEC-03: Pre-check module size before passing to the factory
        if wasm_bytes.len() > config.max_module_size {
            return Err(WasmGuardError::ModuleTooLarge {
                size: wasm_bytes.len(),
                limit: config.max_module_size,
            });
        }

        let backend = factory(&wasm_bytes, config.fuel_limit)?;

        self.guards.push(WasmGuard::new(
            config.name.clone(),
            backend,
            config.advisory,
            None, // manifest_sha256 -- Plan 02 will pass the real value
        ));

        Ok(())
    }

    /// Return the number of loaded guards.
    #[must_use]
    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    /// Return an iterator over the loaded guards as `&dyn Guard`.
    pub fn guards(&self) -> impl Iterator<Item = &WasmGuard> {
        self.guards.iter()
    }

    /// Convert this runtime into a vector of boxed `Guard` trait objects
    /// suitable for registering on the kernel.
    pub fn into_guards(self) -> Vec<Box<dyn Guard>> {
        self.guards
            .into_iter()
            .map(|g| Box::new(g) as Box<dyn Guard>)
            .collect()
    }
}

impl Default for WasmGuardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Mock backend for testing
// ---------------------------------------------------------------------------

/// A mock WASM guard backend for testing.
///
/// Returns a fixed verdict for every invocation.
pub struct MockWasmBackend {
    verdict: GuardVerdict,
    loaded: bool,
}

impl MockWasmBackend {
    /// Create a mock backend that always allows.
    pub fn allowing() -> Self {
        Self {
            verdict: GuardVerdict::Allow,
            loaded: false,
        }
    }

    /// Create a mock backend that always denies with the given reason.
    pub fn denying(reason: &str) -> Self {
        Self {
            verdict: GuardVerdict::Deny {
                reason: Some(reason.to_string()),
            },
            loaded: false,
        }
    }
}

impl WasmGuardAbi for MockWasmBackend {
    fn load_module(&mut self, _wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        self.loaded = true;
        Ok(())
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        if !self.loaded {
            return Err(WasmGuardError::BackendUnavailable);
        }
        Ok(self.verdict.clone())
    }

    fn backend_name(&self) -> &str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// Wasmtime backend (behind feature flag)
// ---------------------------------------------------------------------------

#[cfg(feature = "wasmtime-runtime")]
pub mod wasmtime_backend {
    //! Wasmtime-based WASM guard backend.
    //!
    //! Requires the `wasmtime-runtime` feature.

    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::host::{create_shared_engine, register_host_functions, WasmHostState};
    use wasmtime::{Engine, Linker, Memory, Module, Store};

    use crate::host::MAX_MEMORY_BYTES;

    /// Default maximum module size in bytes (10 MiB).
    const DEFAULT_MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;

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

    /// Load a WASM guard enforcing the Phase 1.3 signing policy.
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

        let verify_span = crate::observability::guard_verify_span(
            crate::observability::VERIFY_MODE_ED25519,
            None,
        );
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
    }

    impl WasmtimeBackend {
        /// Create a new Wasmtime backend with its own shared engine.
        ///
        /// For backward compatibility; callers that want to share an engine
        /// across multiple guards should use [`with_engine`] instead.
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
            }
        }

        /// Create a Wasmtime backend with a shared engine and guard-specific
        /// config that will be accessible to guests via `chio.get_config`.
        pub fn with_engine_and_config(
            engine: Arc<Engine>,
            config: HashMap<String, String>,
        ) -> Self {
            Self {
                engine,
                module: None,
                fuel_limit: 0,
                config,
                max_memory_bytes: MAX_MEMORY_BYTES,
                max_module_size: DEFAULT_MAX_MODULE_SIZE,
                last_fuel_consumed: None,
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
                },
            }
        }
    }

    impl WasmGuardAbi for WasmtimeBackend {
        fn load_module(
            &mut self,
            wasm_bytes: &[u8],
            fuel_limit: u64,
        ) -> Result<(), WasmGuardError> {
            // WGSEC-03: Reject oversized modules before compilation
            if wasm_bytes.len() > self.max_module_size {
                return Err(WasmGuardError::ModuleTooLarge {
                    size: wasm_bytes.len(),
                    limit: self.max_module_size,
                });
            }

            let module = Module::new(&self.engine, wasm_bytes)
                .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;

            // WGSEC-02: Validate that all imports come from the "chio" namespace
            for import in module.imports() {
                if import.module() != "chio" {
                    return Err(WasmGuardError::ImportViolation {
                        module: import.module().to_string(),
                        name: import.name().to_string(),
                    });
                }
            }

            self.module = Some(module);
            self.fuel_limit = fuel_limit;
            Ok(())
        }

        fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
            let module = self
                .module
                .as_ref()
                .ok_or(WasmGuardError::BackendUnavailable)?;

            // WGSEC-01: Create a fresh Store with configurable memory limit
            let host_state =
                WasmHostState::with_memory_limit(self.config.clone(), self.max_memory_bytes);
            let mut store = Store::new(&self.engine, host_state);
            store.limiter(|state| &mut state.limits);
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

            // Create a Linker with host functions registered
            let mut linker: Linker<WasmHostState> = Linker::new(&self.engine);
            register_host_functions(&mut linker)?;

            let instance = pollster::block_on(linker.instantiate_async(&mut store, module))
                .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

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
                        if ptr >= 0
                            && (ptr as usize).saturating_add(request_len as usize) <= mem_size
                        {
                            ptr
                        } else {
                            // Out-of-bounds pointer -- fall back to offset 0
                            tracing::warn!(
                                ptr = ptr,
                                request_len = request_len,
                                mem_size = mem_size,
                                "chio_alloc returned out-of-bounds pointer, falling back to offset 0"
                            );
                            0
                        }
                    }
                    Err(e) => {
                        // chio_alloc call failed -- fall back to offset 0
                        tracing::warn!(
                            error = %e,
                            "chio_alloc call failed, falling back to offset 0"
                        );
                        0
                    }
                }
            } else {
                // No chio_alloc export -- use legacy offset-0 protocol
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
                        // Fallback to legacy offset-64K NUL-terminated string
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
            Err(_) => return None, // call failed -- no reason
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
    // Phase 5.6: Policy-driven loading with placeholders and capability
    // intersection.
    // -------------------------------------------------------------------

    use crate::manifest::GuardManifest;
    use crate::placeholders::{resolve_placeholders_in_json, PlaceholderEnv, PlaceholderError};
    use sha2::Digest;

    /// Names of `chio.*` host functions Chio currently exposes to guests.
    ///
    /// Operators can pass a subset of this list as `policy_allowed_host_fns`
    /// to [`load_guards_from_policy`] to restrict which capabilities any
    /// custom guard may request.
    pub const KNOWN_HOST_FUNCTIONS: &[&str] =
        &["chio.log", "chio.get_config", "chio.get_time_unix_secs"];

    /// A single WASM guard declared in the policy YAML.
    ///
    /// This is the Chio-side equivalent of ClawdStrike's `custom.rs` plugin
    /// entry: it names the module, points at its `.wasm` bytes (either on
    /// disk or inline), declares the host-function capabilities the guard
    /// needs, and carries a JSON config blob that may contain `${ENV_VAR}`
    /// placeholders.
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
        /// the Phase 1.3 signing path ([`crate::manifest::verify_guard_signature`]).
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
    ///    Phase 1.3 signing path ([`crate::manifest::verify_guard_signature`])
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

            // 3. Obtain bytes and enforce Phase 1.3 signing.
            let wasm_bytes = match &guard_spec.module {
                PolicyModuleSource::Path { module_path } => {
                    let bytes = std::fs::read(module_path).map_err(|e| {
                        LoadError::Runtime(WasmGuardError::ModuleLoad {
                            path: module_path.clone(),
                            reason: e.to_string(),
                        })
                    })?;

                    // Build a transient GuardManifest describing just the
                    // identity + signer, so we can reuse the Phase 1.3
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
                    crate::manifest::verify_guard_signature(
                        module_path,
                        &bytes,
                        &transient_manifest,
                    )
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
        if detect_wasm_format(wasm_bytes).unwrap_or(WasmFormat::CoreModule)
            != WasmFormat::CoreModule
        {
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

    // -----------------------------------------------------------------------
    // Tests for wasmtime_backend
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::abi::GuardRequest;

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
        fn chio_alloc_oob_falls_back() {
            // WAT module with chio_alloc that returns 999_999_999 (out-of-bounds).
            // evaluate checks that ptr == 0 (proving fallback occurred).
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
                        ;; Return ALLOW (0) only if ptr == 0 (fallback), else DENY (1)
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
                "expected ALLOW (OOB chio_alloc should fall back to offset 0), got: {result:?}"
            );
        }

        #[test]
        fn chio_alloc_negative_falls_back() {
            // WAT module with chio_alloc that returns -1 (negative pointer).
            // evaluate checks that ptr == 0 (proving fallback occurred).
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
                        ;; Return ALLOW (0) only if ptr == 0 (fallback), else DENY (1)
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
                "expected ALLOW (negative chio_alloc should fall back to offset 0), got: {result:?}"
            );
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
        fn chio_deny_reason_fallback_legacy() {
            // WAT module WITHOUT chio_deny_reason export.
            // Has a NUL-terminated string at offset 65536 ("legacy reason\0").
            let wat = r#"
                (module
                    (import "chio" "log" (func $log (param i32 i32 i32)))
                    (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (data (i32.const 65536) "legacy reason\00")
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
                        Some("legacy reason"),
                        "expected legacy deny reason from offset 64K"
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
        // Security enforcement tests (WGSEC-01, WGSEC-02, WGSEC-03)
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
            let capability = chio_core::capability::CapabilityToken::sign(
                chio_core::capability::CapabilityTokenBody {
                    id: "cap-fuel-test".to_string(),
                    issuer: issuer.public_key(),
                    subject: subject.public_key(),
                    scope: chio_core::capability::ChioScope::default(),
                    issued_at: 0,
                    expires_at: u64::MAX,
                    delegation_chain: vec![],
                },
                &issuer,
            )
            .unwrap();
            let scope = chio_core::capability::ChioScope::default();
            let tool_request = chio_kernel::ToolCallRequest {
                request_id: "req-fuel-test".to_string(),
                capability,
                tool_name: req.tool_name.clone(),
                server_id: req.server_id.clone(),
                agent_id: req.agent_id.clone(),
                arguments: req.arguments.clone(),
                dpop_proof: None,
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
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::ChioScope;
    use chio_kernel::{GuardContext, ToolCallRequest};

    fn make_test_request() -> ToolCallRequest {
        ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: chio_core::capability::CapabilityToken::sign(
                chio_core::capability::CapabilityTokenBody {
                    id: "cap-1".to_string(),
                    issuer: chio_core::crypto::Keypair::generate().public_key(),
                    subject: chio_core::crypto::Keypair::generate().public_key(),
                    scope: ChioScope::default(),
                    issued_at: 0,
                    expires_at: u64::MAX,
                    delegation_chain: vec![],
                },
                &chio_core::crypto::Keypair::generate(),
            )
            .unwrap(),
            tool_name: "test_tool".to_string(),
            server_id: "test_server".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({"key": "value"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn mock_allow_backend() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-allow".to_string(), Box::new(backend), false, None);

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Allow)));
    }

    #[test]
    fn mock_deny_backend() {
        let mut backend = MockWasmBackend::denying("blocked by test");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-deny".to_string(), Box::new(backend), false, None);

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Deny)));
    }

    #[test]
    fn advisory_guard_allows_on_deny() {
        let mut backend = MockWasmBackend::denying("advisory denial");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-advisory".to_string(), Box::new(backend), true, None);
        assert!(guard.is_advisory());

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        // Advisory guards should allow even when the backend denies
        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Allow)));
    }

    #[test]
    fn runtime_manages_multiple_guards() {
        let mut runtime = WasmGuardRuntime::new();
        assert_eq!(runtime.guard_count(), 0);

        let mut b1 = MockWasmBackend::allowing();
        b1.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g1".to_string(), Box::new(b1), false, None));

        let mut b2 = MockWasmBackend::denying("no");
        b2.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g2".to_string(), Box::new(b2), false, None));

        assert_eq!(runtime.guard_count(), 2);

        let boxed = runtime.into_guards();
        assert_eq!(boxed.len(), 2);
    }

    #[test]
    fn guard_request_serialization() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GuardRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tool_name, "read_file");
        assert_eq!(deserialized.scopes.len(), 1);
    }

    #[test]
    fn guard_verdict_helpers() {
        let allow = GuardVerdict::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());

        let deny = GuardVerdict::Deny {
            reason: Some("bad".to_string()),
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
    }

    #[test]
    fn unloaded_mock_fails() {
        let mut backend = MockWasmBackend::allowing();
        // Do NOT call load_module
        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let result = backend.evaluate(&req);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // build_request enrichment tests
    // -------------------------------------------------------------------

    fn make_test_request_with(tool_name: &str, arguments: serde_json::Value) -> ToolCallRequest {
        ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: chio_core::capability::CapabilityToken::sign(
                chio_core::capability::CapabilityTokenBody {
                    id: "cap-1".to_string(),
                    issuer: chio_core::crypto::Keypair::generate().public_key(),
                    subject: chio_core::crypto::Keypair::generate().public_key(),
                    scope: ChioScope::default(),
                    issued_at: 0,
                    expires_at: u64::MAX,
                    delegation_chain: vec![],
                },
                &chio_core::crypto::Keypair::generate(),
            )
            .unwrap(),
            tool_name: tool_name.to_string(),
            server_id: "test_server".to_string(),
            agent_id: "agent-1".to_string(),
            arguments,
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn build_request_action_type_file_access() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.action_type.as_deref(), Some("file_access"));
    }

    #[test]
    fn build_request_extracted_path_for_file_access() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.extracted_path.as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn build_request_action_type_network_egress() {
        let request = make_test_request_with(
            "fetch",
            serde_json::json!({"url": "https://example.com/api"}),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.action_type.as_deref(), Some("network_egress"));
        assert_eq!(req.extracted_target.as_deref(), Some("example.com"));
        assert!(
            req.extracted_path.is_none(),
            "network_egress should not set extracted_path"
        );
    }

    #[test]
    fn build_request_filesystem_roots_from_context() {
        let request = make_test_request_with(
            "read_file",
            serde_json::json!({"path": "/home/user/file.txt"}),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();
        let roots = vec!["/home".to_string(), "/tmp".to_string()];

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: Some(&roots),
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(
            req.filesystem_roots,
            vec!["/home".to_string(), "/tmp".to_string()]
        );
    }

    #[test]
    fn build_request_matched_grant_index_from_context() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(3),
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.matched_grant_index, Some(3));
    }

    #[test]
    fn build_request_action_type_unknown_for_unrecognized_tool() {
        let request = make_test_request_with("test_tool", serde_json::json!({"key": "value"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        // "test_tool" is not a recognized filesystem/network/shell tool,
        // so extract_action returns McpTool (fallback) which we map to "mcp_tool"
        assert_eq!(req.action_type.as_deref(), Some("mcp_tool"));
    }

    // -------------------------------------------------------------------
    // Receipt metadata tests (manifest_sha256, fuel_consumed, evidence)
    // -------------------------------------------------------------------

    #[test]
    fn wasm_guard_stores_manifest_sha256() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-hash".to_string(),
            Box::new(backend),
            false,
            Some("abcdef0123456789".to_string()),
        );
        assert_eq!(guard.manifest_sha256().as_deref(), Some("abcdef0123456789"));
    }

    #[test]
    fn wasm_guard_manifest_sha256_none_when_unset() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-no-hash".to_string(), Box::new(backend), false, None);
        assert!(guard.manifest_sha256().is_none());
    }

    #[test]
    fn wasm_guard_last_fuel_consumed_none_before_evaluate() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-fuel".to_string(), Box::new(backend), false, None);
        assert!(guard.last_fuel_consumed().is_none());
    }

    #[test]
    fn wasm_guard_initial_epoch_id_is_zero() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-epoch".to_string(), Box::new(backend), false, None);

        assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
        assert_eq!(guard.loaded_module().epoch_id(), EpochId::INITIAL);
    }

    #[test]
    fn wasm_guard_replace_loaded_module_assigns_monotonic_epoch_ids() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();
        let guard = WasmGuard::new("test-epoch".to_string(), Box::new(backend), false, None);

        let mut next_backend = MockWasmBackend::allowing();
        next_backend.load_module(b"next", 1000).unwrap();
        let first_replacement = guard
            .replace_loaded_module(Box::new(next_backend), Some("epoch-one".to_string()))
            .unwrap();

        let mut third_backend = MockWasmBackend::allowing();
        third_backend.load_module(b"third", 1000).unwrap();
        let second_replacement = guard
            .replace_loaded_module(Box::new(third_backend), Some("epoch-two".to_string()))
            .unwrap();

        assert_eq!(first_replacement, EpochId::new(1));
        assert_eq!(second_replacement, EpochId::new(2));
        assert!(first_replacement < second_replacement);
        assert_eq!(guard.current_epoch_id(), second_replacement);
        assert_eq!(guard.manifest_sha256().as_deref(), Some("epoch-two"));
    }

    #[test]
    fn mock_backend_last_fuel_consumed_returns_none() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let _ = backend.evaluate(&req).unwrap();
        assert!(
            backend.last_fuel_consumed().is_none(),
            "mock backend should not track fuel"
        );
    }

    #[test]
    fn guard_evidence_metadata_returns_json_structure() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-evidence".to_string(),
            Box::new(backend),
            false,
            Some("sha256hex".to_string()),
        );

        let evidence = guard.guard_evidence_metadata();
        assert!(evidence.is_object());
        assert!(evidence.get("fuel_consumed").is_some());
        assert!(
            evidence["fuel_consumed"].is_null(),
            "fuel should be null before evaluate"
        );
        assert_eq!(evidence["manifest_sha256"], "sha256hex");
    }

    #[test]
    fn guard_evidence_metadata_null_when_no_manifest() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-evidence-null".to_string(),
            Box::new(backend),
            false,
            None,
        );

        let evidence = guard.guard_evidence_metadata();
        assert!(evidence["manifest_sha256"].is_null());
    }
}
