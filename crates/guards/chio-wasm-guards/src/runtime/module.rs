use std::sync::Mutex;

use chio_kernel::KernelError;

use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::epoch::EpochId;
use crate::error::WasmGuardError;

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

    pub(crate) fn evaluate(
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

    pub(crate) fn clear_instance_pre_cache(&self) {
        let mut backend = match self.backend.lock() {
            Ok(backend) => backend,
            Err(poisoned) => poisoned.into_inner(),
        };
        backend.clear_instance_pre_cache();
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
