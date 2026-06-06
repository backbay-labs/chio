use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::error::WasmGuardError;

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
