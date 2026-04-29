//! Error types for the WASM guard runtime.

/// Errors that can occur during WASM guard loading and execution.
#[derive(Debug, thiserror::Error)]
pub enum WasmGuardError {
    /// The `.wasm` module could not be read from disk.
    #[error("failed to read WASM module at {path}: {reason}")]
    ModuleLoad { path: String, reason: String },

    /// The module failed compilation or validation.
    #[error("WASM module compilation failed: {0}")]
    Compilation(String),

    /// The module does not export the required ABI functions.
    #[error("missing required export: {0}")]
    MissingExport(String),

    /// The module's exported function has the wrong signature.
    #[error("invalid export signature for {name}: {reason}")]
    InvalidSignature { name: String, reason: String },

    /// The guest ran out of fuel (CPU budget exhausted).
    #[error("fuel exhausted after {consumed} units (limit: {limit})")]
    FuelExhausted { consumed: u64, limit: u64 },

    /// The guest's memory could not be accessed.
    #[error("guest memory error: {0}")]
    Memory(String),

    /// Serialization or deserialization of the guard request/response failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A runtime trap or unexpected guest abort.
    #[error("WASM trap: {0}")]
    Trap(String),

    /// A host function call failed.
    #[error("host function error: {0}")]
    HostFunction(String),

    /// The module imports from a forbidden (non-chio) namespace.
    #[error("module imports from forbidden namespace \"{module}\": import \"{name}\"")]
    ImportViolation { module: String, name: String },

    /// The module exceeds the configured maximum size.
    #[error("module size {size} bytes exceeds limit of {limit} bytes")]
    ModuleTooLarge { size: usize, limit: usize },

    /// The runtime backend is not available (feature not enabled).
    #[error("WASM runtime backend not available -- enable the 'wasmtime-runtime' feature")]
    BackendUnavailable,

    /// The guard manifest YAML could not be parsed.
    #[error("failed to parse guard manifest: {0}")]
    ManifestParse(String),

    /// The guard manifest could not be read from disk.
    #[error("failed to load guard manifest for {path}: {reason}")]
    ManifestLoad { path: String, reason: String },

    /// SHA-256 hash of the .wasm binary does not match the manifest declaration.
    #[error("wasm hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// The manifest declares an unsupported ABI version.
    #[error("unsupported abi_version \"{version}\" (supported: {supported})")]
    UnsupportedAbiVersion { version: String, supported: String },

    /// The manifest declares a WIT world that this loader does not support.
    #[error("unsupported wit_world {declared}; required \"{required}\". See {migration}")]
    UnsupportedWitWorld {
        declared: String,
        required: String,
        migration: &'static str,
    },

    /// The .wasm binary is neither a valid core module nor a Component Model component.
    #[error("unrecognized WASM format: neither core module nor component")]
    UnrecognizedFormat,

    /// Ed25519 signature verification (or the surrounding envelope check)
    /// failed for a WASM guard module. Emitted by Phase 1.3 signing.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_import_violation_display() {
        let err = WasmGuardError::ImportViolation {
            module: "wasi".to_string(),
            name: "fd_write".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "module imports from forbidden namespace \"wasi\": import \"fd_write\""
        );
    }

    #[test]
    fn error_module_too_large_display() {
        let err = WasmGuardError::ModuleTooLarge {
            size: 20_000_000,
            limit: 10_485_760,
        };
        assert_eq!(
            err.to_string(),
            "module size 20000000 bytes exceeds limit of 10485760 bytes"
        );
    }
}
