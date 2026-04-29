//! Unified `chio.yaml` configuration loader for the Chio runtime.
//!
//! This crate handles:
//! - Parsing the `chio.yaml` file format with `serde::Deserialize` + `deny_unknown_fields`
//! - Environment variable interpolation (`${VAR}` and `${VAR:-default}`)
//! - Post-deserialization validation (duplicate IDs, broken references, incomplete auth)
//! - Sensible defaults so a minimal config needs only `kernel` + one adapter

pub mod interpolation;
pub mod loader;
pub mod schema;
pub mod validation;

#[cfg(feature = "fuzz")]
pub mod fuzz;

// Re-export the main entry points for convenience.
pub use loader::{load_from_file, load_from_str};
pub use schema::{
    AdapterAuthConfig, AdapterConfig, ChioConfig, EdgeConfig, GuardsConfig, KernelConfig,
    LoggingConfig, ReceiptsConfig, TelemetrySection, WasmGuardEntry,
};

/// Errors produced during configuration loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// File could not be read.
    #[error("IO error: {0}")]
    Io(String),

    /// Environment variable interpolation failed (unset variable with no default).
    #[error("interpolation error: {0}")]
    Interpolation(String),

    /// YAML parsing or deserialization failed (including `deny_unknown_fields`).
    #[error("parse error: {0}")]
    Parse(String),

    /// Post-deserialization validation found one or more problems.
    #[error("validation errors:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Validation(Vec<String>),
}
