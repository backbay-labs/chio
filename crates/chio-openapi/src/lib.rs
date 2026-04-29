//! OpenAPI 3.x spec parser and Chio `ToolManifest` generator.
//!
//! This crate parses OpenAPI 3.0 and 3.1 specifications (both YAML and JSON)
//! and generates Chio `ToolManifest` values where each route becomes a
//! `ToolDefinition` with input schema derived from path, query, and body
//! parameters.

mod extensions;
mod generator;
mod parser;
mod policy;

pub use extensions::{ChioExtensions, Sensitivity};
pub use generator::{GeneratorConfig, ManifestGenerator};
pub use parser::{OpenApiSpec, Operation, Parameter, ParameterLocation, PathItem};
pub use policy::{DefaultPolicy, PolicyDecision};

use thiserror::Error;

/// Errors produced by the OpenAPI parser and manifest generator.
#[derive(Debug, Error)]
pub enum OpenApiError {
    /// The input is not valid JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The input is not valid YAML.
    #[error("invalid YAML: {0}")]
    InvalidYaml(#[from] serde_yaml::Error),

    /// The OpenAPI spec is missing a required field.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// The OpenAPI version is not supported.
    #[error("unsupported OpenAPI version: {0}")]
    UnsupportedVersion(String),

    /// A `$ref` could not be resolved.
    #[error("unresolved reference: {0}")]
    UnresolvedRef(String),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, OpenApiError>;

/// Convenience function: parse an OpenAPI spec from a string (auto-detecting
/// JSON vs YAML) and generate a list of `ToolDefinition` values.
///
/// For more control, use `OpenApiSpec::parse` and `ManifestGenerator`
/// directly.
pub fn tools_from_spec(input: &str) -> Result<Vec<chio_core_types::ToolDefinition>> {
    let spec = OpenApiSpec::parse(input)?;
    let generator = ManifestGenerator::new(GeneratorConfig::default());
    Ok(generator.generate_tools(&spec))
}
