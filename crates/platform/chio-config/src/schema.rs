//! Configuration schema types for `chio.yaml`.
//!
//! Every struct uses `deny_unknown_fields` so that typos in config keys
//! are caught at parse time rather than silently ignored.

use serde::Deserialize;

/// Root configuration parsed from `chio.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioConfig {
    /// Kernel configuration (required).
    pub kernel: KernelConfig,

    /// Adapter definitions. At least one is required.
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,

    /// Edge definitions (optional).
    #[serde(default)]
    pub edges: Vec<EdgeConfig>,

    /// Receipt store configuration (optional, defaults applied).
    #[serde(default)]
    pub receipts: ReceiptsConfig,

    /// Logging configuration (optional, defaults applied).
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Telemetry configuration for OpenTelemetry export (optional).
    #[serde(default)]
    pub telemetry: TelemetrySection,

    /// Guard pipeline configuration (optional).
    #[serde(default)]
    pub guards: GuardsConfig,

    /// WASM guard modules loaded at runtime (optional).
    #[serde(default)]
    pub wasm_guards: Vec<WasmGuardEntry>,
}

/// Kernel section -- the only section that is always required.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfig {
    /// Ed25519 signing key (hex or "generate" for dev mode).
    pub signing_key: String,

    /// Receipt store URI (e.g., "sqlite:///var/chio/receipts.db").
    #[serde(default = "default_receipt_store")]
    pub receipt_store: String,

    /// Log level override for the kernel.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// A single adapter entry that connects to an upstream API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// Unique identifier for this adapter, referenced by edges.
    pub id: String,

    /// Protocol type: "openapi", "grpc", "graphql", etc.
    pub protocol: String,

    /// Upstream URL of the API being protected.
    pub upstream: String,

    /// Path to the API specification file (e.g., an OpenAPI spec).
    #[serde(default)]
    pub spec: Option<String>,

    /// Authentication configuration for the upstream connection.
    #[serde(default)]
    pub auth: Option<AdapterAuthConfig>,
}

/// Authentication block for an adapter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterAuthConfig {
    /// Auth type: "bearer", "api_key", "cookie", "mtls", "none".
    #[serde(rename = "type")]
    pub auth_type: String,

    /// Header name (required for bearer and api_key types).
    #[serde(default)]
    pub header: Option<String>,
}

/// An edge that exposes an adapter through a different protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Unique identifier for this edge.
    pub id: String,

    /// Edge protocol: "mcp", "a2a", etc.
    pub protocol: String,

    /// Adapter ID that this edge exposes. Must reference an existing adapter.
    pub expose_from: String,
}

/// Receipt store configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptsConfig {
    /// Store URI.
    #[serde(default = "default_receipt_store")]
    pub store: String,

    /// Number of receipts between Merkle checkpoints.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,

    /// How many days to retain receipts.
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
}

impl Default for ReceiptsConfig {
    fn default() -> Self {
        Self {
            store: default_receipt_store(),
            checkpoint_interval: default_checkpoint_interval(),
            retention_days: default_retention_days(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: "json" or "text".
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

/// Telemetry configuration for OpenTelemetry span export.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    /// Whether OTel export is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// OTel collector endpoint (e.g., "http://localhost:4317").
    #[serde(default)]
    pub endpoint: String,

    /// Service name reported to the collector.
    #[serde(default = "default_telemetry_service_name")]
    pub service_name: String,

    /// Whether to include receipt parameters in span attributes.
    /// Disabled by default to avoid leaking sensitive data.
    #[serde(default)]
    pub include_parameters: bool,

    /// Batch size for span export. 0 = export each span immediately.
    #[serde(default)]
    pub batch_size: usize,
}

impl Default for TelemetrySection {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            service_name: default_telemetry_service_name(),
            include_parameters: false,
            batch_size: 0,
        }
    }
}

fn default_telemetry_service_name() -> String {
    "chio-acp-proxy".to_string()
}

/// Guard pipeline configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardsConfig {
    /// Whether advisory signals can be promoted to deterministic guards
    /// via configuration. Defaults to `false`.
    #[serde(default)]
    pub allow_advisory_promotion: bool,

    /// Names of guards that must pass for every request (in addition to
    /// any guards declared on individual routes). Empty by default.
    #[serde(default)]
    pub required: Vec<String>,
}

/// A single WASM guard entry in the `wasm_guards` array.
///
/// Example YAML:
///
/// ```yaml
/// wasm_guards:
///   - name: custom-pii-guard
///     path: /etc/chio/guards/pii_guard.wasm
///     fuel_limit: 5000000
///     priority: 100
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmGuardEntry {
    /// Human-readable name for this guard (used in receipts and logs).
    pub name: String,

    /// Filesystem path to the `.wasm` module.
    pub path: String,

    /// Maximum fuel units the guest may consume per invocation.
    /// Defaults to 10,000,000 if omitted.
    #[serde(default = "default_wasm_fuel_limit")]
    pub fuel_limit: u64,

    /// Guard evaluation priority. Lower values run first.
    /// Defaults to 1000 if omitted.
    #[serde(default = "default_wasm_priority")]
    pub priority: u32,

    /// If true, a failure in this guard is treated as advisory (logged but
    /// not blocking). Defaults to `false` (fail-closed).
    #[serde(default)]
    pub advisory: bool,
}

fn default_wasm_fuel_limit() -> u64 {
    10_000_000
}

fn default_wasm_priority() -> u32 {
    1000
}

// -- Default value functions --

fn default_receipt_store() -> String {
    "sqlite:///var/chio/receipts.db".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_checkpoint_interval() -> u64 {
    100
}

fn default_retention_days() -> u64 {
    90
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_default_values() {
        let r = ReceiptsConfig::default();
        assert_eq!(r.store, "sqlite:///var/chio/receipts.db");
        assert_eq!(r.checkpoint_interval, 100);
        assert_eq!(r.retention_days, 90);
    }

    #[test]
    fn logging_default_values() {
        let l = LoggingConfig::default();
        assert_eq!(l.level, "info");
        assert_eq!(l.format, "json");
    }

    #[test]
    fn deny_unknown_fields_kernel() {
        let yaml = r#"
            signing_key: "generate"
            bogus_field: true
        "#;
        let result: Result<KernelConfig, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn deny_unknown_fields_adapter() {
        let yaml = r#"
            id: "test"
            protocol: "openapi"
            upstream: "http://localhost:8000"
            not_a_field: 42
        "#;
        let result: Result<AdapterConfig, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_adapter_with_auth() {
        let yaml = r#"
            id: "petstore"
            protocol: "openapi"
            upstream: "http://localhost:8000"
            spec: "./petstore.yaml"
            auth:
              type: "bearer"
              header: "Authorization"
        "#;
        let adapter: AdapterConfig =
            serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"));
        assert_eq!(adapter.id, "petstore");
        let auth = adapter.auth.unwrap_or_else(|| panic!("auth missing"));
        assert_eq!(auth.auth_type, "bearer");
        assert_eq!(
            auth.header.unwrap_or_else(|| panic!("header missing")),
            "Authorization"
        );
    }
}
