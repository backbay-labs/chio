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

/// Kernel default for the maximum capability delegation depth. The file schema
/// does not yet expose this knob, so a config-built kernel takes the same
/// conservative bound the runtime scaffolds use elsewhere.
const DEFAULT_MAX_DELEGATION_DEPTH: u32 = 5;

impl ChioConfig {
    /// Lower this validated file config into the runtime [`chio_kernel::KernelConfig`]
    /// used to construct a `ChioKernel`.
    ///
    /// This is the bridge that makes a loaded `chio.yaml` actually govern kernel
    /// behavior: the operator's `[kernel.deadlines]` budgets flow through
    /// [`KernelDeadlinesFileConfig::to_hot_path_deadline_config`] into the
    /// constructed kernel's `deadlines`, `kernel.signing_key` becomes the
    /// receipt-signing keypair, and the `[receipts]` section governs the
    /// checkpoint cadence (`checkpoint_interval`), retention window
    /// (`retention_days`), and dispatch-intent journal mode
    /// (`dispatch_intent_journal`) rather than silently defaulting them.
    ///
    /// Fields the file schema does not yet express take the kernel's own
    /// defaults, chosen fail-closed: nested sampling and elicitation stay
    /// disabled, no external capability authorities are trusted, and ephemeral
    /// receipt logs are refused so successful dispatch requires durable receipt
    /// persistence. Deployments that need those knobs configure them on the
    /// returned value before construction.
    pub fn to_kernel_config(&self) -> Result<chio_kernel::KernelConfig, crate::ConfigError> {
        let keypair = self.kernel.signing_keypair()?;
        Ok(chio_kernel::KernelConfig {
            keypair,
            ca_public_keys: Vec::new(),
            max_delegation_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            policy_hash: String::new(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            // Fail-closed like the receipt log above: a file-configured
            // deployment must wire a durable revocation store rather than
            // silently accepting an in-memory set that forgets revocations on
            // restart.
            allow_ephemeral_revocation_store: false,
            // Honor the operator's `[receipts]` settings: the checkpoint cadence
            // and the retention window are parsed by this same crate, so they
            // must reach the kernel instead of reverting to hard-coded defaults.
            // The remaining `RetentionConfig` knobs (archive path, size ceiling,
            // tenant scope) are not yet expressed in the file schema and keep
            // their defaults.
            checkpoint_batch_size: self.receipts.checkpoint_interval,
            retention_config: Some(chio_kernel::RetentionConfig {
                retention_days: self.receipts.retention_days,
                ..chio_kernel::RetentionConfig::default()
            }),
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: self.kernel.deadlines.to_hot_path_deadline_config(),
            // Honor the operator's `[receipts].dispatch_intent_journal`: absent
            // means the pre-journal write path (`Off`), matching the staged
            // rollout default, not the enum's own compiled default.
            dispatch_intent_journal: self.receipts.dispatch_intent_journal,
        })
    }
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

    /// Hot-path wall-clock budgets. Optional; validated at load.
    #[serde(default)]
    pub deadlines: KernelDeadlinesFileConfig,
}

impl KernelConfig {
    /// Resolve `signing_key` into the receipt-signing keypair. The literal
    /// `"generate"` mints a fresh ephemeral key for dev mode; any other value is
    /// parsed as a 32-byte Ed25519 seed in lowercase hex.
    pub fn signing_keypair(&self) -> Result<chio_core::crypto::Keypair, crate::ConfigError> {
        if self.signing_key == "generate" {
            return Ok(chio_core::crypto::Keypair::generate());
        }
        chio_core::crypto::Keypair::from_seed_hex(&self.signing_key)
            .map_err(|e| crate::ConfigError::Kernel(format!("invalid kernel.signing_key: {e}")))
    }
}

/// Config-file surface for the runtime hot-path deadline budgets. Only the
/// scalar budgets are exposed here; the per-guard and per-server override maps
/// are set programmatically. All fields optional so an absent
/// `[kernel.deadlines]` table is valid.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelDeadlinesFileConfig {
    #[serde(default)]
    pub guard_pipeline_budget_ms: Option<u64>,
    #[serde(default)]
    pub dispatch_budget_ms: Option<u64>,
    #[serde(default)]
    pub receipt_append_budget_ms: Option<u64>,
    #[serde(default)]
    pub receipt_writer_poll_ms: Option<u64>,
    #[serde(default)]
    pub receipt_writer_stall_ms: Option<u64>,
}

impl KernelDeadlinesFileConfig {
    /// Overlay the file-configured scalar budgets onto the kernel defaults to
    /// produce the runtime deadline config. Each `Some` replaces the matching
    /// field; each `None` keeps the default. This is the bridge that lets an
    /// operator's `[kernel.deadlines]` table actually govern kernel behavior; the
    /// per-guard and per-server override maps are set programmatically, not from
    /// the file, so they retain their defaults.
    pub fn to_hot_path_deadline_config(&self) -> chio_kernel::HotPathDeadlineConfig {
        let mut config = chio_kernel::HotPathDeadlineConfig::default();
        if let Some(ms) = self.guard_pipeline_budget_ms {
            config.guard_pipeline_budget_ms = ms;
        }
        if let Some(ms) = self.dispatch_budget_ms {
            config.dispatch_budget_ms = ms;
        }
        if let Some(ms) = self.receipt_append_budget_ms {
            config.receipt_append_budget_ms = ms;
        }
        if let Some(ms) = self.receipt_writer_poll_ms {
            config.receipt_writer_poll_ms = ms;
        }
        if let Some(ms) = self.receipt_writer_stall_ms {
            config.receipt_writer_stall_ms = ms;
        }
        config
    }
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

    /// Which call classes must durably journal a dispatch intent before
    /// dispatch: `"off"`, `"side_effecting"`, or `"all"`. Absent keeps the
    /// pre-journal write path (`off`), matching the staged rollout; this is
    /// deliberately not the enum's own compiled default (`side_effecting`),
    /// so an existing deployment's file does not silently change behavior
    /// when it upgrades to a binary that understands this key. An
    /// unrecognized value is rejected at config load time rather than
    /// falling back to a default.
    #[serde(default = "default_dispatch_intent_journal")]
    pub dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode,
}

impl Default for ReceiptsConfig {
    fn default() -> Self {
        Self {
            store: default_receipt_store(),
            checkpoint_interval: default_checkpoint_interval(),
            retention_days: default_retention_days(),
            dispatch_intent_journal: default_dispatch_intent_journal(),
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

fn default_dispatch_intent_journal() -> chio_kernel::DispatchIntentJournalMode {
    chio_kernel::DispatchIntentJournalMode::Off
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
        assert_eq!(
            r.dispatch_intent_journal,
            chio_kernel::DispatchIntentJournalMode::Off
        );
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

    #[test]
    fn deadline_scalars_convert_into_kernel_config() {
        let file = KernelDeadlinesFileConfig {
            guard_pipeline_budget_ms: Some(1_500),
            dispatch_budget_ms: Some(2_500),
            receipt_append_budget_ms: Some(750),
            receipt_writer_poll_ms: Some(250),
            receipt_writer_stall_ms: Some(30_000),
        };
        let config = file.to_hot_path_deadline_config();
        assert_eq!(config.guard_pipeline_budget_ms, 1_500);
        assert_eq!(config.dispatch_budget_ms, 2_500);
        assert_eq!(config.receipt_append_budget_ms, 750);
        assert_eq!(config.receipt_writer_poll_ms, 250);
        assert_eq!(config.receipt_writer_stall_ms, 30_000);
    }

    #[test]
    fn absent_deadline_scalars_keep_kernel_defaults() {
        let config = KernelDeadlinesFileConfig::default().to_hot_path_deadline_config();
        let defaults = chio_kernel::HotPathDeadlineConfig::default();
        assert_eq!(
            config.guard_pipeline_budget_ms,
            defaults.guard_pipeline_budget_ms
        );
        assert_eq!(config.dispatch_budget_ms, defaults.dispatch_budget_ms);
        assert_eq!(
            config.receipt_append_budget_ms,
            defaults.receipt_append_budget_ms
        );
        assert_eq!(
            config.receipt_writer_poll_ms,
            defaults.receipt_writer_poll_ms
        );
        assert_eq!(
            config.receipt_writer_stall_ms,
            defaults.receipt_writer_stall_ms
        );
    }

    #[test]
    fn loaded_deadlines_reach_the_constructed_kernel_config() {
        // A loaded `chio.yaml` whose `[kernel.deadlines]` differs from every
        // kernel default must carry those budgets all the way into the runtime
        // `KernelConfig` the kernel is built from. A bridge that lowered
        // `HotPathDeadlineConfig::default()` instead would leave configured
        // budgets disabled; this asserts the operator's values win.
        let yaml = r#"
kernel:
  signing_key: "generate"
  deadlines:
    guard_pipeline_budget_ms: 1500
    dispatch_budget_ms: 2500
    receipt_append_budget_ms: 750
    receipt_writer_poll_ms: 250
    receipt_writer_stall_ms: 30000

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config =
            crate::load_from_str(yaml).unwrap_or_else(|e| panic!("config should load: {e}"));
        let kernel_config = config
            .to_kernel_config()
            .unwrap_or_else(|e| panic!("kernel config should build: {e}"));

        assert_eq!(kernel_config.deadlines.guard_pipeline_budget_ms, 1_500);
        assert_eq!(kernel_config.deadlines.dispatch_budget_ms, 2_500);
        assert_eq!(kernel_config.deadlines.receipt_append_budget_ms, 750);
        assert_eq!(kernel_config.deadlines.receipt_writer_poll_ms, 250);
        assert_eq!(kernel_config.deadlines.receipt_writer_stall_ms, 30_000);

        // The lowered config must actually construct a kernel through the
        // validated entrypoint, proving the budgets reach a live kernel.
        chio_kernel::ChioKernel::try_new(kernel_config)
            .unwrap_or_else(|e| panic!("kernel should construct from config deadlines: {e}"));
    }

    #[test]
    fn loaded_receipt_settings_reach_the_constructed_kernel_config() {
        // A loaded `chio.yaml` whose `[receipts]` section sets a non-default
        // checkpoint cadence and retention window must carry both into the
        // runtime `KernelConfig`. A bridge that hard-coded the checkpoint
        // default and dropped retention would leave the operator's values
        // unenforced; this asserts they win.
        let yaml = r#"
kernel:
  signing_key: "generate"

receipts:
  checkpoint_interval: 250
  retention_days: 30

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config =
            crate::load_from_str(yaml).unwrap_or_else(|e| panic!("config should load: {e}"));
        assert_eq!(config.receipts.checkpoint_interval, 250);
        assert_eq!(config.receipts.retention_days, 30);

        let kernel_config = config
            .to_kernel_config()
            .unwrap_or_else(|e| panic!("kernel config should build: {e}"));

        assert_eq!(kernel_config.checkpoint_batch_size, 250);
        let retention = kernel_config
            .retention_config
            .as_ref()
            .unwrap_or_else(|| panic!("retention config should be honored, not dropped"));
        assert_eq!(retention.retention_days, 30);

        chio_kernel::ChioKernel::try_new(kernel_config)
            .unwrap_or_else(|e| panic!("kernel should construct from config receipts: {e}"));
    }

    #[test]
    fn absent_dispatch_intent_journal_key_lowers_to_off() {
        // No `[receipts].dispatch_intent_journal` key at all: the pre-journal
        // write path must be preserved, not the enum's own compiled default
        // (`SideEffecting`), so upgrading a binary never silently starts
        // journaling for an existing deployment's file.
        let yaml = r#"
kernel:
  signing_key: "generate"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config =
            crate::load_from_str(yaml).unwrap_or_else(|e| panic!("config should load: {e}"));
        assert_eq!(
            config.receipts.dispatch_intent_journal,
            chio_kernel::DispatchIntentJournalMode::Off
        );

        let kernel_config = config
            .to_kernel_config()
            .unwrap_or_else(|e| panic!("kernel config should build: {e}"));
        assert_eq!(
            kernel_config.dispatch_intent_journal,
            chio_kernel::DispatchIntentJournalMode::Off
        );
    }

    #[test]
    fn explicit_dispatch_intent_journal_values_reach_the_constructed_kernel_config() {
        for (value, expected) in [
            ("off", chio_kernel::DispatchIntentJournalMode::Off),
            (
                "side_effecting",
                chio_kernel::DispatchIntentJournalMode::SideEffecting,
            ),
            ("all", chio_kernel::DispatchIntentJournalMode::All),
        ] {
            let yaml = format!(
                r#"
kernel:
  signing_key: "generate"

receipts:
  dispatch_intent_journal: "{value}"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#
            );
            let config = crate::load_from_str(&yaml)
                .unwrap_or_else(|e| panic!("config should load for {value:?}: {e}"));
            assert_eq!(config.receipts.dispatch_intent_journal, expected);

            let kernel_config = config
                .to_kernel_config()
                .unwrap_or_else(|e| panic!("kernel config should build for {value:?}: {e}"));
            assert_eq!(kernel_config.dispatch_intent_journal, expected);

            chio_kernel::ChioKernel::try_new(kernel_config).unwrap_or_else(|e| {
                panic!("kernel should construct with dispatch_intent_journal {value:?}: {e}")
            });
        }
    }

    #[test]
    fn unrecognized_dispatch_intent_journal_value_rejects_at_load() {
        // Fail-closed: an unrecognized value must reject the config at load
        // time, not silently fall back to a default the operator did not ask
        // for.
        let yaml = r#"
kernel:
  signing_key: "generate"

receipts:
  dispatch_intent_journal: "sometimes"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let result = crate::load_from_str(yaml);
        assert!(
            result.is_err(),
            "an unrecognized dispatch_intent_journal value must reject at load, got {result:?}"
        );
    }
}
