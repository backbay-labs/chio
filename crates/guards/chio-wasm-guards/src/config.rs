//! Configuration for WASM guards loaded via `chio.yaml`.

use serde::{Deserialize, Serialize};

/// Default fuel limit per guard invocation (10 million instructions).
pub const DEFAULT_FUEL_LIMIT: u64 = 10_000_000;

/// Configuration entry for a single WASM guard in `chio.yaml`.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmGuardConfig {
    /// Human-readable name for this guard (used in receipts and logs).
    pub name: String,

    /// Filesystem path to the `.wasm` module.
    pub path: String,

    /// Maximum fuel units the guest may consume per invocation.
    /// Defaults to 10,000,000 if omitted.
    #[serde(default = "default_fuel_limit")]
    pub fuel_limit: u64,

    /// Guard evaluation priority. Lower values run first.
    /// Defaults to 1000 if omitted.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// If true, a failure in this guard is treated as advisory (logged but
    /// not blocking). Defaults to `false` (fail-closed).
    #[serde(default)]
    pub advisory: bool,

    /// Maximum linear memory the guest may use, in bytes.
    /// Defaults to 16 MiB if omitted.
    #[serde(default = "default_max_memory_bytes")]
    pub max_memory_bytes: usize,

    /// Maximum module size in bytes. Modules exceeding this limit are
    /// rejected before compilation. Defaults to 10 MiB if omitted.
    #[serde(default = "default_max_module_size")]
    pub max_module_size: usize,
}

fn default_fuel_limit() -> u64 {
    DEFAULT_FUEL_LIMIT
}

fn default_priority() -> u32 {
    1000
}

fn default_max_memory_bytes() -> usize {
    16 * 1024 * 1024
}

fn default_max_module_size() -> usize {
    10 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_with_defaults() {
        let json = r#"{"name": "pii-guard", "path": "/etc/chio/guards/pii.wasm"}"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with defaults");
        assert_eq!(config.name, "pii-guard");
        assert_eq!(config.fuel_limit, DEFAULT_FUEL_LIMIT);
        assert_eq!(config.priority, 1000);
        assert!(!config.advisory);
    }

    #[test]
    fn config_deserializes_with_overrides() {
        let json = r#"{
            "name": "custom",
            "path": "/opt/guard.wasm",
            "fuel_limit": 5000000,
            "priority": 50,
            "advisory": true
        }"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with overrides");
        assert_eq!(config.fuel_limit, 5_000_000);
        assert_eq!(config.priority, 50);
        assert!(config.advisory);
    }

    #[test]
    fn config_round_trips_through_json() {
        let original = WasmGuardConfig {
            name: "test".to_string(),
            path: "/tmp/test.wasm".to_string(),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            max_memory_bytes: 8 * 1024 * 1024,
            max_module_size: 5 * 1024 * 1024,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: WasmGuardConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered.name, original.name);
        assert_eq!(recovered.fuel_limit, original.fuel_limit);
        assert_eq!(recovered.max_memory_bytes, original.max_memory_bytes);
        assert_eq!(recovered.max_module_size, original.max_module_size);
    }

    #[test]
    fn config_missing_name_fails() {
        let json = r#"{"path": "/etc/chio/guards/test.wasm"}"#;
        let result: Result<WasmGuardConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn config_missing_path_fails() {
        let json = r#"{"name": "test"}"#;
        let result: Result<WasmGuardConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn config_all_fields_explicit() {
        let json = r#"{
            "name": "pii-guard",
            "path": "/etc/chio/guards/pii.wasm",
            "fuel_limit": 2000000,
            "priority": 50,
            "advisory": true
        }"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize all fields");
        assert_eq!(config.name, "pii-guard");
        assert_eq!(config.fuel_limit, 2_000_000);
        assert_eq!(config.priority, 50);
        assert!(config.advisory);
    }

    #[test]
    fn config_zero_fuel_limit_allowed() {
        let json = r#"{"name": "test", "path": "/test.wasm", "fuel_limit": 0}"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.fuel_limit, 0);
    }

    #[test]
    fn config_max_priority_allowed() {
        let json = r#"{"name": "test", "path": "/test.wasm", "priority": 4294967295}"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.priority, u32::MAX);
    }

    #[test]
    fn config_deserializes_with_default_memory_and_module_limits() {
        let json = r#"{"name": "pii-guard", "path": "/etc/chio/guards/pii.wasm"}"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with default limits");
        assert_eq!(config.max_memory_bytes, 16 * 1024 * 1024);
        assert_eq!(config.max_module_size, 10 * 1024 * 1024);
    }

    #[test]
    fn config_deserializes_with_overridden_memory_and_module_limits() {
        let json = r#"{
            "name": "custom",
            "path": "/opt/guard.wasm",
            "max_memory_bytes": 8388608,
            "max_module_size": 5242880
        }"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with overrides");
        assert_eq!(config.max_memory_bytes, 8_388_608);
        assert_eq!(config.max_module_size, 5_242_880);
    }
}
