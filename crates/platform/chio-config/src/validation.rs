//! Post-deserialization validation for `ChioConfig`.
//!
//! Collects all validation errors before returning so the user can fix
//! everything in one pass rather than one at a time.

use std::collections::HashSet;

use crate::schema::{AdapterAuthConfig, ChioConfig};
use crate::ConfigError;

/// Validate a deserialized `ChioConfig`, returning all problems found.
pub fn validate(config: &ChioConfig) -> Result<(), ConfigError> {
    let mut errors: Vec<String> = Vec::new();

    validate_adapters_required(config, &mut errors);
    let adapter_ids = validate_adapter_ids_and_required_fields(config, &mut errors);
    validate_edges(config, &adapter_ids, &mut errors);
    validate_auth_blocks(config, &mut errors);
    validate_kernel(config, &mut errors);
    validate_logging(config, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Validation(errors))
    }
}

/// At least one adapter is required.
fn validate_adapters_required(config: &ChioConfig, errors: &mut Vec<String>) {
    if config.adapters.is_empty() {
        errors.push("at least one adapter is required".to_string());
    }
}

/// Adapter IDs must be unique. Required adapter fields must be non-empty.
/// Returns the set of known IDs for edge validation.
fn validate_adapter_ids_and_required_fields(
    config: &ChioConfig,
    errors: &mut Vec<String>,
) -> HashSet<String> {
    let mut seen = HashSet::new();
    for adapter in &config.adapters {
        if adapter.id.is_empty() {
            errors.push("adapter ID must not be empty".to_string());
        } else if adapter.id.trim() != adapter.id {
            errors.push("adapter ID must not contain surrounding whitespace".to_string());
        } else if !seen.insert(adapter.id.clone()) {
            errors.push(format!("duplicate adapter ID: \"{}\"", adapter.id));
        }
        if adapter.protocol.trim().is_empty() {
            errors.push(format!(
                "adapter \"{}\": protocol must not be empty",
                adapter.id
            ));
        }
        if adapter.upstream.trim().is_empty() {
            errors.push(format!(
                "adapter \"{}\": upstream must not be empty",
                adapter.id
            ));
        }
    }
    seen
}

/// Edge `expose_from` must reference an existing adapter ID, and edge IDs must be unique.
fn validate_edges(config: &ChioConfig, adapter_ids: &HashSet<String>, errors: &mut Vec<String>) {
    let mut edge_ids = HashSet::new();
    for edge in &config.edges {
        if edge.id.is_empty() {
            errors.push("edge ID must not be empty".to_string());
        } else if !edge_ids.insert(edge.id.clone()) {
            errors.push(format!("duplicate edge ID: \"{}\"", edge.id));
        }

        if !adapter_ids.contains(&edge.expose_from) {
            errors.push(format!(
                "edge \"{}\" references unknown adapter \"{}\" in expose_from",
                edge.id, edge.expose_from,
            ));
        }
    }
}

/// Auth blocks must be complete: bearer and api_key require a header.
fn validate_auth_blocks(config: &ChioConfig, errors: &mut Vec<String>) {
    for adapter in &config.adapters {
        if let Some(auth) = &adapter.auth {
            validate_single_auth(&adapter.id, auth, errors);
        }
    }
}

fn validate_single_auth(adapter_id: &str, auth: &AdapterAuthConfig, errors: &mut Vec<String>) {
    let valid_types = ["bearer", "api_key", "cookie", "mtls", "none"];
    if !valid_types.contains(&auth.auth_type.as_str()) {
        errors.push(format!(
            "adapter \"{adapter_id}\": unknown auth type \"{}\"; expected one of: {}",
            auth.auth_type,
            valid_types.join(", "),
        ));
        return;
    }

    if let Some(header) = auth.header.as_deref() {
        if header.trim().is_empty() {
            errors.push(format!(
                "adapter \"{adapter_id}\": auth header must not be empty"
            ));
        } else if header.trim() != header {
            errors.push(format!(
                "adapter \"{adapter_id}\": auth header must not contain surrounding whitespace"
            ));
        }
    }

    // bearer and api_key require a header field.
    if (auth.auth_type == "bearer" || auth.auth_type == "api_key") && auth.header.is_none() {
        errors.push(format!(
            "adapter \"{adapter_id}\": auth type \"{}\" requires a \"header\" field",
            auth.auth_type,
        ));
    }
}

/// Kernel signing_key must not be empty.
fn validate_kernel(config: &ChioConfig, errors: &mut Vec<String>) {
    if config.kernel.signing_key.is_empty() {
        errors.push("kernel.signing_key must not be empty".to_string());
    }
    // An unbounded wedged-writer stall is never a valid posture, so a 0 /
    // below-floor receipt-append budget or a zero poll/stall rejects at load.
    // The floor mirrors the runtime kernel's minimum append budget.
    const MIN_RECEIPT_APPEND_BUDGET_MS: u64 = 250;
    let deadlines = &config.kernel.deadlines;
    if let Some(budget) = deadlines.receipt_append_budget_ms {
        if budget < MIN_RECEIPT_APPEND_BUDGET_MS {
            errors.push(format!(
                "kernel.deadlines.receipt_append_budget_ms must be >= {MIN_RECEIPT_APPEND_BUDGET_MS}"
            ));
        }
    }
    if deadlines.receipt_writer_poll_ms == Some(0) {
        errors.push("kernel.deadlines.receipt_writer_poll_ms must be non-zero".to_string());
    }
    if deadlines.receipt_writer_stall_ms == Some(0) {
        errors.push("kernel.deadlines.receipt_writer_stall_ms must be non-zero".to_string());
    }
}

/// Logging level must be a known value.
fn validate_logging(config: &ChioConfig, errors: &mut Vec<String>) {
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.logging.level.as_str()) {
        errors.push(format!(
            "logging.level \"{}\" is not valid; expected one of: {}",
            config.logging.level,
            valid_levels.join(", "),
        ));
    }

    let valid_formats = ["json", "text"];
    if !valid_formats.contains(&config.logging.format.as_str()) {
        errors.push(format!(
            "logging.format \"{}\" is not valid; expected one of: {}",
            config.logging.format,
            valid_formats.join(", "),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::schema::*;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Helper to build a minimal valid config.
    fn minimal_config() -> ChioConfig {
        ChioConfig {
            kernel: KernelConfig {
                signing_key: "generate".to_string(),
                receipt_store: "sqlite:///tmp/test.db".to_string(),
                log_level: "info".to_string(),
                deadlines: KernelDeadlinesFileConfig::default(),
            },
            adapters: vec![AdapterConfig {
                id: "test".to_string(),
                protocol: "openapi".to_string(),
                upstream: "http://localhost:8000".to_string(),
                spec: None,
                auth: None,
            }],
            edges: Vec::new(),
            receipts: ReceiptsConfig::default(),
            logging: LoggingConfig::default(),
            telemetry: TelemetrySection::default(),
            guards: GuardsConfig::default(),
            wasm_guards: Vec::new(),
        }
    }

    fn validation_error(result: Result<(), ConfigError>) -> ConfigError {
        match result {
            Ok(()) => panic!("expected validation error"),
            Err(error) => error,
        }
    }

    #[test]
    fn minimal_valid_config_passes() {
        let config = minimal_config();
        validate(&config).unwrap_or_else(|e| panic!("validation should pass: {e}"));
    }

    #[test]
    fn rejects_zero_receipt_append_budget_in_config_file() -> TestResult {
        let mut config = minimal_config();
        config.kernel.deadlines = KernelDeadlinesFileConfig {
            receipt_append_budget_ms: Some(0),
            ..KernelDeadlinesFileConfig::default()
        };
        let ConfigError::Validation(errors) = validation_error(validate(&config)) else {
            return Err("expected ConfigError::Validation".into());
        };
        assert!(
            errors
                .iter()
                .any(|e| e.contains("receipt_append_budget_ms")),
            "unexpected errors: {errors:?}"
        );
        Ok(())
    }

    #[test]
    fn accepts_absent_deadlines_section() -> TestResult {
        let config = minimal_config();
        validate(&config)?;
        Ok(())
    }

    #[test]
    fn no_adapters_rejected() {
        let mut config = minimal_config();
        config.adapters.clear();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("at least one adapter")),
                    "should mention missing adapter: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn duplicate_adapter_ids_rejected() {
        let mut config = minimal_config();
        config.adapters.push(AdapterConfig {
            id: "test".to_string(),
            protocol: "grpc".to_string(),
            upstream: "http://localhost:9000".to_string(),
            spec: None,
            auth: None,
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("duplicate adapter ID")),
                    "should mention duplicate: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn edge_referencing_missing_adapter_rejected() {
        let mut config = minimal_config();
        config.edges.push(EdgeConfig {
            id: "edge-1".to_string(),
            protocol: "mcp".to_string(),
            expose_from: "nonexistent".to_string(),
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("unknown adapter")),
                    "should mention broken reference: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn incomplete_bearer_auth_rejected() {
        let mut config = minimal_config();
        config.adapters[0].auth = Some(AdapterAuthConfig {
            auth_type: "bearer".to_string(),
            header: None,
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("requires a \"header\"")),
                    "should mention missing header: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn bearer_auth_blank_or_padded_header_rejected() -> TestResult {
        for auth_type in ["bearer", "api_key"] {
            for header in ["", " Authorization"] {
                let mut config = minimal_config();
                config.adapters[0].auth = Some(AdapterAuthConfig {
                    auth_type: auth_type.to_string(),
                    header: Some(header.to_string()),
                });

                let err = validation_error(validate(&config));
                let ConfigError::Validation(errors) = err else {
                    return Err(std::io::Error::other(format!(
                        "wrong error variant for {auth_type} header {header:?}: {err}"
                    ))
                    .into());
                };

                assert!(
                    errors.iter().any(|error| error.contains("auth header")),
                    "should mention invalid {auth_type} auth header for {header:?}: {errors:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn unknown_auth_type_rejected() {
        let mut config = minimal_config();
        config.adapters[0].auth = Some(AdapterAuthConfig {
            auth_type: "oauth2".to_string(),
            header: None,
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("unknown auth type")),
                    "should mention unknown type: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn empty_signing_key_rejected() {
        let mut config = minimal_config();
        config.kernel.signing_key = String::new();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("signing_key")),
                    "should mention signing_key: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn invalid_log_level_rejected() {
        let mut config = minimal_config();
        config.logging.level = "verbose".to_string();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("logging.level")),
                    "should mention log level: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn invalid_log_format_rejected() {
        let mut config = minimal_config();
        config.logging.format = "xml".to_string();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("logging.format")),
                    "should mention log format: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn multiple_errors_collected() {
        let mut config = minimal_config();
        config.adapters.clear(); // no adapters
        config.kernel.signing_key = String::new(); // empty key
        config.logging.level = "bogus".to_string(); // bad level
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.len() >= 3,
                    "should collect at least 3 errors, got {}: {errors:?}",
                    errors.len()
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn valid_edge_passes() {
        let mut config = minimal_config();
        config.edges.push(EdgeConfig {
            id: "edge-1".to_string(),
            protocol: "mcp".to_string(),
            expose_from: "test".to_string(),
        });
        validate(&config).unwrap_or_else(|e| panic!("valid edge should pass: {e}"));
    }

    #[test]
    fn auth_type_none_needs_no_header() {
        let mut config = minimal_config();
        config.adapters[0].auth = Some(AdapterAuthConfig {
            auth_type: "none".to_string(),
            header: None,
        });
        validate(&config).unwrap_or_else(|e| panic!("none auth should pass: {e}"));
    }

    #[test]
    fn adapter_with_no_auth_section_passes() {
        let config = minimal_config();
        // The minimal config already has no auth section; verify this passes.
        assert!(config.adapters[0].auth.is_none());
        validate(&config).unwrap_or_else(|e| panic!("should pass without auth: {e}"));
    }

    #[test]
    fn empty_adapter_id_rejected() {
        let mut config = minimal_config();
        config.adapters[0].id = String::new();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("adapter ID must not be empty")),
                    "should mention empty ID: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn padded_adapter_id_rejected() {
        let mut config = minimal_config();
        config.adapters[0].id = " test".to_string();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("adapter ID must not contain surrounding whitespace")),
                    "should mention padded ID: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn empty_adapter_protocol_and_upstream_rejected() {
        let mut config = minimal_config();
        config.adapters[0].protocol = " ".to_string();
        config.adapters[0].upstream = String::new();
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("protocol must not be empty")),
                    "should mention empty protocol: {errors:?}"
                );
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("upstream must not be empty")),
                    "should mention empty upstream: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn empty_edge_id_rejected() {
        let mut config = minimal_config();
        config.edges.push(EdgeConfig {
            id: String::new(),
            protocol: "mcp".to_string(),
            expose_from: "test".to_string(),
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("edge ID must not be empty")),
                    "should mention empty edge ID: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn api_key_auth_without_header_rejected() {
        let mut config = minimal_config();
        config.adapters[0].auth = Some(AdapterAuthConfig {
            auth_type: "api_key".to_string(),
            header: None,
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("requires a \"header\"")),
                    "should mention missing header for api_key: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn mtls_auth_no_header_passes() {
        let mut config = minimal_config();
        config.adapters[0].auth = Some(AdapterAuthConfig {
            auth_type: "mtls".to_string(),
            header: None,
        });
        validate(&config).unwrap_or_else(|e| panic!("mtls should pass without header: {e}"));
    }

    #[test]
    fn duplicate_edge_ids_rejected() {
        let mut config = minimal_config();
        config.edges.push(EdgeConfig {
            id: "edge-1".to_string(),
            protocol: "mcp".to_string(),
            expose_from: "test".to_string(),
        });
        config.edges.push(EdgeConfig {
            id: "edge-1".to_string(),
            protocol: "a2a".to_string(),
            expose_from: "test".to_string(),
        });
        let err = validation_error(validate(&config));
        match err {
            ConfigError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("duplicate edge ID")),
                    "should mention duplicate edge: {errors:?}"
                );
            }
            other => panic!("wrong error: {other}"),
        }
    }
}
