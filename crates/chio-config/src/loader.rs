//! Configuration loading from file paths and raw strings.

use std::fs;
use std::path::Path;

use crate::interpolation::interpolate_for_loader;
use crate::schema::ChioConfig;
use crate::validation::validate;
use crate::ConfigError;

/// Load and validate an `ChioConfig` from a file path.
///
/// Steps:
/// 1. Read the file contents.
/// 2. Interpolate environment variables.
/// 3. Deserialize from YAML.
/// 4. Run post-deserialization validation.
pub fn load_from_file(path: &Path) -> Result<ChioConfig, ConfigError> {
    let raw = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    load_from_str(&raw)
}

/// Load and validate an `ChioConfig` from a YAML string.
///
/// Useful for testing and for configs embedded in other formats.
pub fn load_from_str(yaml: &str) -> Result<ChioConfig, ConfigError> {
    let interpolated = interpolate_for_loader(yaml)?;
    reject_yaml_tabs(&interpolated)?;
    let config: ChioConfig =
        serde_yml::from_str(&interpolated).map_err(|e| ConfigError::Parse(e.to_string()))?;
    validate(&config)?;
    Ok(config)
}

fn reject_yaml_tabs(yaml: &str) -> Result<(), ConfigError> {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped_double_quote = false;
    let mut block_scalar_parent_indent = None;

    for (line_index, line) in yaml.lines().enumerate() {
        let line_indent = yaml_leading_spaces(line);
        if let Some(parent_indent) = block_scalar_parent_indent {
            if line.trim().is_empty() || line_indent > parent_indent {
                continue;
            }
            block_scalar_parent_indent = None;
        }

        let mut previous_plain = None;
        let mut plain_prefix = String::new();
        let mut block_scalar_candidate = false;
        let mut chars = line.char_indices().peekable();
        while let Some((column_index, ch)) = chars.next() {
            if in_double_quote {
                if escaped_double_quote {
                    escaped_double_quote = false;
                } else if ch == '\\' {
                    escaped_double_quote = true;
                } else if ch == '"' {
                    in_double_quote = false;
                }
                continue;
            }

            if in_single_quote {
                if ch == '\'' {
                    if matches!(chars.peek(), Some((_, '\''))) {
                        let _ = chars.next();
                    } else {
                        in_single_quote = false;
                    }
                }
                continue;
            }

            if ch == '#' && yaml_comment_can_start(previous_plain) {
                break;
            }
            if ch == '"' && yaml_quote_can_start(plain_prefix.trim_end()) {
                in_double_quote = true;
                escaped_double_quote = false;
            } else if ch == '\'' && yaml_quote_can_start(plain_prefix.trim_end()) {
                in_single_quote = true;
            } else if ch == '\t' {
                return Err(ConfigError::Parse(format!(
                    "tab characters are not accepted in YAML syntax at line {}, column {}; use spaces for indentation and quote literal tabs inside strings",
                    line_index + 1,
                    column_index + 1
                )));
            } else if (ch == '|' || ch == '>')
                && yaml_block_indicator_can_start(plain_prefix.trim_end())
            {
                block_scalar_candidate = true;
            } else if block_scalar_candidate
                && !ch.is_whitespace()
                && !matches!(ch, '+' | '-' | '0'..='9')
            {
                block_scalar_candidate = false;
            }
            plain_prefix.push(ch);
            previous_plain = Some(ch);
        }
        if block_scalar_candidate && !in_single_quote && !in_double_quote {
            block_scalar_parent_indent = Some(line_indent);
        }
    }
    Ok(())
}

fn yaml_leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn yaml_quote_can_start(prefix: &str) -> bool {
    prefix.is_empty()
        || prefix.ends_with(':')
        || prefix.ends_with('[')
        || prefix.ends_with('{')
        || prefix.ends_with(',')
        || prefix.ends_with('-')
}

fn yaml_comment_can_start(previous: Option<char>) -> bool {
    match previous {
        None => true,
        Some(ch) => ch.is_whitespace(),
    }
}

fn yaml_block_indicator_can_start(prefix: &str) -> bool {
    prefix.ends_with(':') || prefix.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write as _;

    fn minimal_yaml() -> &'static str {
        r#"
kernel:
  signing_key: "generate"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#
    }

    fn load_error(result: Result<ChioConfig, ConfigError>) -> ConfigError {
        match result {
            Ok(_) => panic!("expected config load error"),
            Err(error) => error,
        }
    }

    #[test]
    fn load_minimal_yaml() {
        let config =
            load_from_str(minimal_yaml()).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "generate");
        assert_eq!(config.adapters.len(), 1);
        assert_eq!(config.adapters[0].id, "petstore");
        // Defaults applied
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.receipts.checkpoint_interval, 100);
        assert_eq!(config.receipts.retention_days, 90);
    }

    #[test]
    fn load_full_yaml() {
        let yaml = r#"
kernel:
  signing_key: "deadbeef"
  receipt_store: "sqlite:///tmp/test.db"
  log_level: "debug"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
    spec: "./petstore.yaml"
    auth:
      type: "bearer"
      header: "Authorization"

edges:
  - id: "mcp-bridge"
    protocol: "mcp"
    expose_from: "petstore"

receipts:
  store: "sqlite:///tmp/receipts.db"
  checkpoint_interval: 50
  retention_days: 30

logging:
  level: "debug"
  format: "text"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "deadbeef");
        assert_eq!(config.kernel.log_level, "debug");
        assert_eq!(config.adapters[0].id, "petstore");
        assert_eq!(config.edges.len(), 1);
        assert_eq!(config.edges[0].expose_from, "petstore");
        assert_eq!(config.receipts.checkpoint_interval, 50);
        assert_eq!(config.logging.format, "text");
    }

    #[test]
    fn interpolation_in_yaml() {
        env::set_var("CHIO_TEST_KEY", "my-secret-key");
        let yaml = r#"
kernel:
  signing_key: "${CHIO_TEST_KEY}"

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "my-secret-key");
        env::remove_var("CHIO_TEST_KEY");
    }

    #[test]
    fn interpolation_with_default() {
        env::remove_var("CHIO_TEST_LOG_LEVEL");
        let yaml = r#"
kernel:
  signing_key: "generate"
  log_level: "${CHIO_TEST_LOG_LEVEL:-warn}"

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.log_level, "warn");
    }

    #[test]
    fn unsafe_interpolation_value_is_rejected_before_yaml_parse() {
        env::set_var(
            "CHIO_TEST_INJECTED_SIGNING_KEY",
            "generate\"\nadapters:\n  - id: injected",
        );
        let yaml = r#"
kernel:
  signing_key: "${CHIO_TEST_INJECTED_SIGNING_KEY}"

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let err = load_error(load_from_str(yaml));
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(msg.contains("CHIO_TEST_INJECTED_SIGNING_KEY"));
                assert!(msg.contains("unsafe interpolation values"));
            }
            other => panic!("wrong error variant: {other}"),
        }
        env::remove_var("CHIO_TEST_INJECTED_SIGNING_KEY");
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r#"
kernel:
  signing_key: "generate"
  mystery: true

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let err = load_error(load_from_str(yaml));
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "should be parse error: {err}"
        );
    }

    #[test]
    fn missing_kernel_rejected() {
        let yaml = r#"
adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let err = load_error(load_from_str(yaml));
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "should be parse error: {err}"
        );
    }

    #[test]
    fn load_from_file_works() {
        let dir = std::env::temp_dir().join("chio_config_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_arc.yaml");
        {
            let mut f =
                fs::File::create(&path).unwrap_or_else(|e| panic!("create file failed: {e}"));
            f.write_all(minimal_yaml().as_bytes())
                .unwrap_or_else(|e| panic!("write failed: {e}"));
        }
        let config =
            load_from_file(&path).unwrap_or_else(|e| panic!("load from file should work: {e}"));
        assert_eq!(config.kernel.signing_key, "generate");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_from_nonexistent_file() {
        let path = Path::new("/tmp/chio_config_nonexistent_12345.yaml");
        let err = load_error(load_from_file(path));
        assert!(
            matches!(err, ConfigError::Io(_)),
            "should be IO error: {err}"
        );
    }

    #[test]
    fn validation_error_from_loader() {
        // Valid YAML but no adapters -- validation should reject.
        let yaml = r#"
kernel:
  signing_key: "generate"
"#;
        let err = load_error(load_from_str(yaml));
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "should be validation error: {err}"
        );
    }

    #[test]
    fn load_yaml_with_guards_and_wasm() {
        let yaml = r#"
kernel:
  signing_key: "generate"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"

guards:
  allow_advisory_promotion: true
  required:
    - internal-network
    - agent-velocity

wasm_guards:
  - name: custom-pii-guard
    path: /etc/chio/guards/pii_guard.wasm
    fuel_limit: 5000000
    priority: 100
    advisory: false
  - name: audit-logger
    path: /etc/chio/guards/audit.wasm
    advisory: true
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert!(config.guards.allow_advisory_promotion);
        assert_eq!(config.guards.required.len(), 2);
        assert_eq!(config.guards.required[0], "internal-network");
        assert_eq!(config.wasm_guards.len(), 2);
        assert_eq!(config.wasm_guards[0].name, "custom-pii-guard");
        assert_eq!(config.wasm_guards[0].fuel_limit, 5_000_000);
        assert_eq!(config.wasm_guards[0].priority, 100);
        assert!(!config.wasm_guards[0].advisory);
        assert_eq!(config.wasm_guards[1].name, "audit-logger");
        assert!(config.wasm_guards[1].advisory);
        // Defaults for second entry
        assert_eq!(config.wasm_guards[1].fuel_limit, 10_000_000);
        assert_eq!(config.wasm_guards[1].priority, 1000);
    }

    #[test]
    fn guards_default_when_omitted() {
        let config =
            load_from_str(minimal_yaml()).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert!(!config.guards.allow_advisory_promotion);
        assert!(config.guards.required.is_empty());
        assert!(config.wasm_guards.is_empty());
    }

    /// Regression: confirm the underlying YAML parser refuses
    /// "billion-laughs" alias-expansion bombs. `serde_yml` uses
    /// `libyml`, which caps alias repetitions; if the limit is ever
    /// removed, malicious `chio.yaml` content could exhaust memory
    /// before reaching `deny_unknown_fields`.
    #[test]
    fn billion_laughs_alias_bomb_is_rejected() {
        let bomb = r#"
a: &a ["x","x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]
kernel:
  signing_key: "generate"
adapters:
  - id: "a"
    protocol: "openapi"
    upstream: "http://localhost:8000"
    extras: [*g,*g,*g,*g,*g,*g,*g,*g,*g,*g]
"#;
        let err = load_error(load_from_str(bomb));
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "alias bomb must be rejected as a parse error, got: {err}"
        );
    }

    /// Regression: confirm the parser rejects deeply nested YAML before
    /// recursing through stack overflow. `libyml` caps recursion depth.
    #[test]
    fn deeply_nested_yaml_is_rejected() {
        let mut deep = String::new();
        for _ in 0..50_000 {
            deep.push_str("- ");
        }
        deep.push_str("\"end\"");
        let err = load_error(load_from_str(&deep));
        // Either a parse error (recursion limit) or a validation error
        // (no kernel/adapters block). Both are acceptable - the key
        // property is "does not crash or hang."
        assert!(
            matches!(err, ConfigError::Parse(_) | ConfigError::Validation(_)),
            "deeply nested YAML must be rejected without panicking, got: {err}"
        );
    }

    #[test]
    fn tab_heavy_plain_scalar_crash_input_is_rejected_before_parse() {
        let crash = concat!(
            "~:\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t0*",
            "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t00x\"   ",
            "\t\t\t\t\t\t\t\t\t\t\t\t\t#",
            "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",
        );
        let err = load_error(load_from_str(crash));
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "tab-heavy fuzz input must be rejected as a parse error, got: {err}"
        );
    }

    #[test]
    fn tabs_in_quoted_scalars_and_comments_are_allowed() {
        let yaml = concat!(
            "# top-level comment with\tliteral tab\n",
            "kernel:\n",
            "  signing_key: \"generate\"\n",
            "\n",
            "adapters:\n",
            "  - id: \"petstore\"\n",
            "    protocol: \"openapi\" # inline comment with\tliteral tab\n",
            "    upstream: \"http://localhost:8000/path\tsegment\"\n",
            "    spec: './pet\tstore.yaml'\n",
        );
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(
            config.adapters[0].upstream,
            "http://localhost:8000/path\tsegment"
        );
        assert_eq!(
            config.adapters[0].spec.as_deref(),
            Some("./pet\tstore.yaml")
        );
    }

    #[test]
    fn tabs_in_block_scalars_are_allowed() {
        let yaml = concat!(
            "kernel:\n",
            "  signing_key: \"generate\"\n",
            "\n",
            "adapters:\n",
            "  - id: \"petstore\"\n",
            "    protocol: \"openapi\"\n",
            "    upstream: |\n",
            "      http://localhost:8000/path\tsegment\n",
            "    spec: >\n",
            "      ./pet\tstore.yaml\n",
        );
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert!(config.adapters[0].upstream.contains('\t'));
        assert!(matches!(
            config.adapters[0].spec.as_deref(),
            Some(spec) if spec.contains('\t')
        ));
    }

    #[test]
    fn quote_after_plain_scalar_does_not_hide_tab_syntax() {
        let yaml = concat!(
            "kernel:\n",
            "  signing_key: \"generate\"\n",
            "\n",
            "adapters:\n",
            "  - id: \"petstore\"\n",
            "    protocol: \"openapi\"\n",
            "    upstream: http://localhost:8000 \"\tsegment\"\n",
        );
        let err = load_error(load_from_str(yaml));
        match err {
            ConfigError::Parse(message) => {
                assert!(message.contains("tab characters are not accepted"));
            }
            other => panic!("wrong error variant: {other}"),
        }
    }
}
