//! Environment variable interpolation for raw YAML strings.
//!
//! Scans the input for `${VAR}` and `${VAR:-default}` patterns and replaces
//! them with the corresponding environment variable value (or the default).
//! This runs on the raw YAML text before typed deserialization so that every
//! string-typed field benefits automatically.

use regex::{Captures, Regex};
use std::env;

use crate::ConfigError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterpolationPolicy {
    Raw,
    LoaderSafeYamlScalar,
}

/// Replace all `${VAR}` and `${VAR:-default}` occurrences in `input`.
///
/// Returns the interpolated string, or an error listing every variable that
/// was referenced but not set (and had no default).
pub fn interpolate(input: &str) -> Result<String, ConfigError> {
    interpolate_with_policy(input, InterpolationPolicy::Raw)
}

/// Replace interpolation tokens for the config loader.
///
/// This path rejects replacement values that can cross or corrupt YAML scalar
/// boundaries before typed deserialization sees the document.
pub(crate) fn interpolate_for_loader(input: &str) -> Result<String, ConfigError> {
    interpolate_with_policy(input, InterpolationPolicy::LoaderSafeYamlScalar)
}

fn interpolate_with_policy(
    input: &str,
    policy: InterpolationPolicy,
) -> Result<String, ConfigError> {
    // Pattern breakdown:
    //   \$\{            -- literal "${"
    //   ([A-Za-z_]\w*)  -- variable name (capture group 1)
    //   (?::-([^}]*))?  -- optional ":-default" (capture group 2)
    //   \}              -- literal "}"
    let re = Regex::new(r"\$\{([A-Za-z_]\w*)(?::-([^}]*))?\}")
        .map_err(|e| ConfigError::Interpolation(format!("regex compile error: {e}")))?;

    let mut missing: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();

    let result = re.replace_all(input, |caps: &Captures<'_>| {
        let var_name = caps.get(1).map_or("", |m| m.as_str());
        match env::var(var_name) {
            Ok(val) => {
                validate_replacement(var_name, "environment value", &val, policy, &mut rejected)
            }
            Err(_) => {
                // Check for a default value.
                if let Some(default_match) = caps.get(2) {
                    let default = default_match.as_str();
                    validate_replacement(var_name, "default value", default, policy, &mut rejected)
                } else {
                    missing.push(var_name.to_string());
                    // Leave a placeholder so the rest of parsing can proceed;
                    // we will return an error after the full scan.
                    String::new()
                }
            }
        }
    });

    if missing.is_empty() {
        if rejected.is_empty() {
            Ok(result.into_owned())
        } else {
            Err(ConfigError::Interpolation(format!(
                "unsafe interpolation values for loader: {}",
                rejected.join(", ")
            )))
        }
    } else {
        Err(ConfigError::Interpolation(format!(
            "unset environment variables with no default: {}",
            missing.join(", ")
        )))
    }
}

fn validate_replacement(
    var_name: &str,
    source: &str,
    value: &str,
    policy: InterpolationPolicy,
    rejected: &mut Vec<String>,
) -> String {
    if policy == InterpolationPolicy::LoaderSafeYamlScalar {
        if let Some(reason) = yaml_scalar_rejection_reason(value) {
            rejected.push(format!("{var_name} {source} {reason}"));
        }
    }
    value.to_string()
}

fn yaml_scalar_rejection_reason(value: &str) -> Option<&'static str> {
    if value.trim() != value {
        return Some("has surrounding whitespace");
    }
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\'' | '#'))
    {
        return Some("contains YAML scalar boundary syntax");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interpolation_error(result: Result<String, ConfigError>) -> ConfigError {
        match result {
            Ok(value) => panic!("expected interpolation error, got {value:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn plain_text_unchanged() {
        let input = "hello world";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "hello world");
    }

    #[test]
    fn simple_var_replacement() {
        env::set_var("CHIO_TEST_SIMPLE", "replaced");
        let input = "key: ${CHIO_TEST_SIMPLE}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: replaced");
        env::remove_var("CHIO_TEST_SIMPLE");
    }

    #[test]
    fn default_value_when_unset() {
        env::remove_var("CHIO_TEST_UNSET_WITH_DEFAULT");
        let input = "key: ${CHIO_TEST_UNSET_WITH_DEFAULT:-fallback}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: fallback");
    }

    #[test]
    fn default_value_overridden_when_set() {
        env::set_var("CHIO_TEST_SET_OVER_DEFAULT", "actual");
        let input = "key: ${CHIO_TEST_SET_OVER_DEFAULT:-fallback}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: actual");
        env::remove_var("CHIO_TEST_SET_OVER_DEFAULT");
    }

    #[test]
    fn missing_var_no_default_is_error() {
        env::remove_var("CHIO_TEST_MISSING_NO_DEFAULT");
        let input = "key: ${CHIO_TEST_MISSING_NO_DEFAULT}";
        let err = interpolation_error(interpolate(input));
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(
                    msg.contains("CHIO_TEST_MISSING_NO_DEFAULT"),
                    "error should name the variable: {msg}"
                );
            }
            other => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn multiple_vars_in_one_string() {
        env::set_var("CHIO_TEST_A", "alpha");
        env::set_var("CHIO_TEST_B", "beta");
        let input = "${CHIO_TEST_A}--${CHIO_TEST_B}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "alpha--beta");
        env::remove_var("CHIO_TEST_A");
        env::remove_var("CHIO_TEST_B");
    }

    #[test]
    fn empty_default_is_valid() {
        env::remove_var("CHIO_TEST_EMPTY_DEFAULT");
        let input = "key: ${CHIO_TEST_EMPTY_DEFAULT:-}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: ");
    }

    #[test]
    fn multiple_missing_vars_all_reported() {
        env::remove_var("CHIO_TEST_X1");
        env::remove_var("CHIO_TEST_X2");
        let input = "${CHIO_TEST_X1} ${CHIO_TEST_X2}";
        let err = interpolation_error(interpolate(input));
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(msg.contains("CHIO_TEST_X1"), "should contain X1: {msg}");
                assert!(msg.contains("CHIO_TEST_X2"), "should contain X2: {msg}");
            }
            other => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn deeply_nested_var_in_yaml() {
        env::set_var("CHIO_TEST_NESTED_HOST", "db.internal");
        env::set_var("CHIO_TEST_NESTED_PORT", "5432");
        let input =
            "connection: postgresql://${CHIO_TEST_NESTED_HOST}:${CHIO_TEST_NESTED_PORT}/mydb";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "connection: postgresql://db.internal:5432/mydb");
        env::remove_var("CHIO_TEST_NESTED_HOST");
        env::remove_var("CHIO_TEST_NESTED_PORT");
    }

    #[test]
    fn var_at_start_of_line() {
        env::set_var("CHIO_TEST_PREFIX", "hello");
        let input = "${CHIO_TEST_PREFIX} world";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "hello world");
        env::remove_var("CHIO_TEST_PREFIX");
    }

    #[test]
    fn dollar_brace_without_var_name_unchanged() {
        // ${} is not a valid variable pattern, should be left as-is
        let input = "no var here: ${}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "no var here: ${}");
    }

    #[test]
    fn mixed_set_and_unset_with_defaults() {
        env::set_var("CHIO_TEST_MIX_SET", "real");
        env::remove_var("CHIO_TEST_MIX_UNSET");
        let input = "${CHIO_TEST_MIX_SET}--${CHIO_TEST_MIX_UNSET:-default_val}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "real--default_val");
        env::remove_var("CHIO_TEST_MIX_SET");
    }

    #[test]
    fn raw_interpolation_preserves_newlines_for_compatibility() {
        env::set_var("CHIO_TEST_RAW_MULTILINE", "one\ntwo");
        let out = interpolate("key: ${CHIO_TEST_RAW_MULTILINE}")
            .unwrap_or_else(|e| panic!("raw interpolation should remain compatible: {e}"));
        assert_eq!(out, "key: one\ntwo");
        env::remove_var("CHIO_TEST_RAW_MULTILINE");
    }

    #[test]
    fn loader_interpolation_rejects_values_with_yaml_boundaries() {
        for (name, value) in [
            ("CHIO_TEST_LOADER_NEWLINE", "one\ntwo"),
            ("CHIO_TEST_LOADER_QUOTE", "break\"quote"),
            ("CHIO_TEST_LOADER_COMMENT", "value # comment"),
            ("CHIO_TEST_LOADER_PADDED", " value"),
        ] {
            env::set_var(name, value);
            let err = interpolation_error(interpolate_for_loader(&format!("key: ${{{name}}}")));
            match err {
                ConfigError::Interpolation(msg) => {
                    assert!(msg.contains(name), "error should name {name}: {msg}");
                    assert!(
                        msg.contains("unsafe interpolation values"),
                        "error should explain unsafe loader interpolation: {msg}"
                    );
                }
                other => panic!("wrong error variant for {name}: {other}"),
            }
            env::remove_var(name);
        }
    }

    #[test]
    fn loader_interpolation_allows_url_like_scalar_fragments() {
        env::set_var(
            "CHIO_TEST_LOADER_URL",
            "https://api.example.com/v1?tenant=acme",
        );
        let out = interpolate_for_loader("upstream: ${CHIO_TEST_LOADER_URL}")
            .unwrap_or_else(|e| panic!("url-like scalar should interpolate: {e}"));
        assert_eq!(out, "upstream: https://api.example.com/v1?tenant=acme");
        env::remove_var("CHIO_TEST_LOADER_URL");
    }

    #[test]
    fn loader_interpolation_rejects_unsafe_default_values() {
        env::remove_var("CHIO_TEST_UNSAFE_DEFAULT");
        let err = interpolation_error(interpolate_for_loader(
            "key: ${CHIO_TEST_UNSAFE_DEFAULT:-one\ntwo}",
        ));
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(msg.contains("CHIO_TEST_UNSAFE_DEFAULT"));
                assert!(msg.contains("default value"));
            }
            other => panic!("wrong error variant: {other}"),
        }
    }
}
