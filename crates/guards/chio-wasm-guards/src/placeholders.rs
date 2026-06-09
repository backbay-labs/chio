//! Placeholder resolution for WASM guard configuration values.
//!
//! This module resolves placeholders in JSON guard configuration. It
//! substitutes `${VAR}` and `${VAR:-default}` references in strings against an
//! injected [`PlaceholderEnv`] rather than reading from `std::env` directly.
//! Tests and callers that need a controlled environment
//! pass their own implementation; production code can use [`ProcessEnv`] which
//! wraps `std::env::var`.
//!
//! # Syntax
//!
//! - `${NAME}` -- substitute the value bound to `NAME`. Undefined names fail
//!   closed with [`PlaceholderError::Undefined`].
//! - `${NAME:-default}` -- substitute `NAME` if set, otherwise use `default`
//!   (which may be empty).
//! - `$$` -- an escape that yields a literal `$` without starting a
//!   placeholder.
//!
//! # Why a trait
//!
//! Reading from the process environment at resolution time would make the
//! behavior untestable in a shared test binary (environment variables are
//! process-global and racy under parallel tests). The trait lets tests inject
//! a deterministic `HashMap`-backed env and lets production wire up the real
//! process env explicitly.

use std::collections::HashMap;

use serde_json::Value;

/// Errors returned by [`resolve_placeholders`] and friends.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlaceholderError {
    /// A `${VAR}` placeholder was encountered with no value bound and no
    /// default supplied. Fail-closed: callers should reject the config.
    #[error("placeholder ${{{0}}} is not defined and has no default")]
    Undefined(String),

    /// A `${...}` expression was not closed before the end of the string.
    #[error("unterminated placeholder starting at byte {offset}")]
    Unterminated {
        /// Byte offset of the opening `${` in the source string.
        offset: usize,
    },

    /// A placeholder had an empty variable name (e.g. `${}` or `${:-x}`).
    #[error("placeholder at byte {offset} has an empty variable name")]
    EmptyName {
        /// Byte offset of the opening `${` in the source string.
        offset: usize,
    },
}

/// Source of variable bindings for placeholder resolution.
///
/// Implementors return `Some(value)` when the variable is bound and `None`
/// otherwise. Returning `None` for a placeholder without a default triggers
/// [`PlaceholderError::Undefined`].
pub trait PlaceholderEnv {
    /// Look up a single variable name.
    fn lookup(&self, name: &str) -> Option<String>;
}

impl PlaceholderEnv for HashMap<String, String> {
    fn lookup(&self, name: &str) -> Option<String> {
        self.get(name).cloned()
    }
}

impl<F> PlaceholderEnv for F
where
    F: Fn(&str) -> Option<String>,
{
    fn lookup(&self, name: &str) -> Option<String> {
        (self)(name)
    }
}

/// A [`PlaceholderEnv`] that reads from the process environment.
///
/// This is the production wiring. Tests should prefer a `HashMap`-backed env.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl PlaceholderEnv for ProcessEnv {
    fn lookup(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Resolve every `${...}` placeholder in `input` against `env`.
///
/// See the module-level docs for the supported syntax.
pub fn resolve_placeholders(
    input: &str,
    env: &dyn PlaceholderEnv,
) -> Result<String, PlaceholderError> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Escape: `$$` -> literal `$`
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'$' {
            out.push('$');
            i += 2;
            continue;
        }

        // Placeholder: `${...}`
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let open_offset = i;
            // Find the matching closing brace.
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j >= bytes.len() {
                return Err(PlaceholderError::Unterminated {
                    offset: open_offset,
                });
            }

            // Safe: we only break on ASCII `{` / `}` / `:` so slicing is
            // always on UTF-8 boundaries.
            let inner = &input[i + 2..j];
            let (name, default) = split_name_and_default(inner);

            if name.is_empty() {
                return Err(PlaceholderError::EmptyName {
                    offset: open_offset,
                });
            }

            let value = match env.lookup(name) {
                Some(v) => v,
                None => match default {
                    Some(d) => d.to_string(),
                    None => return Err(PlaceholderError::Undefined(name.to_string())),
                },
            };

            out.push_str(&value);
            i = j + 1;
            continue;
        }

        // Regular byte -- advance one UTF-8 character.
        // We use char_indices semantics by finding the next char boundary.
        let ch_len = utf8_char_len(b);
        // Defensive: if the header byte was malformed we still advance by 1
        // to avoid infinite loops; the input is already a valid &str so this
        // branch is effectively unreachable.
        let end = (i + ch_len).min(bytes.len());
        out.push_str(&input[i..end]);
        i = end;
    }

    Ok(out)
}

/// Split `${NAME}` or `${NAME:-default}` into `(name, Some(default))`.
///
/// The default portion is everything after the first `:-` delimiter; if no
/// delimiter is present the default is `None`.
fn split_name_and_default(inner: &str) -> (&str, Option<&str>) {
    match inner.find(":-") {
        Some(idx) => (&inner[..idx], Some(&inner[idx + 2..])),
        None => (inner, None),
    }
}

/// Return the UTF-8 encoded length of the codepoint whose leading byte is `b`.
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b & 0xE0 == 0xC0 {
        2
    } else if b & 0xF0 == 0xE0 {
        3
    } else if b & 0xF8 == 0xF0 {
        4
    } else {
        // Continuation byte or invalid header; unreachable for a leading byte
        // of a valid &str.
        1
    }
}

/// Recursively resolve every string leaf in a JSON value.
///
/// Object keys are left untouched (treated as identifiers). Only string values
/// are rewritten. Numbers, bools, and nulls pass through unchanged.
pub fn resolve_placeholders_in_json(
    value: &Value,
    env: &dyn PlaceholderEnv,
) -> Result<Value, PlaceholderError> {
    match value {
        Value::String(s) => Ok(Value::String(resolve_placeholders(s, env)?)),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_placeholders_in_json(item, env)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), resolve_placeholders_in_json(v, env)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn resolves_simple_placeholder() {
        let env = env(&[("API_KEY", "secret-123")]);
        let out = resolve_placeholders("${API_KEY}", &env).unwrap();
        assert_eq!(out, "secret-123");
    }

    #[test]
    fn resolves_placeholder_inside_larger_string() {
        let env = env(&[("HOST", "example.com")]);
        let out = resolve_placeholders("https://${HOST}/api", &env).unwrap();
        assert_eq!(out, "https://example.com/api");
    }

    #[test]
    fn multiple_placeholders_in_one_string() {
        let env = env(&[("A", "one"), ("B", "two")]);
        let out = resolve_placeholders("${A}-${B}", &env).unwrap();
        assert_eq!(out, "one-two");
    }

    #[test]
    fn default_used_when_env_missing() {
        let env = env(&[]);
        let out = resolve_placeholders("${MISSING:-fallback}", &env).unwrap();
        assert_eq!(out, "fallback");
    }

    #[test]
    fn default_ignored_when_env_present() {
        let env = env(&[("SET", "live")]);
        let out = resolve_placeholders("${SET:-fallback}", &env).unwrap();
        assert_eq!(out, "live");
    }

    #[test]
    fn empty_default_is_allowed() {
        let env = env(&[]);
        let out = resolve_placeholders("${MISSING:-}", &env).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn undefined_without_default_errors() {
        let env = env(&[]);
        let err = resolve_placeholders("${MISSING}", &env).unwrap_err();
        assert_eq!(err, PlaceholderError::Undefined("MISSING".to_string()));
    }

    #[test]
    fn dollar_dollar_escapes_to_literal_dollar() {
        let env = env(&[]);
        let out = resolve_placeholders("price: $$5.00", &env).unwrap();
        assert_eq!(out, "price: $5.00");
    }

    #[test]
    fn dollar_dollar_does_not_start_a_placeholder() {
        // $$ { ... } should yield `$ { ... }`
        let env = env(&[]);
        let out = resolve_placeholders("$${NOT_A_VAR}", &env).unwrap();
        assert_eq!(out, "${NOT_A_VAR}");
    }

    #[test]
    fn unterminated_placeholder_errors() {
        let env = env(&[]);
        let err = resolve_placeholders("hello ${UNCLOSED", &env).unwrap_err();
        match err {
            PlaceholderError::Unterminated { offset } => assert_eq!(offset, 6),
            other => panic!("expected Unterminated, got {other:?}"),
        }
    }

    #[test]
    fn empty_name_errors() {
        let env = env(&[]);
        let err = resolve_placeholders("${}", &env).unwrap_err();
        match err {
            PlaceholderError::EmptyName { offset } => assert_eq!(offset, 0),
            other => panic!("expected EmptyName, got {other:?}"),
        }
    }

    #[test]
    fn lone_dollar_is_literal() {
        let env = env(&[]);
        let out = resolve_placeholders("cost is $5", &env).unwrap();
        assert_eq!(out, "cost is $5");
    }

    #[test]
    fn resolves_in_json_string_leaf() {
        let env = env(&[("TOKEN", "abc")]);
        let value = serde_json::json!("Bearer ${TOKEN}");
        let out = resolve_placeholders_in_json(&value, &env).unwrap();
        assert_eq!(out, serde_json::json!("Bearer abc"));
    }

    #[test]
    fn resolves_in_nested_json() {
        let env = env(&[("HOST", "example.com"), ("PORT", "8080")]);
        let value = serde_json::json!({
            "endpoint": "https://${HOST}:${PORT}/",
            "headers": ["X-Trace: ${HOST}"],
            "numbers": [1, 2, 3],
            "nested": {
                "key": "${HOST}-backup"
            }
        });
        let out = resolve_placeholders_in_json(&value, &env).unwrap();
        assert_eq!(
            out,
            serde_json::json!({
                "endpoint": "https://example.com:8080/",
                "headers": ["X-Trace: example.com"],
                "numbers": [1, 2, 3],
                "nested": {
                    "key": "example.com-backup"
                }
            })
        );
    }

    #[test]
    fn non_string_leaves_pass_through_unchanged() {
        let env = env(&[]);
        let value = serde_json::json!({
            "flag": true,
            "count": 42,
            "ratio": 0.5,
            "nothing": null
        });
        let out = resolve_placeholders_in_json(&value, &env).unwrap();
        assert_eq!(out, value);
    }

    #[test]
    fn object_keys_are_not_rewritten() {
        let env = env(&[("X", "y")]);
        // Even though the key contains a ${} pattern, we only rewrite values.
        let value = serde_json::json!({
            "${X}": "${X}"
        });
        let out = resolve_placeholders_in_json(&value, &env).unwrap();
        assert_eq!(out, serde_json::json!({ "${X}": "y" }));
    }

    #[test]
    fn closure_is_usable_as_placeholder_env() {
        let lookup = |name: &str| -> Option<String> {
            match name {
                "ONE" => Some("1".to_string()),
                _ => None,
            }
        };
        let out = resolve_placeholders("${ONE}-${TWO:-2}", &lookup).unwrap();
        assert_eq!(out, "1-2");
    }
}
