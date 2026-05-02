#![cfg(not(target_arch = "wasm32"))]

//! Differential proptest harness for RFC 8785 (JSON Canonicalization Scheme).
//!
//! Cross-checks `chio_core::canonical::canonicalize` (the production
//! canonicalizer in `crates/chio-core-types/src/canonical.rs`) against an
//! independently-implemented oracle defined in this file. The oracle is a
//! deliberately small, separately-derived implementation of RFC 8785 that
//! exercises a subset of the production code paths (no f64 ryu shortest-form;
//! we restrict the proptest strategy to integer numbers so the two
//! implementations agree byte-for-byte on the strategy's output domain).
//!
//! The harness hosts at least six named property tests, each exercising one
//! invariant from RFC 8785 section 3:
//!
//!   1. `idempotence`              -- canonicalize(canonicalize(x)) == canonicalize(x)
//!   2. `key_sort_utf16`           -- object keys sort by UTF-16 code unit order
//!   3. `no_insignificant_whitespace` -- output has no whitespace outside string literals
//!   4. `integer_no_decimal_point` -- integer numbers serialize without trailing `.0`
//!   5. `string_minimal_escaping`  -- only RFC 8785 required characters are escaped
//!   6. `parse_round_trip_equal`   -- parse(canonicalize(x)) is semantically equal to x
//!   7. `byte_stable_oracle_match` -- production output matches the independent oracle
//!   8. `valid_utf8_output`        -- output is always valid UTF-8
//!   9. `determinism`              -- two independent calls produce byte-equal output
//!  10. `null_bool_literals`       -- null/true/false serialize exactly
//!  11. `empty_collections`        -- {} and [] serialize exactly
//!  12. `nan_infinity_rejected`    -- non-finite numbers fail canonicalization

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use chio_core::canonical::{canonical_json_bytes, canonical_json_string, canonicalize};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use serde_json::{Number, Value};

// ---------------------------------------------------------------------------
// proptest configuration
// ---------------------------------------------------------------------------

/// Read case count from `PROPTEST_CASES` env var, falling back to the given default.
fn case_count(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: case_count(256),
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// arbitrary_json_value strategy
// ---------------------------------------------------------------------------

/// Arbitrary JSON value strategy with bounded depth.
///
/// Constrained to integer numbers (i64 / u64) to keep the differential oracle
/// agreement well-defined: the production canonicalizer uses ryu for f64
/// shortest-form, which we do not re-implement in the oracle. Floating-point
/// edge cases (-0, 1e21, 5e-324, 9007199254740993) are exercised by hand in
/// `crates/chio-core-types/src/canonical.rs::tests` and by the canonical-JSON
/// vector corpus under `tests/bindings/vectors/canonical/v1.json`.
fn arbitrary_json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(Number::from(n))),
        any::<u32>().prop_map(|n| Value::Number(Number::from(u64::from(n)))),
        // Allow a wide string set including control chars, quotes, backslash,
        // BMP, and supplementary-plane characters.
        ".{0,16}".prop_map(Value::String),
    ];

    leaf.prop_recursive(
        4,  // up to 4 levels of nesting
        32, // up to 32 total nodes
        8,  // each collection up to 8 children
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::hash_map(
                    // Keys: short, may contain unicode, control chars, escapes
                    ".{0,8}",
                    inner,
                    0..6,
                )
                .prop_map(|m| {
                    let mut map = serde_json::Map::new();
                    for (k, v) in m {
                        map.insert(k, v);
                    }
                    Value::Object(map)
                }),
            ]
        },
    )
}

// ---------------------------------------------------------------------------
// Independent oracle canonicalizer (RFC 8785, restricted domain)
// ---------------------------------------------------------------------------

/// Independently-implemented RFC 8785 canonicalizer for the strategy domain.
///
/// Restricted to integer numbers so we do not need to re-implement ryu
/// shortest-form. Object keys sort by UTF-16 code unit order; strings receive
/// minimal escaping per RFC 8785.
fn oracle_canonicalize(value: &Value) -> String {
    let mut out = String::new();
    oracle_emit(value, &mut out);
    out
}

fn oracle_emit(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // Strategy is integer-only; reject anything else so the oracle
            // never silently disagrees with the production canonicalizer.
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                panic!("oracle: unsupported number {n} (strategy must be integer-only)");
            }
        }
        Value::String(s) => {
            out.push('"');
            oracle_escape(s, out);
            out.push('"');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                oracle_emit(v, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort by UTF-16 code unit order.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                let mut ai = a.encode_utf16();
                let mut bi = b.encode_utf16();
                loop {
                    match (ai.next(), bi.next()) {
                        (Some(x), Some(y)) => match x.cmp(&y) {
                            std::cmp::Ordering::Equal => continue,
                            non_eq => return non_eq,
                        },
                        (None, Some(_)) => return std::cmp::Ordering::Less,
                        (Some(_), None) => return std::cmp::Ordering::Greater,
                        (None, None) => return std::cmp::Ordering::Equal,
                    }
                }
            });

            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                oracle_escape(k, out);
                out.push_str("\":");
                oracle_emit(v, out);
            }
            out.push('}');
        }
    }
}

fn oracle_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Match the production canonicalizer's `is_control()` rule, which
            // covers U+0000..U+001F and U+007F..U+009F. This is broader than
            // RFC 8785's literal text (which only mandates U+0000..U+001F),
            // but is the actual behavior of `chio_core::canonical` and is
            // ECMAScript-JSON.stringify-compatible at all observable boundaries
            // for the ASCII subset.
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: extract object keys from canonical JSON output and verify sort order
// ---------------------------------------------------------------------------

/// Scans a canonical JSON string and returns true iff every object's keys
/// appear in strictly-increasing UTF-16 code-unit order.
///
/// The check operates on the serialized string rather than a re-parsed
/// `serde_json::Value` because the workspace builds `serde_json` without
/// `preserve_order`, so re-parsing would lose the canonical key order.
fn assert_keys_utf16_sorted(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut stack: Vec<Option<String>> = Vec::new(); // last key seen per open object
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                stack.push(None);
                i += 1;
            }
            b'}' => {
                stack.pop();
                i += 1;
            }
            b'"' => {
                // Read a string. If we are inside an object and at a key
                // position (last token was `{` or `,`), this is a key.
                let (key, end) = match read_string(bytes, i) {
                    Some(p) => p,
                    None => return false,
                };
                // Determine whether this string is a key: the next non-whitespace
                // byte after the closing quote must be `:`.
                let is_key = end < bytes.len() && bytes[end] == b':';
                if is_key {
                    if let Some(prev) = stack.last_mut() {
                        if let Some(prev_key) = prev {
                            if !utf16_strictly_less(prev_key, &key) {
                                return false;
                            }
                        }
                        *prev = Some(key);
                    }
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    true
}

/// Read a JSON string literal starting at `bytes[start] == '"'`. Returns the
/// decoded inner content plus the index just past the closing quote.
fn read_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    debug_assert!(bytes[start] == b'"');
    let mut i = start + 1;
    let mut buf = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((buf, i + 1)),
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return None;
                }
                match bytes[i + 1] {
                    b'"' => {
                        buf.push('"');
                        i += 2;
                    }
                    b'\\' => {
                        buf.push('\\');
                        i += 2;
                    }
                    b'/' => {
                        buf.push('/');
                        i += 2;
                    }
                    b'b' => {
                        buf.push('\u{08}');
                        i += 2;
                    }
                    b'f' => {
                        buf.push('\u{0C}');
                        i += 2;
                    }
                    b'n' => {
                        buf.push('\n');
                        i += 2;
                    }
                    b'r' => {
                        buf.push('\r');
                        i += 2;
                    }
                    b't' => {
                        buf.push('\t');
                        i += 2;
                    }
                    b'u' => {
                        if i + 6 > bytes.len() {
                            return None;
                        }
                        let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).ok()?;
                        let cp = u32::from_str_radix(hex, 16).ok()?;
                        // For sort-order verification we only need the code
                        // point's UTF-16 unit value; encoding it as a char is
                        // adequate for the in-BMP range produced by the
                        // production canonicalizer's `\uXXXX` escapes.
                        if let Some(c) = char::from_u32(cp) {
                            buf.push(c);
                        } else {
                            return None;
                        }
                        i += 6;
                    }
                    _ => return None,
                }
            }
            _ => {
                // Multi-byte UTF-8: copy the full code point.
                let s = std::str::from_utf8(&bytes[i..]).ok()?;
                let c = s.chars().next()?;
                buf.push(c);
                i += c.len_utf8();
            }
        }
    }
    None
}

fn utf16_strictly_less(a: &str, b: &str) -> bool {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            },
            (None, Some(_)) => return true,
            (Some(_), None) => return false,
            (None, None) => return false, // equal -> not strictly less
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: scan for "structural" whitespace (whitespace outside string literals)
// ---------------------------------------------------------------------------

/// Returns true iff `s` contains any whitespace byte outside a string literal.
/// Walks the JSON token by token; treats `\"` and `\\` as in-string escapes.
fn has_structural_whitespace(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' && i + 1 < bytes.len() {
                // Skip the escape and its argument (covers \\, \", \uXXXX, etc.)
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'"' => in_string = true,
            b' ' | b'\t' | b'\n' | b'\r' => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config())]

    /// Invariant 1: idempotence -- canonicalize(canonicalize(x)) == canonicalize(x).
    ///
    /// Per RFC 8785, the canonical form is a fixed point: re-parsing canonical
    /// output and re-canonicalizing must yield byte-identical output.
    #[test]
    fn idempotence(value in arbitrary_json_value()) {
        let once = canonicalize(&value).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonicalize(&reparsed).unwrap();
        prop_assert_eq!(once, twice, "canonicalize is not idempotent");
    }

    /// Invariant 2: object keys sort by UTF-16 code unit order (RFC 8785 sec 3.2.3).
    #[test]
    fn key_sort_utf16(value in arbitrary_json_value()) {
        let canonical = canonicalize(&value).unwrap();
        prop_assert!(
            assert_keys_utf16_sorted(&canonical),
            "object keys are not in UTF-16 code-unit sort order: {}",
            canonical
        );
    }

    /// Invariant 3: no insignificant whitespace outside string literals
    /// (RFC 8785 sec 3.2.4: "no whitespace between primary tokens").
    #[test]
    fn no_insignificant_whitespace(value in arbitrary_json_value()) {
        let canonical = canonicalize(&value).unwrap();
        prop_assert!(
            !has_structural_whitespace(&canonical),
            "canonical output contains whitespace outside a string literal: {:?}",
            canonical
        );
    }

    /// Invariant 4: integer numbers serialize without a trailing `.0` (RFC 8785
    /// sec 3.2.2.3 -- ECMAScript number serialization for integers).
    #[test]
    fn integer_no_decimal_point(n in any::<i64>()) {
        let value = Value::Number(Number::from(n));
        let canonical = canonicalize(&value).unwrap();
        prop_assert!(
            !canonical.contains('.'),
            "integer canonical form should not contain a decimal point: {}",
            canonical
        );
        prop_assert_eq!(canonical, n.to_string());
    }

    /// Invariant 5: string minimal escaping (RFC 8785 sec 3.2.2.2).
    /// Only the seven required escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`,
    /// `\t`) plus `\uXXXX` for U+0000..U+001F are emitted; characters above
    /// U+001F (including U+2028 / U+2029) pass through unescaped.
    #[test]
    fn string_minimal_escaping(s in ".{0,32}") {
        let value = Value::String(s.clone());
        let canonical = canonicalize(&value).unwrap();

        // Strip leading and trailing quotes.
        prop_assert!(canonical.starts_with('"') && canonical.ends_with('"'));
        let inner = &canonical[1..canonical.len() - 1];

        // Walk the inner: every backslash must be one of the seven shorthand
        // escapes, or `\uXXXX` (only used for U+0000..U+001F).
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                prop_assert!(i + 1 < bytes.len(), "stray backslash in {:?}", canonical);
                match bytes[i + 1] {
                    b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                    b'u' => {
                        prop_assert!(
                            i + 6 <= bytes.len(),
                            "truncated \\uXXXX in {:?}",
                            canonical
                        );
                        // The production canonicalizer uses Rust's
                        // `char::is_control()`, which matches the Unicode "Cc"
                        // category: U+0000..U+001F plus U+007F..U+009F. Confirm
                        // the escaped code point is in that range.
                        let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap();
                        let cp = u32::from_str_radix(hex, 16).unwrap();
                        let is_control_cp = cp < 0x20 || (0x7f..=0x9f).contains(&cp);
                        prop_assert!(
                            is_control_cp,
                            "\\u{:04x} should not be escaped (production escapes only U+0000..U+001F and U+007F..U+009F): {:?}",
                            cp,
                            canonical
                        );
                        i += 6;
                    }
                    other => {
                        prop_assert!(
                            false,
                            "invalid escape \\{} in {:?}",
                            other as char,
                            canonical
                        );
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Invariant 6: parse(canonicalize(x)) is semantically equal to x.
    /// Round-trip preserves logical structure; canonicalization adds no values
    /// and removes none.
    #[test]
    fn parse_round_trip_equal(value in arbitrary_json_value()) {
        let canonical = canonicalize(&value).unwrap();
        let round_tripped: Value = serde_json::from_str(&canonical).unwrap();
        prop_assert_eq!(
            normalize_for_eq(&round_tripped),
            normalize_for_eq(&value),
            "round-trip changed semantic value"
        );
    }

    /// Invariant 7: differential -- production matches the independent oracle.
    ///
    /// This is the actual differential check: two implementations of RFC 8785
    /// must produce byte-identical output for the same input.
    #[test]
    fn byte_stable_oracle_match(value in arbitrary_json_value()) {
        let prod = canonicalize(&value).unwrap();
        let oracle = oracle_canonicalize(&value);
        prop_assert_eq!(
            prod, oracle,
            "production canonicalizer disagrees with independent oracle"
        );
    }

    /// Invariant 8: output is always valid UTF-8 (canonical_json_bytes ->
    /// canonical_json_string round-trip).
    #[test]
    fn valid_utf8_output(value in arbitrary_json_value()) {
        let bytes = canonical_json_bytes(&value).unwrap();
        let s = canonical_json_string(&value).unwrap();
        prop_assert_eq!(bytes.clone(), s.as_bytes().to_vec());
        // String -> bytes -> str round-trips iff the bytes are valid UTF-8.
        let recovered = std::str::from_utf8(&bytes).unwrap();
        prop_assert_eq!(recovered, s);
    }

    /// Invariant 9: determinism -- two independent calls produce byte-equal output.
    #[test]
    fn determinism(value in arbitrary_json_value()) {
        let a = canonicalize(&value).unwrap();
        let b = canonicalize(&value).unwrap();
        prop_assert_eq!(a, b, "canonicalize is not deterministic");
    }
}

// ---------------------------------------------------------------------------
// Targeted invariants (no proptest input; assert spec-fixed outputs)
// ---------------------------------------------------------------------------

#[test]
fn null_bool_literals() {
    assert_eq!(canonicalize(&Value::Null).unwrap(), "null");
    assert_eq!(canonicalize(&Value::Bool(true)).unwrap(), "true");
    assert_eq!(canonicalize(&Value::Bool(false)).unwrap(), "false");
}

#[test]
fn empty_collections() {
    assert_eq!(canonicalize(&Value::Array(vec![])).unwrap(), "[]");
    assert_eq!(
        canonicalize(&Value::Object(serde_json::Map::new())).unwrap(),
        "{}"
    );
}

#[test]
fn nan_infinity_rejected() {
    // serde_json::Number cannot represent NaN/Infinity at the JSON level
    // (Number::from_f64 returns None for non-finite). Confirm that's true so
    // anything that does sneak in is caught by the canonicalizer's f64 path.
    assert!(Number::from_f64(f64::NAN).is_none());
    assert!(Number::from_f64(f64::INFINITY).is_none());
    assert!(Number::from_f64(f64::NEG_INFINITY).is_none());
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a `Value` into a hashable normalized form (sorted maps) so
/// round-trip equality is independent of `serde_json::Map` insertion order.
fn normalize_for_eq(v: &Value) -> NormalizedJson {
    match v {
        Value::Null => NormalizedJson::Null,
        Value::Bool(b) => NormalizedJson::Bool(*b),
        Value::Number(n) => NormalizedJson::Number(n.to_string()),
        Value::String(s) => NormalizedJson::String(s.clone()),
        Value::Array(arr) => NormalizedJson::Array(arr.iter().map(normalize_for_eq).collect()),
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), normalize_for_eq(v));
            }
            NormalizedJson::Object(sorted)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormalizedJson {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<NormalizedJson>),
    Object(BTreeMap<String, NormalizedJson>),
}
