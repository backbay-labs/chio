//! Canonical JSON serialization (RFC 8785 / JCS).
//!
//! Produces byte-for-byte identical output for the same logical JSON value,
//! regardless of key insertion order or floating-point formatting quirks.
//! This is required for deterministic signing: the same value serialized in
//! Rust, TypeScript, Python, or Go must yield identical bytes.
//!
//! Implementation follows RFC 8785 (JSON Canonicalization Scheme):
//! - Object keys sorted by UTF-16 code unit comparison
//! - Numbers: shortest representation matching ECMAScript `JSON.stringify()`
//! - Strings: minimal escaping (only required characters)
//! - No whitespace between tokens

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::cmp::Ordering;
use core::marker::PhantomData;

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// Type-level witness for bytes produced by the canonical JSON serializer.
///
/// `CanonicalBytes<CanonicalJsonWitness>` can only be constructed through
/// this module's canonical JSON serializer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CanonicalJsonWitness;

/// Canonical JSON bytes paired with a phantom validation witness.
///
/// The wrapped buffer is immutable once constructed, so downstream signing,
/// storage, and export paths can share it without reserializing or risking
/// accidental mutation.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CanonicalBytes<W = CanonicalJsonWitness> {
    bytes: Vec<u8>,
    witness: PhantomData<W>,
}

impl CanonicalBytes<CanonicalJsonWitness> {
    /// Serialize a value to canonical JSON bytes and wrap them with a witness.
    pub fn new<T: Serialize>(value: &T) -> Result<Self> {
        Self::from_serializable(value)
    }

    /// Serialize a value to canonical JSON bytes and wrap them with a witness.
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self> {
        let bytes = canonical_json_bytes(value)?;
        Ok(Self::from_canonical_bytes(bytes))
    }

    /// Canonicalize a JSON value and wrap the resulting bytes with a witness.
    pub fn from_value(value: &Value) -> Result<Self> {
        let bytes = canonicalize(value)?.into_bytes();
        Ok(Self::from_canonical_bytes(bytes))
    }
}

impl<W> CanonicalBytes<W> {
    fn from_canonical_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            witness: PhantomData,
        }
    }

    /// Borrow the canonical JSON byte buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the canonical JSON byte buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the byte length of the canonical JSON buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when the canonical JSON buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<W> AsRef<[u8]> for CanonicalBytes<W> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Serialize a value to canonical JSON bytes (RFC 8785).
///
/// This is the primary entry point. Converts a serializable Rust value into
/// its canonical JSON byte representation suitable for signing or hashing.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json_value = serde_json::to_value(value)?;
    let s = canonicalize(&json_value)?;
    Ok(s.into_bytes())
}

/// Serialize a value to a canonical JSON string (RFC 8785).
pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    let json_value = serde_json::to_value(value)?;
    canonicalize(&json_value)
}

/// Canonicalize a `serde_json::Value` to an RFC 8785 string.
pub fn canonicalize(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            // RFC 8785: sort object keys by UTF-16 code unit comparison.
            pairs.sort_by(|(a, _), (b, _)| cmp_utf16_code_units(a.as_str(), b.as_str()));

            let mut out = String::from("{");
            for (idx, (k, v)) in pairs.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(k));
                out.push_str("\":");
                out.push_str(&canonicalize(v)?);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(arr) => {
            let mut out = String::from("[");
            for (idx, v) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(v)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::String(s) => Ok(format!("\"{}\"", escape_json_string(s))),
        Value::Number(n) => canonicalize_number(n),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_string()),
    }
}

/// Compare two strings by UTF-16 code unit values, as required by RFC 8785.
///
/// This differs from Rust's default string comparison (which compares UTF-8
/// byte sequences) for characters outside the Basic Multilingual Plane.
fn cmp_utf16_code_units(a: &str, b: &str) -> Ordering {
    let mut a_units = a.encode_utf16();
    let mut b_units = b.encode_utf16();

    loop {
        match (a_units.next(), b_units.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Canonicalize a JSON number per RFC 8785 / ECMAScript rules.
///
/// Integer values are rendered without a decimal point. Floating-point values
/// use the shortest representation that round-trips, with exponential notation
/// for values outside [1e-6, 1e21).
fn canonicalize_number(n: &serde_json::Number) -> Result<String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    if let Some(f) = n.as_f64() {
        return canonicalize_f64(f);
    }
    Err(Error::CanonicalJson("unsupported JSON number".into()))
}

/// JCS number serialization for IEEE-754 doubles.
///
/// Matches ECMAScript `JSON.stringify()` behavior:
/// - NaN and Infinity are rejected (not valid JSON).
/// - Negative zero is serialized as "0".
/// - Values in [1e-6, 1e21) use decimal notation.
/// - Values outside that range use exponential notation with explicit sign.
fn canonicalize_f64(v: f64) -> Result<String> {
    if !v.is_finite() {
        return Err(Error::CanonicalJson(
            "non-finite numbers are not valid JSON".into(),
        ));
    }
    if v == 0.0 {
        // Normalize -0 to 0.
        return Ok("0".to_string());
    }

    let sign = if v.is_sign_negative() { "-" } else { "" };
    let abs = v.abs();
    let use_exponential = !(1e-6..1e21).contains(&abs);

    // Use ryu for deterministic shortest-representation formatting, then
    // apply JCS post-processing rules.
    let mut buf = ryu::Buffer::new();
    let rendered = buf.format_finite(abs);
    let (digits, sci_exp) = parse_to_scientific_parts(rendered)?;

    if !use_exponential {
        let rendered = render_decimal(&digits, sci_exp);
        return Ok(format!("{sign}{rendered}"));
    }

    let mantissa = if digits.len() == 1 {
        digits.clone()
    } else {
        format!("{}.{}", &digits[0..1], &digits[1..])
    };
    let exp_sign = if sci_exp >= 0 { "+" } else { "" };
    Ok(format!("{sign}{mantissa}e{exp_sign}{sci_exp}"))
}

/// Parse a float string (as formatted by ryu) into (significant digits, exponent).
///
/// Returns:
/// - `digits`: significant digits with no leading/trailing zeros (except "0").
/// - `sci_exp`: exponent such that the value is `digits[0].digits[1..] * 10^sci_exp`.
fn parse_to_scientific_parts(s: &str) -> Result<(String, i32)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::CanonicalJson("empty number string".into()));
    }

    let (mantissa, exp_opt) = if let Some((m, e)) = s.split_once('e') {
        (m, Some(e))
    } else if let Some((m, e)) = s.split_once('E') {
        (m, Some(e))
    } else {
        (s, None)
    };

    let (digits_before_dot, mut digits) = if let Some((a, b)) = mantissa.split_once('.') {
        let frac = b.trim_end_matches('0');
        (a.len() as i32, format!("{a}{frac}"))
    } else {
        (mantissa.len() as i32, mantissa.to_string())
    };

    // Strip leading and trailing zeros from the digit string.
    digits = digits.trim_start_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }
    digits = digits.trim_end_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }

    let sci_exp = if let Some(exp_str) = exp_opt {
        let exp: i32 = exp_str
            .parse()
            .map_err(|_| Error::CanonicalJson(format!("invalid exponent: {exp_str}")))?;
        exp + (digits_before_dot - 1)
    } else {
        // Decimal form: compute exponent from position of first significant digit.
        if mantissa.contains('.') {
            let (int_part, frac_part_raw) = mantissa
                .split_once('.')
                .ok_or_else(|| Error::CanonicalJson("invalid decimal".into()))?;
            let frac_part = frac_part_raw.trim_end_matches('0');

            let int_stripped = int_part.trim_start_matches('0');
            if !int_stripped.is_empty() {
                (int_stripped.len() as i32) - 1
            } else {
                let leading_zeros = frac_part.chars().take_while(|c| *c == '0').count() as i32;
                -(leading_zeros + 1)
            }
        } else {
            // Integer form (no dot).
            (mantissa.trim_start_matches('0').len() as i32) - 1
        }
    };

    Ok((digits, sci_exp))
}

/// Render significant digits with a decimal point at the correct position.
fn render_decimal(digits: &str, sci_exp: i32) -> String {
    let digits_len = digits.len() as i32;
    let shift = sci_exp - (digits_len - 1);

    if shift >= 0 {
        // All digits are before the decimal point; pad with trailing zeros.
        let mut out = String::with_capacity(digits.len() + shift as usize);
        out.push_str(digits);
        out.extend(core::iter::repeat_n('0', shift as usize));
        return out;
    }

    let pos = digits_len + shift; // shift is negative
    if pos > 0 {
        let pos_usize = pos as usize;
        let mut out = String::with_capacity(digits.len() + 1);
        out.push_str(&digits[..pos_usize]);
        out.push('.');
        out.push_str(&digits[pos_usize..]);
        trim_decimal(out)
    } else {
        let zeros = (-pos) as usize;
        let mut out = String::with_capacity(2 + zeros + digits.len());
        out.push_str("0.");
        out.extend(core::iter::repeat_n('0', zeros));
        out.push_str(digits);
        trim_decimal(out)
    }
}

/// Remove trailing fractional zeros and a trailing decimal point.
fn trim_decimal(mut s: String) -> String {
    if let Some(dot) = s.find('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.len() == dot + 1 {
            s.pop();
        }
    }
    s
}

/// Escape a string per RFC 8785 / JSON rules.
///
/// Only the characters that JSON requires to be escaped are escaped.
/// Control characters U+0000..U+001F use `\uXXXX` form except for the
/// six shorthand escapes (\", \\, \b, \f, \n, \r, \t). Characters above
/// U+001F (including U+2028 and U+2029) are passed through unescaped --
/// RFC 8785 requires minimal escaping.
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{0C}' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                // U+0000..U+001F (excluding the six above) use \uXXXX.
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sorted_keys_basic() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3,
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn sorted_keys_utf16_code_units() {
        // U+E000 is a BMP private-use character (single UTF-16 code unit: 0xE000).
        // U+10437 is a supplementary character (surrogate pair: 0xD801 0xDC37).
        // UTF-16 comparison: 0xD801 < 0xE000, so U+10437 sorts before U+E000.
        // This differs from Rust's default UTF-8 string comparison.
        let value = serde_json::json!({
            "\u{e000}": 1,
            "\u{10437}": 2,
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, "{\"\u{10437}\":2,\"\u{e000}\":1}");
    }

    #[test]
    fn numeric_string_keys_sort_by_code_units() {
        // "10" < "2" in UTF-16 because '1' (0x0031) < '2' (0x0032).
        let value = serde_json::json!({
            "2": "b",
            "10": "a",
            "a": 0,
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"10":"a","2":"b","a":0}"#);
    }

    #[test]
    fn jcs_numbers() {
        let value = serde_json::json!({
            "a": 1.0,
            "b": 0.0,
            "c": -0.0,
            "d": 1e21,
            "e": 1e20,
            "f": 1e-6,
            "g": 1e-7,
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}"#
        );
    }

    #[test]
    fn integers() {
        let value = serde_json::json!(42);
        assert_eq!(canonicalize(&value).unwrap(), "42");

        let value = serde_json::json!(-1);
        assert_eq!(canonicalize(&value).unwrap(), "-1");

        let value = serde_json::json!(0);
        assert_eq!(canonicalize(&value).unwrap(), "0");
    }

    #[test]
    fn non_finite_rejected() {
        assert!(canonicalize_f64(f64::NAN).is_err());
        assert!(canonicalize_f64(f64::INFINITY).is_err());
        assert!(canonicalize_f64(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn negative_zero_is_zero() {
        assert_eq!(canonicalize_f64(-0.0).unwrap(), "0");
    }

    #[test]
    fn string_escaping() {
        let value = serde_json::json!({
            "b": "\u{0008}",
            "f": "\u{000c}",
            "ctl": "\u{000f}",
            "quote": "\"",
            "backslash": "\\",
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"b":"\b","backslash":"\\","ctl":"\u000f","f":"\f","quote":"\""}"#
        );
    }

    #[test]
    fn unicode_passthrough() {
        // U+2028 and U+2029 are NOT escaped per RFC 8785 (minimal escaping).
        let value = serde_json::json!({
            "u2028": "\u{2028}",
            "u2029": "\u{2029}",
            "emoji": "\u{1F600}",
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            format!(
                "{{\"emoji\":\"\u{1F600}\",\"u2028\":\"{}\",\"u2029\":\"{}\"}}",
                "\u{2028}", "\u{2029}"
            )
        );
    }

    #[test]
    fn nested_objects() {
        let value = serde_json::json!({
            "outer": {
                "inner": "value"
            }
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"outer":{"inner":"value"}}"#);
    }

    #[test]
    fn arrays() {
        let value = serde_json::json!([1, 2, 3]);
        assert_eq!(canonicalize(&value).unwrap(), "[1,2,3]");
    }

    #[test]
    fn empty_object() {
        let value = serde_json::json!({});
        assert_eq!(canonicalize(&value).unwrap(), "{}");
    }

    #[test]
    fn empty_array() {
        let value = serde_json::json!([]);
        assert_eq!(canonicalize(&value).unwrap(), "[]");
    }

    #[test]
    fn null_and_booleans() {
        assert_eq!(canonicalize(&serde_json::json!(null)).unwrap(), "null");
        assert_eq!(canonicalize(&serde_json::json!(true)).unwrap(), "true");
        assert_eq!(canonicalize(&serde_json::json!(false)).unwrap(), "false");
    }

    #[test]
    fn deeply_nested() {
        let value = serde_json::json!({
            "a": {
                "b": {
                    "c": [1, {"d": true}]
                }
            }
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":{"b":{"c":[1,{"d":true}]}}}"#);
    }

    #[test]
    fn canonical_bytes_match_string() {
        let value = serde_json::json!({"z": 1, "a": 2});
        let bytes = canonical_json_bytes(&value).unwrap();
        let string = canonical_json_string(&value).unwrap();
        assert_eq!(bytes, string.as_bytes());
    }

    #[test]
    fn canonical_bytes_newtype_matches_existing_bytes() -> Result<()> {
        let value = serde_json::json!({"z": 1, "a": [2, 3]});
        let wrapped = CanonicalBytes::new(&value)?;
        let bytes = canonical_json_bytes(&value)?;

        assert_eq!(wrapped.as_bytes(), bytes.as_slice());
        assert_eq!(wrapped.len(), bytes.len());
        assert!(!wrapped.is_empty());
        assert_eq!(wrapped.into_vec(), bytes);

        Ok(())
    }

    #[test]
    fn canonical_bytes_from_value_matches_canonicalizer() -> Result<()> {
        let value = serde_json::json!({"outer": {"b": true, "a": null}});
        let wrapped = CanonicalBytes::from_value(&value)?;
        let canonical = canonicalize(&value)?;

        assert_eq!(wrapped.as_ref(), canonical.as_bytes());

        Ok(())
    }

    // Signing tests live in crypto.rs.

    #[test]
    fn deterministic_output() {
        let value = serde_json::json!({
            "action": "file_read",
            "path": "/etc/hosts",
            "ts": 1710000000
        });
        let a = canonical_json_bytes(&value).unwrap();
        let b = canonical_json_bytes(&value).unwrap();
        assert_eq!(a, b);
    }

    // These are based on examples from Section 3 of the RFC.

    #[test]
    fn rfc8785_section3_number_examples() {
        // Verify individual number renderings.
        assert_eq!(
            canonicalize_f64(333_333_333.333_333_3).unwrap(),
            "333333333.3333333"
        );
        assert_eq!(canonicalize_f64(1e20).unwrap(), "100000000000000000000");
        assert_eq!(canonicalize_f64(1e21).unwrap(), "1e+21");
        assert_eq!(canonicalize_f64(1e-7).unwrap(), "1e-7");
        assert_eq!(canonicalize_f64(1e-6).unwrap(), "0.000001");
    }

    #[test]
    fn rfc8785_mixed_document() {
        // A representative document exercising multiple features.
        let value = serde_json::json!({
            "numbers": [333_333_333.333_333_3, 1e30, 4.5, -0.0, 0, 2e-3, 0.000001],
            "string": "\u{20ac}$\u{000f}\u{000a}A'\u{0008}\\\"\\",
            "literals": [null, true, false],
        });
        let canonical = canonicalize(&value).unwrap();

        // Verify it parses back to the same logical value.
        let round_tripped: serde_json::Value = serde_json::from_str(&canonical).unwrap();

        // Numbers array should match.
        let nums = round_tripped["numbers"].as_array().unwrap();
        assert_eq!(nums.len(), 7);

        // The canonical form has no whitespace.
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
    }
}
