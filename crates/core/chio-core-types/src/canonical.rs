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

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::cmp::Ordering;
use core::fmt;
use core::marker::PhantomData;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Largest integer magnitude permitted for interoperable JSON exchange
/// (`2^53 - 1`). RFC 7493 (I-JSON) §2.2 requires integers to fall within
/// `[-(2^53 - 1), 2^53 - 1]`: although `2^53` itself round-trips through an
/// IEEE-754 double, it is excluded from the safe range because it shares its
/// representation with `2^53 + 1`, so consumers cannot distinguish the two.
/// Magnitudes above this bound cannot be represented exactly by every
/// conforming consumer and so must be rejected before signing rather than
/// silently coerced.
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

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

/// Strictly parse raw JSON text and canonicalize it to RFC 8785 bytes.
///
/// Unlike [`canonical_json_bytes`], which canonicalizes an already-typed Rust
/// value, this entry point validates *untrusted JSON text* before signing. It
/// enforces I-JSON / RFC 8785 input constraints that a plain
/// `serde_json::Value` round-trip would silently paper over:
///
/// - **Duplicate object keys are rejected.** `serde_json::Value` collapses
///   them with last-wins semantics, which lets two distinct payloads
///   canonicalize to the same bytes (a render-A / sign-B vector). Here a
///   repeated key is a hard error.
/// - **Non-I-JSON numbers are rejected.** Integer literals outside the safe
///   range `[-(2^53 - 1), 2^53 - 1]` cannot be represented losslessly by every
///   conforming consumer; rather than coerce them to a precision-losing `f64`,
///   canonicalization fails. Any number token that parses to an integer-valued
///   `f64` is also rejected: such a token never arrives through serde_json's
///   exact integer path, so it is either a fractional literal the parser rounded
///   onto an integer (for example `9007199254740991.1`) or an integer written in
///   float form (`1.0`, `1e2`). Because the original lexeme cannot be recovered
///   without serde_json's std-only `raw_value` feature, both are refused so the
///   signed bytes always reflect the value actually submitted. Integers must be
///   sent as integer tokens (`100`, not `100.0`).
/// - **Over-precise fractional numbers are rejected.** A decimal literal that
///   carries more significant digits than an `f64` can hold (for example
///   `0.123456789012345678901`) is silently rounded by serde_json onto the
///   nearest double, which canonicalizes to the same bytes as a different,
///   shorter literal (`0.12345678901234568`). Signing the rounded value would
///   resurrect the render-A / sign-B class this API exists to prevent, so any
///   fractional token whose value does not round-trip exactly through the
///   strict path is refused. See [`StrictJson::reject_over_precise_numbers`].
///
/// Well-formed I-JSON input canonicalizes byte-identically to the typed path,
/// with the sole exception of integer-valued float tokens, which the typed path
/// accepts but this stricter entry point rejects for the reason above.
pub fn canonical_json_bytes_from_str(input: &str) -> Result<Vec<u8>> {
    canonical_json_string_from_str(input).map(String::into_bytes)
}

/// Strictly parse raw JSON text and canonicalize it to an RFC 8785 string.
///
/// See [`canonical_json_bytes_from_str`] for the validation contract.
pub fn canonical_json_string_from_str(input: &str) -> Result<String> {
    let value = StrictJson::from_str(input)?;
    // `StrictJson::from_str` has already proven `input` is well-formed I-JSON, so
    // the source text can be scanned for over-precise fractional literals (whose
    // discarded digits are invisible once parsed to `f64`) before signing.
    StrictJson::reject_over_precise_numbers(input)?;
    let mut out = String::new();
    value.write_canonical(&mut out)?;
    Ok(out)
}

/// Canonicalize a `serde_json::Value` to an RFC 8785 string.
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical_value(value, &mut out)?;
    Ok(out)
}

fn write_canonical_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Object(map) => write_canonical_object(map, out),
        Value::Array(arr) => write_canonical_array(arr, out),
        Value::String(s) => {
            out.push('"');
            out.push_str(&escape_json_string(s));
            out.push('"');
            Ok(())
        }
        Value::Number(n) => {
            out.push_str(&canonicalize_number(n)?);
            Ok(())
        }
        Value::Bool(true) => {
            out.push_str("true");
            Ok(())
        }
        Value::Bool(false) => {
            out.push_str("false");
            Ok(())
        }
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
    }
}

fn write_canonical_object(map: &Map<String, Value>, out: &mut String) -> Result<()> {
    let mut pairs: Vec<_> = map.iter().collect();
    // RFC 8785: sort object keys by UTF-16 code unit comparison.
    pairs.sort_by(|(a, _), (b, _)| cmp_utf16_code_units(a.as_str(), b.as_str()));

    out.push('{');
    for (idx, (key, value)) in pairs.into_iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json_string(key));
        out.push_str("\":");
        write_canonical_value(value, out)?;
    }
    out.push('}');
    Ok(())
}

fn write_canonical_array(values: &[Value], out: &mut String) -> Result<()> {
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        write_canonical_value(value, out)?;
    }
    out.push(']');
    Ok(())
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

/// Reject a fractional number token that is not already in shortest canonical form.
///
/// Integer-valued tokens (no fractional part, or a `.0`/exponent that resolves to
/// a whole number) are handled by `visit_f64`'s `fract() == 0.0` guard, so this
/// only inspects tokens whose value has a genuine fractional component. Such a
/// token is canonical only when its significant digits are *exactly* the
/// significant digits of the shortest decimal that round-trips to its `f64` (the
/// form the canonical writer emits via `ryu`). Any other token either carries
/// surplus digits the parser silently rounded away, or sits at the same digit
/// count yet a different value than the shortest rendering (for example
/// `0.12345678901234567`, which parses to the f64 whose shortest form is
/// `0.12345678901234566`: identical 17-digit count, different digits). Comparing
/// only the digit *count* would admit the latter and then sign the rounded value
/// (render-A / sign-B). Comparing the digit *sequence* fails closed: the token is
/// accepted only when it is already the shortest round-tripping decimal.
fn reject_if_over_precise_fractional(token: &str) -> Result<()> {
    let value: f64 = token
        .parse()
        .map_err(|_| Error::CanonicalJson(format!("invalid number token: {token}")))?;
    // Integer-valued doubles never reach the canonical float path (visit_f64
    // already refuses them); skip them here so this check is solely about
    // fractional precision.
    if !value.is_finite() || value.fract() == 0.0 {
        return Ok(());
    }

    let mut buf = ryu::Buffer::new();
    let shortest = buf.format_finite(value.abs());
    // The token and the ryu rendering describe the same f64 (the former parsed to
    // it, the latter rendered from it), so they share magnitude; the only degree
    // of freedom is the significant-digit sequence. Equal sequences mean the
    // submitted token is already the shortest round-tripping decimal; any
    // divergence means precision was lost (or shifted) on parse and the input is
    // refused fail-closed.
    if significant_digits(token) != significant_digits(shortest) {
        return Err(Error::CanonicalJson(format!(
            "number {token} cannot be signed: it is not the shortest decimal that \
             round-trips through an f64 and would be silently rounded to {shortest}; \
             submit the value in its exact shortest double representation"
        )));
    }
    Ok(())
}

/// Extract the significant decimal digits of a JSON number token, in order.
///
/// Only the mantissa (the portion before any `e`/`E`) contributes; leading and
/// trailing zeros are not significant, so they are stripped. An all-zero or
/// integer-zero mantissa yields an empty string. The exponent and sign are
/// ignored because they shift magnitude without adding precision. Comparing the
/// returned sequences (not merely their lengths) detects tokens whose digit
/// *count* matches the shortest rendering but whose digit *values* differ.
fn significant_digits(token: &str) -> String {
    let mantissa = token.split(['e', 'E']).next().unwrap_or(token);
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    digits
        .trim_start_matches('0')
        .trim_end_matches('0')
        .to_string()
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

/// A strictly-validated JSON value tree used by the text-parsing entry points.
///
/// It is deserialized directly from JSON tokens (never through
/// `serde_json::Value`) so that:
/// - duplicate object keys can be detected and rejected, and
/// - number literals can be checked against the I-JSON safe range without first
///   being coerced to a lossy `f64`.
///
/// Key insertion order is preserved during parsing; the canonical writer sorts
/// keys by UTF-16 code unit at emit time, matching the typed path exactly.
enum StrictJson {
    Null,
    Bool(bool),
    /// An integer literal within the I-JSON safe range, preserved exactly.
    Int(i64),
    /// A fractional / exponent number literal, validated as finite.
    Float(f64),
    Str(String),
    Array(Vec<StrictJson>),
    /// Object entries in insertion order; keys are guaranteed unique.
    Object(Vec<(String, StrictJson)>),
}

impl StrictJson {
    fn from_str(input: &str) -> Result<Self> {
        let mut de = serde_json::Deserializer::from_str(input);
        let value = StrictJson::deserialize(&mut de)
            .map_err(|err| Error::CanonicalJson(format!("invalid I-JSON input: {err}")))?;
        de.end()
            .map_err(|err| Error::CanonicalJson(format!("trailing JSON data: {err}")))?;
        Ok(value)
    }

    /// Reject fractional number literals carrying more precision than an `f64`.
    ///
    /// `visit_f64` only ever sees the already-parsed double, so an over-precise
    /// fractional lexeme (for example `0.123456789012345678901`) is
    /// indistinguishable there from the shorter literal it rounds to
    /// (`0.12345678901234568`): both arrive as the same non-integer `f64` and
    /// canonicalize to identical bytes. Signing the rounded value would reopen
    /// the render-A / sign-B class this API exists to close, and serde_json
    /// exposes no raw lexeme without its std-only `raw_value` feature (which this
    /// `no_std + alloc` crate cannot enable).
    ///
    /// This scans the already-validated source text directly. For every fractional
    /// number token it parses the value to `f64`, renders that double back to its
    /// shortest decimal (the form the canonical writer emits via `ryu`), and
    /// rejects the token when it carries more significant digits than the shortest
    /// form. Because `ryu` produces the shortest decimal that round-trips to the
    /// double, any token with extra significant digits necessarily lost precision
    /// during parsing; a token with the same count round-trips exactly. This is
    /// the conservative closure: it admits only fractional literals that survive
    /// the strict path unchanged. The caller invokes it after [`Self::from_str`]
    /// succeeds, so the input here is guaranteed to be well-formed JSON.
    fn reject_over_precise_numbers(input: &str) -> Result<()> {
        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut idx = 0;
        while idx < len {
            let ch = bytes[idx];
            if ch == b'"' {
                // Skip a string literal so digits inside it are never treated as
                // a number token. Backslash escapes the following byte (including
                // an escaped quote), so step over the pair.
                idx += 1;
                while idx < len {
                    match bytes[idx] {
                        b'\\' => idx += 2,
                        b'"' => {
                            idx += 1;
                            break;
                        }
                        _ => idx += 1,
                    }
                }
                continue;
            }

            let starts_number = ch.is_ascii_digit()
                || (ch == b'-' && idx + 1 < len && bytes[idx + 1].is_ascii_digit());
            if !starts_number {
                idx += 1;
                continue;
            }

            let start = idx;
            if ch == b'-' {
                idx += 1;
            }
            while idx < len {
                match bytes[idx] {
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => idx += 1,
                    _ => break,
                }
            }
            // `start..idx` is ASCII, so slicing the original `&str` is valid UTF-8.
            let token = &input[start..idx];
            reject_if_over_precise_fractional(token)?;
        }
        Ok(())
    }

    fn write_canonical(&self, out: &mut String) -> Result<()> {
        match self {
            StrictJson::Null => out.push_str("null"),
            StrictJson::Bool(true) => out.push_str("true"),
            StrictJson::Bool(false) => out.push_str("false"),
            StrictJson::Int(i) => out.push_str(&i.to_string()),
            StrictJson::Float(f) => out.push_str(&canonicalize_f64(*f)?),
            StrictJson::Str(s) => {
                out.push('"');
                out.push_str(&escape_json_string(s));
                out.push('"');
            }
            StrictJson::Array(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out)?;
                }
                out.push(']');
            }
            StrictJson::Object(entries) => {
                // RFC 8785: sort object keys by UTF-16 code unit comparison.
                let mut sorted: Vec<&(String, StrictJson)> = entries.iter().collect();
                sorted.sort_by(|(a, _), (b, _)| cmp_utf16_code_units(a.as_str(), b.as_str()));
                out.push('{');
                for (idx, (key, value)) in sorted.into_iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(&escape_json_string(key));
                    out.push_str("\":");
                    value.write_canonical(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a valid I-JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> core::result::Result<StrictJson, E> {
        Ok(StrictJson::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> core::result::Result<StrictJson, E>
    where
        E: de::Error,
    {
        if v.unsigned_abs() > I_JSON_MAX_SAFE_INTEGER {
            return Err(de::Error::custom(format!(
                "integer {v} outside I-JSON safe range [-(2^53-1), 2^53-1]"
            )));
        }
        Ok(StrictJson::Int(v))
    }

    fn visit_u64<E>(self, v: u64) -> core::result::Result<StrictJson, E>
    where
        E: de::Error,
    {
        if v > I_JSON_MAX_SAFE_INTEGER {
            return Err(de::Error::custom(format!(
                "integer {v} outside I-JSON safe range [-(2^53-1), 2^53-1]"
            )));
        }
        // Safe: v <= 2^53 - 1 < i64::MAX.
        Ok(StrictJson::Int(v as i64))
    }

    fn visit_f64<E>(self, v: f64) -> core::result::Result<StrictJson, E>
    where
        E: de::Error,
    {
        if !v.is_finite() {
            return Err(de::Error::custom("non-finite numbers are not valid JSON"));
        }
        // Reject any integer-valued f64. serde_json hands genuine integer
        // literals (no decimal point or exponent) to visit_i64/visit_u64 via its
        // exact integer path, so a value arriving here with a zero fractional
        // part did not come from a faithful integer token. It is one of:
        //   * a fractional literal whose fractional digits the parser rounded
        //     away (e.g. 9007199254740991.1 -> 9007199254740991.0, or even a
        //     small magnitude with enough fraction digits like 140737488355328.01
        //     -> 140737488355328.0), or
        //   * an integer literal too large for i64/u64, delivered as an
        //     already-lossy f64 (e.g. 184467440737095516160), or
        //   * an integer written in float form (e.g. 1.0, 1e2), which is
        //     ambiguous with the rounded-fractional case above and could equally
        //     be a rounded 1.0000...1.
        // Signing any of these would emit a value the submitter may not have
        // written (the render-A / sign-B class this API exists to prevent).
        // Because serde_json (without the std-only `raw_value` feature, which
        // this no_std + alloc crate cannot enable) exposes no way to recover the
        // original lexeme, and because the magnitude at which a fractional
        // collapses to an integer shrinks without bound as the fraction shrinks
        // (`x.01` collapses near 2^47, `x.0001` lower still), there is no safe
        // magnitude floor. Rejecting every integer-valued f64 is the only
        // closure that admits no precision-losing input. Callers that need an
        // integer must send an integer token (e.g. `100`, not `100.0`/`1e2`).
        if v.fract() == 0.0 {
            return Err(de::Error::custom(format!(
                "number {v} cannot be signed: an integer-valued f64 may be a \
                 rounded fractional or out-of-range integer literal; send an \
                 integer token (within +/-(2^53-1)) instead"
            )));
        }
        Ok(StrictJson::Float(v))
    }

    fn visit_str<E>(self, v: &str) -> core::result::Result<StrictJson, E> {
        Ok(StrictJson::Str(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> core::result::Result<StrictJson, E> {
        Ok(StrictJson::Str(v))
    }

    fn visit_none<E>(self) -> core::result::Result<StrictJson, E> {
        Ok(StrictJson::Null)
    }

    fn visit_unit<E>(self) -> core::result::Result<StrictJson, E> {
        Ok(StrictJson::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<StrictJson, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(StrictJson::Array(items))
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<StrictJson, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries: Vec<(String, StrictJson)> = Vec::new();
        // Track seen keys to reject duplicates instead of silently de-duping.
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
            if seen.insert(key.clone(), ()).is_some() {
                return Err(de::Error::custom(format!("duplicate object key: {key:?}")));
            }
            entries.push((key, value));
        }
        Ok(StrictJson::Object(entries))
    }
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

    #[test]
    fn write_canonical_value_matches_public_canonicalize() -> Result<()> {
        let value = serde_json::json!({
            "z": [{"b": 2, "a": 1}, true, null],
            "a": "\u{000f}\u{2028}",
            "\u{e000}": 1,
            "\u{10437}": 2,
        });
        let expected = concat!(
            r#"{"a":"\u000f"#,
            "\u{2028}",
            r#"","z":[{"a":1,"b":2},true,null],""#,
            "\u{10437}",
            r#"":2,""#,
            "\u{e000}",
            r#"":1}"#,
        );
        let canonical = canonicalize(&value)?;
        let mut written = String::new();
        write_canonical_value(&value, &mut written)?;

        assert_eq!(canonical, expected);
        assert_eq!(written, expected);

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

    // --- BAC-555: strict input validation (duplicate keys / non-I-JSON) ---

    #[test]
    fn strict_rejects_duplicate_keys() {
        // serde_json::Value would silently keep the last value ("last-wins");
        // the strict path must reject the input outright.
        let err = canonical_json_string_from_str(r#"{"a":1,"a":2}"#).unwrap_err();
        match err {
            Error::CanonicalJson(msg) => assert!(
                msg.contains("duplicate object key"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected CanonicalJson error, got {other:?}"),
        }
    }

    #[test]
    fn strict_rejects_duplicate_keys_nested() {
        let err = canonical_json_string_from_str(r#"{"outer":{"x":1,"x":2}}"#).unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)));
    }

    #[test]
    fn strict_rejects_duplicate_keys_last_wins_collapse_proof() {
        // Demonstrates the render-A/sign-B vector: two distinct payloads that
        // collapse to identical bytes via serde_json::Value, both rejected.
        let payload_a = r#"{"amount":1,"amount":1000000}"#;
        let collapsed: Value = serde_json::from_str(payload_a).unwrap();
        // serde_json keeps the last value (1000000), losing the first.
        assert_eq!(collapsed["amount"], serde_json::json!(1_000_000));
        // The strict path refuses to canonicalize the ambiguous input.
        assert!(canonical_json_string_from_str(payload_a).is_err());
    }

    #[test]
    fn strict_rejects_integer_literal_beyond_safe_range() {
        // 2^53 + 1 cannot be represented exactly by an IEEE-754 double; rather
        // than coerce it to a precision-losing value, reject it.
        let err = canonical_json_string_from_str("9007199254740993").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_huge_integer_literal_that_overflows_u64() {
        // 184467440737095516160 > u64::MAX, so serde_json delivers it as a lossy
        // f64. It is integer-valued and far beyond 2^53, so it is rejected.
        let err = canonical_json_string_from_str("184467440737095516160").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_negative_integer_literal_beyond_safe_range() {
        let err = canonical_json_string_from_str("-9007199254740993").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_non_finite_via_overflow() {
        // 1e400 overflows to +Infinity, which is not valid JSON.
        let err = canonical_json_string_from_str("1e400").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_trailing_data() {
        let err = canonical_json_string_from_str(r#"{"a":1} garbage"#).unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_accepts_safe_range_boundary() {
        // 2^53 - 1 is the largest I-JSON safe integer (RFC 7493 §2.2) and must
        // be accepted.
        assert_eq!(
            canonical_json_string_from_str("9007199254740991").unwrap(),
            "9007199254740991"
        );
        assert_eq!(
            canonical_json_string_from_str("-9007199254740991").unwrap(),
            "-9007199254740991"
        );
    }

    #[test]
    fn strict_rejects_safe_range_boundary_plus_one() {
        // 2^53 itself is excluded from the I-JSON safe range: although it round-
        // trips through an f64, it shares that representation with 2^53 + 1, so a
        // conforming consumer cannot distinguish them. It must be rejected.
        let err = canonical_json_string_from_str("9007199254740992").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
        // The negative boundary mirrors it.
        let err = canonical_json_string_from_str("-9007199254740992").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_rounded_fractional_f64() {
        // serde_json (float_roundtrip) rounds a fractional lexeme near the
        // precision boundary onto an integer-valued f64: 9007199254740991.1 is
        // delivered to visit_f64 as 9007199254740991.0. Without rejection it would
        // canonicalize as the integer 9007199254740991, signing a value the
        // submitter never wrote (render-A / sign-B). It must be rejected.
        let err = canonical_json_string_from_str("9007199254740991.1").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");

        // The collapse is not confined to the 2^53 boundary: with enough
        // fractional digits a much smaller magnitude also rounds to an integer.
        // 140737488355328.01 (2^47 + .01) is delivered as 140737488355328.0.
        let err = canonical_json_string_from_str("140737488355328.01").unwrap_err();
        assert!(matches!(err, Error::CanonicalJson(_)), "got {err:?}");
    }

    #[test]
    fn strict_rejects_integer_valued_float_form() {
        // An integer written in float form (decimal point or exponent) reaches
        // visit_f64 as an integer-valued f64, indistinguishable from a rounded
        // fractional, so it is rejected. Callers must send an integer token.
        for input in ["1.0", "100.0", "1e2", "0.0", "-5.0", "2.5e1"] {
            let err = canonical_json_string_from_str(input).unwrap_err();
            assert!(
                matches!(err, Error::CanonicalJson(_)),
                "expected {input} to be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn strict_rejects_over_precise_fractional() {
        // 0.123456789012345678901 carries more significant digits than an f64 can
        // hold; serde_json silently rounds it onto the same double as the shorter
        // 0.12345678901234568, so both would canonicalize to identical bytes. The
        // strict path must reject the over-precise lexeme so signing reflects only
        // values that survive the round trip exactly (render-A / sign-B closure).
        let err = canonical_json_string_from_str(r#"{"x":0.123456789012345678901}"#).unwrap_err();
        match err {
            Error::CanonicalJson(msg) => assert!(
                msg.contains("shortest decimal that round-trips"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected CanonicalJson error, got {other:?}"),
        }

        // The collapse target itself (the f64's own shortest decimal) is exactly
        // representable and is still accepted, canonicalizing to the same value.
        assert_eq!(
            canonical_json_string_from_str(r#"{"x":0.12345678901234568}"#).unwrap(),
            r#"{"x":0.12345678901234568}"#
        );

        // A bare over-precise token (not wrapped in an object) is rejected too,
        // including pi written past double precision and an over-precise value in
        // exponential form. Each stays fractional after parsing, so it exercises
        // the over-precision scan rather than the integer-valued-f64 guard.
        for input in [
            "0.123456789012345678901",
            "3.141592653589793238462643383279",
            "1.234567890123456789e-3",
        ] {
            assert!(
                canonical_json_string_from_str(input).is_err(),
                "expected {input} to be rejected as over-precise"
            );
        }
    }

    #[test]
    fn strict_rejects_same_digit_count_different_value() {
        // Round-3 Codex P2: the prior check compared only the *count* of
        // significant digits, so a token whose digit count equals the ryu
        // shortest rendering but whose digit *value* differs slipped through and
        // got signed as the rounded form (render-A / sign-B). 0.12345678901234567
        // parses to the f64 whose shortest decimal is 0.12345678901234566; both
        // have 17 significant digits. The token is not the shortest round-tripping
        // decimal, so it must be REJECTED.
        let err = canonical_json_string_from_str("0.12345678901234567").unwrap_err();
        match err {
            Error::CanonicalJson(msg) => assert!(
                msg.contains("shortest decimal that round-trips"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected CanonicalJson error, got {other:?}"),
        }

        // The f64's own shortest decimal (...566) IS canonical and is ACCEPTED,
        // canonicalizing to itself.
        assert_eq!(
            canonical_json_string_from_str("0.12345678901234566").unwrap(),
            "0.12345678901234566"
        );

        // A couple more cases that the digit-COUNT comparison would have wrongly
        // accepted. Each token's significant-digit sequence differs from its f64's
        // shortest rendering, so each must be rejected fail-closed:
        //   * 0.12345678901234567 -> shortest 0.12345678901234566 (same 17-digit
        //     count, last digit differs): the canonical render-A/sign-B vector.
        //   * 0.10000000000000001 -> shortest 0.1 (different count, trailing run
        //     of zeros the parser folded away).
        // The first is asserted above; assert the second here as a same-mechanism
        // (over-precise, diverging digits) companion.
        for input in ["0.12345678901234567", "0.10000000000000001"] {
            let err = canonical_json_string_from_str(input).unwrap_err();
            assert!(
                matches!(err, Error::CanonicalJson(_)),
                "expected {input} rejected, got {err:?}"
            );
        }

        // Sanity floor: tokens that already equal their shortest form (even though
        // they look long) stay ACCEPTED, so the fix does not over-reject genuine
        // canonical doubles.
        for input in [
            "0.30000000000000004",
            "9.999999999999999e-1",
            "2251799813685247.5",
        ] {
            let typed: Value = serde_json::from_str(input).unwrap();
            assert_eq!(
                canonical_json_string_from_str(input).unwrap(),
                canonicalize(&typed).unwrap(),
                "expected {input} accepted as already-shortest"
            );
        }
    }

    #[test]
    fn strict_accepts_exactly_representable_fractional() {
        // A normal fractional whose decimal literal is already the shortest form
        // that round-trips through an f64 loses no precision and must be accepted,
        // matching the typed path byte-for-byte. Numbers inside string values must
        // not be mistaken for over-precise number tokens by the source scan.
        let input = r#"{"ratio":3.14159,"note":"pi is 3.14159265358979311599796346854"}"#;
        let typed: Value = serde_json::from_str(input).unwrap();
        let typed_canonical = canonicalize(&typed).unwrap();
        assert_eq!(
            canonical_json_string_from_str(input).unwrap(),
            typed_canonical
        );
    }

    #[test]
    fn strict_accepts_genuine_fractionals() {
        // Numbers with a real fractional part keep a non-zero fract() and are
        // accepted, canonicalized exactly as the typed path would.
        for input in [
            "999999999.5",
            "2251799813685247.5",
            "1.5",
            "3.14159",
            "-0.25",
        ] {
            let typed: Value = serde_json::from_str(input).unwrap();
            let typed_canonical = canonicalize(&typed).unwrap();
            assert_eq!(
                canonical_json_string_from_str(input).unwrap(),
                typed_canonical,
                "strict path diverged from typed path for {input}"
            );
        }
    }

    #[test]
    fn strict_matches_typed_path_for_wellformed_ijson() {
        // For well-formed I-JSON, the strict text path must produce byte-identical
        // output to the existing typed (serde_json::Value) canonicalizer.
        let cases = [
            r#"{"z":1,"a":2,"m":3}"#,
            r#"{"2":"b","10":"a","a":0}"#,
            r#"{"outer":{"inner":"value"}}"#,
            r#"[1,2,3]"#,
            r#"{"a":{"b":{"c":[1,{"d":true}]}}}"#,
            r#"{"flag":true,"none":null,"neg":-42,"frac":1.5}"#,
            r#"{}"#,
            r#"[]"#,
            r#""hello \" \\ \n world""#,
            "null",
            "true",
            "3.14159",
        ];
        for case in cases {
            let typed: Value = serde_json::from_str(case).unwrap();
            let typed_canonical = canonicalize(&typed).unwrap();
            let strict_canonical = canonical_json_string_from_str(case).unwrap();
            assert_eq!(
                strict_canonical, typed_canonical,
                "strict path diverged from typed path for input: {case}"
            );
        }
    }

    #[test]
    fn strict_bytes_match_string() {
        let input = r#"{"z":1,"a":[2,3]}"#;
        let bytes = canonical_json_bytes_from_str(input).unwrap();
        let string = canonical_json_string_from_str(input).unwrap();
        assert_eq!(bytes, string.as_bytes());
    }

    #[test]
    fn strict_roundtrips_losslessly() {
        // A valid typed value canonicalizes deterministically and the canonical
        // form parses back to the same logical value.
        let input = r#"{"action":"file_read","path":"/etc/hosts","ts":1710000000,"ok":true}"#;
        let canonical = canonical_json_string_from_str(input).unwrap();
        let reparsed: Value = serde_json::from_str(&canonical).unwrap();
        let original: Value = serde_json::from_str(input).unwrap();
        assert_eq!(reparsed, original);
        // Deterministic across repeated calls.
        assert_eq!(canonical, canonical_json_string_from_str(input).unwrap());
    }

    #[test]
    fn strict_preserves_unicode_key_ordering() {
        // Same UTF-16 code-unit ordering guarantee as the typed path.
        let input = "{\"\u{e000}\":1,\"\u{10437}\":2}";
        let strict = canonical_json_string_from_str(input).unwrap();
        assert_eq!(strict, "{\"\u{10437}\":2,\"\u{e000}\":1}");
    }
}
