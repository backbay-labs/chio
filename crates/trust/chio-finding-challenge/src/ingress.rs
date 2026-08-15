//! Strict-raw-first ingress for every set of bytes this crate reads.
//!
//! Carried bytes are transport, never authority. A typed value that was
//! deserialized somewhere else proves nothing about what was signed or
//! digested, so every artifact enters through the same gate: bound the size,
//! canonicalize the raw text, require byte equality with the raw form, then
//! deserialize and require the typed value to re-serialize to exactly those
//! bytes. Only then is the digest of those bytes an identity anyone may bind.

use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};

/// Ingress failures. Every variant is a rejection; there is no tolerant path.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingIngressError {
    /// The carried text exceeds the size bound its family pins.
    #[error("carried bytes exceed the size bound")]
    TooLarge,
    /// The carried text is not strict canonical I-JSON.
    #[error("carried bytes are not strict canonical I-JSON")]
    NotCanonical,
    /// The carried text canonicalizes to different bytes than it contains.
    #[error("carried bytes are not their own canonical serialization")]
    NonCanonicalSpelling,
    /// The carried text failed typed deserialization.
    #[error("carried bytes failed typed deserialization")]
    Deserialization,
    /// The typed value re-serializes to bytes other than those carried.
    #[error("typed value does not re-serialize to the carried bytes")]
    TypedDrift,
}

/// Strict-parse carried canonical text into its typed form, returning the
/// typed value and the exact bytes whose digest identifies it.
pub(crate) fn strict_parse<T>(
    text: &str,
    max_bytes: usize,
) -> Result<(T, Vec<u8>), FindingIngressError>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if text.len() > max_bytes {
        return Err(FindingIngressError::TooLarge);
    }
    let strict_bytes =
        canonical_json_bytes_from_str(text).map_err(|_| FindingIngressError::NotCanonical)?;
    if strict_bytes.as_slice() != text.as_bytes() {
        return Err(FindingIngressError::NonCanonicalSpelling);
    }
    let parsed: T = serde_json::from_str(text).map_err(|_| FindingIngressError::Deserialization)?;
    let typed_bytes = canonical_json_bytes(&parsed).map_err(|_| FindingIngressError::TypedDrift)?;
    if typed_bytes != strict_bytes {
        return Err(FindingIngressError::TypedDrift);
    }
    Ok((parsed, strict_bytes))
}
