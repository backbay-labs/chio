use chio_core_types::canonical::canonical_json_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ProjectionMessage, SelectiveDisclosureError};

pub(crate) fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub(crate) fn canonical_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, SelectiveDisclosureError> {
    canonical_json_bytes(value).map_err(|e| SelectiveDisclosureError::CanonicalJson(e.to_string()))
}

pub(crate) fn subject_sha256_hex<T: Serialize>(
    value: &T,
) -> Result<String, SelectiveDisclosureError> {
    Ok(sha256_hex_bytes(&canonical_bytes(value)?))
}

pub(crate) fn hash_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, SelectiveDisclosureError> {
    Ok(Sha256::digest(canonical_bytes(value)?).to_vec())
}

fn is_lower_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
}

#[cfg(feature = "bbs")]
fn is_lower_even_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
}

pub(crate) fn decode_hx_field(field: &str, raw: &str) -> Result<Vec<u8>, SelectiveDisclosureError> {
    if raw.is_empty() {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: "empty string is not a SHA-256 hex digest".to_string(),
        });
    }
    if !is_lower_sha256_hex(raw) {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: "expected 64 lowercase SHA-256 hex characters".to_string(),
        });
    }
    let bytes = hex::decode(raw).map_err(|e| SelectiveDisclosureError::MalformedHexField {
        field: field.to_string(),
        reason: e.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: format!("decoded length {} bytes does not equal 32", bytes.len()),
        });
    }
    Ok(bytes)
}

#[cfg(feature = "bbs")]
pub(crate) fn decode_message_hex(
    field: &str,
    raw: &str,
) -> Result<Vec<u8>, SelectiveDisclosureError> {
    if !is_lower_even_hex(raw) {
        return Err(SelectiveDisclosureError::MalformedHexField {
            field: field.to_string(),
            reason: "expected lowercase even-length hex".to_string(),
        });
    }
    hex::decode(raw).map_err(|e| SelectiveDisclosureError::MalformedHexField {
        field: field.to_string(),
        reason: e.to_string(),
    })
}

pub(crate) fn opt_string_bytes(value: &Option<String>) -> Vec<u8> {
    value
        .as_ref()
        .map_or_else(|| b"\0".to_vec(), |s| s.as_bytes().to_vec())
}

pub(crate) fn u64_le(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(crate) fn bool_byte(value: bool) -> Vec<u8> {
    vec![u8::from(value)]
}

pub(crate) fn push_message(
    out: &mut Vec<ProjectionMessage>,
    field: &str,
    encoding: &str,
    bytes: Vec<u8>,
    wholesale_only: bool,
) {
    out.push(ProjectionMessage {
        index: out.len() as u16,
        field: field.to_string(),
        encoding: encoding.to_string(),
        bytes_hex: hex::encode(bytes),
        wholesale_only,
    });
}
