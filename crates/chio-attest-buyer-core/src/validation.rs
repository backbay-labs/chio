use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_federation::Keyid;
use chio_governance::authorization::GovernanceReceiptCaseKind;
use chio_governance::lease::CapabilityLeaseActionClass;
use serde::Serialize;

use crate::error::ChioPackageError;

pub(crate) fn validate_trust_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if !is_lower_sha256_hex(value) {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be a lowercase 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

pub(crate) fn validate_non_empty(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::TrustedIssuer(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

pub(crate) fn validate_scope_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::LeaseScopeBinding(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

pub(crate) fn validate_context_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() || value.trim() != value {
        return Err(ChioPackageError::VerificationContext(format!(
            "{field} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex_for_scope(
    value: &str,
    field: &str,
) -> Result<(), ChioPackageError> {
    if !is_lower_sha256_hex(value) {
        return Err(ChioPackageError::LeaseScopeBinding(format!(
            "{field} must be a lowercase 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

pub(crate) fn validate_unique_action_classes(
    values: &[CapabilityLeaseActionClass],
    field: &str,
) -> Result<(), ChioPackageError> {
    if values.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{field} contains duplicate action class {value:?}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_unique_case_kinds(
    values: &[GovernanceReceiptCaseKind],
    field: &str,
) -> Result<(), ChioPackageError> {
    if values.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{field} contains duplicate case kind {value:?}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn key_fingerprint(public_key: &PublicKey) -> String {
    Keyid::from_public_key(public_key).0
}

pub(crate) fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn authority_window(
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    label: &str,
) -> Result<(u64, u64), ChioPackageError> {
    let valid_from = valid_from_unix_ms.ok_or_else(|| {
        ChioPackageError::Governance(format!("{label} validFromUnixMs is missing"))
    })?;
    let valid_until = valid_until_unix_ms.ok_or_else(|| {
        ChioPackageError::Governance(format!("{label} validUntilUnixMs is missing"))
    })?;
    if valid_until <= valid_from {
        return Err(ChioPackageError::Governance(format!(
            "{label} validity window is invalid"
        )));
    }
    Ok((valid_from, valid_until))
}

pub(crate) fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_lower_sha256_hex(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn canonical_string<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    canonical_json_string(value).map_err(|error| ChioPackageError::Canonical(error.to_string()))
}
