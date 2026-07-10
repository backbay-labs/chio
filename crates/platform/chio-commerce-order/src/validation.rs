use std::path::Path;

use chrono::{DateTime, Utc};

use super::error::CommerceOrderError;

pub(super) fn require_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_sha256_hex(value: &str) -> Result<(), ()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(())
    }
}

pub(super) fn validate_bundle_relative_path(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.contains('\\') {
        return Err(());
    }
    let path = Path::new(value);
    if path.is_absolute() || value.contains(':') {
        return Err(());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(());
    }
    Ok(())
}

pub(super) fn validate_money(amount_minor: u64, currency: &str, field: &str) -> Result<(), String> {
    if amount_minor == 0 {
        return Err(format!("{field} must be greater than zero"));
    }
    if currency.len() != 3 || currency.bytes().any(|byte| !byte.is_ascii_uppercase()) {
        return Err(format!(
            "{field} currency must be a three-letter uppercase code"
        ));
    }
    Ok(())
}

pub(super) fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, CommerceOrderError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| CommerceOrderError::InvalidArtifact {
            field,
            message: error.to_string(),
        })
}
