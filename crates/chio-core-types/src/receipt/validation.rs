use alloc::format;

use crate::error::{Error, Result};

pub(crate) fn require_exact(value: &str, expected: &str, field: &str) -> Result<()> {
    if value != expected {
        return Err(Error::CanonicalJson(format!(
            "{field} must equal {expected}"
        )));
    }
    Ok(())
}

pub(crate) fn require_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::CanonicalJson(format!("{field} must not be empty")));
    }
    Ok(())
}

pub(crate) fn require_lowercase_hex(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::CanonicalJson(format!(
            "{field} must be non-empty lowercase hex"
        )));
    }
    Ok(())
}

pub(crate) fn require_lowercase_hex_chars(
    value: &str,
    expected_chars: usize,
    field: &str,
) -> Result<()> {
    require_lowercase_hex(value, field)?;
    if value.len() != expected_chars {
        return Err(Error::CanonicalJson(format!(
            "{field} must be exactly {expected_chars} lowercase hex characters"
        )));
    }
    Ok(())
}
