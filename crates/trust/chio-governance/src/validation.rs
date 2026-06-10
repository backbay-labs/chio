use crate::error::GovernanceAuthorizationError;

pub(crate) fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_sha256_hex(
    value: &str,
    field: &str,
) -> Result<(), GovernanceAuthorizationError> {
    if !is_sha256_hex(value) {
        return Err(GovernanceAuthorizationError::InvalidArtifact(format!(
            "{field} must be a 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
