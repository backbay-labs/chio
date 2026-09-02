use chio_core_types::{canonical_json_bytes_from_str, sha256_hex};

use crate::HostedMarketStoreError;

const MAX_JOB_JSON_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn validate_identifier(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), HostedMarketStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(HostedMarketStoreError::Invalid(field))
}

pub(crate) fn validate_canonical_json(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), HostedMarketStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_JOB_JSON_BYTES {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    let raw = std::str::from_utf8(bytes).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    let canonical =
        canonical_json_bytes_from_str(raw).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    if canonical != bytes {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    Ok(())
}

pub(crate) fn verify_payload(digest: &str, bytes: &[u8]) -> Result<(), HostedMarketStoreError> {
    validate_digest(digest, "durable digest")?;
    validate_canonical_json(bytes, "durable JSON")?;
    if sha256_hex(bytes) != digest {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(())
}

pub(crate) fn checked_i64(value: u64, field: &'static str) -> Result<i64, HostedMarketStoreError> {
    if value == 0 {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    i64::try_from(value).map_err(|_| HostedMarketStoreError::Invalid(field))
}

pub(crate) fn checked_nonnegative_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, HostedMarketStoreError> {
    i64::try_from(value).map_err(|_| HostedMarketStoreError::Invalid(field))
}

pub(crate) fn stored_u64(value: i64) -> Result<u64, HostedMarketStoreError> {
    u64::try_from(value).map_err(|_| HostedMarketStoreError::DigestMismatch)
}

/// Map a sqlx failure to the opaque wire error after logging its class.
/// The wire variant stays `Unavailable` so caller and replay semantics are
/// unchanged; the log carries what actually failed so operators can tell
/// pool exhaustion from a constraint rejection or a network fault.
pub(crate) fn unavailable(error: sqlx::Error) -> HostedMarketStoreError {
    let class = match &error {
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode",
        _ => "other",
    };
    tracing::warn!(class, error = %error, "hosted market store operation failed");
    HostedMarketStoreError::Unavailable
}
