//! SIEM backend exporter implementations.
//!
//! Each module implements the `Exporter` trait for a specific SIEM backend.

pub mod cef;
pub mod datadog;
pub mod elastic;
pub mod ocsf_exporter;
pub mod splunk;
pub mod sumo_logic;
pub mod webhook;

use crate::exporter::ExportError;

/// Returns `true` if `endpoint` parses as a URL whose scheme is exactly
/// `https` (case-insensitive per RFC 3986 section 3.1).
///
/// Returns `false` for any other scheme (including `http`, `HTTP`, mixed
/// case variants, or non-URL strings). Exporters that enforce TLS should
/// reject endpoints unless this function returns `true`.
pub(crate) fn endpoint_is_https(endpoint: &str) -> bool {
    match url::Url::parse(endpoint) {
        Ok(parsed) => parsed.scheme().eq_ignore_ascii_case("https"),
        Err(_) => false,
    }
}

/// Returns `Ok(())` if `endpoint` is `https://` (case-insensitive). Otherwise
/// returns an [`ExportError::HttpError`] whose message is `tls_violation_msg`.
///
/// Centralising the TLS gate ensures all exporters apply the same RFC 3986
/// scheme comparison rules, so an `HTTP://` (uppercase) endpoint cannot
/// bypass the plaintext check.
pub(crate) fn require_https_endpoint(
    endpoint: &str,
    tls_violation_msg: &str,
) -> Result<(), ExportError> {
    if endpoint_is_https(endpoint) {
        Ok(())
    } else {
        Err(ExportError::HttpError(tls_violation_msg.to_string()))
    }
}
