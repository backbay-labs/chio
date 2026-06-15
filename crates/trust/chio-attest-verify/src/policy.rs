//! Per-tenant `ExpectedIdentity` policy schema.
//!
//! This module defines the on-disk shape of a per-tenant signed policy file
//! that replaces inline `ExpectedIdentity` construction at every workspace
//! call site. The companion loader is `policy_loader.rs`.
//!
//! # Schema
//!
//! TOML on disk; canonical JSON for signing. Fields:
//!
//! - `tenant_id`: stable opaque tenant identifier. Two policies with the same
//!   `tenant_id` collide; the loader rejects the second one fail-closed.
//! - `version`: monotonically increasing schema-version integer. The loader
//!   refuses any version it does not recognise (currently `1`).
//! - `identity_regexps`: non-empty list of Fulcio SAN regexes. Every regex is
//!   anchored at both ends by the verifier; callers MUST NOT include their
//!   own `^` / `$`. The first regex that matches wins.
//! - `oidc_issuers`: non-empty list of OIDC issuer URLs. Verification fails
//!   closed unless the cert's OIDC issuer matches one of them exactly.
//! - `signed_at`: RFC 3339 UTC timestamp recording when the policy was
//!   signed. The loader rejects policies older than its staleness horizon
//!   (default 90 days).
//! - `signature`: base64-encoded Sigstore signature over the canonical JSON
//!   serialisation of every other field. Verified through the same
//!   `SigstoreVerifier` surface every other attestation flows through.
//! - `pq_identity_regexps`: reserved field for ML-DSA cert identities. Empty
//!   today; present so that adding an ML-DSA-aware cert family in the future
//!   does not require a schema bump.
//!
//! # Fail-closed contract
//!
//! Every constructor on this module rejects malformed or empty inputs at load
//! time. There is no path through this module that yields a `TenantPolicy`
//! whose `identity_regexps` is empty, whose `oidc_issuers` is empty, whose
//! `signed_at` is in the future, or whose regex strings fail to compile.

use std::time::SystemTime;

use chio_core_types::canonical_json_bytes;
use serde::{Deserialize, Serialize};

use crate::AttestError;

/// Currently supported `TenantPolicy` schema version. Future format breaks
/// MUST bump this and add an explicit migration path; the loader rejects any
/// other value fail-closed.
pub const TENANT_POLICY_SCHEMA_VERSION: u32 = 1;

/// Maximum raw TOML policy size accepted at the trust boundary.
pub const MAX_TENANT_POLICY_BYTES: usize = 64 * 1024;

/// Maximum number of tenant identity regexes accepted in one policy.
pub const MAX_IDENTITY_REGEXPS: usize = 32;

/// Maximum byte length of one identity regex.
pub const MAX_IDENTITY_REGEXP_BYTES: usize = 2048;

/// Maximum number of OIDC issuers accepted in one policy.
pub const MAX_OIDC_ISSUERS: usize = 16;

/// Maximum byte length of one OIDC issuer URL.
pub const MAX_OIDC_ISSUER_BYTES: usize = 2048;

/// Maximum byte length of the base64-encoded policy signature field.
pub const MAX_POLICY_SIGNATURE_BYTES: usize = 16 * 1024;

/// Maximum number of reserved PQ identity regexes accepted in one policy.
pub const MAX_PQ_IDENTITY_REGEXPS: usize = 32;

/// Canonical bootstrap tenant identifier shipped under
/// `crates/trust/chio-attest-verify/tests/fixtures/policies/bootstrap.toml`. The
/// bootstrap policy is signed by the workspace release identity (the same
/// identity used for signed binary releases) and is the chicken-and-egg seed
/// every operator inherits before authoring a tenant-specific override.
pub const BOOTSTRAP_TENANT_ID: &str = "bootstrap";

/// Per-tenant `ExpectedIdentity` policy. Loaded once at startup by
/// `TenantPolicyLoader` (see `policy_loader.rs`); call sites resolve their
/// `ExpectedIdentity` through `AttestVerifier::expected_for_tenant` rather
/// than constructing it inline.
///
/// The struct is `#[serde(deny_unknown_fields)]` so that an unknown TOML key
/// (typo, future-version field) is rejected at parse time. Adding a new
/// recognised field MUST coincide with bumping
/// [`TENANT_POLICY_SCHEMA_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPolicy {
    /// Stable opaque tenant identifier. Non-empty. Two policies with the
    /// same `tenant_id` collide: the loader rejects the second fail-closed.
    pub tenant_id: String,
    /// Schema-version integer. Currently must equal
    /// [`TENANT_POLICY_SCHEMA_VERSION`].
    pub version: u32,
    /// Non-empty list of Fulcio SAN regex strings. The verifier anchors each
    /// regex at both ends; callers MUST NOT include their own `^` / `$`.
    pub identity_regexps: Vec<String>,
    /// Non-empty list of OIDC issuer URLs. Verification fails closed unless
    /// the cert's OIDC issuer matches one of them exactly.
    pub oidc_issuers: Vec<String>,
    /// RFC 3339 UTC timestamp recording when the policy was signed. The
    /// loader rejects policies older than its staleness horizon
    /// (default 90 days).
    pub signed_at: String,
    /// Base64-encoded Sigstore signature over the canonical JSON
    /// serialisation of every other field. Verified through the same
    /// `SigstoreVerifier` surface every other attestation flows through.
    pub signature: String,
    /// Reserved for ML-DSA cert identities. Defaulted to an empty vec so
    /// existing TOML files that pre-date the field still parse without
    /// modification.
    #[serde(default)]
    pub pq_identity_regexps: Vec<String>,
}

impl TenantPolicy {
    /// Parse a policy from a TOML byte slice. Performs structural validation
    /// only: signature verification and staleness checks happen in the
    /// loader (`policy_loader.rs`).
    ///
    /// # Errors
    ///
    /// Returns [`AttestError::Malformed`] if the TOML fails to decode, if a
    /// required field is empty, if the schema version is unsupported, or if
    /// any of the regex strings fails to compile.
    pub fn from_toml_slice(bytes: &[u8]) -> Result<Self, AttestError> {
        if bytes.len() > MAX_TENANT_POLICY_BYTES {
            return Err(AttestError::Malformed(format!(
                "policy is {} bytes, exceeding {} byte limit",
                bytes.len(),
                MAX_TENANT_POLICY_BYTES
            )));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|err| AttestError::Malformed(format!("policy is not utf-8: {err}")))?;
        let parsed: Self = toml::from_str(text)
            .map_err(|err| AttestError::Malformed(format!("policy toml decode: {err}")))?;
        parsed.validate_structural()?;
        Ok(parsed)
    }

    /// Structural validation. Run by [`Self::from_toml_slice`] and again by
    /// the loader before any signature check, so that signature failures
    /// always come from a structurally well-formed input.
    pub(crate) fn validate_structural(&self) -> Result<(), AttestError> {
        validate_required_policy_text(&self.tenant_id, "tenant_id")?;
        if self.version != TENANT_POLICY_SCHEMA_VERSION {
            return Err(AttestError::Malformed(format!(
                "unsupported policy version {} (expected {})",
                self.version, TENANT_POLICY_SCHEMA_VERSION
            )));
        }
        if self.identity_regexps.is_empty() {
            return Err(AttestError::Malformed(
                "identity_regexps is empty".to_owned(),
            ));
        }
        if self.identity_regexps.len() > MAX_IDENTITY_REGEXPS {
            return Err(AttestError::Malformed(format!(
                "identity_regexps has {} entries, exceeding {} entry limit",
                self.identity_regexps.len(),
                MAX_IDENTITY_REGEXPS
            )));
        }
        if self.oidc_issuers.is_empty() {
            return Err(AttestError::Malformed("oidc_issuers is empty".to_owned()));
        }
        if self.oidc_issuers.len() > MAX_OIDC_ISSUERS {
            return Err(AttestError::Malformed(format!(
                "oidc_issuers has {} entries, exceeding {} entry limit",
                self.oidc_issuers.len(),
                MAX_OIDC_ISSUERS
            )));
        }
        validate_required_policy_text(&self.signed_at, "signed_at")?;
        validate_required_policy_text(&self.signature, "signature")?;
        if self.signature.len() > MAX_POLICY_SIGNATURE_BYTES {
            return Err(AttestError::Malformed(format!(
                "signature is {} bytes, exceeding {} byte limit",
                self.signature.len(),
                MAX_POLICY_SIGNATURE_BYTES
            )));
        }
        if !self.signature.is_ascii() {
            return Err(AttestError::Malformed(
                "signature must be ASCII base64".to_owned(),
            ));
        }
        for pattern in &self.identity_regexps {
            validate_policy_list_entry(pattern, "identity_regexp")?;
            if pattern.len() > MAX_IDENTITY_REGEXP_BYTES {
                return Err(AttestError::Malformed(format!(
                    "identity_regexp is {} bytes, exceeding {} byte limit",
                    pattern.len(),
                    MAX_IDENTITY_REGEXP_BYTES
                )));
            }
            regex::Regex::new(pattern).map_err(|err| {
                AttestError::Malformed(format!(
                    "identity_regexp {pattern:?} does not compile: {err}"
                ))
            })?;
        }
        for issuer in &self.oidc_issuers {
            validate_policy_list_entry(issuer, "oidc_issuer")?;
            if issuer.len() > MAX_OIDC_ISSUER_BYTES {
                return Err(AttestError::Malformed(format!(
                    "oidc_issuer is {} bytes, exceeding {} byte limit",
                    issuer.len(),
                    MAX_OIDC_ISSUER_BYTES
                )));
            }
        }
        if self.pq_identity_regexps.len() > MAX_PQ_IDENTITY_REGEXPS {
            return Err(AttestError::Malformed(format!(
                "pq_identity_regexps has {} entries, exceeding {} entry limit",
                self.pq_identity_regexps.len(),
                MAX_PQ_IDENTITY_REGEXPS
            )));
        }
        for pattern in &self.pq_identity_regexps {
            validate_policy_list_entry(pattern, "pq_identity_regexp")?;
            if pattern.len() > MAX_IDENTITY_REGEXP_BYTES {
                return Err(AttestError::Malformed(format!(
                    "pq_identity_regexp is {} bytes, exceeding {} byte limit",
                    pattern.len(),
                    MAX_IDENTITY_REGEXP_BYTES
                )));
            }
            regex::Regex::new(pattern).map_err(|err| {
                AttestError::Malformed(format!(
                    "pq_identity_regexp {pattern:?} does not compile: {err}"
                ))
            })?;
        }
        Ok(())
    }

    /// Canonical JSON serialisation used for signing and signature
    /// verification. The `signature` field is excluded from the canonical
    /// form (signing a value over itself is undefined). The returned bytes
    /// are RFC 8785 canonical JSON, so object keys and scalar encodings are
    /// byte-stable across signers.
    ///
    /// # Errors
    ///
    /// Returns [`AttestError::Malformed`] if serialisation fails. This path
    /// should be unreachable for a structurally valid policy.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, AttestError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            tenant_id: &'a str,
            version: u32,
            identity_regexps: &'a [String],
            oidc_issuers: &'a [String],
            signed_at: &'a str,
            pq_identity_regexps: &'a [String],
        }
        let canonical = Canonical {
            tenant_id: &self.tenant_id,
            version: self.version,
            identity_regexps: &self.identity_regexps,
            oidc_issuers: &self.oidc_issuers,
            signed_at: &self.signed_at,
            pq_identity_regexps: &self.pq_identity_regexps,
        };
        canonical_json_bytes(&canonical)
            .map_err(|err| AttestError::Malformed(format!("policy canonical encode: {err}")))
    }

    /// Parse [`Self::signed_at`] as an RFC 3339 UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`AttestError::Malformed`] if the timestamp does not parse or
    /// is in the future.
    pub fn signed_at_system_time(&self, now: SystemTime) -> Result<SystemTime, AttestError> {
        let parsed = parse_rfc3339_utc(&self.signed_at)?;
        if parsed > now {
            return Err(AttestError::Malformed(format!(
                "signed_at {:?} is in the future",
                self.signed_at
            )));
        }
        Ok(parsed)
    }
}

fn validate_required_policy_text(value: &str, field: &'static str) -> Result<(), AttestError> {
    if value.trim().is_empty() {
        return Err(AttestError::Malformed(format!("{field} is empty")));
    }
    if value.trim() != value {
        return Err(AttestError::Malformed(format!(
            "{field} contains surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate_policy_list_entry(value: &str, field: &'static str) -> Result<(), AttestError> {
    if value.trim().is_empty() {
        return Err(AttestError::Malformed(format!(
            "{field} contains an empty entry"
        )));
    }
    if value.trim() != value {
        return Err(AttestError::Malformed(format!(
            "{field} contains an entry with surrounding whitespace"
        )));
    }
    Ok(())
}

/// Minimal RFC 3339 parser restricted to the subset emitted by the policy
/// signing tool: `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractional seconds, no
/// offset). Anything else is rejected fail-closed.
///
/// This avoids pulling `chrono` or `time` into the trust-boundary crate just
/// to parse a single timestamp field.
fn parse_rfc3339_utc(text: &str) -> Result<SystemTime, AttestError> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(AttestError::Malformed(format!(
            "signed_at {text:?} is not RFC3339 UTC of the form YYYY-MM-DDTHH:MM:SSZ"
        )));
    }
    let year = parse_u32(&bytes[0..4], text)?;
    let month = parse_u32(&bytes[5..7], text)? as u8;
    let day = parse_u32(&bytes[8..10], text)? as u8;
    let hour = parse_u32(&bytes[11..13], text)? as u8;
    let minute = parse_u32(&bytes[14..16], text)? as u8;
    let second = parse_u32(&bytes[17..19], text)? as u8;
    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return Err(AttestError::Malformed(format!(
            "signed_at {text:?} has out-of-range fields"
        )));
    }
    let unix_seconds = days_from_civil(year as i64, month as u32, day as u32) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    if unix_seconds < 0 {
        return Err(AttestError::Malformed(format!(
            "signed_at {text:?} predates the unix epoch"
        )));
    }
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_seconds as u64))
}

fn parse_u32(bytes: &[u8], whole: &str) -> Result<u32, AttestError> {
    let s = std::str::from_utf8(bytes).map_err(|_| {
        AttestError::Malformed(format!("signed_at {whole:?} contains non-utf8 digits"))
    })?;
    s.parse::<u32>().map_err(|_| {
        AttestError::Malformed(format!("signed_at {whole:?} contains non-numeric digits"))
    })
}

fn days_in_month(year: u32, month: u8) -> Result<u8, AttestError> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => {
            return Err(AttestError::Malformed(format!(
                "signed_at has out-of-range month {month}"
            )));
        }
    };
    Ok(days)
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Days from `1970-01-01` for the given proleptic Gregorian date. Adapted
/// from Howard Hinnant's `days_from_civil`. Returns a signed value because
/// the staleness window is computed by subtraction.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m_adj = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * m_adj + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}
