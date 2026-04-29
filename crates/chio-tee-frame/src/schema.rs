//! Schema invariants for `chio-tee-frame.v1`.
//!
//! The JSON schema is pinned in
//! `.planning/trajectory/10-tee-replay-harness.md` lines 64-219. This module
//! mirrors the structural and pattern constraints in pure Rust so that
//! constructors and parsers can fail-closed on malformed frames without
//! having to drag in a JSON-Schema validator at runtime.
//!
//! Each `validate_*` helper takes a `&str` slice of the candidate field and
//! returns a [`SchemaError`] on the first violation it finds. The intent is
//! diagnostic clarity, not byte-for-byte JSON-Schema parity: a frame that
//! survives [`validate`] is strictly a subset of frames that survive the
//! published JSON-Schema, so downstream consumers can layer schema-level
//! validation on top without contradicting these checks.

use crate::frame::{Frame, UpstreamSystem, Verdict};

/// Pinned schema version literal. The wire field is the string `"1"`,
/// distinct from the schema name `chio-tee-frame.v1`.
pub const SCHEMA_VERSION: &str = "1";

/// `$id` URI for the v1 schema (informational; surfaced in error messages
/// and may be used by external validators).
pub const SCHEMA_ID: &str = "https://chio.dev/schemas/chio-tee-frame/v1.json";

/// All ways a frame can violate the v1 schema invariants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("schema_version must be \"1\", got {0:?}")]
    SchemaVersion(String),
    #[error("event_id must be a 26-char Crockford ULID, got {0:?}")]
    EventId(String),
    #[error("ts must be RFC3339 UTC with millisecond precision and trailing Z, got {0:?}")]
    Timestamp(String),
    #[error("tee_id violates pattern (3..=64 of [a-z0-9-]; cannot start/end with -): {0:?}")]
    TeeId(String),
    #[error("upstream.operation violates pattern (^[a-z][a-z0-9_.]*$, 1..=128): {0:?}")]
    UpstreamOperation(String),
    #[error("upstream.api_version length must be 1..=32, got {0:?}")]
    UpstreamApiVersion(String),
    #[error("provenance.otel.trace_id must be 32 lowercase hex chars, got {0:?}")]
    TraceId(String),
    #[error("provenance.otel.span_id must be 16 lowercase hex chars, got {0:?}")]
    SpanId(String),
    #[error("request_blob_sha256 must be 64 lowercase hex chars, got {0:?}")]
    RequestBlobSha256(String),
    #[error("response_blob_sha256 must be 64 lowercase hex chars, got {0:?}")]
    ResponseBlobSha256(String),
    #[error("redaction_pass_id violates pattern (^[a-z0-9][a-z0-9._@+-]*$, 1..=128): {0:?}")]
    RedactionPassId(String),
    #[error("deny_reason violates pattern (namespaced lowercase identifier): {0:?}")]
    DenyReason(String),
    #[error("deny_reason MUST be present iff verdict is deny or rewrite (verdict={verdict:?})")]
    DenyReasonGate { verdict: Verdict },
    #[error("tenant_sig must be ed25519:<base64>, got {0:?}")]
    TenantSig(String),
}

/// Validate a frame against every v1 invariant. Returns `Ok(())` if the
/// frame would survive the published JSON-Schema for the structural rules
/// this module covers.
pub fn validate(frame: &Frame) -> Result<(), SchemaError> {
    validate_schema_version(&frame.schema_version)?;
    validate_event_id(&frame.event_id)?;
    validate_timestamp(&frame.ts)?;
    validate_tee_id(&frame.tee_id)?;
    validate_upstream_operation(&frame.upstream.operation)?;
    validate_upstream_api_version(&frame.upstream.api_version)?;
    let _ = frame.upstream.system; // enum already constrains the value.
    validate_trace_id(&frame.provenance.otel.trace_id)?;
    validate_span_id(&frame.provenance.otel.span_id)?;
    validate_blob_hash(&frame.request_blob_sha256)
        .map_err(|s| SchemaError::RequestBlobSha256(s.to_string()))?;
    validate_blob_hash(&frame.response_blob_sha256)
        .map_err(|s| SchemaError::ResponseBlobSha256(s.to_string()))?;
    validate_redaction_pass_id(&frame.redaction_pass_id)?;
    validate_deny_reason_gate(frame)?;
    validate_tenant_sig(&frame.tenant_sig)?;
    Ok(())
}

fn validate_schema_version(value: &str) -> Result<(), SchemaError> {
    if value == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(SchemaError::SchemaVersion(value.to_string()))
    }
}

fn validate_event_id(value: &str) -> Result<(), SchemaError> {
    if value.len() != 26 || !value.chars().all(is_crockford_base32_upper) {
        return Err(SchemaError::EventId(value.to_string()));
    }
    Ok(())
}

/// Crockford base32 (uppercase ULID alphabet): 0-9, A-H, J, K, M, N, P-T, V-Z.
/// Excludes I, L, O, U.
fn is_crockford_base32_upper(c: char) -> bool {
    matches!(
        c,
        '0'..='9'
            | 'A'..='H'
            | 'J'
            | 'K'
            | 'M'
            | 'N'
            | 'P'..='T'
            | 'V'..='Z'
    )
}

fn validate_timestamp(value: &str) -> Result<(), SchemaError> {
    // Pattern: ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return Err(SchemaError::Timestamp(value.to_string()));
    }
    // YYYY-MM-DDTHH:MM:SS.mmmZ
    let separators = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    let digit_positions = [
        0, 1, 2, 3, // year
        5, 6, // month
        8, 9, // day
        11, 12, // hour
        14, 15, // minute
        17, 18, // second
        20, 21, 22, // millisecond
    ];
    for (pos, expected) in separators {
        if bytes[pos] != expected {
            return Err(SchemaError::Timestamp(value.to_string()));
        }
    }
    for pos in digit_positions {
        if !bytes[pos].is_ascii_digit() {
            return Err(SchemaError::Timestamp(value.to_string()));
        }
    }
    Ok(())
}

fn validate_tee_id(value: &str) -> Result<(), SchemaError> {
    let len = value.len();
    if !(3..=64).contains(&len) {
        return Err(SchemaError::TeeId(value.to_string()));
    }
    let bytes = value.as_bytes();
    let head = bytes[0];
    let tail = bytes[len - 1];
    if !is_lower_alnum(head) || !is_lower_alnum(tail) {
        return Err(SchemaError::TeeId(value.to_string()));
    }
    for &b in &bytes[1..len - 1] {
        if !(is_lower_alnum(b) || b == b'-') {
            return Err(SchemaError::TeeId(value.to_string()));
        }
    }
    Ok(())
}

fn is_lower_alnum(b: u8) -> bool {
    b.is_ascii_digit() || b.is_ascii_lowercase()
}

fn validate_upstream_operation(value: &str) -> Result<(), SchemaError> {
    let len = value.len();
    if !(1..=128).contains(&len) {
        return Err(SchemaError::UpstreamOperation(value.to_string()));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return Err(SchemaError::UpstreamOperation(value.to_string()));
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.') {
            return Err(SchemaError::UpstreamOperation(value.to_string()));
        }
    }
    Ok(())
}

fn validate_upstream_api_version(value: &str) -> Result<(), SchemaError> {
    let len = value.len();
    if !(1..=32).contains(&len) {
        return Err(SchemaError::UpstreamApiVersion(value.to_string()));
    }
    Ok(())
}

fn validate_trace_id(value: &str) -> Result<(), SchemaError> {
    if value.len() != 32 || !value.chars().all(is_lower_hex) {
        return Err(SchemaError::TraceId(value.to_string()));
    }
    Ok(())
}

fn validate_span_id(value: &str) -> Result<(), SchemaError> {
    if value.len() != 16 || !value.chars().all(is_lower_hex) {
        return Err(SchemaError::SpanId(value.to_string()));
    }
    Ok(())
}

fn validate_blob_hash(value: &str) -> Result<(), &str> {
    if value.len() == 64 && value.chars().all(is_lower_hex) {
        Ok(())
    } else {
        Err(value)
    }
}

fn is_lower_hex(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f')
}

fn validate_redaction_pass_id(value: &str) -> Result<(), SchemaError> {
    let len = value.len();
    if !(1..=128).contains(&len) {
        return Err(SchemaError::RedactionPassId(value.to_string()));
    }
    let bytes = value.as_bytes();
    if !is_lower_alnum(bytes[0]) {
        return Err(SchemaError::RedactionPassId(value.to_string()));
    }
    for &b in &bytes[1..] {
        if !(is_lower_alnum(b) || b == b'.' || b == b'_' || b == b'@' || b == b'+' || b == b'-') {
            return Err(SchemaError::RedactionPassId(value.to_string()));
        }
    }
    Ok(())
}

fn validate_deny_reason(value: &str) -> Result<(), SchemaError> {
    let len = value.len();
    if !(1..=256).contains(&len) {
        return Err(SchemaError::DenyReason(value.to_string()));
    }
    // Pattern: ^[a-z][a-z0-9_]*(:[a-z][a-z0-9_.]*)*$
    let mut segments = value.split(':');
    let head = segments.next().unwrap_or("");
    if !is_head_segment(head, /* allow_dot */ false) {
        return Err(SchemaError::DenyReason(value.to_string()));
    }
    for seg in segments {
        if !is_head_segment(seg, /* allow_dot */ true) {
            return Err(SchemaError::DenyReason(value.to_string()));
        }
    }
    Ok(())
}

fn is_head_segment(seg: &str, allow_dot: bool) -> bool {
    if seg.is_empty() {
        return false;
    }
    let bytes = seg.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    for &b in &bytes[1..] {
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || (allow_dot && b == b'.');
        if !ok {
            return false;
        }
    }
    true
}

fn validate_deny_reason_gate(frame: &Frame) -> Result<(), SchemaError> {
    match (&frame.verdict, frame.deny_reason.as_deref()) {
        (Verdict::Allow, None) => Ok(()),
        (Verdict::Allow, Some(_)) => Err(SchemaError::DenyReasonGate {
            verdict: Verdict::Allow,
        }),
        (Verdict::Deny, Some(reason)) | (Verdict::Rewrite, Some(reason)) => {
            validate_deny_reason(reason)
        }
        (verdict, None) => Err(SchemaError::DenyReasonGate { verdict: *verdict }),
    }
}

fn validate_tenant_sig(value: &str) -> Result<(), SchemaError> {
    // Pattern: ^ed25519:[A-Za-z0-9+/=]{86,88}$
    let prefix = "ed25519:";
    let Some(payload) = value.strip_prefix(prefix) else {
        return Err(SchemaError::TenantSig(value.to_string()));
    };
    let len = payload.len();
    if !(86..=88).contains(&len) {
        return Err(SchemaError::TenantSig(value.to_string()));
    }
    if !payload.chars().all(is_base64_std) {
        return Err(SchemaError::TenantSig(value.to_string()));
    }
    Ok(())
}

fn is_base64_std(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '=')
}

/// Convenience: the [`UpstreamSystem`] enum has fixed string values defined
/// in [`UpstreamSystem::as_str`]. Not used by [`validate`] directly because
/// the type system already constrains the variants, but downstream code
/// constructing frames from raw strings can call this for symmetry.
pub fn upstream_system_from_str(value: &str) -> Option<UpstreamSystem> {
    UpstreamSystem::parse(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::frame::{Frame, Otel, Provenance, Upstream, UpstreamSystem, Verdict};

    fn good_frame() -> Frame {
        Frame {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-prod-1".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: serde_json::json!({"tool":"x"}),
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        }
    }

    #[test]
    fn good_frame_validates() {
        validate(&good_frame()).unwrap();
    }

    #[test]
    fn schema_version_must_be_one() {
        let mut f = good_frame();
        f.schema_version = "2".to_string();
        assert!(matches!(validate(&f), Err(SchemaError::SchemaVersion(_))));
    }

    #[test]
    fn event_id_rejects_lowercase() {
        let mut f = good_frame();
        f.event_id = "abcdefghijklmnopqrstuvwxyz".to_string();
        assert!(matches!(validate(&f), Err(SchemaError::EventId(_))));
    }

    #[test]
    fn event_id_rejects_excluded_letters() {
        let mut f = good_frame();
        // `I` is excluded from Crockford base32.
        f.event_id = "01H7IZZZZZZZZZZZZZZZZZZZZZ".to_string();
        assert!(matches!(validate(&f), Err(SchemaError::EventId(_))));
    }

    #[test]
    fn timestamp_must_have_millis() {
        let mut f = good_frame();
        f.ts = "2026-04-25T18:02:11Z".to_string();
        assert!(matches!(validate(&f), Err(SchemaError::Timestamp(_))));
    }

    #[test]
    fn tee_id_rejects_leading_dash() {
        let mut f = good_frame();
        f.tee_id = "-bad-id".to_string();
        assert!(matches!(validate(&f), Err(SchemaError::TeeId(_))));
    }

    #[test]
    fn deny_requires_deny_reason() {
        let mut f = good_frame();
        f.verdict = Verdict::Deny;
        f.deny_reason = None;
        assert!(matches!(
            validate(&f),
            Err(SchemaError::DenyReasonGate { .. })
        ));
    }

    #[test]
    fn allow_forbids_deny_reason() {
        let mut f = good_frame();
        f.deny_reason = Some("guard:pii".to_string());
        assert!(matches!(
            validate(&f),
            Err(SchemaError::DenyReasonGate { .. })
        ));
    }

    #[test]
    fn deny_reason_namespaced() {
        let mut f = good_frame();
        f.verdict = Verdict::Rewrite;
        f.deny_reason = Some("guard:pii.email_in_response".to_string());
        validate(&f).unwrap();
    }

    #[test]
    fn deny_reason_rejects_uppercase() {
        let mut f = good_frame();
        f.verdict = Verdict::Deny;
        f.deny_reason = Some("Guard:Bad".to_string());
        assert!(matches!(validate(&f), Err(SchemaError::DenyReason(_))));
    }

    #[test]
    fn tenant_sig_requires_ed25519_prefix() {
        let mut f = good_frame();
        f.tenant_sig = "A".repeat(86);
        assert!(matches!(validate(&f), Err(SchemaError::TenantSig(_))));
    }

    #[test]
    fn upstream_system_from_str_round_trips() {
        for s in ["openai", "anthropic", "aws.bedrock", "mcp", "a2a", "acp"] {
            let parsed = upstream_system_from_str(s).expect("parses");
            assert_eq!(parsed.as_str(), s);
        }
        assert!(upstream_system_from_str("unknown").is_none());
    }
}
