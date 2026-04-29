//! `chio-tee-frame.v1` types.
//!
//! Mirrors the JSON schema pinned in
//! `.planning/trajectory/10-tee-replay-harness.md` lines 64-219. A frame is
//! the unit of capture that the chio-tee shadow runner emits per kernel
//! evaluation. Each frame is signed by the tenant key and serialized with
//! RFC 8785 canonical JSON so downstream replay can re-verify the
//! signature byte-for-byte.
//!
//! The serializer is reused from `chio-core::canonical`; this module owns
//! only the strongly-typed shape and a thin error wrapper.

use core::str::FromStr;

use serde::{Deserialize, Serialize};

use chio_core::canonical::canonical_json_bytes;

use crate::schema::{validate, SchemaError, SCHEMA_VERSION};

/// Strongly-typed view of a `chio-tee-frame.v1` capture event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    /// Pinned literal `"1"` per the schema lock.
    pub schema_version: String,
    /// 26-char Crockford base32 ULID.
    pub event_id: String,
    /// RFC3339 UTC timestamp with millisecond precision and trailing `Z`.
    pub ts: String,
    /// Stable tee identifier per deployment.
    pub tee_id: String,
    /// Upstream system + operation descriptor.
    pub upstream: Upstream,
    /// Canonical-JSON ToolInvocation per the M01 schema. Opaque here; the
    /// M01 validator is the source of truth.
    pub invocation: serde_json::Value,
    /// Provenance envelope (W3C trace context + optional M09 supply chain).
    pub provenance: Provenance,
    /// Lowercase hex SHA-256 of the redacted request blob.
    pub request_blob_sha256: String,
    /// Lowercase hex SHA-256 of the redacted response blob.
    pub response_blob_sha256: String,
    /// Identifier for the redactor pipeline that produced the frame.
    pub redaction_pass_id: String,
    /// Kernel verdict observed by the tee.
    pub verdict: Verdict,
    /// Required iff `verdict` is `deny` or `rewrite`. Namespaced lowercase
    /// reason code (e.g. `guard:pii.email_in_response`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// True iff the kernel would have denied/rewritten under the resolved
    /// policy. Always present; equals `verdict != allow` in shadow/enforce,
    /// always `false` in verdict-only mode.
    pub would_have_blocked: bool,
    /// Ed25519 signature over the canonical-JSON encoding of all other
    /// fields, base64-standard, prefixed `ed25519:`.
    pub tenant_sig: String,
}

/// Upstream system + operation descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub system: UpstreamSystem,
    pub operation: String,
    pub api_version: String,
}

/// Closed enum of upstream systems. Wire form matches the schema enum
/// (lowercase, dotted for `aws.bedrock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamSystem {
    #[serde(rename = "openai")]
    Openai,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "aws.bedrock")]
    AwsBedrock,
    #[serde(rename = "mcp")]
    Mcp,
    #[serde(rename = "a2a")]
    A2a,
    #[serde(rename = "acp")]
    Acp,
}

impl UpstreamSystem {
    /// Wire-form string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamSystem::Openai => "openai",
            UpstreamSystem::Anthropic => "anthropic",
            UpstreamSystem::AwsBedrock => "aws.bedrock",
            UpstreamSystem::Mcp => "mcp",
            UpstreamSystem::A2a => "a2a",
            UpstreamSystem::Acp => "acp",
        }
    }

    /// Inverse of [`UpstreamSystem::as_str`]; returns `None` for unknown
    /// values rather than producing a wildcard variant.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "openai" => UpstreamSystem::Openai,
            "anthropic" => UpstreamSystem::Anthropic,
            "aws.bedrock" => UpstreamSystem::AwsBedrock,
            "mcp" => UpstreamSystem::Mcp,
            "a2a" => UpstreamSystem::A2a,
            "acp" => UpstreamSystem::Acp,
            _ => return None,
        })
    }
}

/// `FromStr` mirror of [`UpstreamSystem::parse`]. Errors are unit-typed
/// because every failure shape is `unknown variant`; callers needing
/// richer diagnostics can use [`UpstreamSystem::parse`] directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownUpstreamSystem;

impl core::fmt::Display for UnknownUpstreamSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown upstream system")
    }
}

impl std::error::Error for UnknownUpstreamSystem {}

impl FromStr for UpstreamSystem {
    type Err = UnknownUpstreamSystem;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        UpstreamSystem::parse(value).ok_or(UnknownUpstreamSystem)
    }
}

/// Provenance envelope mounted on every frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub otel: Otel,
    /// Optional M09 SBOM-style provenance superset; opaque here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply_chain: Option<serde_json::Value>,
}

/// W3C trace-context fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Otel {
    /// W3C trace-id, 32 lowercase hex chars.
    pub trace_id: String,
    /// W3C span-id, 16 lowercase hex chars.
    pub span_id: String,
}

/// Closed enum of kernel verdicts captured by the tee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
    Rewrite,
}

/// Errors returned by [`canonicalize`] and [`parse`].
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// JSON serialization failure (pre-canonicalization).
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Canonical-JSON serialization failure (RFC 8785).
    #[error("canonical json error: {0}")]
    Canonical(String),
    /// v1 schema invariant violation (post-decode for [`parse`],
    /// pre-encode for [`canonicalize`]).
    #[error("schema violation: {0}")]
    Schema(#[from] SchemaError),
}

/// Builder-style payload for [`Frame::build`]. Groups the 13 frame fields
/// to keep the constructor under the clippy `too_many_arguments` limit
/// while preserving the named-field ergonomics of the wire-level type.
#[derive(Debug, Clone)]
pub struct FrameInputs {
    pub event_id: String,
    pub ts: String,
    pub tee_id: String,
    pub upstream: Upstream,
    pub invocation: serde_json::Value,
    pub provenance: Provenance,
    pub request_blob_sha256: String,
    pub response_blob_sha256: String,
    pub redaction_pass_id: String,
    pub verdict: Verdict,
    pub deny_reason: Option<String>,
    pub would_have_blocked: bool,
    pub tenant_sig: String,
}

impl Frame {
    /// Construct a frame with the pinned `schema_version` already filled
    /// in. Validates against the v1 schema before returning.
    pub fn build(inputs: FrameInputs) -> Result<Self, FrameError> {
        let frame = Frame {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: inputs.event_id,
            ts: inputs.ts,
            tee_id: inputs.tee_id,
            upstream: inputs.upstream,
            invocation: inputs.invocation,
            provenance: inputs.provenance,
            request_blob_sha256: inputs.request_blob_sha256,
            response_blob_sha256: inputs.response_blob_sha256,
            redaction_pass_id: inputs.redaction_pass_id,
            verdict: inputs.verdict,
            deny_reason: inputs.deny_reason,
            would_have_blocked: inputs.would_have_blocked,
            tenant_sig: inputs.tenant_sig,
        };
        validate(&frame)?;
        Ok(frame)
    }
}

/// Encode a frame to canonical JSON bytes (RFC 8785) using
/// [`chio_core::canonical::canonical_json_bytes`]. Validates the frame
/// against the v1 schema before encoding.
pub fn canonicalize(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    validate(frame)?;
    canonical_json_bytes(frame).map_err(|e| FrameError::Canonical(e.to_string()))
}

/// Parse canonical-JSON bytes back into a [`Frame`]. The result is then
/// validated against the v1 schema; bytes that decode but violate an
/// invariant return [`FrameError::Schema`].
pub fn parse(bytes: &[u8]) -> Result<Frame, FrameError> {
    let frame: Frame = serde_json::from_slice(bytes)?;
    validate(&frame)?;
    Ok(frame)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
            invocation: serde_json::json!({"tool":"noop"}),
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
    fn round_trip_canonicalize_parse() {
        let frame = good_frame();
        let bytes = canonicalize(&frame).expect("canonicalize");
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed, frame);
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let frame = good_frame();
        let a = canonicalize(&frame).expect("first canonicalize");
        let parsed = parse(&a).expect("parse");
        let b = canonicalize(&parsed).expect("second canonicalize");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_rejects_unknown_field() {
        // Serialize a known-good frame, then re-parse as a `Value`, inject
        // an unknown field, and re-encode. `serde(deny_unknown_fields)`
        // should reject it.
        let frame = good_frame();
        let mut value = serde_json::to_value(&frame).expect("frame to value");
        if let Some(map) = value.as_object_mut() {
            map.insert("extra_field".to_string(), serde_json::json!("boom"));
        }
        let bytes = serde_json::to_vec(&value).expect("serialize");
        let result = parse(&bytes);
        assert!(matches!(result, Err(FrameError::Json(_))));
    }

    #[test]
    fn parse_rejects_bad_event_id() {
        let mut frame = good_frame();
        frame.event_id = "lowercase-id-not-ulid".to_string();
        // Intentionally bypass validation by serializing directly.
        let bytes = serde_json::to_vec(&frame).expect("serialize");
        let result = parse(&bytes);
        assert!(matches!(result, Err(FrameError::Schema(_))));
    }

    #[test]
    fn canonicalize_uses_sorted_keys() {
        let frame = good_frame();
        let bytes = canonicalize(&frame).expect("canonicalize");
        let s = std::str::from_utf8(&bytes).expect("utf8");
        // RFC 8785 sorts object keys; "deny_reason" is absent for an
        // `Allow` frame because of `skip_serializing_if`. The first key
        // must be `event_id` since "e" < "i" < "p" < "r" < "s" < "t" < "u" < "v" < "w" but
        // also < "schema_version". Let's just assert the schema version
        // appears later than event_id.
        let pos_event = s.find("\"event_id\"").expect("event_id present");
        let pos_schema = s
            .find("\"schema_version\"")
            .expect("schema_version present");
        assert!(pos_event < pos_schema);
    }
}
