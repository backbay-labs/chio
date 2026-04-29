//! Bridge re-exports for the `chio-tee-frame.v1` types.
//!
//! `chio-tee-frame` is the wire-format crate; `chio-tee` is the runtime
//! sidecar. The runtime constructs and consumes frames through the same
//! type names without taking a direct dependency on the schema crate at
//! every call site, so this module re-exports the public surface as
//! `chio_tee::frame::*`.
//!
//! Adding new exports here is the supported way to extend the bridge;
//! avoid pulling `chio_tee_frame` directly into runtime modules outside
//! this file.

pub use chio_tee_frame::{
    canonicalize, parse, validate, Frame, FrameError, FrameInputs, Otel, Provenance, SchemaError,
    Upstream, UpstreamSystem, Verdict, FRAME_VERSION, SCHEMA_ID, SCHEMA_VERSION,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bridge_re_exports_round_trip() {
        let frame = Frame {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-bridge".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Mcp,
                operation: "tool.call".to_string(),
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
        };
        validate(&frame).expect("validate via bridge");
        let bytes = canonicalize(&frame).expect("canonicalize via bridge");
        let parsed = parse(&bytes).expect("parse via bridge");
        assert_eq!(parsed, frame);
    }

    #[test]
    fn bridge_surfaces_frame_error() {
        let bad = b"{\"schema_version\":\"1\"}";
        let result = parse(bad);
        assert!(matches!(result, Err(FrameError::Json(_))));
    }

    #[test]
    fn bridge_exposes_schema_constants() {
        assert_eq!(SCHEMA_VERSION, "1");
        assert_eq!(FRAME_VERSION, "chio-tee-frame.v1");
        assert!(SCHEMA_ID.starts_with("https://chio.dev/schemas/chio-tee-frame/"));
    }
}
