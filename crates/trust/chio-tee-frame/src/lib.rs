//! Wire format for Chio TEE replay frames.
//!
//! The Rust types in [`frame`] mirror the v1 JSON schema field-for-field;
//! [`schema`] holds the structural and pattern invariants. The normative
//! wire-level specification is `spec/PROTOCOL.md`.
//!
//! Encoding reuses [`chio_core::canonical::canonical_json_bytes`]
//! (RFC 8785) so a frame signed in Rust round-trips byte-for-byte to
//! verifiers in TypeScript, Python, or Go.

#![forbid(unsafe_code)]

pub mod frame;
pub mod schema;

pub use frame::{
    canonicalize, parse, Frame, FrameError, FrameInputs, Otel, Provenance, Upstream,
    UpstreamSystem, Verdict,
};
pub use schema::{
    signing_payload, validate, validate_signed, verify_tenant_sig, SchemaError, SCHEMA_ID,
    SCHEMA_VERSION,
};

/// Frame schema version label. The on-the-wire field [`SCHEMA_VERSION`] is
/// the literal `"1"`; [`FRAME_VERSION`] is the textual schema name.
pub const FRAME_VERSION: &str = "chio-tee-frame.v1";
