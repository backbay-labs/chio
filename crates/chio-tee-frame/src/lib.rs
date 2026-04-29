//! Wire format for Chio TEE replay frames.
//!
//! Phase 1 of M10. T1 landed the skeleton; T3 lands the v1 frame schema.
//!
//! See `.planning/trajectory/10-tee-replay-harness.md` lines 64-219 for
//! the canonical JSON-Schema. The Rust types in [`frame`] mirror that
//! schema field-for-field; [`schema`] holds the structural and pattern
//! invariants.
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
pub use schema::{validate, SchemaError, SCHEMA_ID, SCHEMA_VERSION};

/// Frame schema version label. The on-the-wire field [`SCHEMA_VERSION`] is
/// the literal `"1"`; [`FRAME_VERSION`] is the textual schema name.
pub const FRAME_VERSION: &str = "chio-tee-frame.v1";
