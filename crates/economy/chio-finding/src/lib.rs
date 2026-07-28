//! Cognition-market finding artifacts for the Chio protocol.
//!
//! The signed information-good artifact (`chio.finding.v1`) with
//! fail-closed pure validation and inline signing. Challenge and
//! status-feed artifacts land with their owning milestones (M5/M6).
//! Design: docs/research/cognition-market/ARCHITECTURE.md section 4 and
//! ADR-0017. No storage, no I/O, no kernel wiring.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto};

mod types;
mod validate;

pub use types::*;
pub use validate::*;
