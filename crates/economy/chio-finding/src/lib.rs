//! Cognition-market finding artifacts for the Chio protocol.
//!
//! The signed information-good artifact (`chio.finding.v1`) with
//! fail-closed pure validation and inline signing, plus the M2 market
//! families: the reusable challenge-verifier profile, the unsigned replay
//! recipe input, seller market terms, issuer seller authorization, the
//! live bond-backing allocation, the verifier facet report, and the venue
//! admission bundle. Challenge and status-feed artifacts land with their
//! owning milestones (M5/M6). Design:
//! docs/research/cognition-market/ARCHITECTURE.md sections 4-5 and
//! ADR-0017. No storage, no I/O, no kernel wiring.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto};

mod admission;
mod authorization;
mod backing;
mod envelope;
mod profile;
mod recipe;
mod report;
mod terms;
mod types;
mod validate;

pub use admission::*;
pub use authorization::*;
pub use backing::*;
pub use envelope::{signed_envelope_sha256, verify_pinned_envelope};
pub use profile::*;
pub use recipe::*;
pub use report::*;
pub use terms::*;
pub use types::*;
pub use validate::*;
