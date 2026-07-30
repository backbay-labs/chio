//! Cognition-market finding artifacts for the Chio protocol.
//!
//! The signed information-good artifact (`chio.finding.v1`) with
//! fail-closed pure validation and inline signing, plus supporting market
//! primitives: the reusable challenge-verifier profile, the unsigned replay
//! recipe input, seller market terms, issuer seller authorization, the
//! live bond-backing allocation, the verifier facet report, and the venue
//! admission bundle, the purchase terminals: the unsigned buyer
//! purchase context, the settled purchase record, and the failed-delivery
//! terminal, and the challenge and audit lane: the class-gated challenge,
//! its signed outcome and enforcement instruction, the finalized bond
//! snapshot, the audit epoch and report, and the unsigned replay
//! observation preimage. Status-feed artifacts have no resolver in this
//! crate yet; callers that need them supply their own. Design:
//! docs/research/cognition-market/ARCHITECTURE.md sections 4-5 and
//! ADR-0017. No storage, no I/O, no kernel wiring.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto};

mod admission;
mod audit_epoch;
mod audit_report;
mod authorization;
mod backing;
mod challenge;
mod challenge_enforcement;
mod challenge_outcome;
mod envelope;
mod failed_delivery;
mod finalized_bond_snapshot;
mod profile;
mod purchase_context;
mod purchase_record;
mod recipe;
mod recovery_context;
mod replay_observation;
mod report;
mod terms;
mod types;
mod validate;

pub use admission::*;
pub use audit_epoch::*;
pub use audit_report::*;
pub use authorization::*;
pub use backing::*;
pub use challenge::*;
pub use challenge_enforcement::*;
pub use challenge_outcome::*;
pub use envelope::{signed_envelope_sha256, verify_pinned_envelope};
pub use failed_delivery::*;
pub use finalized_bond_snapshot::*;
pub use profile::*;
pub use purchase_context::*;
pub use purchase_record::*;
pub use recipe::*;
pub use recovery_context::*;
pub use replay_observation::*;
pub use report::*;
pub use terms::*;
pub use types::*;
pub use validate::*;
