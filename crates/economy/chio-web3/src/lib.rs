//! Chio web3 settlement, anchoring, and official-chain contract types.
//!
//! These types freeze the first official web3 execution surface on top of the
//! Chio extension substrate. They define identity bindings, trust profiles,
//! contract packages, chain configuration, anchoring proofs, oracle evidence,
//! settlement lifecycle artifacts, and qualification matrices that later
//! live-money work must honor.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical, capability, crypto, hashing, merkle, receipt};
pub use chio_credit as credit;

pub mod anchors;
pub mod chain;
pub mod contracts;
pub mod error;
pub mod identity;
pub mod qualification;
pub mod settlement;
pub mod settlement_proof;
pub mod trust_profile;
pub(crate) mod validation;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod review_thread_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod settlement_identity_evidence_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod settlement_proof_event_tests;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
