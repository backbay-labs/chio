//! Open-market economics and penalty contracts for the Chio protocol.
//!
//! This crate models open bidding for tool access along with the bonds and
//! penalties that back it. It defines the bidding flow, fee schedules,
//! evidence references, authority checks, and penalty evaluation state machines.
//! It builds on the listing and governance surfaces in `chio-listing` and
//! `chio-governance`.
//!
//! # Modules
//!
//! - [`bidding`] - bid/ask/accept flow and the signed bidding artifacts.
//! - [`fee_schedule`] - economics scopes, bond requirements, and fee schedules.
//! - [`penalty`] - abuse classes, penalty artifacts, issue requests, and states.
//! - [`evidence`] - evidence references and evaluation finding codes.
//! - [`evaluation`] - penalty evaluation requests and fail-closed market rules.
//! - `finding_admission` - admission-gated cognition-market bid seam.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, capability, crypto, receipt};
pub use chio_governance as governance;
pub use chio_listing as listing;

pub(crate) mod authority;
pub mod bidding;
pub mod evaluation;
pub mod evidence;
pub mod fee_schedule;
pub mod finding_admission;
pub mod finding_audit;
pub mod finding_bid_policy;
pub mod finding_penalty;
pub mod finding_pheromone;
pub mod finding_slash_amount;
pub mod fiscal_adapter;
#[cfg(kani)]
mod kani_public_harnesses;
pub mod penalty;
pub mod purchase_verification;
pub mod recovery;
pub(crate) mod validation;

#[cfg(test)]
mod tests;
