//! Chio federated trust, quorum, and shared reputation contracts.
//!
//! These contracts extend Chio's local listing, governance, and open-market
//! surfaces into one bounded cross-operator federation lane. Federation stays
//! evidence-referential and fail-closed: visibility may flow across operators,
//! but runtime trust still requires explicit local activation and review.

#![forbid(unsafe_code)]

pub use chio_core_types::{capability, receipt};
pub use chio_listing as listing;
pub use chio_open_market as open_market;

pub mod activation;
pub mod artifacts;
pub mod bilateral;
pub mod bilateral_dsse;
pub mod bilateral_verifier;
#[cfg(any(test, feature = "demo"))]
pub mod demo;
pub mod error;
pub mod frost;
pub mod metrics;
pub mod open_admission;
pub mod pheromone_gossip;
pub mod qualification;
pub mod quorum;
pub mod reputation;
pub mod revocation_gossip;
pub mod treaty;
pub mod trust_establishment;
pub(crate) mod validation;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
