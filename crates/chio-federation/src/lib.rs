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
pub mod metrics;
pub mod open_admission;
pub mod pheromone_gossip;
pub mod qualification;
pub mod quorum;
pub mod reputation;
pub mod revocation_gossip;
pub mod treaty;
// Chio selective-disclosure section 6 BBS+ projection. Default-off
// behind the honestly-named `bbs-stub` feature: the implementation is a
// STUB BBS+ that captures the deterministic projection and
// disclose/withhold semantics but offers no privacy-preserving cryptographic property.
// Real BLS12-381 BBS+ signing is deferred.
#[cfg(feature = "bbs-stub")]
pub mod selective_disclosure;
pub mod trust_establishment;
pub(crate) mod validation;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
