//! Capability tokens, scoped grants, attenuation, and governed execution metadata.
//!
//! Capability submodules are the public API. This root intentionally contains
//! no flat re-export layer so callers import the domain they depend on.

pub mod attenuation;
pub mod caveat;
pub mod crypto_floor;
pub mod features;
pub mod governance;
pub mod runtime_attestation;
pub mod scope;
pub mod token;
pub mod trust_policy;
pub mod validation;
pub mod workload_identity;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod delegation_trust_root_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
