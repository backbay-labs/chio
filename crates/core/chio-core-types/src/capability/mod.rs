//! Capability tokens, scoped grants, attenuation, and governed execution metadata.
//!
//! Capability submodules are the public API. This root intentionally contains
//! no flat re-export layer so callers import the domain they depend on.

pub mod aggregate_invocation;
pub mod attenuation;
pub mod caveat;
pub mod crypto_floor;
pub mod cumulative_approval;
pub mod features;
pub mod governance;
pub mod runtime_attestation;
pub mod scope;
pub mod supplemental_authorization;
pub mod threshold_approval;
pub mod token;
pub mod trust_policy;
pub mod validation;
pub mod workload_identity;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod caveat_and_delegation_guard_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod delegation_trust_root_tests;

#[cfg(test)]
mod aggregate_invocation_tests;

#[cfg(test)]
mod cumulative_approval_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod threshold_approval_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
