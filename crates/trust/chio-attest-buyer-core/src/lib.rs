//! Offline Chio buyer and auditor proof package verification.

#![forbid(unsafe_code)]

pub mod claims;
pub mod context;
pub mod disclosure;
pub mod error;
pub mod issuer;
pub mod oracle;
pub mod proof_package;
pub mod report;
pub mod revocation;
pub mod trust_bundle;
pub(crate) mod validation;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
