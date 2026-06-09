//! Generic governance charters and case evaluation for the Chio protocol.
//!
//! This crate is used to author and evaluate governance charters and to
//! authorize governed actions against a signed lease. It defines the
//! capability-lease artifacts and action classes (scoped observation,
//! delegated action, narrow destructive), governance-receipt artifacts, and
//! verification helpers. It builds on the listing surface in `chio-listing`.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto, receipt};
pub use chio_listing as listing;

pub mod authorization;
pub mod error;
pub mod evaluation;
pub mod generic;
pub mod lease;
pub(crate) mod validation;

#[cfg(test)]
mod tests;
