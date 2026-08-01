//! Generic listing and trust-activation contracts for the Chio protocol.
//!
//! This crate is used to publish, discover, compare, and activate marketplace
//! listings. It defines the signed `Listing` artifact, listing search and
//! comparison, SLA and pricing-hint shapes, and the trust-activation flow that
//! turns a discovered listing into a locally admissible one. Listings are
//! signed by their namespace owner and verification is pure. The governance
//! and open-market crates build on these types.
//!
//! # Modules
//!
//! - [`discovery`] -- listing search, comparison, and admissibility
//!   resolution.

#![forbid(unsafe_code)]

pub use chio_core_types::capability::scope::MonetaryAmount;
pub use chio_core_types::{canonical_json_bytes, crypto, receipt};

pub mod discovery;
pub mod outcome;
pub use discovery::{
    compare, provider_signing_key, resolve_admissible_listing, search, Listing, ListingComparison,
    ListingComparisonRow, ListingPricingHint, ListingQuery, ListingSearchResponse, ListingSla,
    SignedListingPricingHint, LISTING_COMPARISON_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    LISTING_SEARCH_SCHEMA, MAX_MARKETPLACE_SEARCH_LIMIT,
};

mod listing;
mod search;
mod trust_activation;
mod util;

pub use listing::*;
pub use search::*;
pub use trust_activation::*;
pub use util::*;

#[cfg(test)]
mod tests;
