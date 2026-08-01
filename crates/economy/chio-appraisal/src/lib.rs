//! Runtime attestation appraisal artifacts and marketplace pricing for the
//! Chio protocol.
//!
//! This crate is used to appraise runtime attestation evidence and to derive
//! marketplace prices from it. It defines appraisal descriptors and an
//! artifact inventory, the attestation-verifier family taxonomy, and the
//! deterministic marketplace invocation-pricing model
//! (`compute_checked_marketplace_invocation_price`,
//! `compute_marketplace_invocation_price`, base prices, reputation tiers, and
//! tier discounts). Settlement-facing callers should use the checked pricing
//! boundary; the unchecked compute helper remains for compatibility with
//! callers that already validate their inputs. The underwriting, credit, and
//! market crates build on these types.
//!
//! # Modules
//!
//! - [`marketplace_pricing`] -- per-invocation pricing with reputation-tier
//!   discounts.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical, capability, crypto, error, receipt, Error};

pub mod marketplace_pricing;

pub use marketplace_pricing::{
    compute_checked_marketplace_invocation_price, compute_fiscal_marketplace_invocation_price,
    compute_marketplace_invocation_price, self_test_fiscal_marketplace_discount_adapter,
    FiscalMarketplaceDiscounts, FiscalMarketplacePricingError, MarketplaceBasePrice,
    MarketplaceInvocationPrice, MarketplacePricingContext, MarketplacePricingError,
    MarketplaceReputationTier, TIER_DISCOUNT_PER_HUNDRED,
};

pub use chio_core_types::runtime_attestation::AttestationVerifierFamily;

mod appraisal;
mod artifact_inventory;
mod descriptor;
mod types;
mod validate;

pub use appraisal::*;
pub use artifact_inventory::*;
pub use descriptor::*;
pub use types::*;

#[cfg(test)]
mod tests;
