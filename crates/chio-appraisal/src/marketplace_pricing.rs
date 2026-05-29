//! Marketplace pricing helper.
//!
//! `chio-appraisal` already models the runtime-attestation appraisal
//! surface. This helper reuses the crate's deterministic-evaluation
//! contract (output is a deterministic function of inputs) by adding
//! a small per-invocation pricing helper for guard manifests. No new
//! pricing primitives are introduced: the helper combines a manifest
//! base price with tenant context to produce a final price in the
//! manifest's currency.
//!
//! The helper is intentionally pure and storage-agnostic. Callers
//! inject the manifest base price plus a tenant pricing context
//! assembled from the publish path (manifest) and reputation tier
//! ascertainment.

use serde::{Deserialize, Serialize};

/// Tenant-side reputation tier visible to the pricing helper. Mirrors
/// the four-tier shape of `chio_reputation::ReputationTier` without
/// pulling in the dependency: callers convert their concrete tier into
/// this enum before invoking the helper.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceReputationTier {
    /// Default tier. Highest invocation price (no discount).
    #[default]
    Tier0,
    /// Trusted publisher tier with a small discount.
    Tier1,
    /// High-trust tier.
    Tier2,
    /// Highest-trust tier with the largest discount.
    Tier3,
}

/// Tenant-supplied pricing context. Holds the bits the helper needs
/// to compute a deterministic invocation price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplacePricingContext {
    /// Tenant identifier surfaced for audit trails. The helper does
    /// not inspect this value.
    pub tenant_id: String,
    /// Tenant's current reputation tier.
    pub reputation_tier: MarketplaceReputationTier,
}

impl MarketplacePricingContext {
    /// Build a context with the supplied tenant id and reputation tier.
    #[must_use]
    pub fn new(tenant_id: impl Into<String>, reputation_tier: MarketplaceReputationTier) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            reputation_tier,
        }
    }
}

/// Manifest base price input mirror. Mirrors
/// `chio_guard_registry::GuardPrice` so chio-appraisal does not need
/// to depend on the registry crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceBasePrice {
    /// Amount per invocation in the currency's smallest unit.
    pub units: u64,
    /// ISO 4217 currency code.
    pub currency: String,
}

impl MarketplaceBasePrice {
    /// Construct a base price.
    #[must_use]
    pub fn new(units: u64, currency: impl Into<String>) -> Self {
        Self {
            units,
            currency: currency.into(),
        }
    }
}

/// Fully resolved per-invocation price emitted by
/// [`compute_marketplace_invocation_price`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceInvocationPrice {
    /// Final price in minor units after applying tier-based adjustments.
    pub units: u64,
    /// Currency carried over from the input manifest base price.
    pub currency: String,
    /// Reputation tier consumed to compute the price (preserved for
    /// audit trails).
    pub applied_tier: MarketplaceReputationTier,
    /// Numerator of the discount fraction applied. Zero means no
    /// discount; the denominator is fixed at `100`.
    pub discount_basis_points_per_hundred: u32,
}

/// Discount table consumed by [`compute_marketplace_invocation_price`].
///
/// The table is intentionally small and deterministic. Tier0 pays the
/// full sticker price (no discount). Higher tiers receive monotonic
/// discounts. Discounts are expressed as units per hundred so the
/// resolution is one percent: a value of `5` means a five-percent
/// discount applied via integer arithmetic.
pub const TIER_DISCOUNT_PER_HUNDRED: [u32; 4] = [0, 5, 10, 20];

/// Compute the per-invocation price for a guard manifest under a
/// given tenant pricing context.
///
/// The helper is deterministic in `(base, ctx)`: equal inputs produce
/// equal outputs. Zero-priced manifests stay zero-priced regardless of
/// tier (free-tier guards are pinned at zero). The
/// discount math is integer-only; rounding is half-down by truncation,
/// matching minor-unit pricing semantics.
#[must_use]
pub fn compute_marketplace_invocation_price(
    base: &MarketplaceBasePrice,
    ctx: &MarketplacePricingContext,
) -> MarketplaceInvocationPrice {
    let tier_index = ctx.reputation_tier as usize;
    let discount = TIER_DISCOUNT_PER_HUNDRED
        .get(tier_index)
        .copied()
        .unwrap_or(0);

    let units = if base.units == 0 {
        0
    } else {
        let kept_per_hundred = 100u128.saturating_sub(u128::from(discount));
        let scaled = u128::from(base.units).saturating_mul(kept_per_hundred) / 100u128;
        u64::try_from(scaled).unwrap_or(u64::MAX)
    };

    MarketplaceInvocationPrice {
        units,
        currency: base.currency.clone(),
        applied_tier: ctx.reputation_tier,
        discount_basis_points_per_hundred: discount,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_base_price_stays_zero() {
        let base = MarketplaceBasePrice::new(0, "USD");
        let ctx = MarketplacePricingContext::new("tenant-a", MarketplaceReputationTier::Tier3);
        let priced = compute_marketplace_invocation_price(&base, &ctx);
        assert_eq!(priced.units, 0);
        assert_eq!(priced.currency, "USD");
        assert_eq!(priced.applied_tier, MarketplaceReputationTier::Tier3);
        assert_eq!(priced.discount_basis_points_per_hundred, 20);
    }

    #[test]
    fn tier_0_pays_sticker_price() {
        let base = MarketplaceBasePrice::new(1_000, "USD");
        let ctx = MarketplacePricingContext::new("tenant-a", MarketplaceReputationTier::Tier0);
        let priced = compute_marketplace_invocation_price(&base, &ctx);
        assert_eq!(priced.units, 1_000);
        assert_eq!(priced.discount_basis_points_per_hundred, 0);
    }

    #[test]
    fn higher_tier_yields_monotonic_discount() {
        let base = MarketplaceBasePrice::new(1_000, "USD");
        let t0 = compute_marketplace_invocation_price(
            &base,
            &MarketplacePricingContext::new("a", MarketplaceReputationTier::Tier0),
        )
        .units;
        let t1 = compute_marketplace_invocation_price(
            &base,
            &MarketplacePricingContext::new("a", MarketplaceReputationTier::Tier1),
        )
        .units;
        let t2 = compute_marketplace_invocation_price(
            &base,
            &MarketplacePricingContext::new("a", MarketplaceReputationTier::Tier2),
        )
        .units;
        let t3 = compute_marketplace_invocation_price(
            &base,
            &MarketplacePricingContext::new("a", MarketplaceReputationTier::Tier3),
        )
        .units;
        assert_eq!(t0, 1_000);
        assert_eq!(t1, 950);
        assert_eq!(t2, 900);
        assert_eq!(t3, 800);
        assert!(t0 >= t1 && t1 >= t2 && t2 >= t3);
    }

    #[test]
    fn pricing_helper_is_deterministic() {
        let base = MarketplaceBasePrice::new(2_500, "EUR");
        let ctx = MarketplacePricingContext::new("tenant-x", MarketplaceReputationTier::Tier2);
        let first = compute_marketplace_invocation_price(&base, &ctx);
        let second = compute_marketplace_invocation_price(&base, &ctx);
        assert_eq!(first, second);
        assert_eq!(first.currency, "EUR");
    }

    #[test]
    fn saturating_math_never_panics() {
        let base = MarketplaceBasePrice::new(u64::MAX, "USD");
        let ctx = MarketplacePricingContext::new("a", MarketplaceReputationTier::Tier3);
        let priced = compute_marketplace_invocation_price(&base, &ctx);
        // 80% of u64::MAX fits inside u64.
        assert!(priced.units > 0);
    }
}
