//! Per-invocation marketplace pricing for guard manifests.
//!
//! Combines a manifest base price with tenant context to produce a final
//! price in the manifest's currency. Output is a deterministic function of
//! inputs.
//!
//! The helper is pure and storage-agnostic. Callers inject the manifest
//! base price plus a tenant pricing context assembled from the publish path
//! (manifest) and reputation tier ascertainment.

use chio_fiscal::{
    FiscalDenialReason, FiscalDomain, FiscalDomainParams, FiscalParams, FiscalResolution,
    FiscalResolver,
};
use serde::{Deserialize, Serialize};

/// Errors raised by checked marketplace pricing boundaries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarketplacePricingError {
    /// Tenant id is required so downstream audit records can bind a
    /// computed price to the party whose tier was applied.
    #[error("marketplace pricing tenant_id must be non-empty and must not contain surrounding whitespace")]
    EmptyTenantId,
    /// Marketplace prices use ISO-style uppercase three-letter currency
    /// codes at this boundary.
    #[error(
        "marketplace pricing currency `{currency}` must be a three-letter uppercase ISO 4217 code"
    )]
    InvalidCurrency { currency: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FiscalMarketplacePricingError {
    #[error(transparent)]
    Pricing(#[from] MarketplacePricingError),
    #[error("fiscal marketplace pricing denied: {0:?}")]
    Denied(FiscalDenialReason),
    #[error("fiscal marketplace pricing arithmetic overflowed")]
    ArithmeticOverflow,
}

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

    /// Build and validate a pricing context for fail-closed callers.
    pub fn try_new(
        tenant_id: impl Into<String>,
        reputation_tier: MarketplaceReputationTier,
    ) -> Result<Self, MarketplacePricingError> {
        let context = Self::new(tenant_id, reputation_tier);
        context.validate()?;
        Ok(context)
    }

    /// Validate fields required by settlement-grade pricing consumers.
    pub fn validate(&self) -> Result<(), MarketplacePricingError> {
        if self.tenant_id.trim().is_empty() || self.tenant_id.trim() != self.tenant_id {
            return Err(MarketplacePricingError::EmptyTenantId);
        }
        Ok(())
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

    /// Build and validate a base price for fail-closed callers.
    pub fn try_new(
        units: u64,
        currency: impl Into<String>,
    ) -> Result<Self, MarketplacePricingError> {
        let base = Self::new(units, currency);
        base.validate()?;
        Ok(base)
    }

    /// Validate fields required by settlement-grade pricing consumers.
    pub fn validate(&self) -> Result<(), MarketplacePricingError> {
        validate_currency_code(&self.currency)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalMarketplaceDiscounts {
    pub discounts: [u32; 4],
}

impl FiscalDomainParams for FiscalMarketplaceDiscounts {
    fn from_fiscal_params(params: &FiscalParams) -> Option<Self> {
        match params {
            FiscalParams::MarketplaceDiscountPerHundred { discounts } => Some(Self {
                discounts: *discounts,
            }),
            _ => None,
        }
    }
}

/// Compute the per-invocation price for a guard manifest under a
/// given tenant pricing context.
///
/// This compatibility function assumes its inputs were already
/// validated by the caller. New marketplace catalog and settlement
/// consumers should prefer [`compute_checked_marketplace_invocation_price`].
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
    let discount = discount_for_reputation_tier(ctx.reputation_tier);

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

/// Validate inputs and compute the per-invocation price for
/// settlement-facing marketplace consumers.
pub fn compute_checked_marketplace_invocation_price(
    base: &MarketplaceBasePrice,
    ctx: &MarketplacePricingContext,
) -> Result<MarketplaceInvocationPrice, MarketplacePricingError> {
    base.validate()?;
    ctx.validate()?;
    Ok(compute_marketplace_invocation_price(base, ctx))
}

pub fn compute_fiscal_marketplace_invocation_price(
    base: &MarketplaceBasePrice,
    ctx: &MarketplacePricingContext,
    resolver: &FiscalResolver<'_>,
) -> Result<MarketplaceInvocationPrice, FiscalMarketplacePricingError> {
    base.validate()?;
    ctx.validate()?;
    let discounts = match resolver
        .resolve::<FiscalMarketplaceDiscounts>(FiscalDomain::MarketplaceDiscountPerHundred, None)
    {
        FiscalResolution::Governed { params, .. } => params.discounts,
        FiscalResolution::Fallback(_) => TIER_DISCOUNT_PER_HUNDRED,
        FiscalResolution::Denied(reason) => {
            return Err(FiscalMarketplacePricingError::Denied(reason));
        }
    };
    compute_marketplace_invocation_price_with_discounts(base, ctx, &discounts)
}

fn compute_marketplace_invocation_price_with_discounts(
    base: &MarketplaceBasePrice,
    ctx: &MarketplacePricingContext,
    discounts: &[u32; 4],
) -> Result<MarketplaceInvocationPrice, FiscalMarketplacePricingError> {
    let discount = discounts
        .get(ctx.reputation_tier as usize)
        .copied()
        .ok_or(FiscalMarketplacePricingError::ArithmeticOverflow)?;
    let kept_per_hundred = 100_u128
        .checked_sub(u128::from(discount))
        .ok_or(FiscalMarketplacePricingError::ArithmeticOverflow)?;
    let units = u128::from(base.units)
        .checked_mul(kept_per_hundred)
        .map(|scaled| scaled / 100)
        .and_then(|scaled| u64::try_from(scaled).ok())
        .ok_or(FiscalMarketplacePricingError::ArithmeticOverflow)?;
    Ok(MarketplaceInvocationPrice {
        units,
        currency: base.currency.clone(),
        applied_tier: ctx.reputation_tier,
        discount_basis_points_per_hundred: discount,
    })
}

fn discount_for_reputation_tier(tier: MarketplaceReputationTier) -> u32 {
    TIER_DISCOUNT_PER_HUNDRED
        .get(tier as usize)
        .copied()
        .unwrap_or(0)
}

fn validate_currency_code(currency: &str) -> Result<(), MarketplacePricingError> {
    if currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Ok(());
    }
    Err(MarketplacePricingError::InvalidCurrency {
        currency: currency.to_string(),
    })
}

pub fn self_test_fiscal_marketplace_discount_adapter() -> Result<(), String> {
    let base = MarketplaceBasePrice::new(10_000, "USD");
    for tier in [
        MarketplaceReputationTier::Tier0,
        MarketplaceReputationTier::Tier1,
        MarketplaceReputationTier::Tier2,
        MarketplaceReputationTier::Tier3,
    ] {
        let context = MarketplacePricingContext::new("fiscal-readiness", tier);
        let legacy = compute_checked_marketplace_invocation_price(&base, &context)
            .map_err(|error| error.to_string())?;
        let installed = compute_marketplace_invocation_price_with_discounts(
            &base,
            &context,
            &TIER_DISCOUNT_PER_HUNDRED,
        )
        .map_err(|error| error.to_string())?;
        if installed != legacy {
            return Err("marketplace-discount bootstrap parity failed".to_owned());
        }
    }
    Ok(())
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
    fn discount_for_reputation_tier_uses_table_order() {
        assert_eq!(
            discount_for_reputation_tier(MarketplaceReputationTier::Tier0),
            0
        );
        assert_eq!(
            discount_for_reputation_tier(MarketplaceReputationTier::Tier1),
            5
        );
        assert_eq!(
            discount_for_reputation_tier(MarketplaceReputationTier::Tier2),
            10
        );
        assert_eq!(
            discount_for_reputation_tier(MarketplaceReputationTier::Tier3),
            20
        );
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

    #[test]
    fn checked_pricing_accepts_canonical_currency_and_tenant() {
        let base = MarketplaceBasePrice::try_new(1_000, "USD")
            .unwrap_or_else(|error| panic!("base should validate: {error}"));
        let ctx = MarketplacePricingContext::try_new("tenant-a", MarketplaceReputationTier::Tier1)
            .unwrap_or_else(|error| panic!("context should validate: {error}"));
        let priced = compute_checked_marketplace_invocation_price(&base, &ctx)
            .unwrap_or_else(|error| panic!("pricing should validate: {error}"));
        assert_eq!(priced.units, 950);
        assert_eq!(priced.currency, "USD");
    }

    #[test]
    fn checked_pricing_rejects_non_canonical_currency_codes() {
        for currency in ["", "usd", " USD", "US", "US1", "USDD"] {
            let base = MarketplaceBasePrice::new(1_000, currency);
            let ctx = MarketplacePricingContext::new("tenant-a", MarketplaceReputationTier::Tier1);
            let error = compute_checked_marketplace_invocation_price(&base, &ctx)
                .err()
                .unwrap_or_else(|| panic!("currency `{currency}` should be rejected"));
            assert_eq!(
                error,
                MarketplacePricingError::InvalidCurrency {
                    currency: currency.to_string()
                }
            );
        }
    }

    #[test]
    fn checked_pricing_rejects_empty_tenant_id() {
        let base = MarketplaceBasePrice::new(1_000, "USD");
        let ctx = MarketplacePricingContext::new("  ", MarketplaceReputationTier::Tier1);
        let error = compute_checked_marketplace_invocation_price(&base, &ctx)
            .err()
            .unwrap_or_else(|| panic!("empty tenant should be rejected"));
        assert_eq!(error, MarketplacePricingError::EmptyTenantId);
    }

    #[test]
    fn checked_pricing_rejects_padded_tenant_id() {
        let base = MarketplaceBasePrice::new(1_000, "USD");
        for tenant_id in [" tenant-a", "tenant-a "] {
            let ctx = MarketplacePricingContext::new(tenant_id, MarketplaceReputationTier::Tier1);
            let error = compute_checked_marketplace_invocation_price(&base, &ctx)
                .err()
                .unwrap_or_else(|| panic!("padded tenant `{tenant_id}` should be rejected"));
            assert_eq!(error, MarketplacePricingError::EmptyTenantId);
        }
    }

    #[test]
    fn fiscal_discount_table_preserves_bootstrap_parity_and_changes_output() {
        let base = MarketplaceBasePrice::new(1_001, "USD");
        for tier in [
            MarketplaceReputationTier::Tier0,
            MarketplaceReputationTier::Tier1,
            MarketplaceReputationTier::Tier2,
            MarketplaceReputationTier::Tier3,
        ] {
            let ctx = MarketplacePricingContext::new("tenant-a", tier);
            assert_eq!(
                compute_marketplace_invocation_price_with_discounts(
                    &base,
                    &ctx,
                    &TIER_DISCOUNT_PER_HUNDRED,
                )
                .ok(),
                Some(compute_marketplace_invocation_price(&base, &ctx))
            );
        }

        let ctx = MarketplacePricingContext::new("tenant-a", MarketplaceReputationTier::Tier3);
        let priced =
            compute_marketplace_invocation_price_with_discounts(&base, &ctx, &[0, 10, 20, 30]).ok();
        assert_eq!(priced.as_ref().map(|price| price.units), Some(700));
        assert_eq!(
            priced.map(|price| price.discount_basis_points_per_hundred),
            Some(30)
        );
    }
}
