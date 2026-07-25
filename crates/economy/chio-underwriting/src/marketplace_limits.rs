//! Reputation-weighted credit limit helper.
//!
//! Emits a marketplace credit limit decision keyed off
//! `UnderwritingDecisionOutcome` (Approve / ReduceCeiling / StepUp / Deny),
//! surfaced by the CLI in `chio guard market info`. Deterministic and
//! storage-agnostic.
//!
//! Soft-dep: the revocation oracle revokes guard publisher
//! credentials on the same sparse-Merkle root that revokes capabilities.
//! When a revocation signal is provided, the helper denies regardless
//! of reputation tier (fail-closed). Without a revocation signal the
//! helper proceeds on tier-weighted limits only.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_fiscal::{
    FiscalDenialReason, FiscalDomain, FiscalDomainParams, FiscalParams, FiscalResolution,
    FiscalResolver,
};
use serde::{Deserialize, Serialize};

use crate::UnderwritingDecisionOutcome;

/// Reputation tier mirror used by the credit-limit helper. Mirrors the
/// four-tier shape of `chio_reputation::ReputationTier` without forcing
/// the underwriting crate to depend on the reputation crate. Callers
/// translate their concrete tier into this enum at the call site.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceLimitTier {
    /// Default tier. Smallest credit ceiling.
    #[default]
    Tier0,
    /// Trusted tier with a moderate ceiling.
    Tier1,
    /// High-trust tier.
    Tier2,
    /// Highest-trust tier with the largest ceiling.
    Tier3,
}

/// Per-tier credit ceiling table in minor units (for example USD cents).
/// The ceilings are monotonically increasing with tier so that a higher
/// tier never receives a smaller credit limit than a lower tier.
pub const MARKETPLACE_TIER_LIMIT_UNITS: [u64; 4] = [10_000, 50_000, 250_000, 1_000_000];
pub const MARKETPLACE_TIER_LIMIT_CURRENCY: &str = "USD";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalTierLimits {
    pub ceilings: [MonetaryAmount; 4],
}

impl FiscalDomainParams for FiscalTierLimits {
    fn from_fiscal_params(params: &FiscalParams) -> Option<Self> {
        match params {
            FiscalParams::TierLimits { ceilings } => Some(Self {
                ceilings: ceilings.clone(),
            }),
            _ => None,
        }
    }
}

/// Inputs consumed by [`compute_marketplace_credit_limit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceCreditLimitRequest {
    /// Cluster operator (tenant) identifier surfaced for audit trails.
    pub tenant_id: String,
    /// Tenant's current reputation tier.
    pub reputation_tier: MarketplaceLimitTier,
    /// ISO 4217 currency code applied to the limit ceiling.
    pub currency: String,
    /// Whether the revocation oracle currently lists the publisher
    /// or any of the publisher's credentials as revoked. Fail-closed:
    /// `true` denies the limit regardless of tier.
    pub publisher_revoked: bool,
}

/// Output of [`compute_marketplace_credit_limit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceCreditLimitDecision {
    /// Underwriting outcome consumed by callers that already render
    /// `UnderwritingDecisionOutcome`.
    pub outcome: UnderwritingDecisionOutcome,
    /// Approved ceiling in minor units. Zero on rejection.
    pub limit_units: u64,
    /// Currency carried over from the request.
    pub currency: String,
    /// Reputation tier applied to compute the ceiling. Preserved for
    /// audit trails.
    pub applied_tier: MarketplaceLimitTier,
    /// Stable, machine-readable reason string. Non-empty for
    /// rejections; empty when the limit is approved.
    pub reason: String,
}

/// Compute the marketplace credit limit for a tenant.
///
/// Soft-dep on the revocation oracle: if `publisher_revoked` is true,
/// the helper rejects with `outcome = Rejected` regardless of tier.
/// Otherwise the limit is the tier ceiling.
#[must_use]
pub fn compute_marketplace_credit_limit(
    request: &MarketplaceCreditLimitRequest,
) -> MarketplaceCreditLimitDecision {
    if request.publisher_revoked {
        return MarketplaceCreditLimitDecision {
            outcome: UnderwritingDecisionOutcome::Deny,
            limit_units: 0,
            currency: request.currency.clone(),
            applied_tier: request.reputation_tier,
            reason: "publisher_credentials_revoked".to_owned(),
        };
    }

    if request.currency != MARKETPLACE_TIER_LIMIT_CURRENCY {
        return MarketplaceCreditLimitDecision {
            outcome: UnderwritingDecisionOutcome::Deny,
            limit_units: 0,
            currency: request.currency.clone(),
            applied_tier: request.reputation_tier,
            reason: "unsupported_limit_currency".to_owned(),
        };
    }

    let tier_index = request.reputation_tier as usize;
    let limit_units = MARKETPLACE_TIER_LIMIT_UNITS
        .get(tier_index)
        .copied()
        .unwrap_or(0);

    MarketplaceCreditLimitDecision {
        outcome: UnderwritingDecisionOutcome::Approve,
        limit_units,
        currency: request.currency.clone(),
        applied_tier: request.reputation_tier,
        reason: String::new(),
    }
}

pub fn compute_fiscal_marketplace_credit_limit(
    request: &MarketplaceCreditLimitRequest,
    resolver: &FiscalResolver<'_>,
) -> Result<MarketplaceCreditLimitDecision, FiscalDenialReason> {
    match resolver.resolve::<FiscalTierLimits>(FiscalDomain::TierLimits, Some(&request.currency)) {
        FiscalResolution::Governed { params, .. } => Ok(
            compute_marketplace_credit_limit_with_amounts(request, &params.ceilings),
        ),
        FiscalResolution::Fallback(_) => resolver
            .bootstrap_tier_limits(&request.currency)
            .map(|limits| compute_marketplace_credit_limit_with_units(request, limits))
            .ok_or(FiscalDenialReason::VerificationFailed),
        FiscalResolution::Denied(reason) => Err(reason),
    }
}

fn compute_marketplace_credit_limit_with_amounts(
    request: &MarketplaceCreditLimitRequest,
    ceilings: &[MonetaryAmount; 4],
) -> MarketplaceCreditLimitDecision {
    if request.publisher_revoked {
        return denied_credit_limit(request, "publisher_credentials_revoked");
    }
    let Some(limit) = ceilings.get(request.reputation_tier as usize) else {
        return denied_credit_limit(request, "invalid_reputation_tier");
    };
    if limit.currency != request.currency {
        return denied_credit_limit(request, "unsupported_limit_currency");
    }
    approved_credit_limit(request, limit.units)
}

fn compute_marketplace_credit_limit_with_units(
    request: &MarketplaceCreditLimitRequest,
    ceilings: &[u64; 4],
) -> MarketplaceCreditLimitDecision {
    if request.publisher_revoked {
        return denied_credit_limit(request, "publisher_credentials_revoked");
    }
    let Some(limit_units) = ceilings.get(request.reputation_tier as usize).copied() else {
        return denied_credit_limit(request, "invalid_reputation_tier");
    };
    approved_credit_limit(request, limit_units)
}

fn approved_credit_limit(
    request: &MarketplaceCreditLimitRequest,
    limit_units: u64,
) -> MarketplaceCreditLimitDecision {
    MarketplaceCreditLimitDecision {
        outcome: UnderwritingDecisionOutcome::Approve,
        limit_units,
        currency: request.currency.clone(),
        applied_tier: request.reputation_tier,
        reason: String::new(),
    }
}

fn denied_credit_limit(
    request: &MarketplaceCreditLimitRequest,
    reason: &str,
) -> MarketplaceCreditLimitDecision {
    MarketplaceCreditLimitDecision {
        outcome: UnderwritingDecisionOutcome::Deny,
        limit_units: 0,
        currency: request.currency.clone(),
        applied_tier: request.reputation_tier,
        reason: reason.to_owned(),
    }
}

pub fn self_test_fiscal_tier_limits_adapter() -> Result<(), String> {
    for tier in [
        MarketplaceLimitTier::Tier0,
        MarketplaceLimitTier::Tier1,
        MarketplaceLimitTier::Tier2,
        MarketplaceLimitTier::Tier3,
    ] {
        for publisher_revoked in [false, true] {
            let request = MarketplaceCreditLimitRequest {
                tenant_id: "fiscal-readiness".to_owned(),
                reputation_tier: tier,
                currency: MARKETPLACE_TIER_LIMIT_CURRENCY.to_owned(),
                publisher_revoked,
            };
            let legacy = compute_marketplace_credit_limit(&request);
            let installed = compute_marketplace_credit_limit_with_units(
                &request,
                &MARKETPLACE_TIER_LIMIT_UNITS,
            );
            if installed != legacy {
                return Err("tier-limit bootstrap parity failed".to_owned());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(tier: MarketplaceLimitTier, revoked: bool) -> MarketplaceCreditLimitRequest {
        MarketplaceCreditLimitRequest {
            tenant_id: "tenant-a".to_owned(),
            reputation_tier: tier,
            currency: "USD".to_owned(),
            publisher_revoked: revoked,
        }
    }

    #[test]
    fn tier_0_gets_the_smallest_ceiling() {
        let decision =
            compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier0, false));
        assert!(matches!(
            decision.outcome,
            UnderwritingDecisionOutcome::Approve
        ));
        assert_eq!(decision.limit_units, MARKETPLACE_TIER_LIMIT_UNITS[0]);
        assert_eq!(decision.currency, "USD");
    }

    #[test]
    fn higher_tier_yields_monotonic_ceiling() {
        let t0 = compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier0, false))
            .limit_units;
        let t1 = compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier1, false))
            .limit_units;
        let t2 = compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier2, false))
            .limit_units;
        let t3 = compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier3, false))
            .limit_units;
        assert!(t0 < t1 && t1 < t2 && t2 < t3);
    }

    #[test]
    fn revocation_oracle_denies_regardless_of_tier() {
        let decision =
            compute_marketplace_credit_limit(&request(MarketplaceLimitTier::Tier3, true));
        assert!(matches!(
            decision.outcome,
            UnderwritingDecisionOutcome::Deny
        ));
        assert_eq!(decision.limit_units, 0);
        assert_eq!(decision.reason, "publisher_credentials_revoked");
    }

    #[test]
    fn legacy_limits_deny_an_unconfigured_currency() {
        let mut unsupported = request(MarketplaceLimitTier::Tier3, false);
        unsupported.currency = "EUR".to_owned();
        let decision = compute_marketplace_credit_limit(&unsupported);
        assert!(matches!(
            decision.outcome,
            UnderwritingDecisionOutcome::Deny
        ));
        assert_eq!(decision.limit_units, 0);
        assert_eq!(decision.reason, "unsupported_limit_currency");
    }

    #[test]
    fn helper_is_deterministic() {
        let req = request(MarketplaceLimitTier::Tier2, false);
        let first = compute_marketplace_credit_limit(&req);
        let second = compute_marketplace_credit_limit(&req);
        assert_eq!(first, second);
    }

    #[test]
    fn fiscal_tier_limits_preserve_bootstrap_parity_and_apply_governed_units() {
        for tier in [
            MarketplaceLimitTier::Tier0,
            MarketplaceLimitTier::Tier1,
            MarketplaceLimitTier::Tier2,
            MarketplaceLimitTier::Tier3,
        ] {
            let request = request(tier, false);
            assert_eq!(
                compute_marketplace_credit_limit_with_units(
                    &request,
                    &MARKETPLACE_TIER_LIMIT_UNITS
                ),
                compute_marketplace_credit_limit(&request)
            );
        }

        let governed = [
            MonetaryAmount {
                units: 20_000,
                currency: "USD".to_owned(),
            },
            MonetaryAmount {
                units: 60_000,
                currency: "USD".to_owned(),
            },
            MonetaryAmount {
                units: 300_000,
                currency: "USD".to_owned(),
            },
            MonetaryAmount {
                units: 2_000_000,
                currency: "USD".to_owned(),
            },
        ];
        let decision = compute_marketplace_credit_limit_with_amounts(
            &request(MarketplaceLimitTier::Tier3, false),
            &governed,
        );
        assert_eq!(decision.limit_units, 2_000_000);
    }
}
