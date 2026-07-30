//! The predeclared slash and distribution arithmetic.
//!
//! Every number that moves a seller's collateral is computed here, in
//! checked integer arithmetic, from amounts the seller and venue signed
//! before any sale. Nothing in this module reads mutable state or accepts
//! a caller-chosen total: a misconfigured promise must reject rather than
//! quietly settle for less than it advertised.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use chio_core_types::capability::scope::MonetaryAmount;

/// One buyer's verified realized spend on the liable listing, keyed by
/// the authoritative purchase key so remainder order is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHarm {
    /// Authoritative purchase key from the settled purchase record.
    pub purchase_key: String,
    /// Immutable rail-tagged destination frozen at capture finalization.
    pub destination: String,
    /// Realized spend the purchase record attests, in the bond currency.
    pub realized_spend_units: u64,
}

/// One entry of the deterministic distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionEntry {
    pub destination: String,
    pub amount_units: u64,
}

/// The complete checked outcome: what is slashed, what reaches harmed
/// buyers, and what reaches the community fund.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashDistribution {
    pub slash: MonetaryAmount,
    pub buyer_pool_units: u64,
    pub community_fund_units: u64,
    /// Ordered by purchase key, then the community fund last.
    pub entries: Vec<DistributionEntry>,
}

/// Typed rejections. Every variant refuses to compute a distribution
/// rather than truncating one.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SlashAmountError {
    #[error("every amount must share one currency")]
    CurrencyMismatch,
    #[error("checked arithmetic overflowed")]
    Overflow,
    #[error("candidate amount exceeds the signed listing requirement")]
    CandidateAboveRequirement,
    #[error("the community fund destination must be distinct from every buyer destination")]
    CommunityFundCollision,
    #[error("distribution entries do not sum to the slash")]
    DistributionMismatch,
}

/// Inputs to the predeclared formula, each from a signed artifact.
pub struct SlashInputs<'a> {
    /// Seller precommitment from the admitted market terms.
    pub base_finding_stake: &'a MonetaryAmount,
    /// Sum of open per-sale encumbrances against the allocation.
    pub open_per_sale_encumbrances: u64,
    /// Live collateral the finalized bond snapshot observed.
    pub live_allocated_collateral: u64,
    /// The signed listing bond requirement, which caps the candidate.
    pub listing_required_amount: &'a MonetaryAmount,
    /// The community fund destination pinned by the venue admission.
    pub community_fund_destination: &'a str,
}

/// Compute the slash and its deterministic distribution.
///
/// `candidate = base_finding_stake + open_per_sale_encumbrances`, capped
/// by the signed listing requirement; `slash = min(live collateral,
/// candidate)`; `buyer_pool = min(slash, total verified realized spend)`;
/// the remainder goes only to the community fund. The buyer pool is
/// allocated pro rata by realized spend, with the remainder distributed
/// one unit at a time in purchase-key order so the result is identical on
/// every replay.
pub fn compute_slash_distribution(
    inputs: &SlashInputs<'_>,
    harms: &[VerifiedHarm],
) -> Result<SlashDistribution, SlashAmountError> {
    let currency = &inputs.base_finding_stake.currency;
    if &inputs.listing_required_amount.currency != currency {
        return Err(SlashAmountError::CurrencyMismatch);
    }
    if harms
        .iter()
        .any(|harm| harm.destination == inputs.community_fund_destination)
    {
        return Err(SlashAmountError::CommunityFundCollision);
    }

    let candidate = inputs
        .base_finding_stake
        .units
        .checked_add(inputs.open_per_sale_encumbrances)
        .ok_or(SlashAmountError::Overflow)?;
    if candidate > inputs.listing_required_amount.units {
        return Err(SlashAmountError::CandidateAboveRequirement);
    }
    let slash_units = candidate.min(inputs.live_allocated_collateral);

    let mut total_harm: u64 = 0;
    for harm in harms {
        total_harm = total_harm
            .checked_add(harm.realized_spend_units)
            .ok_or(SlashAmountError::Overflow)?;
    }
    let buyer_pool_units = slash_units.min(total_harm);
    let community_fund_units = slash_units
        .checked_sub(buyer_pool_units)
        .ok_or(SlashAmountError::Overflow)?;

    let mut ordered: Vec<&VerifiedHarm> = harms.iter().collect();
    ordered.sort_by(|left, right| left.purchase_key.cmp(&right.purchase_key));

    let mut entries = Vec::with_capacity(ordered.len().saturating_add(1));
    let mut allocated: u64 = 0;
    if buyer_pool_units > 0 && total_harm > 0 {
        for harm in &ordered {
            // Floor division first, so no buyer can be allocated more than
            // its pro rata share before the remainder pass runs.
            let share = u128::from(buyer_pool_units)
                .checked_mul(u128::from(harm.realized_spend_units))
                .ok_or(SlashAmountError::Overflow)?
                / u128::from(total_harm);
            let share = u64::try_from(share).map_err(|_| SlashAmountError::Overflow)?;
            allocated = allocated
                .checked_add(share)
                .ok_or(SlashAmountError::Overflow)?;
            entries.push(DistributionEntry {
                destination: harm.destination.clone(),
                amount_units: share,
            });
        }
        // Floor division leaves at most one unit per buyer unallocated.
        // Hand those out in purchase-key order so two evaluators reach the
        // same distribution byte for byte.
        let mut remainder = buyer_pool_units
            .checked_sub(allocated)
            .ok_or(SlashAmountError::Overflow)?;
        for entry in entries.iter_mut() {
            if remainder == 0 {
                break;
            }
            entry.amount_units = entry
                .amount_units
                .checked_add(1)
                .ok_or(SlashAmountError::Overflow)?;
            remainder -= 1;
        }
        entries.retain(|entry| entry.amount_units > 0);
    }
    if community_fund_units > 0 {
        entries.push(DistributionEntry {
            destination: inputs.community_fund_destination.to_owned(),
            amount_units: community_fund_units,
        });
    }

    let summed = entries
        .iter()
        .try_fold(0_u64, |total, entry| total.checked_add(entry.amount_units))
        .ok_or(SlashAmountError::Overflow)?;
    if summed != slash_units {
        return Err(SlashAmountError::DistributionMismatch);
    }

    Ok(SlashDistribution {
        slash: MonetaryAmount {
            units: slash_units,
            currency: currency.clone(),
        },
        buyer_pool_units,
        community_fund_units,
        entries,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn usd(units: u64) -> MonetaryAmount {
        MonetaryAmount {
            units,
            currency: "USD".to_owned(),
        }
    }

    fn harm(key: &str, destination: &str, units: u64) -> VerifiedHarm {
        VerifiedHarm {
            purchase_key: key.to_owned(),
            destination: destination.to_owned(),
            realized_spend_units: units,
        }
    }

    fn inputs<'a>(stake: &'a MonetaryAmount, required: &'a MonetaryAmount) -> SlashInputs<'a> {
        SlashInputs {
            base_finding_stake: stake,
            open_per_sale_encumbrances: 0,
            live_allocated_collateral: u64::MAX,
            listing_required_amount: required,
            community_fund_destination: "rail:community",
        }
    }

    #[test]
    fn the_distribution_always_sums_to_the_slash() {
        let stake = usd(50);
        let required = usd(5_000);
        let mut base = inputs(&stake, &required);
        base.open_per_sale_encumbrances = 700;
        // Three buyers whose pro rata shares do not divide evenly.
        let harms = [
            harm("key-c", "rail:c", 100),
            harm("key-a", "rail:a", 100),
            harm("key-b", "rail:b", 100),
        ];
        let distribution = compute_slash_distribution(&base, &harms).expect("distribution");
        assert_eq!(distribution.slash, usd(750));
        assert_eq!(distribution.buyer_pool_units, 300);
        assert_eq!(distribution.community_fund_units, 450);
        let summed: u64 = distribution
            .entries
            .iter()
            .map(|entry| entry.amount_units)
            .sum();
        assert_eq!(summed, 750);
    }

    #[test]
    fn the_remainder_order_is_deterministic_by_purchase_key() {
        let stake = usd(0);
        let required = usd(5_000);
        let mut base = inputs(&stake, &required);
        base.open_per_sale_encumbrances = 10;
        // 10 units across three equal claims: shares floor to 3 each, and
        // the single remaining unit must land on the lowest purchase key.
        let harms = [
            harm("key-c", "rail:c", 10),
            harm("key-a", "rail:a", 10),
            harm("key-b", "rail:b", 10),
        ];
        let first = compute_slash_distribution(&base, &harms).expect("distribution");
        let reordered = [
            harm("key-b", "rail:b", 10),
            harm("key-c", "rail:c", 10),
            harm("key-a", "rail:a", 10),
        ];
        let second = compute_slash_distribution(&base, &reordered).expect("distribution");
        assert_eq!(first, second, "input order must not change the outcome");
        let key_a = first
            .entries
            .iter()
            .find(|entry| entry.destination == "rail:a")
            .expect("key-a entry");
        assert_eq!(key_a.amount_units, 4, "the remainder unit goes to key-a");
    }

    #[test]
    fn the_buyer_pool_never_exceeds_verified_harm() {
        let stake = usd(900);
        let required = usd(5_000);
        let base = inputs(&stake, &required);
        let harms = [harm("key-a", "rail:a", 100)];
        let distribution = compute_slash_distribution(&base, &harms).expect("distribution");
        assert_eq!(distribution.buyer_pool_units, 100);
        assert_eq!(distribution.community_fund_units, 800);
    }

    #[test]
    fn a_zero_harm_slash_pays_only_the_community_fund() {
        let stake = usd(400);
        let required = usd(5_000);
        let base = inputs(&stake, &required);
        let distribution = compute_slash_distribution(&base, &[]).expect("distribution");
        assert_eq!(distribution.buyer_pool_units, 0);
        assert_eq!(distribution.community_fund_units, 400);
        assert_eq!(distribution.entries.len(), 1);
        assert_eq!(distribution.entries[0].destination, "rail:community");
    }

    #[test]
    fn live_collateral_caps_the_slash() {
        let stake = usd(900);
        let required = usd(5_000);
        let mut base = inputs(&stake, &required);
        base.live_allocated_collateral = 250;
        let harms = [harm("key-a", "rail:a", 900)];
        let distribution = compute_slash_distribution(&base, &harms).expect("distribution");
        assert_eq!(distribution.slash, usd(250));
        assert_eq!(distribution.buyer_pool_units, 250);
        assert_eq!(distribution.community_fund_units, 0);
    }

    #[test]
    fn a_candidate_above_the_signed_requirement_rejects_rather_than_clamping() {
        let stake = usd(5_000);
        let required = usd(4_999);
        let mut base = inputs(&stake, &required);
        base.open_per_sale_encumbrances = 1;
        assert_eq!(
            compute_slash_distribution(&base, &[]).unwrap_err(),
            SlashAmountError::CandidateAboveRequirement
        );
    }

    #[test]
    fn overflow_and_currency_and_collision_reject() {
        let stake = usd(u64::MAX);
        let required = usd(u64::MAX);
        let mut base = inputs(&stake, &required);
        base.open_per_sale_encumbrances = 1;
        assert_eq!(
            compute_slash_distribution(&base, &[]).unwrap_err(),
            SlashAmountError::Overflow
        );

        let stake = usd(10);
        let foreign = MonetaryAmount {
            units: 5_000,
            currency: "EUR".to_owned(),
        };
        let base = inputs(&stake, &foreign);
        assert_eq!(
            compute_slash_distribution(&base, &[]).unwrap_err(),
            SlashAmountError::CurrencyMismatch
        );

        let stake = usd(10);
        let required = usd(5_000);
        let base = inputs(&stake, &required);
        let harms = [harm("key-a", "rail:community", 10)];
        assert_eq!(
            compute_slash_distribution(&base, &harms).unwrap_err(),
            SlashAmountError::CommunityFundCollision
        );
    }
}
