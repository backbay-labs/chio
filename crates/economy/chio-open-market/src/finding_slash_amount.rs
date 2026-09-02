//! The predeclared slash and distribution arithmetic.
//!
//! Every number that moves a seller's collateral is computed here, in
//! checked integer arithmetic, from amounts the seller and venue signed
//! before any sale. Nothing in this module reads mutable state or accepts
//! a caller-chosen total: a misconfigured promise must reject rather than
//! quietly settle for less than it advertised.

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

/// Maximum harmed-buyer destinations in the unbatched v1 settlement.
pub const MAX_UNBATCHED_BUYER_DESTINATIONS: usize = 15;

/// Checked numeric allocation before verified destinations are attached.
///
/// `buyer_awards[index]` belongs to the verified harm at the same index.
/// Slots at or above `buyer_count` are always zero. Keeping this arithmetic
/// projection fixed-size makes the money invariant independently verifiable
/// while [`compute_slash_distribution`] remains the destination-bearing API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashAllocation {
    pub slash_units: u64,
    pub buyer_pool_units: u64,
    pub community_fund_units: u64,
    pub buyer_count: usize,
    pub buyer_awards: [u64; MAX_UNBATCHED_BUYER_DESTINATIONS],
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
    #[error("verified harm purchase keys must be unique")]
    DuplicatePurchaseKey,
    #[error("verified harm destinations must be unique aggregates")]
    DuplicateBuyerDestination,
    #[error("unbatched v1 supports at most 15 harmed-buyer destinations")]
    TooManyBuyerDestinations,
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

fn validate_harm_identities(
    harms: &[VerifiedHarm],
    community_fund_destination: &str,
) -> Result<(), SlashAmountError> {
    if harms
        .iter()
        .any(|harm| harm.destination == community_fund_destination)
    {
        return Err(SlashAmountError::CommunityFundCollision);
    }
    for (index, harm) in harms.iter().enumerate() {
        for other in harms.iter().skip(index.saturating_add(1)) {
            if harm.purchase_key == other.purchase_key {
                return Err(SlashAmountError::DuplicatePurchaseKey);
            }
            if harm.destination == other.destination {
                return Err(SlashAmountError::DuplicateBuyerDestination);
            }
        }
    }
    Ok(())
}

/// Compute the checked numeric challenge award for verified ordered harms.
///
/// This is the production arithmetic core used by
/// [`compute_slash_distribution`]. The caller supplies one realized-spend
/// total per distinct, verified destination in deterministic purchase-key
/// order. The production coordinator establishes this contract by folding
/// authoritative purchase records by admitted destination. Candidate and harm
/// accumulation use checked arithmetic. A candidate above the signed
/// requirement rejects instead of being clamped, while live collateral caps
/// the successful slash.
pub fn compute_slash_allocation(
    base_finding_stake_units: u64,
    open_per_sale_encumbrances: u64,
    live_allocated_collateral: u64,
    listing_required_units: u64,
    ordered_realized_spend_units: &[u64],
) -> Result<SlashAllocation, SlashAmountError> {
    if ordered_realized_spend_units.len() > MAX_UNBATCHED_BUYER_DESTINATIONS {
        return Err(SlashAmountError::TooManyBuyerDestinations);
    }

    let candidate = base_finding_stake_units
        .checked_add(open_per_sale_encumbrances)
        .ok_or(SlashAmountError::Overflow)?;
    if candidate > listing_required_units {
        return Err(SlashAmountError::CandidateAboveRequirement);
    }
    let slash_units = candidate.min(live_allocated_collateral);

    let mut total_harm = 0_u64;
    for harm_units in ordered_realized_spend_units {
        total_harm = total_harm
            .checked_add(*harm_units)
            .ok_or(SlashAmountError::Overflow)?;
    }
    let buyer_pool_units = slash_units.min(total_harm);
    let community_fund_units = slash_units
        .checked_sub(buyer_pool_units)
        .ok_or(SlashAmountError::Overflow)?;

    let mut buyer_awards = [0_u64; MAX_UNBATCHED_BUYER_DESTINATIONS];
    let mut allocated = 0_u64;
    if buyer_pool_units > 0 && total_harm > 0 {
        for (index, harm_units) in ordered_realized_spend_units.iter().enumerate() {
            if *harm_units == 0 {
                continue;
            }
            let share = u128::from(buyer_pool_units)
                .checked_mul(u128::from(*harm_units))
                .ok_or(SlashAmountError::Overflow)?
                / u128::from(total_harm);
            let share = u64::try_from(share).map_err(|_| SlashAmountError::Overflow)?;
            buyer_awards[index] = share;
            allocated = allocated
                .checked_add(share)
                .ok_or(SlashAmountError::Overflow)?;
        }

        // The sum of floor-divided shares leaves fewer units than there are
        // nonzero harms. Award at most one remainder unit per harmed buyer in
        // the caller's deterministic purchase-key order.
        let mut remainder = buyer_pool_units
            .checked_sub(allocated)
            .ok_or(SlashAmountError::Overflow)?;
        for (index, harm_units) in ordered_realized_spend_units.iter().enumerate() {
            if remainder == 0 {
                break;
            }
            if *harm_units == 0 {
                continue;
            }
            buyer_awards[index] = buyer_awards[index]
                .checked_add(1)
                .ok_or(SlashAmountError::Overflow)?;
            remainder -= 1;
        }
        if remainder != 0 {
            return Err(SlashAmountError::DistributionMismatch);
        }
    }

    let summed_buyer_awards = buyer_awards[..ordered_realized_spend_units.len()]
        .iter()
        .try_fold(0_u64, |sum, award| sum.checked_add(*award))
        .ok_or(SlashAmountError::Overflow)?;
    if summed_buyer_awards != buyer_pool_units {
        return Err(SlashAmountError::DistributionMismatch);
    }
    if buyer_pool_units
        .checked_add(community_fund_units)
        .ok_or(SlashAmountError::Overflow)?
        != slash_units
    {
        return Err(SlashAmountError::DistributionMismatch);
    }

    Ok(SlashAllocation {
        slash_units,
        buyer_pool_units,
        community_fund_units,
        buyer_count: ordered_realized_spend_units.len(),
        buyer_awards,
    })
}

/// Compute the slash and its deterministic distribution.
///
/// `candidate = base_finding_stake + open_per_sale_encumbrances`, capped
/// by the signed listing requirement; `slash = min(live collateral,
/// candidate)`; `buyer_pool = min(slash, total verified realized spend)`;
/// the remainder goes only to the community fund. The buyer pool is
/// allocated pro rata by realized spend, with the remainder distributed
/// one unit at a time in purchase-key order so the result is identical on
/// every replay. `harms` must contain one aggregate entry per distinct,
/// authoritatively verified destination; the production challenge coordinator
/// folds admitted purchase records into that shape before calling this API.
pub fn compute_slash_distribution(
    inputs: &SlashInputs<'_>,
    harms: &[VerifiedHarm],
) -> Result<SlashDistribution, SlashAmountError> {
    let currency = &inputs.base_finding_stake.currency;
    if &inputs.listing_required_amount.currency != currency {
        return Err(SlashAmountError::CurrencyMismatch);
    }
    validate_harm_identities(harms, inputs.community_fund_destination)?;

    let mut ordered: Vec<&VerifiedHarm> = harms.iter().collect();
    ordered.sort_by(|left, right| left.purchase_key.cmp(&right.purchase_key));
    let ordered_harms: Vec<u64> = ordered
        .iter()
        .map(|harm| harm.realized_spend_units)
        .collect();
    let allocation = compute_slash_allocation(
        inputs.base_finding_stake.units,
        inputs.open_per_sale_encumbrances,
        inputs.live_allocated_collateral,
        inputs.listing_required_amount.units,
        &ordered_harms,
    )?;

    let mut entries = Vec::with_capacity(ordered.len().saturating_add(1));
    for (harm, share) in ordered.iter().zip(allocation.buyer_awards.iter()) {
        if *share > 0 {
            entries.push(DistributionEntry {
                destination: harm.destination.clone(),
                amount_units: *share,
            });
        }
    }
    if allocation.community_fund_units > 0 {
        entries.push(DistributionEntry {
            destination: inputs.community_fund_destination.to_owned(),
            amount_units: allocation.community_fund_units,
        });
    }

    let summed = entries
        .iter()
        .try_fold(0_u64, |total, entry| total.checked_add(entry.amount_units))
        .ok_or(SlashAmountError::Overflow)?;
    if summed != allocation.slash_units {
        return Err(SlashAmountError::DistributionMismatch);
    }

    Ok(SlashDistribution {
        slash: MonetaryAmount {
            units: allocation.slash_units,
            currency: currency.clone(),
        },
        buyer_pool_units: allocation.buyer_pool_units,
        community_fund_units: allocation.community_fund_units,
        entries,
    })
}

/// Distribute an evaluator-signed slash amount without re-reading the
/// mutable exposure that originally sized it.
///
/// The coordinator calls this only after the outcome was recorded in the
/// same transaction that fenced exposure and blocked new sales. Existing
/// reservations may settle or expire while claims are collected, but
/// those later category changes cannot rewrite the terminal signed amount.
pub fn compute_frozen_slash_distribution(
    slash: &MonetaryAmount,
    community_fund_destination: &str,
    harms: &[VerifiedHarm],
) -> Result<SlashDistribution, SlashAmountError> {
    validate_harm_identities(harms, community_fund_destination)?;
    let mut ordered: Vec<&VerifiedHarm> = harms.iter().collect();
    ordered.sort_by(|left, right| left.purchase_key.cmp(&right.purchase_key));
    let ordered_harms: Vec<u64> = ordered
        .iter()
        .map(|harm| harm.realized_spend_units)
        .collect();
    let allocation =
        compute_slash_allocation(slash.units, 0, slash.units, slash.units, &ordered_harms)?;

    let mut entries = Vec::with_capacity(ordered.len().saturating_add(1));
    for (harm, share) in ordered.iter().zip(allocation.buyer_awards.iter()) {
        if *share > 0 {
            entries.push(DistributionEntry {
                destination: harm.destination.clone(),
                amount_units: *share,
            });
        }
    }
    if allocation.community_fund_units > 0 {
        entries.push(DistributionEntry {
            destination: community_fund_destination.to_owned(),
            amount_units: allocation.community_fund_units,
        });
    }
    let summed = entries
        .iter()
        .try_fold(0_u64, |total, entry| total.checked_add(entry.amount_units))
        .ok_or(SlashAmountError::Overflow)?;
    if summed != slash.units {
        return Err(SlashAmountError::DistributionMismatch);
    }
    Ok(SlashDistribution {
        slash: slash.clone(),
        buyer_pool_units: allocation.buyer_pool_units,
        community_fund_units: allocation.community_fund_units,
        entries,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const COMMUNITY_FUND_DESTINATION: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

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

    #[test]
    fn frozen_slash_distribution_does_not_depend_on_later_exposure_categories() {
        let harms = vec![
            harm("purchase-a", "buyer-a", 60),
            harm("purchase-b", "buyer-b", 40),
        ];
        let first = compute_frozen_slash_distribution(&usd(300), "community", &harms)
            .expect("frozen distribution");
        let replay = compute_frozen_slash_distribution(&usd(300), "community", &harms)
            .expect("replayed frozen distribution");
        assert_eq!(first, replay);
        assert_eq!(first.slash, usd(300));
        assert_eq!(first.buyer_pool_units, 100);
        assert_eq!(first.community_fund_units, 200);
    }

    fn inputs<'a>(stake: &'a MonetaryAmount, required: &'a MonetaryAmount) -> SlashInputs<'a> {
        SlashInputs {
            base_finding_stake: stake,
            open_per_sale_encumbrances: 0,
            live_allocated_collateral: u64::MAX,
            listing_required_amount: required,
            community_fund_destination: COMMUNITY_FUND_DESTINATION,
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
    fn a_buyer_without_verified_spend_is_never_paid() {
        let stake = usd(0);
        let required = usd(10_000);
        let mut base = inputs(&stake, &required);
        base.open_per_sale_encumbrances = 15;
        // The zero-spend record sorts first, so it is exactly the entry the
        // remainder pass would reach before any harmed buyer.
        let harms = [
            harm("key-a", "rail:a", 0),
            harm("key-b", "rail:b", 10),
            harm("key-c", "rail:c", 10),
        ];
        let distribution = compute_slash_distribution(&base, &harms).expect("distribution");
        assert!(
            !distribution
                .entries
                .iter()
                .any(|entry| entry.destination == "rail:a"),
            "a record with no realized spend must not appear in the distribution"
        );
        let paid: u64 = distribution
            .entries
            .iter()
            .filter(|entry| entry.destination != COMMUNITY_FUND_DESTINATION)
            .map(|entry| entry.amount_units)
            .sum();
        assert_eq!(paid, distribution.buyer_pool_units);
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
        assert_eq!(
            distribution.entries[0].destination,
            COMMUNITY_FUND_DESTINATION
        );
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
    fn unbatched_allocation_enforces_the_fifteen_destination_cap() {
        let at_cap = compute_slash_allocation(15, 0, 15, 15, &[1; 15])
            .expect("fifteen destinations remain unbatched");
        assert_eq!(at_cap.buyer_count, 15);
        assert_eq!(at_cap.buyer_pool_units, 15);
        assert_eq!(at_cap.buyer_awards, [1; 15]);
        assert_eq!(
            compute_slash_allocation(1, 0, 1, 1, &[1; 16]).unwrap_err(),
            SlashAmountError::TooManyBuyerDestinations
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
        let harms = [harm("key-a", COMMUNITY_FUND_DESTINATION, 10)];
        assert_eq!(
            compute_slash_distribution(&base, &harms).unwrap_err(),
            SlashAmountError::CommunityFundCollision
        );
    }

    #[test]
    fn duplicate_purchase_and_destination_identities_reject() {
        let stake = usd(10);
        let required = usd(5_000);
        let base = inputs(&stake, &required);
        let duplicate_purchase = [harm("key-a", "rail:a", 4), harm("key-a", "rail:b", 6)];
        let duplicate_destination = [harm("key-a", "rail:a", 4), harm("key-b", "rail:a", 6)];

        assert_eq!(
            compute_slash_distribution(&base, &duplicate_purchase).unwrap_err(),
            SlashAmountError::DuplicatePurchaseKey
        );
        assert_eq!(
            compute_frozen_slash_distribution(&usd(10), "community", &duplicate_purchase)
                .unwrap_err(),
            SlashAmountError::DuplicatePurchaseKey
        );
        assert_eq!(
            compute_slash_distribution(&base, &duplicate_destination).unwrap_err(),
            SlashAmountError::DuplicateBuyerDestination
        );
        assert_eq!(
            compute_frozen_slash_distribution(&usd(10), "community", &duplicate_destination)
                .unwrap_err(),
            SlashAmountError::DuplicateBuyerDestination
        );
    }
}
