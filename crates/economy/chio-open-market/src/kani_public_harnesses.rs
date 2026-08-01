//! Public Kani proof hooks for cognition-market challenge economics.
//!
//! # Scope
//!
//! The harness calls the production
//! [`crate::finding_slash_amount::compute_slash_allocation`] function used by
//! the destination-bearing slash allocator. It proves the M5
//! challenge-outcome envelope over three verified harmed buyers in the fixed
//! realized-harm ratio `1:2:3`, with symbolic full-range `u64` bond inputs:
//!
//! - candidate and harm accumulation overflow fail closed;
//! - a candidate above the signed listing requirement fails closed;
//! - a successful slash never exceeds live allocated collateral or the
//!   signed listing requirement;
//! - the buyer pool never exceeds verified realized harm;
//! - each buyer award is bounded by that slot's verified realized harm;
//! - only the three verified buyer slots can receive a buyer award;
//! - a sixteenth unbatched destination fails closed; and
//! - buyer awards plus the community-fund remainder sum exactly to the slash.
//!
//! # Bounds and assumptions
//!
//! The `1:2:3` bound makes the buyer pool symbolic over every value from zero
//! through six, exercising pro-rata floor division, deterministic remainder
//! assignment, and a community-fund remainder. A `0:2:3` witness checks that
//! zero-harm slots are omitted. Full-width concrete witnesses check harm
//! accumulation overflow and the sixteenth-destination rejection. Bond values
//! remain unconstrained `u64` values, so the symbolic proof includes zero,
//! `u64::MAX`, checked candidate overflow, live-collateral caps, and
//! signed-requirement cap failures. There are no `kani::assume` restrictions.
//! The production wrapper maps these ordered slots only to distinct, admitted
//! destinations reverified and aggregated from the M4 purchase index.
//! Signature, storage, ordering, destination aggregation, and
//! authoritative-index validity remain covered by the runtime challenge
//! enforcement tests.

use crate::finding_slash_amount::{
    compute_slash_allocation, SlashAmountError, MAX_UNBATCHED_BUYER_DESTINATIONS,
};

/// Prove the production challenge award is bond-capped and exact-sum.
///
/// This is not a model of the allocator. The harness invokes the production
/// arithmetic core, independently classifies every checked-arithmetic
/// rejection branch, and constrains every successful output by the M5 money
/// invariants.
#[kani::proof]
#[kani::unwind(17)]
pub fn public_challenge_outcome_envelope_is_bond_capped_and_exact_sum() {
    let over_destination_cap = [0_u64; MAX_UNBATCHED_BUYER_DESTINATIONS + 1];
    assert!(matches!(
        compute_slash_allocation(0, 0, 0, 0, &over_destination_cap),
        Err(SlashAmountError::TooManyBuyerDestinations)
    ));
    assert!(matches!(
        compute_slash_allocation(0, 0, 0, 0, &[u64::MAX, 1, 0]),
        Err(SlashAmountError::Overflow)
    ));
    assert!(matches!(
        compute_slash_allocation(4, 0, 4, 4, &[0, 2, 3]),
        Ok(allocation)
            if allocation.buyer_pool_units == 4
                && allocation.community_fund_units == 0
                && allocation.buyer_awards[0] == 0
                && allocation.buyer_awards[1] == 2
                && allocation.buyer_awards[2] == 2
    ));

    let base_units: u64 = kani::any();
    let open_encumbrance_units: u64 = kani::any();
    let live_collateral_units: u64 = kani::any();
    let required_units: u64 = kani::any();
    let harm_a = 1_u64;
    let harm_b = 2_u64;
    let harm_c = 3_u64;
    let harms = [harm_a, harm_b, harm_c];

    let result = compute_slash_allocation(
        base_units,
        open_encumbrance_units,
        live_collateral_units,
        required_units,
        &harms,
    );
    let Some(candidate) = base_units.checked_add(open_encumbrance_units) else {
        assert!(matches!(result, Err(SlashAmountError::Overflow)));
        return;
    };
    if candidate > required_units {
        assert!(matches!(
            result,
            Err(SlashAmountError::CandidateAboveRequirement)
        ));
        return;
    }
    let total_harm = harm_a + harm_b + harm_c;

    let allocation = match result {
        Ok(allocation) => allocation,
        Err(_) => {
            assert!(false);
            return;
        }
    };
    let expected_slash = candidate.min(live_collateral_units);
    let expected_buyer_pool = expected_slash.min(total_harm);
    let buyer_sum = u128::from(allocation.buyer_awards[0])
        + u128::from(allocation.buyer_awards[1])
        + u128::from(allocation.buyer_awards[2]);
    let unused_sum = u128::from(allocation.buyer_awards[3])
        + u128::from(allocation.buyer_awards[4])
        + u128::from(allocation.buyer_awards[5])
        + u128::from(allocation.buyer_awards[6])
        + u128::from(allocation.buyer_awards[7])
        + u128::from(allocation.buyer_awards[8])
        + u128::from(allocation.buyer_awards[9])
        + u128::from(allocation.buyer_awards[10])
        + u128::from(allocation.buyer_awards[11])
        + u128::from(allocation.buyer_awards[12])
        + u128::from(allocation.buyer_awards[13])
        + u128::from(allocation.buyer_awards[14]);
    assert!(
        allocation.slash_units == expected_slash
            && allocation.slash_units <= live_collateral_units
            && allocation.slash_units <= required_units
            && allocation.buyer_count == harms.len()
            && allocation.buyer_pool_units == expected_buyer_pool
            && allocation.buyer_pool_units <= allocation.slash_units
            && allocation.buyer_pool_units <= total_harm
            && allocation.buyer_awards[0] <= harm_a
            && allocation.buyer_awards[1] <= harm_b
            && allocation.buyer_awards[2] <= harm_c
            && allocation
                .buyer_pool_units
                .checked_add(allocation.community_fund_units)
                == Some(allocation.slash_units)
            && buyer_sum == u128::from(allocation.buyer_pool_units)
            && unused_sum == 0
            && buyer_sum + u128::from(allocation.community_fund_units)
                == u128::from(allocation.slash_units)
    );
}
