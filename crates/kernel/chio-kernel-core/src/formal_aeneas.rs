// Aeneas production source for the pure, extraction-safe decision core.
//
// The runtime-facing `formal_core` module calls these helpers. Inputs that
// depend on strings, vectors, or runtime structs are projected to booleans or
// bounded integers before crossing this boundary.

pub struct BudgetCommitResult {
    pub accepted: bool,
    pub remaining_invocations: u64,
    pub remaining_units: u64,
}

#[cfg_attr(chio_creusot_contracts, derive(DeepModel))]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(any(test, kani), derive(Debug))]
pub struct ReservationLedger {
    /// Exposure not yet assigned a terminal amount bucket.
    pub reserved: u64,
    /// Realized spend.
    pub committed: u64,
    /// Reversed exposure plus unused reconciliation remainder.
    pub released: u64,
    /// Deliberately non-unwound exposure.
    pub retained: u64,
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (
        state.reserved@ == 0
            && (state.committed@ != 0 || state.released@ != 0 || state.retained@ != 0)
    ))
)]
pub(crate) fn ledger_is_terminal(state: ReservationLedger) -> bool {
    state.reserved == 0 && (state.committed != 0 || state.released != 0 || state.retained != 0)
}

/// Apply one reservation transition.
///
/// Reservation law (normative text in `chio-kernel/src/budget_store.rs`):
/// 1. Partition: reserved amount equals committed plus released plus retained
///    plus outstanding at every reachable state, and outstanding is nonnegative.
/// 2. Terminal uniqueness: a terminal admission has no outstanding amount and
///    exactly one terminal classification.
/// 3. Child splits: admitted sibling shares never exceed the parent share, and
///    every child independently obeys clauses 1 and 2.
///
/// The bounded lifecycle model, scalar transition, journal replay, and
/// stateful store sequence tests independently enforce this partition.
/// Agreement across those surfaces is required because none observes every
/// production side effect.
///
/// Operations are 0 = reserve, 1 = commit, 2 = release, and 3 = retain.
/// Unknown operations, over-disposition, reserve-after-terminal, and arithmetic
/// overflow return the exact input state with `false`. Commit and release
/// amounts may both be nonzero after a reconcile that realizes less than its
/// exposure; the absorbing terminal state supplies the single disposition.
#[cfg_attr(
    chio_creusot_contracts,
    ensures(!result.1 ==> result.0 == state)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(result.1 && op@ == 0 ==>
        result.0.reserved@ + result.0.committed@ + result.0.released@ + result.0.retained@
            == state.reserved@ + state.committed@ + state.released@ + state.retained@ + amount@
    )
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(result.1 && op@ != 0 ==>
        result.0.reserved@ + result.0.committed@ + result.0.released@ + result.0.retained@
            == state.reserved@ + state.committed@ + state.released@ + state.retained@
    )
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(state.reserved@ == 0
        && (state.committed@ != 0 || state.released@ != 0 || state.retained@ != 0)
        ==> result.0 == state
    )
)]
// Explicit matches keep checked-add semantics transparent to Aeneas.
#[allow(clippy::manual_map)]
pub fn ledger_apply(state: ReservationLedger, op: u8, amount: u64) -> (ReservationLedger, bool) {
    let Some(total) = state.reserved.checked_add(state.committed) else {
        return (state, false);
    };
    let Some(total) = total.checked_add(state.released) else {
        return (state, false);
    };
    let Some(total) = total.checked_add(state.retained) else {
        return (state, false);
    };

    if op > 3 || (op == 0 && ledger_is_terminal(state)) {
        return (state, false);
    }

    if op == 0 {
        if total.checked_add(amount).is_none() {
            return (state, false);
        }
        return match state.reserved.checked_add(amount) {
            Some(reserved) => (ReservationLedger { reserved, ..state }, true),
            None => (state, false),
        };
    }

    if amount > state.reserved {
        return (state, false);
    }

    let outstanding = state.reserved - amount;
    let updated = match op {
        1 => match state.committed.checked_add(amount) {
            Some(committed) => Some(ReservationLedger {
                reserved: outstanding,
                committed,
                ..state
            }),
            None => None,
        },
        2 => match state.released.checked_add(amount) {
            Some(released) => Some(ReservationLedger {
                reserved: outstanding,
                released,
                ..state
            }),
            None => None,
        },
        3 => match state.retained.checked_add(amount) {
            Some(retained) => Some(ReservationLedger {
                reserved: outstanding,
                retained,
                ..state
            }),
            None => None,
        },
        _ => None,
    };

    match updated {
        Some(next) => (next, true),
        None => (state, false),
    }
}

pub struct InclusionStep {
    pub consume_sibling: bool,
    pub sibling_on_left: bool,
    pub next_index: u64,
    pub next_size: u64,
}

#[allow(clippy::manual_is_multiple_of, clippy::needless_bool)] // Aeneas scalar subset.
pub fn inclusion_step(index: u64, size: u64) -> InclusionStep {
    let sibling_on_left = index % 2 != 0;
    let right_sibling_exists = match index.checked_add(1) {
        Some(sibling) => {
            if sibling < size {
                true
            } else {
                false
            }
        }
        None => false,
    };
    InclusionStep {
        consume_sibling: sibling_on_left || right_sibling_exists,
        sibling_on_left,
        next_index: index / 2,
        next_size: size / 2 + size % 2,
    }
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(now@ < issued_at@ ==> result == 1u8)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(issued_at@ <= now@ && expires_at@ <= now@ ==> result == 2u8)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(issued_at@ <= now@ && now@ < expires_at@ ==> result == 0u8)
)]
pub fn classify_time_window_code(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at {
        1
    } else if now >= expires_at {
        2
    } else {
        0
    }
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (issued_at@ <= now@ && now@ < expires_at@))
)]
pub fn time_window_valid(now: u64, issued_at: u64, expires_at: u64) -> bool {
    classify_time_window_code(now, issued_at, expires_at) == 0
}

pub fn exact_or_wildcard_covers_by_flags(
    parent_is_wildcard: bool,
    parent_equals_child: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child
}

pub fn prefix_wildcard_or_exact_covers_by_flags(
    parent_is_wildcard: bool,
    parent_has_prefix_wildcard: bool,
    prefix_matches: bool,
    exact_matches: bool,
) -> bool {
    parent_is_wildcard || (parent_has_prefix_wildcard && prefix_matches) || exact_matches
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (!parent_has_cap || (child_has_cap && child_value@ <= parent_value@)))
)]
pub fn optional_u32_cap_is_subset(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    !parent_has_cap || (child_has_cap && child_value <= parent_value)
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (!parent_requires_true || child_requires_true))
)]
pub fn required_true_is_preserved(parent_requires_true: bool, child_requires_true: bool) -> bool {
    !parent_requires_true || child_requires_true
}

pub fn monetary_cap_is_subset_by_parts(
    child_has_cap: bool,
    child_units: u64,
    parent_has_cap: bool,
    parent_units: u64,
    currency_matches: bool,
) -> bool {
    !parent_has_cap || (child_has_cap && currency_matches && child_units <= parent_units)
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (
        invocation_cost@ <= remaining_invocations@ && unit_cost@ <= remaining_units@
    ))
)]
pub fn budget_precheck(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    invocation_cost <= remaining_invocations && unit_cost <= remaining_units
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result.accepted == (
        invocation_cost@ <= remaining_invocations@ && unit_cost@ <= remaining_units@
    ))
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(result.accepted ==>
        result.remaining_invocations@ == remaining_invocations@ - invocation_cost@)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(result.accepted ==>
        result.remaining_units@ == remaining_units@ - unit_cost@)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(!result.accepted ==>
        result.remaining_invocations@ == remaining_invocations@)
)]
#[cfg_attr(
    chio_creusot_contracts,
    ensures(!result.accepted ==>
        result.remaining_units@ == remaining_units@)
)]
pub fn budget_commit(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> BudgetCommitResult {
    if budget_precheck(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    ) {
        BudgetCommitResult {
            accepted: true,
            remaining_invocations: remaining_invocations - invocation_cost,
            remaining_units: remaining_units - unit_cost,
        }
    } else {
        BudgetCommitResult {
            accepted: false,
            remaining_invocations,
            remaining_units,
        }
    }
}

pub fn dpop_freshness_valid(now: u64, issued_at: u64, ttl_secs: u64, max_skew_secs: u64) -> bool {
    issued_at <= now.saturating_add(max_skew_secs) && issued_at.saturating_add(ttl_secs) >= now
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (!dpop_required || (proof_present && proof_valid && nonce_fresh)))
)]
pub fn dpop_admits(
    dpop_required: bool,
    proof_present: bool,
    proof_valid: bool,
    nonce_fresh: bool,
) -> bool {
    !dpop_required || (proof_present && proof_valid && nonce_fresh)
}

pub fn nonce_admits(already_live: bool) -> bool {
    !already_live
}

pub fn guard_step_allows(core_authorized: bool, guard_allows: bool) -> bool {
    core_authorized && guard_allows
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (token_revoked || ancestor_revoked))
)]
pub fn revocation_snapshot_denies(token_revoked: bool, ancestor_revoked: bool) -> bool {
    token_revoked || ancestor_revoked
}

#[cfg_attr(
    chio_creusot_contracts,
    ensures(result == (
        capability_matches
            && request_matches
            && verdict_matches
            && policy_hash_matches
            && evidence_class_matches
    ))
)]
pub fn receipt_fields_coupled(
    capability_matches: bool,
    request_matches: bool,
    verdict_matches: bool,
    policy_hash_matches: bool,
    evidence_class_matches: bool,
) -> bool {
    capability_matches
        && request_matches
        && verdict_matches
        && policy_hash_matches
        && evidence_class_matches
}

#[cfg(test)]
mod reservation_ledger_tests {
    use super::*;

    #[test]
    fn partial_realization_can_release_remainder_under_one_terminal_state() {
        let (reserved, valid) = ledger_apply(ReservationLedger::default(), 0, 8);
        assert!(valid);
        let (released, valid) = ledger_apply(reserved, 2, 3);
        assert!(valid);
        let (terminal, valid) = ledger_apply(released, 1, 5);
        assert!(valid);
        assert_eq!(
            terminal,
            ReservationLedger {
                reserved: 0,
                committed: 5,
                released: 3,
                retained: 0,
            }
        );
        assert_eq!(ledger_apply(terminal, 0, 1), (terminal, false));
    }

    #[test]
    fn overflow_and_over_disposition_are_exact_no_ops() {
        let boundary = ReservationLedger {
            reserved: u64::MAX,
            ..ReservationLedger::default()
        };
        assert_eq!(ledger_apply(boundary, 0, 1), (boundary, false));

        let reserved = ReservationLedger {
            reserved: 4,
            ..ReservationLedger::default()
        };
        assert_eq!(ledger_apply(reserved, 3, 5), (reserved, false));
    }

    #[test]
    fn aggregate_overflow_with_individually_valid_buckets_is_an_exact_no_op() {
        let (full, valid) = ledger_apply(ReservationLedger::default(), 0, u64::MAX);
        assert!(valid);
        let (mixed, valid) = ledger_apply(full, 1, u64::MAX - 1);
        assert!(valid);
        assert_eq!(mixed.reserved, 1);
        assert_eq!(mixed.committed, u64::MAX - 1);
        assert_eq!(ledger_apply(mixed, 0, 1), (mixed, false));

        let invalid_input = ReservationLedger {
            reserved: 1,
            committed: u64::MAX,
            released: 0,
            retained: 0,
        };
        assert_eq!(ledger_apply(invalid_input, 2, 1), (invalid_input, false));
    }
}
