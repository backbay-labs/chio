use creusot_std::prelude::*;

#[allow(dead_code)]
mod aeneas_body {
    use creusot_std::{
        prelude::*,
        std::{clone::Clone, cmp::PartialEq, default::Default},
    };

    include!("../../../../crates/kernel/chio-kernel-core/src/formal_aeneas.rs");
}

pub use aeneas_body::{BudgetCommitResult, ReservationLedger};

#[ensures(result == (issued_at@ <= now@ && now@ < expires_at@))]
pub fn time_window_valid_contract(now: u64, issued_at: u64, expires_at: u64) -> bool {
    aeneas_body::time_window_valid(now, issued_at, expires_at)
}

#[ensures(result == (
    invocation_cost@ <= remaining_invocations@ && unit_cost@ <= remaining_units@
))]
pub fn budget_precheck_contract(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    aeneas_body::budget_precheck(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    )
}

#[ensures(result.accepted == (
    invocation_cost@ <= remaining_invocations@ && unit_cost@ <= remaining_units@
))]
#[ensures(result.accepted ==>
    result.remaining_invocations@ == remaining_invocations@ - invocation_cost@)]
#[ensures(result.accepted ==>
    result.remaining_units@ == remaining_units@ - unit_cost@)]
#[ensures(!result.accepted ==>
    result.remaining_invocations@ == remaining_invocations@)]
#[ensures(!result.accepted ==>
    result.remaining_units@ == remaining_units@)]
pub fn budget_commit_contract(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> BudgetCommitResult {
    aeneas_body::budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    )
}

#[ensures(!result.1 ==> result.0 == state)]
#[ensures(result.1 && op@ == 0 ==>
    result.0.reserved@ + result.0.committed@ + result.0.released@ + result.0.retained@
        == state.reserved@ + state.committed@ + state.released@ + state.retained@ + amount@
)]
#[ensures(result.1 && op@ != 0 ==>
    result.0.reserved@ + result.0.committed@ + result.0.released@ + result.0.retained@
        == state.reserved@ + state.committed@ + state.released@ + state.retained@
)]
#[ensures(state.reserved@ == 0
    && (state.committed@ != 0 || state.released@ != 0 || state.retained@ != 0)
    ==> result.0 == state)]
pub fn ledger_apply_conservation_contract(
    state: ReservationLedger,
    op: u8,
    amount: u64,
) -> (ReservationLedger, bool) {
    aeneas_body::ledger_apply(state, op, amount)
}

#[ensures(result == (!parent_has_cap || (child_has_cap && child_value@ <= parent_value@)))]
pub fn optional_u32_cap_subset_contract(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    aeneas_body::optional_u32_cap_is_subset(
        child_has_cap,
        child_value,
        parent_has_cap,
        parent_value,
    )
}

#[ensures(result == (!parent_requires_true || child_requires_true))]
pub fn required_true_preserved_contract(
    parent_requires_true: bool,
    child_requires_true: bool,
) -> bool {
    aeneas_body::required_true_is_preserved(parent_requires_true, child_requires_true)
}

#[ensures(result == (!dpop_required || (proof_present && proof_valid && nonce_fresh)))]
pub fn dpop_admits_contract(
    dpop_required: bool,
    proof_present: bool,
    proof_valid: bool,
    nonce_fresh: bool,
) -> bool {
    aeneas_body::dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh)
}

#[ensures(result == (token_revoked || ancestor_revoked))]
pub fn revocation_snapshot_denies_contract(token_revoked: bool, ancestor_revoked: bool) -> bool {
    aeneas_body::revocation_snapshot_denies(token_revoked, ancestor_revoked)
}

#[ensures(result == (
    capability_matches
        && request_matches
        && verdict_matches
        && policy_hash_matches
        && evidence_class_matches
))]
pub fn receipt_fields_coupled_contract(
    capability_matches: bool,
    request_matches: bool,
    verdict_matches: bool,
    policy_hash_matches: bool,
    evidence_class_matches: bool,
) -> bool {
    aeneas_body::receipt_fields_coupled(
        capability_matches,
        request_matches,
        verdict_matches,
        policy_hash_matches,
        evidence_class_matches,
    )
}
