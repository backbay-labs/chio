#![allow(dead_code)]

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

pub fn classify_time_window_code(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at {
        1
    } else if now >= expires_at {
        2
    } else {
        0
    }
}

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

pub fn optional_u32_cap_is_subset(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    !parent_has_cap || (child_has_cap && child_value <= parent_value)
}

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

pub fn budget_precheck(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    invocation_cost <= remaining_invocations && unit_cost <= remaining_units
}

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

pub fn revocation_snapshot_denies(token_revoked: bool, ancestor_revoked: bool) -> bool {
    token_revoked || ancestor_revoked
}

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
