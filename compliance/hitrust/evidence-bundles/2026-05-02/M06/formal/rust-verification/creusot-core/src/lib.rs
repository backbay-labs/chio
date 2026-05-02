use creusot_std::prelude::*;

#[ensures(result == (issued_at@ <= now@ && now@ < expires_at@))]
pub fn time_window_valid_contract(now: u64, issued_at: u64, expires_at: u64) -> bool {
    issued_at <= now && now < expires_at
}

#[requires(cost@ <= remaining@)]
#[ensures(result@ == remaining@ - cost@)]
#[ensures(result@ <= remaining@)]
pub fn budget_commit_remaining_contract(remaining: u64, cost: u64) -> u64 {
    remaining - cost
}

#[ensures(result == (!parent_has_cap || (child_has_cap && child_value@ <= parent_value@)))]
pub fn optional_u32_cap_subset_contract(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    !parent_has_cap || (child_has_cap && child_value <= parent_value)
}

#[ensures(result == (!parent_requires_true || child_requires_true))]
pub fn required_true_preserved_contract(
    parent_requires_true: bool,
    child_requires_true: bool,
) -> bool {
    !parent_requires_true || child_requires_true
}

#[ensures(result == (!dpop_required || (proof_present && proof_valid && nonce_fresh)))]
pub fn dpop_admits_contract(
    dpop_required: bool,
    proof_present: bool,
    proof_valid: bool,
    nonce_fresh: bool,
) -> bool {
    !dpop_required || (proof_present && proof_valid && nonce_fresh)
}

#[ensures(result == (token_revoked || ancestor_revoked))]
pub fn revocation_snapshot_denies_contract(token_revoked: bool, ancestor_revoked: bool) -> bool {
    token_revoked || ancestor_revoked
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
    capability_matches
        && request_matches
        && verdict_matches
        && policy_hash_matches
        && evidence_class_matches
}
