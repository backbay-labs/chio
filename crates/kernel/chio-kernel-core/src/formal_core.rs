//! Pure helpers shared by runtime code and formal verification lanes.
//!
//! This module deliberately avoids heap allocation, IO, crypto, async, and
//! external crates so Kani, Creusot wrappers, and Aeneas can reason about the
//! same branch logic used by the portable kernel core.

#![allow(dead_code)]

use crate::formal_aeneas;

/// Time-window classification for capability validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeWindowStatus {
    /// `issued_at <= now < expires_at`.
    Valid,
    /// `now < issued_at`.
    NotYetValid,
    /// `now >= expires_at`.
    Expired,
}

/// Classify a capability time window at `now`.
#[must_use]
pub fn classify_time_window(now: u64, issued_at: u64, expires_at: u64) -> TimeWindowStatus {
    match formal_aeneas::classify_time_window_code(now, issued_at, expires_at) {
        0 => TimeWindowStatus::Valid,
        1 => TimeWindowStatus::NotYetValid,
        _ => TimeWindowStatus::Expired,
    }
}

/// Predicate form of [`classify_time_window`].
#[must_use]
pub fn time_window_valid(now: u64, issued_at: u64, expires_at: u64) -> bool {
    matches!(
        classify_time_window(now, issued_at, expires_at),
        TimeWindowStatus::Valid
    )
}

/// Exact match with `*` parent wildcard.
#[must_use]
pub fn exact_or_wildcard_covers(parent: &str, child: &str) -> bool {
    formal_aeneas::exact_or_wildcard_covers_by_flags(parent == "*", parent == child)
}

/// Exact match, `*`, or parent suffix wildcard (`prefix*`) coverage.
#[must_use]
pub fn prefix_wildcard_or_exact_covers(parent: &str, child: &str) -> bool {
    let parent_is_wildcard = parent == "*";
    let parent_prefix = parent.strip_suffix('*');
    let parent_has_prefix_wildcard = parent_prefix.is_some();
    let prefix_matches = parent_prefix.is_some_and(|prefix| child.starts_with(prefix));
    formal_aeneas::prefix_wildcard_or_exact_covers_by_flags(
        parent_is_wildcard,
        parent_has_prefix_wildcard,
        prefix_matches,
        parent == child,
    )
}

/// Optional u32 cap subset predicate.
///
/// If the parent has no cap, every child cap state is a subset. If the parent
/// has a cap, the child must also have one and it must be no larger.
#[must_use]
pub fn optional_u32_cap_is_subset(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    formal_aeneas::optional_u32_cap_is_subset(
        child_has_cap,
        child_value,
        parent_has_cap,
        parent_value,
    )
}

/// Required-true preservation for boolean constraints such as DPoP.
#[must_use]
pub fn required_true_is_preserved(parent_requires_true: bool, child_requires_true: bool) -> bool {
    formal_aeneas::required_true_is_preserved(parent_requires_true, child_requires_true)
}

/// Optional monetary cap subset predicate with currency equality projected by
/// the caller.
#[must_use]
pub fn monetary_cap_is_subset_by_parts(
    child_has_cap: bool,
    child_units: u64,
    parent_has_cap: bool,
    parent_units: u64,
    currency_matches: bool,
) -> bool {
    formal_aeneas::monetary_cap_is_subset_by_parts(
        child_has_cap,
        child_units,
        parent_has_cap,
        parent_units,
        currency_matches,
    )
}

/// Bounded budget precheck used by the Lean model, Kani harnesses, and
/// Creusot wrapper contracts.
#[must_use]
pub fn budget_precheck(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    formal_aeneas::budget_precheck(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    )
}

/// Result of a pure budget commit model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetCommitResult {
    pub accepted: bool,
    pub remaining_invocations: u64,
    pub remaining_units: u64,
}

/// Commit against the bounded budget model.
#[must_use]
pub fn budget_commit(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> BudgetCommitResult {
    let committed = formal_aeneas::budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    );
    BudgetCommitResult {
        accepted: committed.accepted,
        remaining_invocations: committed.remaining_invocations,
        remaining_units: committed.remaining_units,
    }
}

/// DPoP freshness window check with saturating arithmetic.
#[must_use]
pub fn dpop_freshness_valid(now: u64, issued_at: u64, ttl_secs: u64, max_skew_secs: u64) -> bool {
    formal_aeneas::dpop_freshness_valid(now, issued_at, ttl_secs, max_skew_secs)
}

/// DPoP admission model for grant-required proof checks.
#[must_use]
pub fn dpop_admits(
    dpop_required: bool,
    proof_present: bool,
    proof_valid: bool,
    nonce_fresh: bool,
) -> bool {
    formal_aeneas::dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh)
}

/// Nonce model: an already-live nonce must not be accepted again.
#[must_use]
pub fn nonce_admits(already_live: bool) -> bool {
    formal_aeneas::nonce_admits(already_live)
}

/// Guard outcome used by the pure guard-composition model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardStep {
    Allow,
    Deny,
    Error,
}

/// Guard pipeline model. Core authorization must pass, and every guard must
/// return allow. Deny and error are both fail-closed.
#[must_use]
pub fn guard_pipeline_allows(core_authorized: bool, guards: &[GuardStep]) -> bool {
    guards.iter().fold(core_authorized, |allowed, guard| {
        formal_aeneas::guard_step_allows(allowed, matches!(guard, GuardStep::Allow))
    })
}

/// Revocation projection model for the presented token and its ancestors.
#[must_use]
pub fn revocation_snapshot_denies(token_revoked: bool, ancestor_revoked: bool) -> bool {
    formal_aeneas::revocation_snapshot_denies(token_revoked, ancestor_revoked)
}

/// Receipt coupling model for the fields that make a decision auditable.
#[must_use]
pub fn receipt_fields_coupled(
    capability_matches: bool,
    request_matches: bool,
    verdict_matches: bool,
    policy_hash_matches: bool,
    evidence_class_matches: bool,
) -> bool {
    formal_aeneas::receipt_fields_coupled(
        capability_matches,
        request_matches,
        verdict_matches,
        policy_hash_matches,
        evidence_class_matches,
    )
}

/// Result of a bounded three-key composite quota authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositeQuotaResult {
    pub accepted: bool,
    pub captured: [u8; 3],
}

/// Authorize one invocation against every applicable quota or none.
#[must_use]
pub fn composite_quota_authorize(
    captured: [u8; 3],
    maximum: [u8; 3],
    applicable: [bool; 3],
) -> CompositeQuotaResult {
    let mut next = captured;
    for index in 0..3 {
        if !applicable[index] {
            continue;
        }
        let Some(value) = captured[index].checked_add(1) else {
            return CompositeQuotaResult {
                accepted: false,
                captured,
            };
        };
        if value > maximum[index] {
            return CompositeQuotaResult {
                accepted: false,
                captured,
            };
        }
        next[index] = value;
    }
    CompositeQuotaResult {
        accepted: true,
        captured: next,
    }
}

/// Existing quota keys preserve the maximum established on first use.
#[must_use]
pub const fn quota_maximum_compatible(
    initialized: bool,
    existing_maximum: u8,
    presented_maximum: u8,
) -> bool {
    !initialized || existing_maximum == presented_maximum
}

/// Projection of the signed family-binding preservation predicate.
#[must_use]
pub const fn family_binding_preserved(
    fields_match: [bool; 8],
    root_maximum: u8,
    descendant_maximum: u8,
) -> bool {
    fields_match[0]
        && fields_match[1]
        && fields_match[2]
        && fields_match[3]
        && fields_match[4]
        && fields_match[5]
        && fields_match[6]
        && fields_match[7]
        && root_maximum == descendant_maximum
}

/// Count distinct eligible signer IDs in a bounded three-token approval set.
#[must_use]
pub fn threshold_distinct_eligible_signers(
    signer_ids: [u8; 3],
    present: [bool; 3],
    eligible: [bool; 3],
) -> u8 {
    let mut seen = [false; 3];
    let mut count = 0_u8;
    for index in 0..3 {
        if !present[index] {
            continue;
        }
        let signer = usize::from(signer_ids[index]);
        if signer >= eligible.len() || !eligible[signer] || seen[signer] {
            continue;
        }
        seen[signer] = true;
        count += 1;
    }
    count
}

#[cfg(test)]
mod protocol_primitive_tests {
    use super::*;

    #[test]
    fn composite_quota_failure_preserves_every_member() {
        let before = [0, 1, 0];
        let result = composite_quota_authorize(before, [1, 1, 1], [true; 3]);
        assert!(!result.accepted);
        assert_eq!(result.captured, before);
    }

    #[test]
    fn duplicate_approval_signer_counts_once() {
        assert_eq!(
            threshold_distinct_eligible_signers([0, 0, 1], [true; 3], [true; 3]),
            2
        );
    }
}
