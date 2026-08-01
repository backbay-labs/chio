//! Pure helpers shared by runtime code and formal verification lanes.
//!
//! This module deliberately avoids heap allocation, IO, crypto, async, and
//! external crates so Kani, Creusot wrappers, and Aeneas can reason about the
//! same branch logic used by the portable kernel core.

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
#[allow(dead_code)]
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

/// Failure produced while projecting runtime budget state into the bounded
/// admission model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAdmissionProjectionError {
    /// Adding the requested cost to the committed total overflowed `u64`.
    TotalCostOverflow,
}

/// Project an invocation counter and optional cap into the bounded budget
/// admission predicate used by production budget stores.
#[must_use]
pub fn budget_increment_admits(invocation_count: u32, max_invocations: Option<u32>) -> bool {
    max_invocations.is_none_or(|max| {
        budget_precheck(
            u64::from(max.saturating_sub(invocation_count)),
            u64::MAX,
            1,
            0,
        )
    })
}

/// Project a production budget row and optional caps into the bounded budget
/// admission predicates.
///
/// The overflow result is distinct from a cap denial so callers retain their
/// existing fail-closed error attribution.
pub fn budget_charge_admits(
    invocation_count: u32,
    committed_cost_units: u64,
    cost_units: u64,
    max_invocations: Option<u32>,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
) -> Result<bool, BudgetAdmissionProjectionError> {
    let invocation_allowed = max_invocations.is_none_or(|max| {
        budget_commit(
            u64::from(max.saturating_sub(invocation_count)),
            u64::MAX,
            1,
            0,
        )
        .accepted
    });
    let per_invocation_allowed = max_cost_per_invocation
        .is_none_or(|max| budget_commit(u64::MAX, max, 0, cost_units).accepted);
    let total_allowed = match max_total_cost_units {
        Some(max_total) => {
            let new_total = committed_cost_units
                .checked_add(cost_units)
                .ok_or(BudgetAdmissionProjectionError::TotalCostOverflow)?;
            committed_cost_units <= max_total
                && budget_commit(
                    u64::MAX,
                    max_total.saturating_sub(committed_cost_units),
                    0,
                    cost_units,
                )
                .accepted
                && new_total <= max_total
        }
        None => true,
    };

    Ok(invocation_allowed && per_invocation_allowed && total_allowed)
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

/// Project the atomic production verifier result into the four-axis DPoP
/// admission model.
#[must_use]
pub fn dpop_verification_admits(
    dpop_required: bool,
    proof_present: bool,
    verification_succeeded: bool,
) -> bool {
    dpop_admits(
        dpop_required,
        proof_present,
        verification_succeeded,
        verification_succeeded,
    )
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

impl From<crate::Verdict> for GuardStep {
    fn from(verdict: crate::Verdict) -> Self {
        match verdict {
            crate::Verdict::Allow => Self::Allow,
            crate::Verdict::Deny => Self::Deny,
            crate::Verdict::PendingApproval => Self::Error,
        }
    }
}

/// Guard pipeline model. Core authorization must pass, and every guard must
/// return allow. Deny and error are both fail-closed.
#[must_use]
pub fn guard_pipeline_allows(core_authorized: bool, guards: &[GuardStep]) -> bool {
    guards.iter().fold(core_authorized, |allowed, guard| {
        formal_aeneas::guard_step_allows(allowed, matches!(guard, GuardStep::Allow))
    })
}

/// Decide whether one projected guard result permits pipeline continuation.
#[must_use]
pub fn guard_step_admits(step: GuardStep) -> bool {
    guard_pipeline_allows(true, core::slice::from_ref(&step))
}

/// Require the verified projection and the observed guard step to agree before
/// runtime continuation. A mismatched allow result remains fail-closed.
#[must_use]
pub fn guard_projection_allows_continuation(
    projected_allows: bool,
    observed_step: GuardStep,
) -> bool {
    projected_allows && matches!(observed_step, GuardStep::Allow)
}

/// Runtime branch represented by a revocation lookup result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationCheckTarget {
    /// The capability presented for dispatch.
    PresentedToken,
    /// One capability in the presented delegation chain.
    Ancestor,
}

/// Revocation projection model for the presented token and its ancestors.
#[must_use]
pub fn revocation_snapshot_denies(token_revoked: bool, ancestor_revoked: bool) -> bool {
    formal_aeneas::revocation_snapshot_denies(token_revoked, ancestor_revoked)
}

/// Project one production revocation lookup into the verified snapshot
/// predicate while preserving lazy lookup and error attribution.
#[must_use]
pub fn revocation_lookup_denies(target: RevocationCheckTarget, is_revoked: bool) -> bool {
    match target {
        RevocationCheckTarget::PresentedToken => revocation_snapshot_denies(is_revoked, false),
        RevocationCheckTarget::Ancestor => revocation_snapshot_denies(false, is_revoked),
    }
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

/// Delivery-contract admission verdict over an expected and observed output
/// digest. `Allow` requires exact equality of the two digests; every other
/// case denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryVerdict {
    /// The observed output digest equals the grant's committed digest.
    Allow,
    /// The observed digest differs from the committed digest.
    Deny,
}

/// Compare an expected output digest against the observed post-transform
/// output digest. This is the sole decision in the delivery contract:
/// an Allow is returned only when the two digests are byte-identical.
///
/// The comparison is pure and total so the formal-verification lanes can
/// prove `verdict == Allow implies expected == observed` over the same
/// branch the durable terminal takes.
#[must_use]
pub fn delivery_contract_admits(expected: &str, observed: &str) -> DeliveryVerdict {
    if expected.as_bytes() == observed.as_bytes() {
        DeliveryVerdict::Allow
    } else {
        DeliveryVerdict::Deny
    }
}

#[cfg(test)]
mod delivery_contract_tests {
    use super::{delivery_contract_admits, DeliveryVerdict};

    #[test]
    fn identical_digests_admit() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            delivery_contract_admits(digest, digest),
            DeliveryVerdict::Allow
        );
    }

    #[test]
    fn any_difference_denies() {
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let observed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0";
        assert_eq!(
            delivery_contract_admits(expected, observed),
            DeliveryVerdict::Deny
        );
        assert_eq!(
            delivery_contract_admits(expected, ""),
            DeliveryVerdict::Deny
        );
        assert_eq!(
            delivery_contract_admits("", expected),
            DeliveryVerdict::Deny
        );
    }
}
