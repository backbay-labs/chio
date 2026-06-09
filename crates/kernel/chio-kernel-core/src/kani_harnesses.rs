use crate::formal_core::{
    budget_commit, budget_precheck, classify_time_window, dpop_admits, dpop_freshness_valid,
    guard_pipeline_allows, monetary_cap_is_subset_by_parts, nonce_admits,
    optional_u32_cap_is_subset, receipt_fields_coupled, required_true_is_preserved,
    revocation_snapshot_denies, GuardStep, TimeWindowStatus,
};

fn guard_step(value: u8) -> GuardStep {
    match value % 3 {
        0 => GuardStep::Allow,
        1 => GuardStep::Deny,
        _ => GuardStep::Error,
    }
}

#[kani::proof]
fn time_window_classifier_matches_valid_predicate() {
    let now = u64::from(kani::any::<u8>());
    let issued_at = u64::from(kani::any::<u8>());
    let expires_at = u64::from(kani::any::<u8>());

    let classified_valid = matches!(
        classify_time_window(now, issued_at, expires_at),
        TimeWindowStatus::Valid
    );

    assert_eq!(classified_valid, issued_at <= now && now < expires_at);
}

#[kani::proof]
fn optional_caps_never_widen_parent_cap() {
    let child_has_cap = kani::any::<bool>();
    let parent_has_cap = kani::any::<bool>();
    let child_value = u32::from(kani::any::<u8>());
    let parent_value = u32::from(kani::any::<u8>());

    let result =
        optional_u32_cap_is_subset(child_has_cap, child_value, parent_has_cap, parent_value);

    if parent_has_cap && result {
        assert!(child_has_cap);
        assert!(child_value <= parent_value);
    }
}

#[kani::proof]
fn monetary_caps_never_widen_parent_cap() {
    let child_has_cap = kani::any::<bool>();
    let parent_has_cap = kani::any::<bool>();
    let child_units = u64::from(kani::any::<u8>());
    let parent_units = u64::from(kani::any::<u8>());
    let currency_matches = kani::any::<bool>();

    let result = monetary_cap_is_subset_by_parts(
        child_has_cap,
        child_units,
        parent_has_cap,
        parent_units,
        currency_matches,
    );

    if parent_has_cap && result {
        assert!(child_has_cap);
        assert!(currency_matches);
        assert!(child_units <= parent_units);
    }
}

#[kani::proof]
fn dpop_required_missing_or_invalid_fails_closed() {
    let proof_present = kani::any::<bool>();
    let proof_valid = kani::any::<bool>();
    let nonce_fresh = kani::any::<bool>();

    let admitted = dpop_admits(true, proof_present, proof_valid, nonce_fresh);

    if !proof_present || !proof_valid || !nonce_fresh {
        assert!(!admitted);
    }
}

#[kani::proof]
fn dpop_replayed_nonce_never_admits() {
    assert!(!nonce_admits(true));
}

#[kani::proof]
fn dpop_freshness_rejects_future_beyond_skew() {
    let now = u64::from(kani::any::<u8>());
    let ttl = u64::from(kani::any::<u8>());
    let skew = u64::from(kani::any::<u8>());
    kani::assume(now <= 200);
    kani::assume(skew <= 20);
    kani::assume(ttl <= 60);
    let issued_at = now.saturating_add(skew).saturating_add(1);

    assert!(!dpop_freshness_valid(now, issued_at, ttl, skew));
}

#[kani::proof]
fn budget_commit_never_increases_remaining_counters() {
    let remaining_invocations = u64::from(kani::any::<u8>());
    let remaining_units = u64::from(kani::any::<u8>());
    let invocation_cost = u64::from(kani::any::<u8>());
    let unit_cost = u64::from(kani::any::<u8>());

    let committed = budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    );

    assert!(committed.remaining_invocations <= remaining_invocations);
    assert!(committed.remaining_units <= remaining_units);
}

#[kani::proof]
fn two_sequential_budget_commits_cannot_overspend() {
    let remaining_invocations = u64::from(kani::any::<u8>());
    let remaining_units = u64::from(kani::any::<u8>());
    let first_invocation_cost = u64::from(kani::any::<u8>());
    let first_unit_cost = u64::from(kani::any::<u8>());
    let second_invocation_cost = u64::from(kani::any::<u8>());
    let second_unit_cost = u64::from(kani::any::<u8>());

    let first = budget_commit(
        remaining_invocations,
        remaining_units,
        first_invocation_cost,
        first_unit_cost,
    );
    let second = budget_commit(
        first.remaining_invocations,
        first.remaining_units,
        second_invocation_cost,
        second_unit_cost,
    );

    if first.accepted && second.accepted {
        assert!(first_invocation_cost + second_invocation_cost <= remaining_invocations);
        assert!(first_unit_cost + second_unit_cost <= remaining_units);
    }
}

#[kani::proof]
fn guard_deny_or_error_dominates_pipeline() {
    let core_authorized = kani::any::<bool>();
    let first = guard_step(kani::any::<u8>());
    let second = guard_step(kani::any::<u8>());
    let guards = [first, second];

    let allowed = guard_pipeline_allows(core_authorized, &guards);

    if !core_authorized || guards.iter().any(|guard| *guard != GuardStep::Allow) {
        assert!(!allowed);
    }
}

#[kani::proof]
fn revocation_snapshot_denies_presented_token_or_ancestor() {
    let token_revoked = kani::any::<bool>();
    let ancestor_revoked = kani::any::<bool>();

    let denied = revocation_snapshot_denies(token_revoked, ancestor_revoked);

    assert_eq!(denied, token_revoked || ancestor_revoked);
}

#[kani::proof]
fn receipt_coupling_requires_every_field_match() {
    let capability_matches = kani::any::<bool>();
    let request_matches = kani::any::<bool>();
    let verdict_matches = kani::any::<bool>();
    let policy_hash_matches = kani::any::<bool>();
    let evidence_class_matches = kani::any::<bool>();

    let coupled = receipt_fields_coupled(
        capability_matches,
        request_matches,
        verdict_matches,
        policy_hash_matches,
        evidence_class_matches,
    );

    if coupled {
        assert!(capability_matches);
        assert!(request_matches);
        assert!(verdict_matches);
        assert!(policy_hash_matches);
        assert!(evidence_class_matches);
    }
}

#[kani::proof]
fn subset_helpers_preserve_parent_requirements() {
    let parent_requires = kani::any::<bool>();
    let child_requires = kani::any::<bool>();

    if required_true_is_preserved(parent_requires, child_requires) && parent_requires {
        assert!(child_requires);
    }

    assert!(crate::formal_aeneas::exact_or_wildcard_covers_by_flags(
        true, false
    ));
    assert!(
        crate::formal_aeneas::prefix_wildcard_or_exact_covers_by_flags(false, true, true, false)
    );
    assert!(!budget_precheck(0, 0, 1, 0));
}
