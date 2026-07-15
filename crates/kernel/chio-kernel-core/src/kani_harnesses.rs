use crate::formal_aeneas::{ledger_apply, ledger_is_terminal, ReservationLedger};
use crate::formal_core::{
    budget_charge_admits, budget_commit, budget_increment_admits, budget_precheck,
    classify_time_window, dpop_admits, dpop_freshness_valid, dpop_verification_admits,
    exact_or_wildcard_covers, guard_pipeline_allows, guard_projection_allows_continuation,
    guard_step_admits, monetary_cap_is_subset_by_parts, nonce_admits, optional_u32_cap_is_subset,
    prefix_wildcard_or_exact_covers, receipt_fields_coupled, required_true_is_preserved,
    revocation_lookup_denies, revocation_snapshot_denies, GuardStep, RevocationCheckTarget,
    TimeWindowStatus,
};

fn guard_step(value: u8) -> GuardStep {
    match value % 3 {
        0 => GuardStep::Allow,
        1 => GuardStep::Deny,
        _ => GuardStep::Error,
    }
}

fn ledger_transition_oracle(
    state: ReservationLedger,
    op: u8,
    amount: u64,
) -> (ReservationLedger, bool) {
    let Some(total) = state.reserved.checked_add(state.committed) else {
        return (state, false);
    };
    let Some(total) = total.checked_add(state.released) else {
        return (state, false);
    };
    let Some(total) = total.checked_add(state.retained) else {
        return (state, false);
    };
    let terminal =
        state.reserved == 0 && (state.committed != 0 || state.released != 0 || state.retained != 0);

    if op > 3 || (op == 0 && terminal) {
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

    let reserved = state.reserved - amount;
    match op {
        1 => match state.committed.checked_add(amount) {
            Some(committed) => (
                ReservationLedger {
                    reserved,
                    committed,
                    ..state
                },
                true,
            ),
            None => (state, false),
        },
        2 => match state.released.checked_add(amount) {
            Some(released) => (
                ReservationLedger {
                    reserved,
                    released,
                    ..state
                },
                true,
            ),
            None => (state, false),
        },
        3 => match state.retained.checked_add(amount) {
            Some(retained) => (
                ReservationLedger {
                    reserved,
                    retained,
                    ..state
                },
                true,
            ),
            None => (state, false),
        },
        _ => (state, false),
    }
}

#[kani::proof]
fn scalar_helpers_match_reference_predicates() {
    let now = u64::from(kani::any::<u8>());
    let issued_at = u64::from(kani::any::<u8>());
    let expires_at = u64::from(kani::any::<u8>());
    let expected_window = if now < issued_at {
        TimeWindowStatus::NotYetValid
    } else if now >= expires_at {
        TimeWindowStatus::Expired
    } else {
        TimeWindowStatus::Valid
    };
    let expected_window_code = match expected_window {
        TimeWindowStatus::Valid => 0,
        TimeWindowStatus::NotYetValid => 1,
        TimeWindowStatus::Expired => 2,
    };
    let expected_window_valid = matches!(expected_window, TimeWindowStatus::Valid);
    assert_eq!(
        crate::formal_aeneas::classify_time_window_code(now, issued_at, expires_at),
        expected_window_code,
    );
    assert_eq!(
        classify_time_window(now, issued_at, expires_at),
        expected_window
    );
    assert_eq!(
        crate::formal_aeneas::time_window_valid(now, issued_at, expires_at),
        expected_window_valid,
    );
    assert_eq!(
        crate::formal_core::time_window_valid(now, issued_at, expires_at),
        expected_window_valid,
    );

    let parent_is_wildcard = kani::any::<bool>();
    let parent_equals_child = kani::any::<bool>();
    assert_eq!(
        crate::formal_aeneas::exact_or_wildcard_covers_by_flags(
            parent_is_wildcard,
            parent_equals_child,
        ),
        parent_is_wildcard || parent_equals_child,
    );
    let parent_has_prefix_wildcard = kani::any::<bool>();
    let prefix_matches = kani::any::<bool>();
    let exact_matches = kani::any::<bool>();
    assert_eq!(
        crate::formal_aeneas::prefix_wildcard_or_exact_covers_by_flags(
            parent_is_wildcard,
            parent_has_prefix_wildcard,
            prefix_matches,
            exact_matches,
        ),
        parent_is_wildcard || (parent_has_prefix_wildcard && prefix_matches) || exact_matches,
    );
    assert!(exact_or_wildcard_covers("*", "child"));
    assert!(exact_or_wildcard_covers("same", "same"));
    assert!(!exact_or_wildcard_covers("parent", "child"));
    assert!(prefix_wildcard_or_exact_covers("*", "child"));
    assert!(prefix_wildcard_or_exact_covers("service*", "service.read"));
    assert!(prefix_wildcard_or_exact_covers("same", "same"));
    assert!(!prefix_wildcard_or_exact_covers("service*", "other.read"));
    assert!(!prefix_wildcard_or_exact_covers("parent", "child"));

    let child_has_cap = kani::any::<bool>();
    let child_value = u32::from(kani::any::<u8>());
    let parent_has_cap = kani::any::<bool>();
    let parent_value = u32::from(kani::any::<u8>());
    let expected_optional_cap = !parent_has_cap || (child_has_cap && child_value <= parent_value);
    assert_eq!(
        crate::formal_aeneas::optional_u32_cap_is_subset(
            child_has_cap,
            child_value,
            parent_has_cap,
            parent_value,
        ),
        expected_optional_cap,
    );
    assert_eq!(
        optional_u32_cap_is_subset(child_has_cap, child_value, parent_has_cap, parent_value),
        expected_optional_cap,
    );

    let parent_requires_true = kani::any::<bool>();
    let child_requires_true = kani::any::<bool>();
    let expected_required = !parent_requires_true || child_requires_true;
    assert_eq!(
        crate::formal_aeneas::required_true_is_preserved(parent_requires_true, child_requires_true,),
        expected_required,
    );
    assert_eq!(
        required_true_is_preserved(parent_requires_true, child_requires_true),
        expected_required,
    );

    let child_units = u64::from(kani::any::<u8>());
    let parent_units = u64::from(kani::any::<u8>());
    let currency_matches = kani::any::<bool>();
    let expected_monetary =
        !parent_has_cap || (child_has_cap && currency_matches && child_units <= parent_units);
    assert_eq!(
        crate::formal_aeneas::monetary_cap_is_subset_by_parts(
            child_has_cap,
            child_units,
            parent_has_cap,
            parent_units,
            currency_matches,
        ),
        expected_monetary,
    );
    assert_eq!(
        monetary_cap_is_subset_by_parts(
            child_has_cap,
            child_units,
            parent_has_cap,
            parent_units,
            currency_matches,
        ),
        expected_monetary,
    );

    let remaining_invocations = u64::from(kani::any::<u8>());
    let remaining_units = u64::from(kani::any::<u8>());
    let invocation_cost = u64::from(kani::any::<u8>());
    let unit_cost = u64::from(kani::any::<u8>());
    let expected_budget = invocation_cost <= remaining_invocations && unit_cost <= remaining_units;
    assert_eq!(
        crate::formal_aeneas::budget_precheck(
            remaining_invocations,
            remaining_units,
            invocation_cost,
            unit_cost,
        ),
        expected_budget,
    );
    assert_eq!(
        budget_precheck(
            remaining_invocations,
            remaining_units,
            invocation_cost,
            unit_cost,
        ),
        expected_budget,
    );
    let extracted_commit = crate::formal_aeneas::budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    );
    let projected_commit = budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    );
    let expected_remaining_invocations = if expected_budget {
        remaining_invocations - invocation_cost
    } else {
        remaining_invocations
    };
    let expected_remaining_units = if expected_budget {
        remaining_units - unit_cost
    } else {
        remaining_units
    };
    assert_eq!(extracted_commit.accepted, expected_budget);
    assert_eq!(
        extracted_commit.remaining_invocations,
        expected_remaining_invocations,
    );
    assert_eq!(extracted_commit.remaining_units, expected_remaining_units);
    assert_eq!(projected_commit.accepted, expected_budget);
    assert_eq!(
        projected_commit.remaining_invocations,
        expected_remaining_invocations,
    );
    assert_eq!(projected_commit.remaining_units, expected_remaining_units);

    let invocation_count = u32::from(kani::any::<u8>());
    let max_invocations = u32::from(kani::any::<u8>());
    let has_invocation_cap = kani::any::<bool>();
    let invocation_cap = has_invocation_cap.then_some(max_invocations);
    assert_eq!(
        budget_increment_admits(invocation_count, invocation_cap),
        !has_invocation_cap || invocation_count < max_invocations,
    );
    let committed_cost = u64::from(kani::any::<u8>());
    let cost = u64::from(kani::any::<u8>());
    let max_per_invocation = u64::from(kani::any::<u8>());
    let max_total = u64::from(kani::any::<u8>());
    let has_per_invocation_cap = kani::any::<bool>();
    let has_total_cap = kani::any::<bool>();
    let expected_charge = (!has_invocation_cap || invocation_count < max_invocations)
        && (!has_per_invocation_cap || cost <= max_per_invocation)
        && (!has_total_cap || committed_cost + cost <= max_total);
    assert_eq!(
        budget_charge_admits(
            invocation_count,
            committed_cost,
            cost,
            invocation_cap,
            has_per_invocation_cap.then_some(max_per_invocation),
            has_total_cap.then_some(max_total),
        ),
        Ok(expected_charge),
    );

    let ttl_secs = u64::from(kani::any::<u8>());
    let max_skew_secs = u64::from(kani::any::<u8>());
    let expected_freshness =
        issued_at <= now.saturating_add(max_skew_secs) && issued_at.saturating_add(ttl_secs) >= now;
    assert_eq!(
        crate::formal_aeneas::dpop_freshness_valid(now, issued_at, ttl_secs, max_skew_secs,),
        expected_freshness,
    );
    assert_eq!(
        dpop_freshness_valid(now, issued_at, ttl_secs, max_skew_secs),
        expected_freshness,
    );
    let dpop_required = kani::any::<bool>();
    let proof_present = kani::any::<bool>();
    let proof_valid = kani::any::<bool>();
    let nonce_fresh = kani::any::<bool>();
    let expected_dpop = !dpop_required || (proof_present && proof_valid && nonce_fresh);
    assert_eq!(
        crate::formal_aeneas::dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh,),
        expected_dpop,
    );
    assert_eq!(
        dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh),
        expected_dpop,
    );
    let verification_succeeded = kani::any::<bool>();
    assert_eq!(
        dpop_verification_admits(dpop_required, proof_present, verification_succeeded),
        !dpop_required || (proof_present && verification_succeeded),
    );
    let already_live = kani::any::<bool>();
    assert_eq!(
        crate::formal_aeneas::nonce_admits(already_live),
        !already_live
    );
    assert_eq!(nonce_admits(already_live), !already_live);

    let core_authorized = kani::any::<bool>();
    let guard_allows = kani::any::<bool>();
    assert_eq!(
        crate::formal_aeneas::guard_step_allows(core_authorized, guard_allows),
        core_authorized && guard_allows,
    );
    let step = guard_step(kani::any::<u8>());
    assert_eq!(guard_step_admits(step), step == GuardStep::Allow);
    assert_eq!(
        guard_projection_allows_continuation(core_authorized, step),
        core_authorized && step == GuardStep::Allow,
    );
    assert_eq!(
        guard_pipeline_allows(core_authorized, &[step]),
        core_authorized && step == GuardStep::Allow,
    );

    let token_revoked = kani::any::<bool>();
    let ancestor_revoked = kani::any::<bool>();
    let expected_revocation = token_revoked || ancestor_revoked;
    assert_eq!(
        crate::formal_aeneas::revocation_snapshot_denies(token_revoked, ancestor_revoked),
        expected_revocation,
    );
    assert_eq!(
        revocation_snapshot_denies(token_revoked, ancestor_revoked),
        expected_revocation,
    );
    assert_eq!(
        revocation_lookup_denies(RevocationCheckTarget::PresentedToken, token_revoked),
        token_revoked,
    );
    assert_eq!(
        revocation_lookup_denies(RevocationCheckTarget::Ancestor, ancestor_revoked),
        ancestor_revoked,
    );

    let capability_matches = kani::any::<bool>();
    let request_matches = kani::any::<bool>();
    let verdict_matches = kani::any::<bool>();
    let policy_hash_matches = kani::any::<bool>();
    let evidence_class_matches = kani::any::<bool>();
    let expected_receipt = capability_matches
        && request_matches
        && verdict_matches
        && policy_hash_matches
        && evidence_class_matches;
    assert_eq!(
        crate::formal_aeneas::receipt_fields_coupled(
            capability_matches,
            request_matches,
            verdict_matches,
            policy_hash_matches,
            evidence_class_matches,
        ),
        expected_receipt,
    );
    assert_eq!(
        receipt_fields_coupled(
            capability_matches,
            request_matches,
            verdict_matches,
            policy_hash_matches,
            evidence_class_matches,
        ),
        expected_receipt,
    );
}

#[kani::proof]
fn reservation_ledger_matches_one_step_oracle() {
    let state = ReservationLedger {
        reserved: u64::from(kani::any::<u8>()),
        committed: u64::from(kani::any::<u8>()),
        released: u64::from(kani::any::<u8>()),
        retained: u64::from(kani::any::<u8>()),
    };
    let op = kani::any::<u8>();
    let amount = u64::from(kani::any::<u8>());
    let expected_terminal =
        state.reserved == 0 && (state.committed != 0 || state.released != 0 || state.retained != 0);
    assert_eq!(ledger_is_terminal(state), expected_terminal);
    assert_eq!(
        ledger_apply(state, op, amount),
        ledger_transition_oracle(state, op, amount)
    );
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

    let atomic_required = kani::any::<bool>();
    let verification_succeeded = kani::any::<bool>();
    assert_eq!(
        dpop_verification_admits(atomic_required, proof_present, verification_succeeded,),
        !atomic_required || (proof_present && verification_succeeded),
    );
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

    for step in guards {
        let projected = guard_step_admits(step);
        assert_eq!(projected, step == GuardStep::Allow);
        assert_eq!(
            guard_projection_allows_continuation(projected, step),
            step == GuardStep::Allow,
        );
        if step != GuardStep::Allow {
            assert!(!guard_projection_allows_continuation(true, step));
        }
    }

    assert!(!guard_projection_allows_continuation(
        false,
        GuardStep::Allow,
    ));
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
