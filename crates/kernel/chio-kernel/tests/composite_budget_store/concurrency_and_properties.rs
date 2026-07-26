use super::*;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

#[test]
fn real_threads_cannot_partially_reserve_overlapping_quota_sets() {
    let store = Arc::new(InMemoryBudgetStore::new());
    let barrier = Arc::new(Barrier::new(3));
    let shared = quota(
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        "aggregate:thread-shared",
        1,
    );

    let spawn_authorization = |operation_id: &'static str, private_owner: &'static str| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let shared = shared.clone();
        thread::spawn(move || {
            let private = quota(
                BudgetQuotaProfile::AggregateFamilyInvocation,
                private_owner,
                1,
            );
            let request =
                authorize_request(operation_id, canonical_quotas(vec![shared, private]), 0);
            barrier.wait();
            store
                .authorize_budget_hold(request)
                .expect("threaded composite authorization")
        })
    };

    let left = spawn_authorization("thread-left", "family:thread-left");
    let right = spawn_authorization("thread-right", "family:thread-right");
    barrier.wait();
    let decisions = [
        left.join().expect("left thread"),
        right.join().expect("right thread"),
    ];
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)))
            .count(),
        1
    );
    assert_usage(&quota_usage(&store, &shared.key), 1, 0);

    let left_key = BudgetQuotaKey {
        profile: BudgetQuotaProfile::AggregateFamilyInvocation,
        owner_id: "family:thread-left".to_string(),
        grant_index: None,
    };
    let right_key = BudgetQuotaKey {
        profile: BudgetQuotaProfile::AggregateFamilyInvocation,
        owner_id: "family:thread-right".to_string(),
        grant_index: None,
    };
    let private_reserved = store
        .get_invocation_quota_usage(&left_key)
        .expect("query left private quota")
        .map_or(0, |usage| usage.reserved_invocations)
        + store
            .get_invocation_quota_usage(&right_key)
            .expect("query right private quota")
            .map_or(0, |usage| usage.reserved_invocations);
    assert_eq!(private_reserved, 1);
}

#[test]
fn real_threads_serialize_cumulative_sixty_plus_sixty() {
    let store = Arc::new(InMemoryBudgetStore::new());
    let barrier = Arc::new(Barrier::new(3));
    let account = cumulative_account();

    let spawn_reservation = |operation_id: &'static str| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let account = account.clone();
        thread::spawn(move || {
            let request = cumulative_request(operation_id, account, 100, 100, 60);
            barrier.wait();
            store
                .authorize_budget_hold(request)
                .expect("threaded cumulative authorization")
        })
    };

    let left = spawn_reservation("cumulative-thread-left");
    let right = spawn_reservation("cumulative-thread-right");
    barrier.wait();
    let decisions = [
        left.join().expect("left thread"),
        right.join().expect("right thread"),
    ];
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| {
                matches!(decision, BudgetAuthorizeHoldDecision::ApprovalRequired(_))
            })
            .count(),
        1
    );
    let reserved_after = decisions
        .iter()
        .filter_map(|decision| match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                authorized.cumulative_approval.as_ref()
            }
            BudgetAuthorizeHoldDecision::ApprovalRequired(required) => {
                Some(&required.cumulative_approval)
            }
            _ => None,
        })
        .map(|usage| usage.reserved_authorized_after.units)
        .collect::<Vec<_>>();
    assert!(reserved_after.contains(&60));
    assert!(reserved_after.contains(&120));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn any_exhausted_quota_keeps_the_other_composite_members_unchanged(
        exhausted_index in 0usize..3,
        maximum in 1u32..5,
    ) {
        let store = InMemoryBudgetStore::new();
        let quotas = three_quotas(maximum);
        let exhausted = quotas[exhausted_index].clone();
        let prefill_quotas = canonical_quotas(
            quotas.iter().filter(|quota| {
                quota.key == exhausted.key
                    || quota.key.profile == BudgetQuotaProfile::GrantInvocation
            }).cloned().collect()
        );

        for attempt in 0..maximum {
            let request = authorize_request(
                &format!("property-prefill:{exhausted_index}:{maximum}:{attempt}"),
                prefill_quotas.clone(),
                0,
            );
            prop_assert!(matches!(
                store.authorize_budget_hold(request),
                Ok(BudgetAuthorizeHoldDecision::Authorized(_))
            ));
        }
        let denied = store
            .authorize_budget_hold(authorize_request(
                &format!("property-denied:{exhausted_index}:{maximum}"),
                quotas.clone(),
                0,
            ))
            .expect("evaluate property composite hold");
        prop_assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));

        for quota in &quotas {
            let was_prefilled = prefill_quotas
                .iter()
                .any(|prefilled| prefilled.key == quota.key);
            let usage = store
                .get_invocation_quota_usage(&quota.key)
                .expect("query property quota");
            if was_prefilled {
                let usage = usage.expect("prefilled quota exists");
                prop_assert_eq!(usage.reserved_invocations, maximum);
                prop_assert_eq!(usage.captured_invocations, 0);
                prop_assert_eq!(usage.quota.max_invocations, maximum);
            } else {
                prop_assert!(usage.is_none());
            }
        }
    }
}
