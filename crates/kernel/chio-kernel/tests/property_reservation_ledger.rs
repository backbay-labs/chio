#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;

use chio_kernel::budget_store::{BudgetCaptureInvocationRequest, BudgetInvocationCaptureDecision};
use chio_kernel::{BudgetStore, InMemoryBudgetStore};
use chio_kernel_core::{BudgetRegistry, InMemoryBudgetRegistry};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};

const CAPABILITY_ID: &str = "cap-reservation-property";
const GRANT_INDEX: usize = 0;

/// Stateful check of the reservation law.
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
/// This randomized lane exercises real `InMemoryBudgetStore` mutations, not
/// kernel lifecycle or drop paths. The production runtime-admission hook,
/// `PostAdmissionDropGuard`, receipt metadata, monetary journal, and final
/// usage are exercised together by
/// `chio-kernel/src/kernel/tests/drop_guard_proptest.rs`.
#[derive(Debug, Clone)]
enum ReservationOp {
    Authorize(u8),
    Reverse,
    Release(u8),
    Reconcile(u8),
}

fn operation_strategy() -> impl Strategy<Value = ReservationOp> {
    prop_oneof![
        (1u8..=16).prop_map(ReservationOp::Authorize),
        Just(ReservationOp::Reverse),
        (0u8..=20).prop_map(ReservationOp::Release),
        (0u8..=20).prop_map(ReservationOp::Reconcile),
    ]
}

#[derive(Debug, Clone)]
struct OpenHold {
    id: String,
    remaining: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalClass {
    Committed,
    Released,
}

#[derive(Debug, Default)]
struct HoldAudit {
    authorized: u64,
    consumed: u64,
    terminal: Option<TerminalClass>,
}

fn assert_store_conservation(
    store: &InMemoryBudgetStore,
    terminal_history: &HashMap<String, TerminalClass>,
) {
    let events = store
        .list_mutation_events(usize::MAX, Some(CAPABILITY_ID), Some(GRANT_INDEX))
        .expect("in-memory journal is available");
    let mut reserved_total = 0u128;
    let mut committed = 0u128;
    let mut released = 0u128;
    let mut outstanding = 0u128;
    let mut invocations = 0u64;
    let mut holds = HashMap::<String, HoldAudit>::new();

    for event in events {
        match event.kind.as_str() {
            "authorize_exposure" if event.allowed == Some(true) => {
                let amount = u128::from(event.exposure_units);
                reserved_total += amount;
                outstanding += amount;
                invocations += 1;
                if let Some(hold_id) = event.hold_id {
                    let old = holds.insert(
                        hold_id,
                        HoldAudit {
                            authorized: event.exposure_units,
                            ..HoldAudit::default()
                        },
                    );
                    assert!(old.is_none());
                }
            }
            "authorize_exposure" | "increment_invocation" => {
                if event.allowed == Some(true) {
                    invocations += 1;
                }
            }
            "capture_invocation" => {}
            "reverse_exposure" => {
                let amount = u128::from(event.exposure_units);
                outstanding = outstanding
                    .checked_sub(amount)
                    .expect("reverse cannot exceed outstanding exposure");
                released += amount;
                invocations = invocations
                    .checked_sub(1)
                    .expect("reverse cannot precede invocation admission");
                if let Some(hold_id) = event.hold_id {
                    let hold = holds
                        .get_mut(&hold_id)
                        .expect("reverse names an admitted hold");
                    hold.consumed += event.exposure_units;
                    assert_eq!(hold.consumed, hold.authorized);
                    assert!(hold.terminal.replace(TerminalClass::Released).is_none());
                }
            }
            "release_exposure" => {
                let amount = u128::from(event.exposure_units);
                outstanding = outstanding
                    .checked_sub(amount)
                    .expect("release cannot exceed outstanding exposure");
                released += amount;
                if let Some(hold_id) = event.hold_id {
                    let hold = holds
                        .get_mut(&hold_id)
                        .expect("release names an admitted hold");
                    hold.consumed += event.exposure_units;
                    assert!(hold.consumed <= hold.authorized);
                    if hold.consumed == hold.authorized {
                        assert!(hold.terminal.replace(TerminalClass::Released).is_none());
                    }
                }
            }
            "reconcile_spend" => {
                let exposure = u128::from(event.exposure_units);
                let realized = u128::from(event.realized_spend_units);
                assert!(realized <= exposure);
                outstanding = outstanding
                    .checked_sub(exposure)
                    .expect("reconcile cannot exceed outstanding exposure");
                committed += realized;
                released += exposure - realized;
                if let Some(hold_id) = event.hold_id {
                    let hold = holds
                        .get_mut(&hold_id)
                        .expect("reconcile names an admitted hold");
                    hold.consumed += event.exposure_units;
                    assert_eq!(hold.consumed, hold.authorized);
                    assert!(hold.terminal.replace(TerminalClass::Committed).is_none());
                }
            }
            kind => panic!("unexpected journal mutation kind {kind}"),
        }

        assert_eq!(reserved_total, outstanding + committed + released);
        assert_eq!(u128::from(event.total_cost_exposed_after), outstanding);
        assert_eq!(u128::from(event.total_cost_realized_spend_after), committed);
        assert_eq!(u64::from(event.invocation_count_after), invocations);
    }

    for (hold_id, terminal) in terminal_history {
        let audit = holds
            .get(hold_id)
            .expect("terminal history names an admitted hold");
        assert_eq!(
            audit.terminal.as_ref(),
            Some(terminal),
            "terminal history has no matching concrete disposition"
        );
        assert_eq!(audit.consumed, audit.authorized);
    }
    for (hold_id, audit) in holds {
        if let Some(terminal) = audit.terminal {
            assert_eq!(terminal_history.get(&hold_id), Some(&terminal));
        }
    }

    let usage = store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("in-memory usage is available");
    if let Some(usage) = usage {
        assert_eq!(u64::from(usage.invocation_count), invocations);
        assert_eq!(u128::from(usage.total_cost_exposed), outstanding);
        assert_eq!(u128::from(usage.total_cost_realized_spend), committed);
    } else {
        assert_eq!((invocations, outstanding, committed), (0, 0, 0));
    }
}

fn terminal_hold(
    store: &InMemoryBudgetStore,
    open: &mut Vec<OpenHold>,
    terminal_history: &mut HashMap<String, TerminalClass>,
    class: TerminalClass,
    realized_hint: u8,
) {
    let Some(hold) = open.pop() else {
        return;
    };
    match class {
        TerminalClass::Released => store
            .reverse_charge_cost_with_ids(
                CAPABILITY_ID,
                GRANT_INDEX,
                hold.remaining,
                Some(&hold.id),
                Some(&format!("{}:reverse", hold.id)),
            )
            .expect("open hold reverses exactly once"),
        TerminalClass::Committed => {
            let capture = store
                .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                    capability_id: CAPABILITY_ID.to_string(),
                    grant_index: GRANT_INDEX,
                    hold_id: hold.id.clone(),
                    event_id: format!("{}:capture-invocation", hold.id),
                    trusted_time: None,
                    authority: None,
                })
                .expect("open hold captures its invocation before reconciliation");
            assert!(matches!(
                capture,
                BudgetInvocationCaptureDecision::Captured(_)
            ));
            store
                .settle_charge_cost_with_ids(
                    CAPABILITY_ID,
                    GRANT_INDEX,
                    hold.remaining,
                    u64::from(realized_hint).min(hold.remaining),
                    Some(&hold.id),
                    Some(&format!("{}:reconcile", hold.id)),
                )
                .expect("open dispatch-captured hold reconciles exactly once");
        }
    }
    assert!(terminal_history.insert(hold.id, class).is_none());
}

#[test]
#[should_panic(expected = "terminal history has no matching concrete disposition")]
fn omitted_release_is_detected_by_terminal_history_replay() {
    let store = InMemoryBudgetStore::new();
    let allowed = store
        .try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            None,
            8,
            None,
            None,
            Some("omitted-release-hold"),
            Some("omitted-release-hold:authorize"),
        )
        .expect("bounded authorization succeeds");
    assert!(allowed);
    let terminal_history =
        HashMap::from([("omitted-release-hold".to_string(), TerminalClass::Released)]);

    assert_store_conservation(&store, &terminal_history);
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/property_reservation_ledger.txt",
        ))),
        .. ProptestConfig::default()
    })]

    #[test]
    fn mixed_store_reservation_sequences_preserve_the_journal_law(
        operations in proptest::collection::vec(operation_strategy(), 1..96),
    ) {
        let store = InMemoryBudgetStore::new();
        let mut open = Vec::<OpenHold>::new();
        let mut terminal_history = HashMap::<String, TerminalClass>::new();
        let mut next_hold = 0u64;

        for (operation_index, operation) in operations.into_iter().enumerate() {
            match operation {
                ReservationOp::Authorize(amount) => {
                    next_hold += 1;
                    let hold_id = format!("reservation-hold-{next_hold}");
                    let allowed = store
                        .try_charge_cost_with_ids(
                            CAPABILITY_ID,
                            GRANT_INDEX,
                            None,
                            u64::from(amount),
                            None,
                            None,
                            Some(&hold_id),
                            Some(&format!("{hold_id}:authorize")),
                        )
                        .expect("bounded authorization cannot overflow");
                    assert!(allowed);
                    open.push(OpenHold {
                        id: hold_id,
                        remaining: u64::from(amount),
                    });
                }
                ReservationOp::Reverse => terminal_hold(
                    &store,
                    &mut open,
                    &mut terminal_history,
                    TerminalClass::Released,
                    0,
                ),
                ReservationOp::Release(amount) => {
                    if let Some(hold) = open.last_mut() {
                        let released = u64::from(amount).min(hold.remaining);
                        if released > 0 {
                            store
                                .reduce_charge_cost_with_ids(
                                CAPABILITY_ID,
                                GRANT_INDEX,
                                released,
                                Some(&hold.id),
                                Some(&format!("{}:release:{operation_index}", hold.id)),
                            )
                                .expect("release is bounded by outstanding exposure");
                            hold.remaining -= released;
                        }
                        if hold.remaining == 0 {
                            let terminal = open.pop().expect("last_mut established an open hold");
                            assert!(terminal_history
                                .insert(terminal.id, TerminalClass::Released)
                                .is_none());
                        }
                    }
                }
                ReservationOp::Reconcile(realized) => terminal_hold(
                    &store,
                    &mut open,
                    &mut terminal_history,
                    TerminalClass::Committed,
                    realized,
                ),
            }

            assert_store_conservation(&store, &terminal_history);
        }
    }

    #[test]
    fn admitted_child_shares_remain_bounded_and_release_exactly_once(
        operations in proptest::collection::vec((0u8..=1, 1u16..=6_000), 1..96),
    ) {
        const PARENT: &str = "parent-reservation-property";
        const PARENT_SHARE: u16 = 10_000;
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent(PARENT.to_string(), PARENT_SHARE)
            .expect("bounded parent registers");
        let mut admitted = Vec::<(String, u16)>::new();
        let mut next_child = 0u64;

        for (kind, share) in operations {
            if kind == 0 {
                next_child += 1;
                let child = format!("child-reservation-{next_child}");
                if registry
                    .try_admit_child(PARENT, child.clone(), share)
                    .is_ok()
                {
                    admitted.push((child, share));
                }
            } else if let Some((child, expected_share)) = admitted.pop() {
                registry
                    .release_child(PARENT, &child, expected_share)
                    .expect("admitted child releases with its recorded share");
            }

            let split = registry.split(PARENT).expect("registered parent remains present");
            assert!(split.current_total_child_bps() <= u32::from(PARENT_SHARE));
            let expected_sum: u32 = admitted.iter().map(|(_, share)| u32::from(*share)).sum();
            assert_eq!(split.current_total_child_bps(), expected_sum);
        }
    }
}
