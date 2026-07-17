// Post-admission disposition-table property test. For every combination of
// {monetary, non-monetary} x {pre-dispatch, post-dispatch} x {lease
// present, absent}, a directly constructed PostAdmissionDropGuard must
// obey the fail-closed disposition table:
//   - post-dispatch drop: exactly one Cancelled terminal receipt;
//     reservations and monetary exposure retained (never released); the
//     reservation marker present iff a chio_runtime admission block was present;
//   - pre-dispatch drop: no receipt; reservations released iff a
//     chio_runtime admission block was present.

use proptest::prelude::*;

const DROP_GUARD_HOLD_ID: &str = "hold-drop-guard-tests";

struct CountingReleaseRuntimeAdmissionHook {
    admissions: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for CountingReleaseRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-counting-release-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.admissions.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "adm-drop-proptest",
                "accepted": true,
                "reserved_destructive_lease_id": "lease-drop-proptest",
                "failure_code": null
            }
        }))))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            "lease-drop-proptest"
        );
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn assert_drop_guard_budget_conservation(
    kernel: &ChioKernel,
    capability_id: &str,
    monetary: bool,
    dispatch_started: bool,
) -> Result<(), TestCaseError> {
    let (events, usage) = kernel
        .with_budget_store(|store| {
            Ok((
                store.list_mutation_events(usize::MAX, Some(capability_id), Some(0))?,
                store.get_usage(capability_id, 0)?,
            ))
        })
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
    let mut admitted = 0u128;
    let mut outstanding = 0u128;
    let mut committed = 0u128;
    let mut released = 0u128;
    let mut invocations = 0u64;
    let mut drop_hold_authorizations = 0u64;
    let mut drop_hold_reversals = 0u64;
    let mut drop_hold_other_terminal_mutations = 0u64;

    for event in events {
        if event.hold_id.as_deref() == Some(DROP_GUARD_HOLD_ID) {
            match event.kind {
                crate::budget_store::BudgetMutationKind::AuthorizeExposure
                    if event.allowed == Some(true) =>
                {
                    drop_hold_authorizations += 1;
                }
                crate::budget_store::BudgetMutationKind::ReverseExposure
                | crate::budget_store::BudgetMutationKind::ExpireHold => {
                    prop_assert_eq!(event.exposure_units, 5);
                    drop_hold_reversals += 1;
                }
                crate::budget_store::BudgetMutationKind::ReleaseExposure
                | crate::budget_store::BudgetMutationKind::ReconcileSpend => {
                    drop_hold_other_terminal_mutations += 1;
                }
                crate::budget_store::BudgetMutationKind::IncrementInvocation
                | crate::budget_store::BudgetMutationKind::AuthorizeExposure => {}
            }
        }
        match event.kind {
            crate::budget_store::BudgetMutationKind::IncrementInvocation => {
                if event.allowed == Some(true) {
                    invocations += 1;
                }
            }
            crate::budget_store::BudgetMutationKind::AuthorizeExposure => {
                if event.allowed == Some(true) {
                    let exposure = u128::from(event.exposure_units);
                    admitted += exposure;
                    outstanding += exposure;
                    invocations += 1;
                }
            }
            crate::budget_store::BudgetMutationKind::ReverseExposure
            | crate::budget_store::BudgetMutationKind::ExpireHold => {
                let exposure = u128::from(event.exposure_units);
                prop_assert!(outstanding >= exposure);
                prop_assert!(invocations > 0);
                outstanding -= exposure;
                released += exposure;
                invocations -= 1;
            }
            crate::budget_store::BudgetMutationKind::ReleaseExposure => {
                let exposure = u128::from(event.exposure_units);
                prop_assert!(outstanding >= exposure);
                outstanding -= exposure;
                released += exposure;
            }
            crate::budget_store::BudgetMutationKind::ReconcileSpend => {
                let exposure = u128::from(event.exposure_units);
                let realized = u128::from(event.realized_spend_units);
                prop_assert!(realized <= exposure);
                prop_assert!(outstanding >= exposure);
                outstanding -= exposure;
                committed += realized;
                released += exposure - realized;
            }
        }
        prop_assert_eq!(admitted, outstanding + committed + released);
        prop_assert_eq!(u128::from(event.total_cost_exposed_after), outstanding);
        prop_assert_eq!(u128::from(event.total_cost_realized_spend_after), committed);
        prop_assert_eq!(u64::from(event.invocation_count_after), invocations);
    }

    match usage {
        Some(usage) => {
            prop_assert_eq!(u64::from(usage.invocation_count), invocations);
            prop_assert_eq!(u128::from(usage.total_cost_exposed), outstanding);
            prop_assert_eq!(u128::from(usage.total_cost_realized_spend), committed);
        }
        None => prop_assert_eq!((invocations, outstanding, committed), (0, 0, 0)),
    }
    if monetary {
        prop_assert_eq!(drop_hold_authorizations, 1);
        prop_assert_eq!(drop_hold_other_terminal_mutations, 0);
        if dispatch_started {
            prop_assert_eq!(drop_hold_reversals, 0);
            prop_assert_eq!(outstanding, admitted);
            prop_assert_eq!(committed, 0);
            prop_assert_eq!(released, 0);
            prop_assert_eq!(invocations, 1);
        } else {
            prop_assert_eq!(drop_hold_reversals, 1);
            prop_assert_eq!(outstanding, 0);
            prop_assert_eq!(committed, 0);
            prop_assert_eq!(released, admitted);
            prop_assert_eq!(invocations, 0);
        }
    } else {
        prop_assert_eq!(drop_hold_authorizations, 0);
        prop_assert_eq!(drop_hold_reversals, 0);
        prop_assert_eq!(drop_hold_other_terminal_mutations, 0);
    }
    Ok(())
}

// Exhaustively enumerated rather than randomly sampled: with only 8 cells
// in the {monetary} x {dispatch phase} x {lease} table, a per-run random
// draw of all three bools leaves roughly an 11% chance of any single cell
// going undrawn across 32 cases. Walking all 8 combinations deterministically
// guarantees full coverage on every run while keeping proptest's
// prop_assert! machinery (TestCaseError) for the per-case assertions.
#[test]
fn drop_guard_disposition_table() -> Result<(), TestCaseError> {
    let combinations: [(bool, bool, bool); 8] = [
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ];

    for (monetary, dispatch_started, lease_present) in combinations {
        let mut kernel = make_kernel(make_config());
        let admissions = std::sync::Arc::new(AtomicU64::new(0));
        let releases = std::sync::Arc::new(AtomicU64::new(0));
        if lease_present {
            kernel.set_runtime_admission_hook(std::sync::Arc::new(
                CountingReleaseRuntimeAdmissionHook {
                    admissions: std::sync::Arc::clone(&admissions),
                    releases: std::sync::Arc::clone(&releases),
                },
            ));
        }

        let agent_kp = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
            300,
        );
        let request = make_request_with_arguments(
            "req-chio-runtime-drop-proptest",
            &cap,
            "destructive_update",
            "srv-chio-runtime",
            serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        );
        let admission = kernel.run_runtime_admission_hook(&request, None, 0, 0, Some(0));
        prop_assert!(admission.allowed);
        prop_assert_eq!(admissions.load(Ordering::SeqCst), u64::from(lease_present));
        let runtime_admission_metadata = admission.metadata;
        let extra_metadata = runtime_admission_metadata.clone();
        if monetary {
            // Authorize a real hold so pre-dispatch cleanup can reverse it and
            // post-dispatch cleanup can retain it as outcome-unknown exposure.
            authorize_fabricated_drop_hold(&kernel, &cap.id)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let budget_mutation = match monetary.then(make_fabricated_drop_charge) {
            Some(charge) => PreExecutionBudgetMutation::Charge(charge),
            None => PreExecutionBudgetMutation::None,
        };

        let mut guard = PostAdmissionDropGuard::new(
            &kernel,
            &request,
            &cap,
            Some(0),
            &budget_mutation,
            None,
            PostAdmissionReceiptContext {
                evaluation_context: EvaluationReceiptContext::default(),
                extra_metadata,
                runtime_admission_metadata,
                pre_invocation_guard_evidence: Vec::new(),
            },
            // Root cap (no delegation parent): the child-budget release is a
            // no-op regardless, so the newly-inserted gate does not alter this
            // disposition-table coverage. `true` keeps the prior behavior.
            true,
        );
        if dispatch_started {
            guard.mark_dispatch_started();
        }
        drop(guard);

        let receipt_log = kernel.receipt_log();
        if dispatch_started {
            prop_assert_eq!(
                receipt_log.len(),
                1,
                "post-dispatch drop must record exactly one terminal receipt"
            );
            let receipt = receipt_log.get(0);
            prop_assert!(receipt.is_some_and(|receipt| receipt.is_cancelled()));
            prop_assert_eq!(
                releases.load(Ordering::SeqCst),
                0,
                "post-dispatch drop must retain reservations"
            );
            let marker = receipt
                .and_then(|receipt| receipt.metadata.as_ref())
                .and_then(|metadata| metadata.get("chio_runtime"))
                .and_then(|runtime| runtime.get("reservations_retained_fail_closed"))
                .and_then(serde_json::Value::as_bool);
            prop_assert_eq!(
                receipt
                    .and_then(|receipt| receipt.metadata.as_ref())
                    .and_then(|metadata| metadata.get("chio_runtime"))
                    .and_then(|runtime| runtime.get("post_dispatch_outcome_unknown"))
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );
            if monetary {
                prop_assert_eq!(
                    receipt
                        .and_then(|receipt| receipt.metadata.as_ref())
                        .and_then(|metadata| metadata.get("chio_runtime"))
                        .and_then(|runtime| runtime.get("retained_budget_hold_id"))
                        .and_then(serde_json::Value::as_str),
                    Some(DROP_GUARD_HOLD_ID)
                );
                prop_assert_eq!(
                    receipt
                        .and_then(|receipt| receipt.metadata.as_ref())
                        .and_then(|metadata| metadata.get("chio_runtime"))
                        .and_then(|runtime| runtime.get("retained_budget_exposure_units"))
                        .and_then(serde_json::Value::as_u64),
                    Some(5)
                );
            }
            if lease_present {
                prop_assert_eq!(
                    marker,
                    Some(true),
                    "retained reservations must be marked on the receipt"
                );
                prop_assert_eq!(
                    receipt
                        .and_then(|receipt| receipt.metadata.as_ref())
                        .and_then(|metadata| metadata.get("chio_runtime"))
                        .and_then(|runtime| runtime.get("retained_destructive_lease_id"))
                        .and_then(serde_json::Value::as_str),
                    Some("lease-drop-proptest")
                );
            } else {
                prop_assert_eq!(
                    marker,
                    None,
                    "no retained marker without a chio_runtime admission block"
                );
            }
        } else {
            prop_assert_eq!(
                receipt_log.len(),
                0,
                "pre-dispatch drop is the receipt-free fully-unwound exit"
            );
            let expected_releases = u64::from(lease_present);
            prop_assert_eq!(
                releases.load(Ordering::SeqCst),
                expected_releases,
                "pre-dispatch drop must release exactly when admission metadata exists"
            );
        }
        assert_drop_guard_budget_conservation(&kernel, &cap.id, monetary, dispatch_started)?;
    }

    Ok(())
}
