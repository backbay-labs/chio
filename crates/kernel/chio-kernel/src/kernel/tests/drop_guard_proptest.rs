// Post-admission drop-guard disposition-table property test. For every combination of
// {monetary, non-monetary} x {pre-dispatch, post-dispatch} x {lease
// present, absent}, a directly constructed PostAdmissionDropGuard must
// obey the fail-closed disposition table:
//   - post-dispatch drop: exactly one Cancelled terminal receipt;
//     reservations retained (never released); the retained marker present
//     iff a chio_runtime admission block was present;
//   - pre-dispatch drop: no receipt; reservations released iff a
//     chio_runtime admission block was present.

use proptest::prelude::*;

struct CountingReleaseRuntimeAdmissionHook {
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
        Ok(RuntimeAdmissionDecision::allow(None))
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
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
        let releases = std::sync::Arc::new(AtomicU64::new(0));
        kernel.set_runtime_admission_hook(std::sync::Arc::new(
            CountingReleaseRuntimeAdmissionHook {
                releases: std::sync::Arc::clone(&releases),
            },
        ));

        let agent_kp = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant(
                "srv-chio-runtime",
                "destructive_update",
            )]),
            300,
        );
        let request = make_request_with_arguments(
            "req-chio-runtime-drop-proptest",
            &cap,
            "destructive_update",
            "srv-chio-runtime",
            serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        );
        let extra_metadata = lease_present.then(|| {
            serde_json::json!({
                "chio_runtime": {
                    "admission_id": "adm-drop-proptest",
                    "accepted": true,
                    "reserved_destructive_lease_id": "lease-drop-proptest",
                    "failure_code": null
                }
            })
        });
        if monetary {
            // A monetary drop reverses a real hold; authorize one so the
            // pre-dispatch unwind is clean (a failed reversal would record a
            // fault receipt).
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
                extra_metadata,
                pre_invocation_guard_evidence: Vec::new(),
                verified_payee_binding: None,
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
            if lease_present {
                prop_assert_eq!(
                    marker,
                    Some(true),
                    "retained reservations must be marked on the receipt"
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
    }

    Ok(())
}
