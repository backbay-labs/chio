use super::*;

use chio_log_redact::redacted;

use crate::payment::{
    PaymentAdapter, PaymentJournalRecord, PaymentJournalState, PaymentSettleAction,
    RailSettlementState,
};
use crate::receipt_store::{
    DispatchIntentReconciler, DispatchIntentRecord, DispatchIntentResolution, ReceiptStoreError,
    SideEffectClass,
};

/// Terminal outcome of reconciling one incomplete payment-journal row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentReconcileOutcome {
    /// Money moved and the attested receipt already exists; closed.
    ClosedAttested,
    /// Money moved; a reconciliation receipt was emitted for the rail
    /// reference.
    ClosedReconciled {
        /// `rail:authorization_id` reference an operator can match against
        /// rail-side records.
        rail_reference: String,
    },
    /// Funds were only held and the hold was released; closed.
    Released,
    /// The outcome could not be settled or determined; operator incident.
    ReconcileFailed {
        /// Why the row could not be resolved.
        detail: String,
    },
}

/// Summary of one reconciliation pass over the payment journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaymentReconcileReport {
    /// Rows that reached a terminal closed or released state.
    pub resolved: u64,
    /// Rows marked as operator incidents.
    pub reconcile_failed: u64,
}

impl ChioKernel {
    /// Reconcile every incomplete payment-journal row created at least
    /// `horizon_secs` ago. Deterministic per row and idempotent: each
    /// request resolves to exactly one of closed, released, or a
    /// reconcile-failed incident; a second pass finds nothing and moves no
    /// money. Runs once at store attach and is public so embedders can
    /// drive it explicitly.
    pub fn reconcile_payment_journal(
        &self,
        horizon_secs: u64,
    ) -> Result<PaymentReconcileReport, KernelError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        let cutoff = now_ms.saturating_sub(horizon_secs.saturating_mul(1_000));
        let rows = self.with_budget_store(|store| {
            store
                .list_incomplete_payment_journal(cutoff)
                .map_err(KernelError::from)
        })?;
        let mut report = PaymentReconcileReport::default();
        for record in &rows {
            match resolve_and_finalize_payment_journal_row(self, record)? {
                PaymentReconcileOutcome::ReconcileFailed { .. } => report.reconcile_failed += 1,
                _ => report.resolved += 1,
            }
        }
        Ok(report)
    }
}

/// Resolve one incomplete row and apply its terminal journal transition:
/// successful outcomes close the row; failures move it to `ReconcileFailed`
/// with a loud operator incident. Shared by the boot pass and the monetary
/// dispatch-intent reconciler.
pub(crate) fn resolve_and_finalize_payment_journal_row(
    kernel: &ChioKernel,
    record: &PaymentJournalRecord,
) -> Result<PaymentReconcileOutcome, KernelError> {
    let outcome = resolve_incomplete_payment_journal_row(kernel, record)?;
    match &outcome {
        PaymentReconcileOutcome::ReconcileFailed { detail } => {
            kernel.with_budget_store(|store| {
                store
                    .advance_payment_journal(
                        &record.request_id,
                        record.state,
                        PaymentJournalState::ReconcileFailed,
                        None,
                        None,
                        None,
                    )
                    .map_err(KernelError::from)
            })?;
            tracing::error!(
                request_id = %record.request_id,
                rail = %record.rail,
                authorization_id = ?record.authorization_id,
                detail = %redacted!(&detail),
                "payment reconcile failed; operator incident"
            );
        }
        _ => {
            kernel.with_budget_store(|store| {
                store
                    .close_payment_journal(&record.request_id)
                    .map_err(KernelError::from)
            })?;
        }
    }
    Ok(outcome)
}

/// The deterministic per-row resolver. Never selects a new amount: a
/// `Settling` row replays exactly its recorded settle action and amount, and
/// every ambiguity resolves to a `ReconcileFailed` incident rather than a
/// guess.
fn resolve_incomplete_payment_journal_row(
    kernel: &ChioKernel,
    record: &PaymentJournalRecord,
) -> Result<PaymentReconcileOutcome, KernelError> {
    let Some(adapter) = kernel.payment_adapter.as_deref() else {
        return Ok(PaymentReconcileOutcome::ReconcileFailed {
            detail: "no payment adapter configured for reconcile".to_string(),
        });
    };
    match record.state {
        PaymentJournalState::HoldPlaced => {
            // Authorize may or may not have fired; no authorization id is
            // durable. The side-effect-free state query keyed by the durable
            // reference answers which, and the returned state distinguishes
            // a live hold from funds that already moved: only a proven
            // hold-only state is ever released.
            match adapter.settlement_state(&record.request_id, record.authorization_id.as_deref()) {
                Ok(RailSettlementState::NoAuthorization) => {
                    // Authorize never took effect: nothing to release on the
                    // rail, and funds never moved.
                    reverse_hold_best_effort(kernel, record);
                    Ok(PaymentReconcileOutcome::Released)
                }
                Ok(RailSettlementState::Held { authorization_id }) => {
                    // A live hold with no settlement: no price was ever
                    // chosen, so release is the only sound, price-free
                    // completion.
                    Ok(release_hold_and_report(
                        kernel,
                        adapter,
                        record,
                        &authorization_id,
                    ))
                }
                Ok(RailSettlementState::Settled {
                    authorization_id,
                    result,
                }) => {
                    // Funds already moved: releasing here would reverse the
                    // local hold and erase the only record of the charge.
                    // Record the rail reference and emit a reconciliation
                    // receipt for the already-moved amount instead.
                    let mut settled_record = record.clone();
                    settled_record.authorization_id = Some(authorization_id.clone());
                    settled_record.transaction_id = Some(result.transaction_id.clone());
                    emit_reconciliation_receipt(kernel, &settled_record)?;
                    Ok(PaymentReconcileOutcome::ClosedReconciled {
                        rail_reference: format!("{}:{authorization_id}", record.rail),
                    })
                }
                Err(error) => {
                    // The adapter cannot say whether funds moved: never
                    // guess. A silent release here could erase the only
                    // record of a charge that already happened.
                    Ok(PaymentReconcileOutcome::ReconcileFailed {
                        detail: format!("settlement state during reconcile is unknown: {error}"),
                    })
                }
            }
        }
        PaymentJournalState::Authorized => {
            // Authorize succeeded but no terminal action was ever committed.
            // For the in-tree prepaid X402/ACP adapters, funds move inside
            // authorize itself, and this state spans the entire tool-
            // execution window (the post-execution settle is skipped when
            // authorization.settled == true, so the journal never advances
            // past Authorized until close). A crash anywhere in that window
            // must not be resolved by guessing: the side-effect-free state
            // query keyed by the durable reference and authorization id
            // answers whether funds already moved, exactly like the
            // HoldPlaced arm above, so a release is never issued against
            // money that already moved.
            let Some(authorization_id) = record.authorization_id.as_deref() else {
                return Ok(PaymentReconcileOutcome::ReconcileFailed {
                    detail: "authorized row missing authorization_id".to_string(),
                });
            };
            match adapter.settlement_state(&record.request_id, Some(authorization_id)) {
                Ok(RailSettlementState::NoAuthorization) => {
                    // The rail has no record of this authorization: nothing
                    // to release, and funds never moved.
                    reverse_hold_best_effort(kernel, record);
                    Ok(PaymentReconcileOutcome::Released)
                }
                Ok(RailSettlementState::Held { authorization_id }) => {
                    // A live hold with no settlement: no price was ever
                    // chosen, so release is the only sound, price-free
                    // completion.
                    Ok(release_hold_and_report(
                        kernel,
                        adapter,
                        record,
                        &authorization_id,
                    ))
                }
                Ok(RailSettlementState::Settled {
                    authorization_id,
                    result,
                }) => {
                    // Funds already moved -- the common case for the
                    // in-tree prepaid rails, which settle at authorize.
                    // Releasing here would reverse the local hold and erase
                    // the only record of the charge. Record the rail
                    // reference and emit a reconciliation receipt for the
                    // already-moved amount instead.
                    let mut settled_record = record.clone();
                    settled_record.authorization_id = Some(authorization_id.clone());
                    settled_record.transaction_id = Some(result.transaction_id.clone());
                    emit_reconciliation_receipt(kernel, &settled_record)?;
                    Ok(PaymentReconcileOutcome::ClosedReconciled {
                        rail_reference: format!("{}:{authorization_id}", record.rail),
                    })
                }
                Err(error) => {
                    // The adapter cannot say whether funds moved: never
                    // guess. A silent release here could erase the only
                    // record of a charge that already happened.
                    Ok(PaymentReconcileOutcome::ReconcileFailed {
                        detail: format!("settlement state during reconcile is unknown: {error}"),
                    })
                }
            }
        }
        PaymentJournalState::Settling => {
            // A terminal action IS durable; replay it exactly. The adapter
            // contract makes capture and release idempotent on
            // (authorization_id, reference), so the replay moves money at
            // most once.
            let Some(authorization_id) = record.authorization_id.as_deref() else {
                return Ok(PaymentReconcileOutcome::ReconcileFailed {
                    detail: "settling row missing authorization_id".to_string(),
                });
            };
            match record.settle_action {
                Some(PaymentSettleAction::Capture) => {
                    let Some(amount) = record.settle_amount_units else {
                        return Ok(PaymentReconcileOutcome::ReconcileFailed {
                            detail: "settling capture row missing settle_amount_units".to_string(),
                        });
                    };
                    match adapter.capture(
                        authorization_id,
                        amount,
                        &record.currency,
                        &record.request_id,
                    ) {
                        Ok(_) => {
                            emit_reconciliation_receipt(kernel, record)?;
                            Ok(PaymentReconcileOutcome::ClosedReconciled {
                                rail_reference: format!("{}:{authorization_id}", record.rail),
                            })
                        }
                        Err(error) => Ok(PaymentReconcileOutcome::ReconcileFailed {
                            detail: format!("capture replay during reconcile failed: {error}"),
                        }),
                    }
                }
                Some(PaymentSettleAction::Release) => {
                    match adapter.release(authorization_id, &record.request_id) {
                        Ok(_) => {
                            reverse_hold_best_effort(kernel, record);
                            Ok(PaymentReconcileOutcome::Released)
                        }
                        Err(error) => Ok(PaymentReconcileOutcome::ReconcileFailed {
                            detail: format!("release replay during reconcile failed: {error}"),
                        }),
                    }
                }
                None => Ok(PaymentReconcileOutcome::ReconcileFailed {
                    detail: "settling row missing its committed settle action".to_string(),
                }),
            }
        }
        PaymentJournalState::Settled => {
            // The money moved but the row never closed, so the receipt may
            // not have committed. Receipts carry no request id, so the
            // conservative resolution is to emit a signed reconciliation
            // receipt for the already-moved amount; a duplicate next to an
            // existing attested receipt is advisory surplus, never a second
            // charge.
            emit_reconciliation_receipt(kernel, record)?;
            let rail_reference = record
                .authorization_id
                .as_deref()
                .map(|authorization_id| format!("{}:{authorization_id}", record.rail))
                .unwrap_or_else(|| record.rail.clone());
            Ok(PaymentReconcileOutcome::ClosedReconciled { rail_reference })
        }
        PaymentJournalState::Closed | PaymentJournalState::ReconcileFailed => {
            Ok(PaymentReconcileOutcome::ClosedAttested)
        }
    }
}

/// Release a hold proven to carry no settlement and report the outcome.
/// Releasing is idempotent and price-free, so success always reverses the
/// local exposure and closes the row; a release failure is an operator
/// incident, never a silent retry loop.
fn release_hold_and_report(
    kernel: &ChioKernel,
    adapter: &dyn PaymentAdapter,
    record: &PaymentJournalRecord,
    authorization_id: &str,
) -> PaymentReconcileOutcome {
    match adapter.release(authorization_id, &record.request_id) {
        Ok(_) => {
            reverse_hold_best_effort(kernel, record);
            PaymentReconcileOutcome::Released
        }
        Err(error) => PaymentReconcileOutcome::ReconcileFailed {
            detail: format!("release during reconcile failed: {error}"),
        },
    }
}

/// Return held-but-never-captured budget capacity. Best-effort: capacity is
/// fail-closed under-spend and the orphaned-hold sweeper also releases
/// leaked holds, so a reverse failure is warned, never fatal to the pass.
fn reverse_hold_best_effort(kernel: &ChioKernel, record: &PaymentJournalRecord) {
    let Some(hold_id) = record.hold_id.as_deref() else {
        return;
    };
    let reversed = kernel.with_budget_store(|store| {
        store
            .reverse_budget_hold(crate::budget_store::BudgetReverseHoldRequest {
                capability_id: record.capability_id.clone(),
                grant_index: record.grant_index as usize,
                reversed_exposure_units: record.amount_units,
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:reconcile-reverse")),
                authority: None,
            })
            .map_err(KernelError::from)
    });
    if let Err(error) = reversed {
        tracing::warn!(
            request_id = %record.request_id,
            hold_id = %hold_id,
            reason = %redacted!(&error.to_string()),
            "budget hold reverse during payment reconcile failed; the hold sweeper will release it"
        );
    }
}

/// Emit a signed reconciliation receipt attesting the already-moved amount,
/// so a settled rail movement is never left without a durable record.
fn emit_reconciliation_receipt(
    kernel: &ChioKernel,
    record: &PaymentJournalRecord,
) -> Result<(), KernelError> {
    let receipt_content = receipt_content_for_output(None, None)?;
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "requestId": record.request_id,
        "rail": record.rail,
    }))
    .map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "failed to hash reconciliation parameters: {error}"
        ))
    })?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let metadata = serde_json::json!({
        "financial": {
            "cost_charged": record.settle_amount_units.unwrap_or(record.amount_units),
            "currency": record.currency,
            "payment_reference": record.authorization_id,
            "settlement_status": "settled",
        },
        "payment_reconciliation": {
            "requestId": record.request_id,
            "rail": record.rail,
            "authorizationId": record.authorization_id,
            "transactionId": record.transaction_id,
        },
    });
    let receipt = kernel.build_and_sign_receipt(ReceiptParams {
        request_id: Some(&record.request_id),
        capability_id: &record.capability_id,
        tool_name: "payment.reconcile",
        server_id: &record.rail,
        decision: Decision::Allow,
        action,
        content_hash: receipt_content.content_hash,
        canonical_content: receipt_content.canonical_content,
        metadata: Some(metadata),
        timestamp,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: record.tenant_id.clone(),
    })?;
    kernel.record_chio_receipt(&receipt)
}

/// Bridges the generic dispatch-intent boot reconcile to the money-path
/// resolver: a monetary orphan is resolved by looking up its payment-journal
/// row and running the deterministic completion. Non-monetary orphans keep
/// the default outcome-unknown dead-letter.
pub struct MonetaryDispatchIntentReconciler<'a> {
    /// Kernel whose payment adapter and budget store drive the resolution.
    pub kernel: &'a ChioKernel,
}

impl DispatchIntentReconciler for MonetaryDispatchIntentReconciler<'_> {
    fn resolve(
        &self,
        intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError> {
        if intent.side_effect_class != SideEffectClass::Monetary {
            return DefaultDispatchIntentReconciler.resolve(intent);
        }
        let row = self
            .kernel
            .with_budget_store(|store| {
                store
                    .get_payment_journal(&intent.request_id)
                    .map_err(KernelError::from)
            })
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
        let Some(record) = row else {
            // No incomplete journal row. This is usually a clean
            // termination (closed against a receipt), but the money-path
            // pass may instead have already given up on this exact request
            // and left a ReconcileFailed row: get_payment_journal never
            // surfaces that row (it is a closed incident, not an
            // incomplete one), so treating it the same as a clean close
            // would hide a genuine, unresolved money-path incident behind
            // a healthy dispatch-intent surface. Check for that incident
            // before reporting clean.
            let reconcile_failed_rail = self
                .kernel
                .with_budget_store(|store| {
                    store
                        .payment_journal_reconcile_failed_rail(&intent.request_id)
                        .map_err(KernelError::from)
                })
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
            if let Some(rail) = reconcile_failed_rail {
                return Ok(DispatchIntentResolution::DeadLetter {
                    detail: format!(
                        "payment journal reconcile failed for rail {rail}; an operator must \
                         resolve the payment-journal incident before this intent can be \
                         treated as clean"
                    ),
                });
            }
            // The money path already terminated cleanly. Record the rail
            // reference the intent carries.
            let rail_reference = intent
                .rail_authorization_id
                .clone()
                .or_else(|| intent.rail.clone())
                .unwrap_or_default();
            return Ok(DispatchIntentResolution::MonetaryReconciled { rail_reference });
        };
        match resolve_and_finalize_payment_journal_row(self.kernel, &record)
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?
        {
            PaymentReconcileOutcome::ReconcileFailed { detail } => {
                Ok(DispatchIntentResolution::DeadLetter { detail })
            }
            PaymentReconcileOutcome::ClosedReconciled { rail_reference } => {
                Ok(DispatchIntentResolution::MonetaryReconciled { rail_reference })
            }
            PaymentReconcileOutcome::ClosedAttested => {
                let rail_reference = record
                    .authorization_id
                    .as_deref()
                    .map(|authorization_id| format!("{}:{authorization_id}", record.rail))
                    .unwrap_or_else(|| record.rail.clone());
                Ok(DispatchIntentResolution::MonetaryReconciled { rail_reference })
            }
            PaymentReconcileOutcome::Released => Ok(DispatchIntentResolution::SafeToReplay),
        }
    }
}
