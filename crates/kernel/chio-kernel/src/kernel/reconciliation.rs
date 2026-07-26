//! Reconcile-by-nonce: the entry point where a mediated pre-execution
//! authorization becomes an authoritative spend.
//!
//! The mediated `/v1/evaluate` route reserves a durable budget hold at the
//! worst-case cost and mints a signed execution nonce bound to that hold
//! (`reserved_hold_id`). The caller executes the real tool downstream at a
//! server that shares the budget store, then presents the nonce back here with
//! the measured realized cost. This module settles the exact reserved hold at
//! that realized cost, releases the reserved-minus-realized difference back to
//! the grant, and signs a completed, authoritative mediated-spend receipt.
//!
//! It also exposes the reserved-hold TTL reaper: a wrapper that settles expired,
//! unreconciled reserved holds at their reserved worst-case (forfeit). The TTL
//! deadline itself is stamped from the minted nonce's exact expiry at reserve
//! time, so a hold never expires before its own nonce. Fail-closed on the money
//! path.

use chio_log_redact::redacted;

use super::*;

use crate::budget_store::{
    BudgetCaptureInvocationRequest, BudgetHoldSnapshot, BudgetInvocationCaptureDecision,
    BudgetReconcileHoldRequest,
};
use crate::execution_nonce::{
    consume_execution_nonce, verify_execution_nonce_without_consume, SignedExecutionNonce,
};

/// Canonical inert currency stamped onto the signed receipt for a zero-exposure
/// invocation reconcile. Such a reserve carries no reserved currency, so its
/// realized currency is never validated (see step 3); using this fixed,
/// attacker-uncontrollable value keeps an unchecked caller-supplied string off
/// the signed artifact while still marking the receipt as carrying no monetary
/// envelope.
const INVOCATION_RECONCILE_RECEIPT_CURRENCY: &str = "";

impl ChioKernel {
    /// Settle every expired, unreconciled reserved budget hold at its reserved
    /// worst-case, forfeiting the reserved amount to realized spend. In the
    /// two-phase reserve/reconcile flow the only evidence a spend occurred is the
    /// caller's reconcile; an expired-and-unreconciled hold may correspond to a
    /// call that executed and spent, so releasing it would under-count real spend
    /// and fail open for a cumulative spend cap. Self-healing and fail-closed: a
    /// still-valid reserved hold and any reconciled/reversed/released hold are
    /// never touched, and a settled hold is idempotent under repeated reaps.
    /// Returns the number of holds settled. The sidecar drives this on a timer
    /// (startup wiring is a later task); this method is the reachable primitive.
    pub fn reap_expired_reserved_budget_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, KernelError> {
        // Reserved holds this reap will settle (open, past their reserved expiry)
        // still hold their delegated child's sibling-sum share admitted. Capture
        // that set before settling so the parent's headroom is released once, and
        // only, for the holds the store actually forfeits. The predicate mirrors
        // the store reaper's contract (open + reserved_until <= now).
        let tracked = self.tracked_reserved_sibling_hold_ids();
        let (expiring, already_closed) = self.with_budget_store(|store| {
            let mut expiring = Vec::new();
            let mut already_closed = Vec::new();
            for hold_id in &tracked {
                match store.get_budget_hold(hold_id)? {
                    Some(hold)
                        if hold.disposition.is_open()
                            && hold
                                .reserved_until
                                .is_some_and(|until| until <= now_unix_secs) =>
                    {
                        expiring.push(hold_id.clone());
                    }
                    Some(hold) if !hold.disposition.is_open() => {
                        already_closed.push(hold_id.clone());
                    }
                    None => already_closed.push(hold_id.clone()),
                    Some(_) => {}
                }
            }
            Ok((expiring, already_closed))
        })?;
        for hold_id in already_closed {
            self.release_reserved_sibling_share_for_hold(&hold_id);
        }
        // Run the store reap but do NOT propagate its error yet. If the store
        // settled some holds before failing partway through the sweep, those
        // closed holds' sibling shares must still be released, or a closed hold's
        // admitted share leaks (the next sweep no longer sees it as open) and
        // wrongly denies valid sibling reservations until restart.
        let reap_result =
            self.with_budget_store(|store| Ok(store.reap_expired_reserved_holds(now_unix_secs)?));

        // Release the sibling share for exactly those expiring holds the store
        // actually closed. Re-query each hold's disposition: a hold now closed or
        // missing was forfeited, so its share is freed; a hold still open was not
        // settled by the store, so its share is retained. Fail-closed on the
        // re-query itself: a hold whose disposition cannot be read keeps its share
        // held, so a read error never frees a share for a still-open hold.
        for hold_id in &expiring {
            let closed = match self.with_budget_store(|store| Ok(store.get_budget_hold(hold_id)?)) {
                Ok(Some(hold)) => !hold.disposition.is_open(),
                Ok(None) => true,
                Err(_) => false,
            };
            if closed {
                self.release_reserved_sibling_share_for_hold(hold_id);
            }
        }

        // Propagate any store reap error only after the settled holds' shares are
        // released.
        let settled = reap_result?;
        Ok(settled)
    }

    /// Reconcile the reserved budget hold named by a presented execution nonce
    /// at its measured realized cost, producing an authoritative mediated-spend
    /// receipt. Fail-closed at every step.
    ///
    /// Order of checks:
    /// 1. The presented `arguments` must hash to the nonce's bound parameter
    ///    hash (the caller must have executed the exact call the nonce authorizes).
    /// 2. The nonce must name a reserved hold (`reserved_hold_id`).
    /// 3. The realized currency must equal the currency the grant/hold was
    ///    authorized in. This is checked BEFORE the nonce is consumed, so a
    ///    mismatch is rejected fail-closed without burning the nonce or settling,
    ///    and an unchecked caller-supplied currency never reaches a signed receipt.
    /// 4. The nonce is VERIFIED (schema, expiry, signature under the kernel key,
    ///    and that it has not already been consumed) but is NOT yet marked
    ///    consumed. A forged or tampered nonce fails the signature check; an
    ///    already-settled nonce fails the replay check; neither is ever marked.
    /// 5. The named hold must still be open. A missing or already-closed hold is
    ///    rejected. This open-to-closed settle is the mutual-exclusion point: two
    ///    concurrent presentations of the same nonce cannot both settle because
    ///    the store closes the hold atomically (the second finds it closed and is
    ///    rejected here), so deferring the nonce mark opens no double-settle window.
    /// 6. The hold is settled at `min(realized_cost, reserved)` -- realized cost
    ///    is CLAMPED to the reserved worst-case, since the payer never authorized
    ///    more than the reserved envelope. A realized cost of zero settles the
    ///    hold at zero, releasing the entire reserved amount back to the grant.
    /// 7. The nonce is marked consumed (single-use replay) ONLY after the settle
    ///    succeeds. A transient store error at step 6 therefore leaves the nonce
    ///    unconsumed, so the caller can re-present the same signed nonce and settle
    ///    at realized cost instead of forfeiting the reservation. Once the hold is
    ///    closed a replay is already rejected at step 5, so marking after
    ///    settlement is safe.
    /// 8. A completed allow receipt is signed with the reconciled hold lineage
    ///    and the nonce id, so `is_authoritative_spend_receipt` accepts it.
    pub fn reconcile_reserved_authorization_by_nonce(
        &self,
        presented_nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        realized_cost: &ToolInvocationCost,
    ) -> Result<ToolCallResponse, KernelError> {
        // (1) The caller must present the exact arguments the nonce authorized.
        // The nonce binding carries the signed parameter hash; comparing it to
        // the presented arguments ties the realized-cost claim to the signed call.
        let action = ToolCallAction::from_parameters(arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash arguments for reconcile-by-nonce binding: {e}"
            ))
        })?;
        if action.parameter_hash != presented_nonce.nonce.bound_to.parameter_hash {
            return Err(KernelError::Internal(
                "reconcile-by-nonce arguments do not match the nonce parameter binding".to_string(),
            ));
        }

        // (2) The nonce must name a reserved hold. Read the signed hold id up
        // front so the caller-supplied realized currency can be validated against
        // the reserved grant currency BEFORE the nonce is verified and consumed.
        let reserved_hold_id = presented_nonce.reserved_hold_id().ok_or_else(|| {
            KernelError::Internal(
                "presented nonce does not name a reserved budget hold; nothing to reconcile"
                    .to_string(),
            )
        })?;
        let bound_capability_id = presented_nonce.nonce.bound_to.capability_id.clone();

        // (3) Currency check (fail-closed): reject a realized currency that
        // differs from the currency the grant/hold was authorized in, before
        // settling or signing, so an unchecked caller-supplied currency is never
        // stamped onto a signed authoritative receipt. Doing this ahead of nonce
        // consumption means a mismatch does not burn the nonce (the caller can
        // retry with the correct currency). Defers to the signature check below
        // when the named hold is absent, so a forged/tampered nonce is still
        // rejected as a nonce error rather than masked by hold-not-found.
        self.with_budget_store(|store| {
            let Some(hold) = store.get_budget_hold(reserved_hold_id)? else {
                return Ok(());
            };
            if hold.authorized_exposure_units == 0 {
                return Ok(());
            }
            match hold.reserved_currency.as_deref() {
                Some(reserved) if reserved == realized_cost.currency => Ok(()),
                Some(reserved) => Err(KernelError::Internal(format!(
                    "reconcile-by-nonce realized currency `{}` does not match the reserved grant currency `{reserved}`",
                    realized_cost.currency
                ))),
                // A non-monetary invocation reservation carries zero exposure and
                // no currency, so there is no monetary envelope to validate; it
                // settles the invocation at zero. A monetary hold always records
                // its currency when reserved, so a missing currency alongside a
                // non-zero exposure is a corrupted reserved hold and stays
                // fail-closed.
                None => Err(KernelError::Internal(format!(
                    "reconcile-by-nonce cannot validate realized currency for reserved hold `{reserved_hold_id}`: no reserved grant currency recorded"
                ))),
            }
        })?;

        // (4) Verify the nonce but do NOT consume it yet. Verifying against the
        // nonce's own binding makes the binding self-check trivially pass while
        // the signature check (over the full body including reserved_hold_id)
        // still rejects any forgery or tamper, and the replay peek rejects an
        // already-consumed nonce. The single-use mark is deferred to step 7 so a
        // transient settle error below leaves the nonce replayable for a retry.
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal(
                "execution nonce store is not installed; cannot reconcile by nonce".to_string(),
            )
        })?;
        let now_unix = current_unix_timestamp();
        let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
        verify_execution_nonce_without_consume(
            presented_nonce,
            &self.config.keypair.public_key(),
            &presented_nonce.nonce.bound_to,
            now,
            store,
        )
        .map_err(|error| {
            KernelError::Internal(format!("reconcile-by-nonce rejected the nonce: {error}"))
        })?;

        // (5)+(6) Look up the exact hold and reconcile it, all under one budget
        // store lock so the open-state check and the settle are atomic.
        let realized_units = realized_cost.units;
        let (hold, committed_before, reconcile, guarantee_level, budget_profile, metering_profile) =
            self.with_budget_store(|store| {
                let hold: BudgetHoldSnapshot =
                    store.get_budget_hold(reserved_hold_id)?.ok_or_else(|| {
                        KernelError::Internal(format!(
                            "reserved budget hold `{reserved_hold_id}` not found for reconcile-by-nonce"
                        ))
                    })?;
                if !hold.disposition.is_open() {
                    return Err(KernelError::Internal(format!(
                        "reserved budget hold `{reserved_hold_id}` is {} and cannot be reconciled",
                        hold.disposition.as_str()
                    )));
                }
                if hold.capability_id != bound_capability_id {
                    return Err(KernelError::Internal(format!(
                        "reserved budget hold `{reserved_hold_id}` capability does not match the nonce binding"
                    )));
                }

                let exposed = hold.remaining_exposure_units;
                // CLAMP: the payer authorized only the reserved worst-case.
                let realized = realized_units.min(exposed);
                let committed_before = match store.get_usage(&hold.capability_id, hold.grant_index)? {
                    Some(usage) => usage.committed_cost_units()?,
                    None => exposed,
                };
                let capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                    capability_id: hold.capability_id.clone(),
                    grant_index: hold.grant_index,
                    hold_id: hold.hold_id.clone(),
                    event_id: format!("{}:capture-invocation", hold.hold_id),
                    trusted_time: None,
                    authority: hold.authority.clone(),
                })?;
                let capture = match capture {
                    BudgetInvocationCaptureDecision::Captured(mutation)
                    | BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => mutation,
                };
                let reconcile = if exposed == 0 {
                    capture
                } else {
                    store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: hold.capability_id.clone(),
                        grant_index: hold.grant_index,
                        exposed_cost_units: exposed,
                        realized_spend_units: realized,
                        hold_id: Some(hold.hold_id.clone()),
                        event_id: Some(format!("{}:reconcile", hold.hold_id)),
                        authority: hold.authority.clone(),
                    })?
                };
                Ok((
                    hold,
                    committed_before,
                    reconcile,
                    store.budget_guarantee_level(),
                    store.budget_authority_profile(),
                    store.budget_metering_profile(),
                ))
            })?;

        // (7) The hold settled successfully and is now closed, so take the
        // single-use nonce mark. Deferring it to here means a transient store
        // error at the settle above left the nonce unconsumed, so the caller can
        // re-present the same signed nonce and settle at realized cost rather than
        // forfeiting the reservation. A consume failure now is non-fatal: the
        // settle is already irreversible and the closed hold alone rejects any
        // replay (a second presentation fails the open-hold check at step 5), so
        // log it and continue rather than deny a spend that truly committed.
        if let Err(error) = consume_execution_nonce(
            store,
            presented_nonce.nonce_id(),
            presented_nonce.expires_at(),
        ) {
            warn!(
                nonce_id = %presented_nonce.nonce_id(),
                hold_id = %hold.hold_id,
                reason = %redacted!(&error),
                "failed to mark the reconcile nonce consumed after an irreversible settlement; \
                 the closed hold still rejects any replay"
            );
        }

        // The reserved hold is now settled (closed), so release the sibling-sum
        // share it kept admitted, freeing the parent's headroom for a sibling.
        // Done before the receipt is built so a later signing error still frees
        // the headroom; a no-op for a root hold that never held a share.
        self.release_reserved_sibling_share_for_hold(reserved_hold_id);

        let exposed = hold.remaining_exposure_units;
        let realized = realized_units.min(exposed);

        // Currency stamped onto the signed receipt. A monetary hold validated the
        // realized currency against the reserved grant currency in step 3, so it is
        // safe to echo. A zero-exposure invocation reserve carries no reserved
        // currency and never validated the realized currency, so normalize it to the
        // inert value rather than land an unchecked caller-supplied string on a
        // signed artifact (the step-3 guarantee).
        let receipt_currency = if hold.authorized_exposure_units == 0 {
            INVOCATION_RECONCILE_RECEIPT_CURRENCY.to_string()
        } else {
            realized_cost.currency.clone()
        };

        // Reconstruct the authorize lineage from the reserved hold so the
        // receipt records the same guarantee/authority context the reserving
        // authorization committed, plus the reconcile terminal and the nonce id.
        let authorize_metadata = BudgetCommitMetadata {
            authority: hold.authority.clone(),
            guarantee_level,
            budget_profile,
            metering_profile,
            budget_commit_index: None,
            event_id: Some(format!("{}:authorize", hold.hold_id)),
            recorded_at_unix_seconds: Some(now_unix),
        };
        let charge = BudgetChargeResult {
            grant_index: hold.grant_index,
            cost_charged: exposed,
            currency: receipt_currency.clone(),
            budget_total: exposed,
            new_committed_cost_units: committed_before,
            budget_hold_id: hold.hold_id.clone(),
            authorize_metadata,
            invocation_capture: None,
        };
        let budget_metadata = self.budget_execution_receipt_metadata(
            &charge,
            Some(("reconciled", &reconcile)),
            Some(presented_nonce.nonce_id()),
        );

        // Report the GRANT's budget and delegation lineage, recorded on the reserved
        // hold at reserve time, so dashboards and reports see the grant ceiling and
        // true lineage rather than this single reservation's exposure. A grant with a
        // per-invocation cap but no `max_total_cost` records u64::MAX as its sentinel
        // ceiling; that sentinel must never surface on a signed receipt, so treat it
        // (and a hold reserved before these fields existed, or a zero-exposure
        // invocation reserve) as having no recorded ceiling and fall back to this
        // reservation's bounded exposure and the nonce subject.
        let grant_budget_total = hold
            .reserved_budget_total
            .filter(|&total| total != u64::MAX)
            .unwrap_or(exposed);
        // Remaining is the grant ceiling minus the grant's TOTAL committed spend
        // after this settle (committed_before - exposed + realized), not just this
        // reconcile's realized cost. Subtracting only the realized cost would ignore
        // every other reservation or spend already committed on the grant and
        // overstate the remaining budget. Mirrors the inline unmeasured-cost path.
        let committed_after = reconcile.committed_cost_units_after;
        let financial = FinancialReceiptMetadata {
            grant_index: hold.grant_index as u32,
            cost_charged: realized,
            currency: receipt_currency,
            budget_remaining: grant_budget_total.saturating_sub(committed_after),
            budget_total: grant_budget_total,
            delegation_depth: hold.reserved_delegation_depth.unwrap_or(0),
            root_budget_holder: hold
                .reserved_root_budget_holder
                .clone()
                .unwrap_or_else(|| presented_nonce.nonce.bound_to.subject_id.clone()),
            // Stamp the rail transaction id captured for a prepaid MustPrepay
            // reservation (recorded on the reserved hold at reserve time), so the
            // authoritative reconciled receipt ties the spend to the payment that
            // funded it. `None` for a mediated reserve that carried no prepayment.
            payment_reference: hold.reserved_payment_reference.clone(),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: realized_cost.breakdown.clone(),
            oracle_evidence: None,
            attempted_cost: None,
        };
        let metadata = merge_metadata_objects(
            Some(serde_json::json!({ "financial": financial })),
            Some(budget_metadata),
        );

        let receipt_content = receipt_content_for_output(None, None)?;
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: presented_nonce.reserving_request_id(),
            capability_id: &bound_capability_id,
            tool_name: &presented_nonce.nonce.bound_to.tool_name,
            server_id: &presented_nonce.nonce.bound_to.tool_server,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp: now_unix,
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: None,
        })?;

        let request_id = presented_nonce
            .reserving_request_id()
            .map(str::to_string)
            .unwrap_or_else(|| receipt.id.clone());

        // The nonce is already consumed and the hold closed: settlement is
        // IRREVERSIBLE by this point. If the durable receipt persist fails now, a
        // retry cannot recreate the receipt (the nonce is a replay, the hold is
        // closed), so the caller would be left with no authoritative receipt for a
        // spend that really settled. Return the signed authoritative receipt and log
        // the persist failure rather than surfacing only the error. A settlement
        // FAILURE earlier (forged/replayed nonce, closed hold, currency mismatch)
        // still fails closed above, before this point.
        if let Err(error) = self.record_chio_receipt(&receipt) {
            warn!(
                request_id = %request_id,
                hold_id = %hold.hold_id,
                nonce_id = %presented_nonce.nonce_id(),
                receipt_id = %receipt.id,
                reason = %redacted!(&error),
                "durable receipt persistence failed after an irreversible reconcile settlement; \
                 returning the signed authoritative receipt"
            );
        }

        info!(
            request_id = %request_id,
            hold_id = %hold.hold_id,
            nonce_id = %presented_nonce.nonce_id(),
            realized,
            reserved = exposed,
            "reconciled reserved authorization by nonce"
        );

        Ok(ToolCallResponse {
            request_id,
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }
}
