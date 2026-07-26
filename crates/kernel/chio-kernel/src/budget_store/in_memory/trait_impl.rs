impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        let (captured, _event_seq, event_id, _usage) =
            inner.capture_invocation_reservations(&request)?;
        let event = inner
            .events
            .iter()
            .find(|event| event.event_id == event_id)
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "capture event disappeared while building decision".to_string(),
                )
            })?;
        let mutation = BudgetHoldMutationDecision {
            hold_id: event.hold_id,
            admission_binding: event.admission_binding,
            exposure_units: event.exposure_units,
            realized_spend_units: event.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                event.total_cost_exposed_after,
                event.total_cost_realized_spend_after,
            )?,
            invocation_count_after: event.invocation_count_after,
            invocation_quota_usages: event.invocation_quota_usages,
            cumulative_approval: event.cumulative_approval,
            invocation_state: event.invocation_state_after,
            monetary_state: event.monetary_state_after,
            metadata: budget_commit_metadata(
                self,
                event.authority,
                Some(event.event_seq),
                Some(event.event_id),
                Some(event.recorded_at),
            ),
        };
        Ok(if captured {
            BudgetInvocationCaptureDecision::Captured(mutation)
        } else {
            BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)
        })
    }

    fn authorize_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        let (authorized, event) = inner.authorize_cumulative_approval(&request)?;
        let mutation = BudgetHoldMutationDecision {
            hold_id: event.hold_id,
            admission_binding: event.admission_binding,
            exposure_units: event.exposure_units,
            realized_spend_units: event.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                event.total_cost_exposed_after,
                event.total_cost_realized_spend_after,
            )?,
            invocation_count_after: event.invocation_count_after,
            invocation_quota_usages: event.invocation_quota_usages,
            cumulative_approval: event.cumulative_approval,
            invocation_state: event.invocation_state_after,
            monetary_state: event.monetary_state_after,
            metadata: budget_commit_metadata(
                self,
                event.authority,
                Some(event.event_seq),
                Some(event.event_id),
                Some(event.recorded_at),
            ),
        };
        Ok(if authorized {
            BudgetCumulativeApprovalAuthorizationDecision::Authorized(mutation)
        } else {
            BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(mutation)
        })
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        let (cancelled, _event_seq, _usage) = inner.cancel_captured_before_dispatch(&request)?;
        let event = inner
            .events
            .iter()
            .find(|event| event.event_id == request.event_id)
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cancellation event disappeared while building decision".to_string(),
                )
            })?;
        let mutation = BudgetHoldMutationDecision {
            hold_id: event.hold_id,
            admission_binding: event.admission_binding,
            exposure_units: event.exposure_units,
            realized_spend_units: event.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                event.total_cost_exposed_after,
                event.total_cost_realized_spend_after,
            )?,
            invocation_count_after: event.invocation_count_after,
            invocation_quota_usages: event.invocation_quota_usages,
            cumulative_approval: event.cumulative_approval,
            invocation_state: event.invocation_state_after,
            monetary_state: event.monetary_state_after,
            metadata: budget_commit_metadata(
                self,
                event.authority,
                Some(event.event_seq),
                Some(event.event_id),
                Some(event.recorded_at),
            ),
        };
        Ok(if cancelled {
            BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(mutation)
        } else {
            BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation)
        })
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.reverse_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.reduce_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.get_usage(capability_id, grant_index)
    }

    fn get_invocation_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        Ok(self.lock_inner()?.get_invocation_quota_usage(key))
    }

    fn get_cumulative_approval_account_usage(
        &self,
        key: &BudgetCumulativeApprovalAccountKey,
    ) -> Result<Option<BudgetCumulativeApprovalAccountUsage>, BudgetStoreError> {
        Ok(self
            .lock_inner()?
            .get_cumulative_approval_account_usage(key))
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        Ok(self
            .lock_inner()?
            .get_cumulative_approval_operation_usage(operation_id))
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        self.lock_inner()?
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        let event = inner.authorize_composite_budget_hold(&request)?;
        if request.hold_id.as_deref().is_some_and(|hold_id| {
            inner
                .holds
                .get(hold_id)
                .is_some_and(|hold| hold.invocation_state == BudgetInvocationState::Reversed)
        }) {
            return Err(BudgetStoreError::Invariant(
                "budget authorization replay references a terminally reversed hold".to_string(),
            ));
        }
        if let Some((hold_id, capture)) = request.hold_id.as_deref().and_then(|hold_id| {
            let hold = inner.holds.get(hold_id)?;
            if hold.invocation_state != BudgetInvocationState::Captured {
                return None;
            }
            inner
                .events
                .iter()
                .find(|event| {
                    event.hold_id.as_deref() == Some(hold_id)
                        && event.kind == BudgetMutationKind::CaptureInvocation
                })
                .map(|capture| (hold_id.to_string(), capture.clone()))
        }) {
            return Ok(BudgetAuthorizeHoldDecision::AlreadyCaptured(
                BudgetHoldMutationDecision {
                    hold_id: Some(hold_id),
                    admission_binding: capture.admission_binding,
                    exposure_units: capture.exposure_units,
                    realized_spend_units: capture.realized_spend_units,
                    committed_cost_units_after: checked_committed_cost_units(
                        capture.total_cost_exposed_after,
                        capture.total_cost_realized_spend_after,
                    )?,
                    invocation_count_after: capture.invocation_count_after,
                    invocation_quota_usages: capture.invocation_quota_usages,
                    cumulative_approval: capture.cumulative_approval,
                    invocation_state: BudgetInvocationState::Captured,
                    monetary_state: capture.monetary_state_after,
                    metadata: budget_commit_metadata(
                        self,
                        capture.authority,
                        Some(capture.event_seq),
                        Some(capture.event_id),
                        Some(capture.recorded_at),
                    ),
                },
            ));
        }
        if let Some(hold_id) = request.hold_id.as_deref() {
            inner.ensure_latest_hold_event(hold_id, event.event_seq, "authorization")?;
        } else {
            inner.ensure_latest_usage_event(
                &request.capability_id,
                request.grant_index,
                event.event_seq,
                "authorization",
            )?;
        }
        let committed_cost_units_after = checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?;
        let metadata = budget_commit_metadata(
            self,
            event.authority.clone(),
            Some(event.event_seq),
            Some(event.event_id.clone()),
            Some(event.recorded_at),
        );

        if event.authorization_outcome == Some(BudgetAuthorizationOutcome::Denied) {
            return Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: event.hold_id,
                admission_binding: event.admission_binding,
                attempted_exposure_units: event.exposure_units,
                committed_cost_units_after,
                invocation_count_after: event.invocation_count_after,
                invocation_quota_usages: event.invocation_quota_usages,
                cumulative_approval: event.cumulative_approval,
                invocation_state: event.invocation_state_after,
                monetary_state: event.monetary_state_after,
                metadata,
            }));
        }

        if let Some(cumulative) = event.cumulative_approval.clone() {
            if cumulative.state == BudgetCumulativeApprovalState::PendingApproval {
                return Ok(BudgetAuthorizeHoldDecision::ApprovalRequired(
                    ApprovalRequiredBudgetHold {
                        hold_id: event.hold_id.ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "cumulative approval hold_id disappeared".to_string(),
                            )
                        })?,
                        admission_binding: event.admission_binding.ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "cumulative approval admission binding disappeared".to_string(),
                            )
                        })?,
                        authorized_exposure_units: event.exposure_units,
                        committed_cost_units_after,
                        invocation_count_after: event.invocation_count_after,
                        invocation_quota_usages: event.invocation_quota_usages,
                        cumulative_approval: cumulative,
                        invocation_state: event.invocation_state_after,
                        monetary_state: event.monetary_state_after,
                        metadata,
                    },
                ));
            }
        }

        if event.authorization_outcome != Some(BudgetAuthorizationOutcome::Authorized) {
            return Err(BudgetStoreError::Invariant(
                "budget authorization event has no terminal outcome".to_string(),
            ));
        }

        Ok(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: event.hold_id,
                admission_binding: event.admission_binding,
                authorized_exposure_units: event.exposure_units,
                committed_cost_units_after,
                invocation_count_after: event.invocation_count_after,
                invocation_quota_usages: event.invocation_quota_usages,
                cumulative_approval: event.cumulative_approval,
                invocation_state: event.invocation_state_after,
                monetary_state: event.monetary_state_after,
                metadata,
            },
        ))
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        inner.reverse_charge_cost_with_expected_state(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
            request.expected_cumulative_approval_state,
        )?;
        self.recorded_mutation_decision(&inner, request.event_id.as_deref())
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        inner.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.recorded_mutation_decision(&inner, request.event_id.as_deref())
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        inner.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.recorded_mutation_decision(&inner, request.event_id.as_deref())
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        request.validate()?;
        let mut inner = self.lock_inner()?;
        inner.capture_budget_hold(&request)?;
        self.recorded_mutation_decision(&inner, request.event_id.as_deref())
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let hold_ids = {
            let inner = self.lock_inner()?;
            inner
                .holds
                .iter()
                .filter(|(_, hold)| hold_is_open(hold))
                .map(|(hold_id, _)| hold_id.clone())
                .collect::<Vec<_>>()
        };
        let mut reconciled = 0;
        let mut reversed = 0;
        for hold_id in hold_ids {
            let hold = self.get_budget_hold(&hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!("budget hold `{hold_id}` disappeared"))
            })?;
            if let Some(realized) = realized_by_hold.get(&hold_id) {
                self.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                    capability_id: hold.capability_id.clone(),
                    grant_index: hold.grant_index,
                    hold_id: hold_id.clone(),
                    event_id: format!("{hold_id}:reap-capture-invocation"),
                    trusted_time: None,
                    authority: hold.authority.clone(),
                })?;
                if hold.remaining_exposure_units > 0 {
                    self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: hold.capability_id,
                        grant_index: hold.grant_index,
                        exposed_cost_units: hold.remaining_exposure_units,
                        realized_spend_units: (*realized).min(hold.remaining_exposure_units),
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reconcile")),
                        authority: hold.authority,
                    })?;
                }
                reconciled += 1;
            } else {
                self.reverse_budget_hold(BudgetReverseHoldRequest {
                    capability_id: hold.capability_id,
                    grant_index: hold.grant_index,
                    reversed_exposure_units: hold.remaining_exposure_units,
                    hold_id: Some(hold_id.clone()),
                    event_id: Some(format!("{hold_id}:reap-reverse")),
                    authority: hold.authority,
                    expected_cumulative_approval_state: None,
                })?;
                reversed += 1;
            }
        }
        Ok((reconciled, reversed))
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(self
            .lock_inner()?
            .holds
            .values()
            .filter(|hold| hold_is_open(hold))
            .count())
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(Some(
            self.lock_inner()?
                .holds
                .iter()
                .filter(|(_, hold)| {
                    hold_is_open(hold)
                        && hold.reserved_until.is_some()
                        && hold.reserved_envelope.delegation_depth > 0
                })
                .map(|(hold_id, _)| hold_id.clone())
                .collect(),
        ))
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let prefix = format!("budget-hold:{request_id}:");
        let nonce_prefix = format!("nonce-preflight-budget-hold:{request_id}:");
        Ok(Some(self.lock_inner()?.holds.keys().any(|hold_id| {
            hold_id.starts_with(&prefix) || hold_id.starts_with(&nonce_prefix)
        })))
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        Ok(self.lock_inner()?.holds.get(hold_id).map(|hold| {
            let disposition = if hold_is_open(hold) {
                BudgetHoldDispositionView::Open
            } else if hold.monetary_state == BudgetMonetaryState::Reconciled
                || (hold.monetary_state == BudgetMonetaryState::None
                    && hold.invocation_state == BudgetInvocationState::Captured)
            {
                BudgetHoldDispositionView::Reconciled
            } else if hold.monetary_state == BudgetMonetaryState::Released {
                BudgetHoldDispositionView::Released
            } else {
                BudgetHoldDispositionView::Reversed
            };
            BudgetHoldSnapshot {
                hold_id: hold_id.to_string(),
                capability_id: hold.capability_id.clone(),
                grant_index: hold.grant_index,
                authorized_exposure_units: hold.authorized_exposure_units,
                remaining_exposure_units: hold.remaining_exposure_units,
                disposition,
                reserved_until: hold.reserved_until,
                reserved_currency: hold.reserved_currency.clone(),
                reserved_payment_reference: hold.reserved_payment_reference.clone(),
                reserved_budget_total: hold.reserved_envelope.budget_total,
                reserved_delegation_depth: Some(hold.reserved_envelope.delegation_depth),
                reserved_root_budget_holder: Some(
                    hold.reserved_envelope.root_budget_holder.clone(),
                ),
                authority: hold.authority.clone(),
            }
        }))
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        let hold = inner.holds.get_mut(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget hold `{hold_id}` not found"))
        })?;
        if !hold_is_open(hold) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not open"
            )));
        }
        hold.reserved_until = Some(reserved_until_unix_secs);
        hold.reserved_currency = Some(currency.to_string());
        hold.reserved_payment_reference = payment_reference.map(str::to_string);
        hold.reserved_envelope = envelope.clone();
        Ok(())
    }

    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        let hold = inner.holds.get_mut(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget hold `{hold_id}` not found"))
        })?;
        if hold.capability_id != capability_id
            || hold.grant_index != grant_index
            || hold.authorized_exposure_units != 0
            || !hold_is_open(hold)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not an open invocation authorization"
            )));
        }
        hold.reserved_until = Some(reserved_until_unix_secs);
        hold.reserved_currency = None;
        hold.reserved_payment_reference = None;
        hold.reserved_envelope = envelope.clone();
        Ok(())
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        let hold_ids = {
            let inner = self.lock_inner()?;
            inner
                .holds
                .iter()
                .filter(|(_, hold)| {
                    hold_is_open(hold)
                        && hold
                            .reserved_until
                            .is_some_and(|until| until <= now_unix_secs)
                })
                .map(|(hold_id, _)| hold_id.clone())
                .collect::<Vec<_>>()
        };
        for hold_id in &hold_ids {
            let hold = self.get_budget_hold(hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!("budget hold `{hold_id}` disappeared"))
            })?;
            self.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: hold.capability_id.clone(),
                grant_index: hold.grant_index,
                hold_id: hold_id.clone(),
                event_id: format!("{hold_id}:ttl-reap-capture-invocation"),
                trusted_time: None,
                authority: hold.authority.clone(),
            })?;
            if hold.remaining_exposure_units > 0 {
                self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: hold.capability_id,
                    grant_index: hold.grant_index,
                    exposed_cost_units: hold.remaining_exposure_units,
                    realized_spend_units: hold.remaining_exposure_units,
                    hold_id: Some(hold_id.clone()),
                    event_id: Some(format!("{hold_id}:ttl-reap-settle")),
                    authority: hold.authority,
                })?;
            }
        }
        Ok(hold_ids.len())
    }
}

fn hold_is_open(hold: &BudgetHoldState) -> bool {
    match hold.monetary_state {
        BudgetMonetaryState::Exposed => true,
        BudgetMonetaryState::None => hold.invocation_state == BudgetInvocationState::Authorized,
        BudgetMonetaryState::Released
        | BudgetMonetaryState::Reconciled
        | BudgetMonetaryState::Captured
        | BudgetMonetaryState::Reversed => false,
    }
}
