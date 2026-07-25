use super::*;

impl SqliteBudgetStore {
    pub(crate) fn release_composite_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        if request.released_exposure_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary release is not a state transition".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            hold_id,
            &request.capability_id,
            request.grant_index,
            Some(request.released_exposure_units),
            Some(0),
            request.authority.as_ref(),
            None,
            None,
        )? {
            transaction.rollback()?;
            return Ok(decision);
        }
        let hold = load_structured_hold(&transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` crossed the dispatch commitment fence"
            )));
        }
        if hold.monetary_state != BudgetMonetaryState::Exposed
            || hold.remaining_exposure < request.released_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary exposure is not releasable"
            )));
        }
        let quota_states = load_quota_states(&transaction, &hold)?;
        let cumulative = load_cumulative_snapshot(&transaction, &hold)?;
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        if usage.total_cost_exposed < request.released_exposure_units {
            return Err(BudgetStoreError::Invariant(
                "cannot release more than total budget exposure".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.total_cost_exposed -= request.released_exposure_units;
        usage.seq = event_seq;
        usage.updated_at = unix_now();
        write_usage(&transaction, &usage)?;
        let remaining = hold.remaining_exposure - request.released_exposure_units;
        let monetary_after = if remaining == 0 {
            BudgetMonetaryState::Released
        } else {
            BudgetMonetaryState::Exposed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = ?2, monetary_state = ?3,
                disposition = ?4, authority_id = ?5, lease_id = ?6,
                lease_epoch = ?7, updated_at = ?8
            WHERE hold_id = ?1 AND invocation_state = 'authorized'
              AND monetary_state = 'exposed' AND remaining_exposure_units >= ?9
            "#,
            params![
                hold_id,
                budget_u64_to_sqlite(remaining, "remaining_exposure_units")?,
                budget_monetary_state_text(monetary_after),
                if remaining == 0 { "released" } else { "open" },
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                unix_now(),
                budget_u64_to_sqlite(request.released_exposure_units, "released_exposure_units",)?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget release compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            event_seq,
            Some(event_seq),
            request.released_exposure_units,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        let cumulative_snapshot =
            cumulative
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                });
        write_transition_projection(
            &transaction,
            &event.event_id,
            &hold,
            None,
            hold.invocation_state,
            hold.invocation_state,
            hold.monetary_state,
            monetary_after,
            &quota_states,
            &quota_states,
            cumulative_snapshot,
            cumulative
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative
                .as_ref()
                .and_then(|(_, _, _, digest)| digest.as_deref()),
            None,
            None,
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::ReleaseExposure,
            event_id,
            event_seq,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(decision)
    }

    pub(crate) fn reverse_composite_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reversal requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reversal requires event_id".to_string())
        })?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        let hold = load_structured_hold(&transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        let reverse_kind = if hold.quotas.is_empty() {
            BudgetMutationKind::ReverseExposure
        } else {
            BudgetMutationKind::ReverseInvocation
        };
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            event_id,
            reverse_kind,
            hold_id,
            &request.capability_id,
            request.grant_index,
            Some(request.reversed_exposure_units),
            Some(0),
            request.authority.as_ref(),
            None,
            request.expected_cumulative_approval_state,
        )? {
            transaction.rollback()?;
            return Ok(decision);
        }
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationState::Authorized
            || hold.remaining_exposure != request.reversed_exposure_units
            || (hold.remaining_exposure > 0 && hold.monetary_state != BudgetMonetaryState::Exposed)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot be reversed in its current state"
            )));
        }
        let quota_before = load_quota_states(&transaction, &hold)?;
        let mut quota_after = quota_before.clone();
        for state in &mut quota_after {
            if state.reserved == 0 {
                return Err(BudgetStoreError::Invariant(
                    "invocation quota reservation is incomplete".to_string(),
                ));
            }
            state.reserved -= 1;
            state.version = state.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation quota version overflowed u64".to_string())
            })?;
        }
        let cumulative_before = load_cumulative_snapshot(&transaction, &hold)?;
        let cumulative_after = cumulative_before
            .as_ref()
            .map(|(cumulative, state, account, digest)| {
                if request
                    .expected_cumulative_approval_state
                    .is_some_and(|expected| expected != *state)
                    || !matches!(
                        state,
                        BudgetCumulativeApprovalState::PendingApproval
                            | BudgetCumulativeApprovalState::Authorized
                    )
                {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval state changed before reversal".to_string(),
                    ));
                }
                if account.reserved < cumulative.requested_authorized.units {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval reservation is incomplete".to_string(),
                    ));
                }
                let mut account = account.clone();
                account.reserved -= cumulative.requested_authorized.units;
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                Ok::<_, BudgetStoreError>((
                    cumulative.clone(),
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    account,
                    digest.clone(),
                ))
            })
            .transpose()?;
        if cumulative_before.is_none() && request.expected_cumulative_approval_state.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget hold has no cumulative approval participant".to_string(),
            ));
        }
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        if usage.invocation_count == 0 || usage.total_cost_exposed < request.reversed_exposure_units
        {
            return Err(BudgetStoreError::Invariant(
                "budget usage has no reversible reservation".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.invocation_count -= 1;
        usage.total_cost_exposed -= request.reversed_exposure_units;
        usage.seq = event_seq;
        usage.updated_at = unix_now();
        write_usage(&transaction, &usage)?;
        for state in &quota_after {
            write_quota_state(&transaction, state)?;
        }
        if let Some((cumulative, state, account, _)) = cumulative_after.as_ref() {
            write_cumulative_account(&transaction, account)?;
            let changed = transaction.execute(
                r#"
                UPDATE budget_cumulative_approval_operations
                SET state = ?2, account_version = ?3
                WHERE operation_id = ?1 AND hold_id = ?4
                  AND state IN ('pending_approval', 'authorized')
                "#,
                params![
                    &cumulative.operation_id,
                    cumulative_state_text(*state),
                    budget_u64_to_sqlite(account.version, "cumulative_account_version")?,
                    hold_id,
                ],
            )?;
            if changed != 1 {
                return Err(BudgetStoreError::Invariant(
                    "cumulative reversal compare-and-set failed".to_string(),
                ));
            }
        }
        let monetary_after = if request.reversed_exposure_units == 0 {
            hold.monetary_state
        } else {
            BudgetMonetaryState::Reversed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, invocation_captured = 0,
                invocation_state = 'reversed', monetary_state = ?2,
                disposition = 'reversed', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'authorized'
            "#,
            params![
                hold_id,
                budget_monetary_state_text(monetary_after),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                unix_now(),
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget reversal compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            reverse_kind,
            None,
            event_seq,
            Some(event_seq),
            request.reversed_exposure_units,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            &transaction,
            &event.event_id,
            &hold,
            None,
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Reversed,
            hold.monetary_state,
            monetary_after,
            &quota_before,
            &quota_after,
            cumulative_before
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative_after
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative_after
                .as_ref()
                .and_then(|(_, _, _, digest)| digest.as_deref()),
            None,
            request.expected_cumulative_approval_state,
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(&transaction, reverse_kind, event_id, event_seq)?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(decision)
    }

    pub(crate) fn cancel_captured_composite_hold(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        request.validate()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            &request.event_id,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
            None,
            Some(0),
            request.authority.as_ref(),
            None,
            Some(BudgetCumulativeApprovalState::Captured),
        )? {
            transaction.rollback()?;
            return Ok(
                BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(decision),
            );
        }
        let hold = load_structured_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "unknown composite budget hold `{}`",
                request.hold_id
            ))
        })?;
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.cumulative.is_none() {
            return Err(BudgetStoreError::Invariant(
                "captured composite invocation reservations are terminal".to_string(),
            ));
        }
        if hold.invocation_state != BudgetInvocationState::Captured
            || (hold.remaining_exposure > 0 && hold.monetary_state != BudgetMonetaryState::Exposed)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` cannot be cancelled before dispatch in its current state",
                request.hold_id
            )));
        }

        let quota_before = load_quota_states(&transaction, &hold)?;
        let mut quota_after = quota_before.clone();
        for state in &mut quota_after {
            if state.captured == 0 {
                return Err(BudgetStoreError::Invariant(
                    "captured invocation quota is incomplete".to_string(),
                ));
            }
            state.captured -= 1;
            state.version = state.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation quota version overflowed u64".to_string())
            })?;
        }
        let cumulative_before = load_cumulative_snapshot(&transaction, &hold)?;
        let cumulative_after = cumulative_before
            .as_ref()
            .map(|(cumulative, state, account, digest)| {
                if *state != BudgetCumulativeApprovalState::Captured
                    || account.captured < cumulative.requested_authorized.units
                {
                    return Err(BudgetStoreError::Invariant(
                        "captured cumulative approval is incomplete".to_string(),
                    ));
                }
                let mut account = account.clone();
                account.captured -= cumulative.requested_authorized.units;
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                Ok::<_, BudgetStoreError>((
                    cumulative.clone(),
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    account,
                    digest.clone(),
                ))
            })
            .transpose()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "captured cancellation requires a cumulative approval participant".to_string(),
                )
            })?;
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        if usage.invocation_count == 0 || usage.total_cost_exposed < hold.remaining_exposure {
            return Err(BudgetStoreError::Invariant(
                "budget usage has no captured reservation to cancel".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.invocation_count -= 1;
        usage.total_cost_exposed -= hold.remaining_exposure;
        usage.seq = event_seq;
        usage.updated_at = unix_now();
        write_usage(&transaction, &usage)?;
        for state in &quota_after {
            write_quota_state(&transaction, state)?;
        }
        write_cumulative_account(&transaction, &cumulative_after.2)?;
        let changed = transaction.execute(
            r#"
            UPDATE budget_cumulative_approval_operations
            SET state = 'reversed_before_dispatch', account_version = ?2
            WHERE operation_id = ?1 AND hold_id = ?3 AND state = 'captured'
            "#,
            params![
                &cumulative_after.0.operation_id,
                budget_u64_to_sqlite(cumulative_after.2.version, "cumulative_account_version")?,
                &request.hold_id,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "cumulative cancellation compare-and-set failed".to_string(),
            ));
        }
        let monetary_after = if hold.remaining_exposure == 0 {
            hold.monetary_state
        } else {
            BudgetMonetaryState::Reversed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, invocation_captured = 0,
                invocation_state = 'reversed', monetary_state = ?2,
                disposition = 'reversed', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'captured'
            "#,
            params![
                &request.hold_id,
                budget_monetary_state_text(monetary_after),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                unix_now(),
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "captured cancellation compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            Some(true),
            event_seq,
            Some(event_seq),
            hold.remaining_exposure,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            &transaction,
            &event.event_id,
            &hold,
            None,
            BudgetInvocationState::Captured,
            BudgetInvocationState::Reversed,
            hold.monetary_state,
            monetary_after,
            &quota_before,
            &quota_after,
            cumulative_before
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            Some(CumulativeSnapshot {
                request: &cumulative_after.0,
                state: cumulative_after.1,
                account: &cumulative_after.2,
            }),
            cumulative_after.3.as_deref(),
            None,
            Some(BudgetCumulativeApprovalState::Captured),
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            &request.event_id,
            event_seq,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(
            decision,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_composite_hold(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_units: u64,
        realized_units: u64,
        hold_id: &str,
        event_id: &str,
        authority: Option<&BudgetEventAuthority>,
        kind: BudgetMutationKind,
        monetary_after: BudgetMonetaryState,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (decision, changed) = self.settle_composite_hold_in_transaction(
            &transaction,
            capability_id,
            grant_index,
            exposed_units,
            realized_units,
            hold_id,
            event_id,
            authority,
            kind,
            monetary_after,
        )?;
        if changed {
            self.commit_joint_transaction(transaction)?;
            self.sync_joint_anchor(&connection)?;
        } else {
            transaction.rollback()?;
        }
        Ok(decision)
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_composite_hold_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
        exposed_units: u64,
        realized_units: u64,
        hold_id: &str,
        event_id: &str,
        authority: Option<&BudgetEventAuthority>,
        kind: BudgetMutationKind,
        monetary_after: BudgetMonetaryState,
    ) -> Result<(BudgetHoldMutationDecision, bool), BudgetStoreError> {
        if exposed_units == 0 || realized_units > exposed_units {
            return Err(BudgetStoreError::Invariant(
                "monetary settlement requires positive exposure and spend not above exposure"
                    .to_string(),
            ));
        }
        self.validate_joint_authority(authority)?;
        if let Some(decision) = replay_transition(
            self,
            transaction,
            event_id,
            kind,
            hold_id,
            capability_id,
            grant_index,
            Some(exposed_units),
            Some(realized_units),
            authority,
            None,
            None,
        )? {
            return Ok((decision, false));
        }
        let hold = load_structured_hold(transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        validate_transition_identity(
            self,
            transaction,
            &hold,
            capability_id,
            grant_index,
            authority,
        )?;
        if hold.invocation_state != BudgetInvocationState::Captured
            || hold.monetary_state != BudgetMonetaryState::Exposed
            || hold.remaining_exposure != exposed_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not dispatch-captured and settleable"
            )));
        }
        let quota_states = load_quota_states(transaction, &hold)?;
        let cumulative = load_cumulative_snapshot(transaction, &hold)?;
        let mut usage = load_usage_or_default(transaction, capability_id, grant_index)?;
        if usage.total_cost_exposed < exposed_units {
            return Err(BudgetStoreError::Invariant(
                "settlement exceeds total budget exposure".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(transaction)?;
        usage.total_cost_exposed -= exposed_units;
        usage.total_cost_realized_spend = usage
            .total_cost_realized_spend
            .checked_add(realized_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("realized budget spend overflowed u64".to_string())
            })?;
        usage.seq = event_seq;
        usage.updated_at = unix_now();
        write_usage(transaction, &usage)?;
        let next_authority = authority.or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, monetary_state = ?2,
                disposition = 'reconciled', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'captured'
              AND monetary_state = 'exposed'
            "#,
            params![
                hold_id,
                budget_monetary_state_text(monetary_after),
                next_authority.map(|value| value.authority_id.as_str()),
                next_authority.map(|value| value.lease_id.as_str()),
                next_authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                unix_now(),
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget settlement compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            transaction,
            Some(event_id),
            Some(hold_id),
            authority,
            capability_id,
            grant_index,
            kind,
            None,
            event_seq,
            Some(event_seq),
            exposed_units,
            realized_units,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            transaction,
            &event.event_id,
            &hold,
            None,
            hold.invocation_state,
            hold.invocation_state,
            hold.monetary_state,
            monetary_after,
            &quota_states,
            &quota_states,
            cumulative
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative
                .as_ref()
                .and_then(|(_, _, _, digest)| digest.as_deref()),
            None,
            None,
        )?;
        let decision = transition_decision_from_event(self, transaction, event)?;
        self.append_joint_commit(transaction, kind, event_id, event_seq)?;
        Ok((decision, true))
    }

    pub(crate) fn reconcile_composite_hold_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetReconcileHoldRequest,
    ) -> Result<(BudgetReconcileHoldDecision, bool), BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold_in_transaction(
            transaction,
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant("composite reconciliation requires hold_id".to_string())
            })?,
            request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite reconciliation requires event_id".to_string(),
                )
            })?,
            request.authority.as_ref(),
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryState::Reconciled,
        )
    }

    pub(crate) fn reconcile_composite_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant("composite reconciliation requires hold_id".to_string())
            })?,
            request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite reconciliation requires event_id".to_string(),
                )
            })?,
            request.authority.as_ref(),
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryState::Reconciled,
        )
    }

    pub(crate) fn capture_composite_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite monetary capture requires hold_id".to_string(),
                )
            })?,
            request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite monetary capture requires event_id".to_string(),
                )
            })?,
            request.authority.as_ref(),
            BudgetMutationKind::CaptureSpend,
            BudgetMonetaryState::Captured,
        )
    }
}
