use super::*;

impl SqliteBudgetStore {
    pub(crate) fn authorize_composite_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        request.validate()?;
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        let identity = transaction
            .query_row(
                r#"
                SELECT capability_id, grant_index
                FROM budget_authorization_holds WHERE hold_id = ?1
                "#,
                params![&request.hold_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "unknown cumulative approval hold `{}`",
                    request.hold_id
                ))
            })?;
        let grant_index = usize::try_from(identity.1)
            .map_err(|_| BudgetStoreError::Invariant("invalid hold grant_index".to_string()))?;
        if identity.0 != request.capability_id || grant_index != request.grant_index {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval capability or grant does not match durable hold".to_string(),
            ));
        }
        let hold = load_structured_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget hold `{}` is not a composite hold",
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
        if hold.admission != request.admission_binding {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval admission binding does not match durable hold".to_string(),
            ));
        }
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            &request.event_id,
            BudgetMutationKind::AuthorizeCumulativeApproval,
            &request.hold_id,
            &identity.0,
            grant_index,
            Some(0),
            Some(0),
            request.authority.as_ref(),
            None,
            None,
        )? {
            let stored = transaction.query_row(
                r#"
                SELECT operation_id, cumulative_approval_set_digest
                FROM budget_mutation_events WHERE event_id = ?1
                "#,
                params![&request.event_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )?;
            if stored.0.as_deref() != Some(request.operation_id.as_str())
                || stored.1.as_deref() != Some(request.approval_set_digest.as_str())
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{}` was reused for a different mutation",
                    request.event_id
                )));
            }
            transaction.rollback()?;
            return Ok(BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(decision));
        }

        if hold.admission.operation_id != request.operation_id {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval operation does not match admission binding".to_string(),
            ));
        }
        let (cumulative, state_before, account_before, existing_digest) =
            load_cumulative_snapshot(&transaction, &hold)?.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget hold has no cumulative approval participant".to_string(),
                )
            })?;
        if cumulative.operation_id != request.operation_id
            || state_before != BudgetCumulativeApprovalState::PendingApproval
            || existing_digest.is_some()
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval participant is not pending".to_string(),
            ));
        }
        let mut account_after = account_before.clone();
        account_after.version = account_after.version.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("cumulative approval version overflowed u64".to_string())
        })?;
        let quota_states = load_quota_states(&transaction, &hold)?;
        let usage = load_usage_or_default(&transaction, &hold.capability_id, hold.grant_index)?;
        let event_seq = allocate_budget_replication_seq(&transaction)?;

        write_cumulative_account(&transaction, &account_after)?;
        let changed = transaction.execute(
            r#"
            UPDATE budget_cumulative_approval_operations
            SET state = ?2, approval_set_digest = ?3, account_version = ?4
            WHERE operation_id = ?1 AND hold_id = ?5
              AND state = ?6 AND approval_set_digest IS NULL
            "#,
            params![
                &request.operation_id,
                cumulative_state_text(BudgetCumulativeApprovalState::Authorized),
                &request.approval_set_digest,
                budget_u64_to_sqlite(account_after.version, "cumulative_account_version")?,
                &request.hold_id,
                cumulative_state_text(BudgetCumulativeApprovalState::PendingApproval),
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval compare-and-set failed".to_string(),
            ));
        }
        let next_authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET authorization_outcome = 'authorized',
                authority_id = ?2, lease_id = ?3, lease_epoch = ?4,
                updated_at = ?5
            WHERE hold_id = ?1 AND authorization_outcome = 'approval_required'
            "#,
            params![
                &request.hold_id,
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
                "cumulative approval hold compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &hold.capability_id,
            hold.grant_index,
            BudgetMutationKind::AuthorizeCumulativeApproval,
            Some(true),
            event_seq,
            Some(usage.seq),
            0,
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
            Some(BudgetAuthorizationOutcome::Authorized),
            hold.invocation_state,
            hold.invocation_state,
            hold.monetary_state,
            hold.monetary_state,
            &quota_states,
            &quota_states,
            Some(CumulativeSnapshot {
                request: &cumulative,
                state: state_before,
                account: &account_before,
            }),
            Some(CumulativeSnapshot {
                request: &cumulative,
                state: BudgetCumulativeApprovalState::Authorized,
                account: &account_after,
            }),
            Some(&request.approval_set_digest),
            None,
            None,
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::AuthorizeCumulativeApproval,
            &request.event_id,
            event_seq,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(BudgetCumulativeApprovalAuthorizationDecision::Authorized(
            decision,
        ))
    }
}
