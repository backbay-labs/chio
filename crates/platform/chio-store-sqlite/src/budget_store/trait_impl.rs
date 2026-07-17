use super::*;

impl BudgetStore for SqliteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_increment_with_event_id(capability_id, grant_index, max_invocations, None)
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
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

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
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

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
        self.charge_cost_with_optional_journal(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
            None,
        )
    }

    fn list_open_holds_older_than(
        &self,
        older_than_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<chio_kernel::budget_store::OpenHoldSummary>, BudgetStoreError> {
        // Hold rows stamp created_at in unix seconds; the trait API speaks
        // milliseconds, so convert at the boundary.
        let cutoff_secs = (older_than_unix_ms / 1_000).min(i64::MAX as u64) as i64;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, created_at \
             FROM budget_authorization_holds \
             WHERE disposition = 'open' AND created_at <= ?1 \
             ORDER BY created_at ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![cutoff_secs, limit.min(i64::MAX as usize) as i64],
            |row| {
                Ok(chio_kernel::budget_store::OpenHoldSummary {
                    hold_id: row.get::<_, String>(0)?,
                    capability_id: row.get::<_, String>(1)?,
                    grant_index: row.get::<_, i64>(2)?.clamp(0, i64::from(u32::MAX)) as u32,
                    remaining_exposure_units: row.get::<_, i64>(3)?.max(0) as u64,
                    created_at_unix_ms: (row.get::<_, i64>(4)?.max(0) as u64).saturating_mul(1_000),
                })
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Read the open hold's remainder and owning grant inside the
        // transaction; a non-open or absent hold is an idempotent no-op.
        let row: Option<(String, i64, i64, bool)> = transaction
            .query_row(
                "SELECT capability_id, grant_index, remaining_exposure_units, \
                        invocation_count_debited \
                 FROM budget_authorization_holds WHERE hold_id = ?1 AND disposition = 'open'",
                params![hold_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((capability_id, grant_index, remaining, invocation_count_debited)) = row else {
            return Ok(false);
        };
        let remaining = remaining.max(0);
        let now = unix_now();
        // Release capacity by exactly the remainder and return the hold's
        // invocation debit, mirroring the normal reverse path: the call
        // never completed, so it must not permanently consume a
        // max_invocations slot. Never touch realized spend: an expired hold
        // returns capacity without recording spend.
        transaction.execute(
            "UPDATE capability_grant_budgets \
             SET total_cost_exposed = MAX(total_cost_exposed - ?1, 0), \
                 invocation_count = CASE WHEN ?5 THEN MAX(invocation_count - 1, 0) \
                                         ELSE invocation_count END, \
                 updated_at = ?2 \
             WHERE capability_id = ?3 AND grant_index = ?4",
            params![
                remaining,
                now,
                capability_id,
                grant_index,
                invocation_count_debited
            ],
        )?;
        transaction.execute(
            "UPDATE budget_authorization_holds \
             SET disposition = 'expired', remaining_exposure_units = 0, updated_at = ?1 \
             WHERE hold_id = ?2",
            params![now, hold_id],
        )?;
        let usage: Option<(u64, u32, u64, u64)> = transaction
            .query_row(
                "SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend \
                 FROM capability_grant_budgets WHERE capability_id = ?1 AND grant_index = ?2",
                params![capability_id, grant_index],
                |row| {
                    Ok((
                        budget_u64_from_row(row, 0, "seq")?,
                        budget_u32_from_row(row, 1, "invocation_count")?,
                        budget_u64_from_row(row, 2, "total_cost_exposed")?,
                        budget_u64_from_row(row, 3, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;
        let (usage_seq, invocation_count_after, exposed_after, realized_after) =
            usage.unwrap_or((0, 0, 0, 0));
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(&format!("{hold_id}:expire")),
            Some(hold_id),
            None,
            &capability_id,
            grant_index.max(0) as usize,
            BudgetMutationKind::ExpireHold,
            Some(true),
            event_seq,
            Some(usage_seq),
            remaining as u64,
            0,
            None,
            None,
            None,
            invocation_count_after,
            exposed_after,
            realized_after,
        )?;
        transaction.commit()?;
        Ok(true)
    }

    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM budget_authorization_holds WHERE disposition = 'open'",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        // Same-transaction hold + journal write: the optional journal row
        // joins the single Immediate transaction the charge path opens, so
        // the money path's recoverable record commits exactly when the hold
        // does.
        let allowed = self.charge_cost_with_optional_journal(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
            request.payment_journal.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        let committed_cost_units_after = usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()?
            .unwrap_or(0);
        let invocation_count_after = usage.as_ref().map_or(0, |usage| usage.invocation_count);
        let metadata = chio_kernel::budget_store::budget_commit_metadata(
            self,
            request.authority,
            allowed
                .then(|| usage.as_ref().map(|usage| usage.seq))
                .flatten(),
            request.event_id,
        );

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                metadata,
            }))
        }
    }

    fn record_payment_journal(
        &self,
        entry: &chio_kernel::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_payment_journal_tx(&transaction, entry, false)?;
        transaction.commit()?;
        Ok(())
    }

    fn advance_payment_journal(
        &self,
        request_id: &str,
        expected: chio_kernel::payment::PaymentJournalState,
        next: chio_kernel::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<chio_kernel::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        use chio_kernel::payment::PaymentJournalState as State;
        // A Settling advance MUST carry the committed settle intent so
        // recovery can replay the exact rail call; any other transition
        // MUST NOT carry one.
        if next == State::Settling && settle.is_none() {
            return Err(BudgetStoreError::Invariant(
                "advance to Settling requires a settle intent".to_string(),
            ));
        }
        if next != State::Settling && settle.is_some() {
            return Err(BudgetStoreError::Invariant(
                "settle intent is only valid on the Settling transition".to_string(),
            ));
        }
        let (settle_action, settle_amount) = match settle {
            Some(intent) => (
                Some(settle_action_str(intent.action)),
                intent
                    .amount_units
                    .map(|units| units.min(i64::MAX as u64) as i64),
            ),
            None => (None, None),
        };
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE payment_journal SET \
               state = ?1, \
               authorization_id = COALESCE(?2, authorization_id), \
               transaction_id = COALESCE(?3, transaction_id), \
               settle_action = COALESCE(?4, settle_action), \
               settle_amount_units = COALESCE(?5, settle_amount_units), \
               updated_at = ?6 \
             WHERE request_id = ?7 AND state = ?8",
            params![
                journal_state_str(next),
                authorization_id,
                transaction_id,
                settle_action,
                settle_amount,
                journal_now_unix_ms(),
                request_id,
                journal_state_str(expected),
            ],
        )?;
        if changed == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "payment journal advance conflict for `{request_id}`: row is not in the \
                 expected {expected:?} state"
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Idempotent: an already-closed or absent row changes nothing. A
        // reconcile-failed row stays put; the incident is cleared by an
        // operator, never by a stray close.
        let changed = transaction.execute(
            "UPDATE payment_journal SET state = 'closed', updated_at = ?1 \
             WHERE request_id = ?2 AND state NOT IN ('closed', 'reconcile_failed')",
            params![journal_now_unix_ms(), request_id],
        )?;
        transaction.commit()?;
        Ok(changed > 0)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT request_id, capability_id, grant_index, hold_id, rail, authorization_id, \
                    transaction_id, amount_units, settle_action, settle_amount_units, currency, \
                    state, created_at, tenant_id \
             FROM payment_journal \
             WHERE state NOT IN ('closed', 'reconcile_failed') AND created_at <= ?1 \
             ORDER BY created_at ASC",
        )?;
        let cutoff = older_than_unix_ms.min(i64::MAX as u64) as i64;
        let rows = statement.query_map(params![cutoff], |row| {
            Ok::<PaymentJournalRow, rusqlite::Error>((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(payment_journal_row_to_record(row?)?);
        }
        Ok(out)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT request_id, capability_id, grant_index, hold_id, rail, authorization_id, \
                    transaction_id, amount_units, settle_action, settle_amount_units, currency, \
                    state, created_at, tenant_id \
             FROM payment_journal \
             WHERE request_id = ?1 AND state NOT IN ('closed', 'reconcile_failed')",
        )?;
        let mut rows = statement.query_map(params![request_id], |row| {
            Ok::<PaymentJournalRow, rusqlite::Error>((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
            ))
        })?;
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        Ok(Some(payment_journal_row_to_record(row?)?))
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT rail FROM payment_journal WHERE request_id = ?1 AND state = 'reconcile_failed'",
                params![request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(BudgetStoreError::from)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
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
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReverseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3,
                updated_at = ?4,
                seq = ?5,
                total_cost_exposed = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                invocation_count - 1,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reversed,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReverseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count - 1,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
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
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units < cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
            let remaining = hold.remaining_exposure_units - cost_units;
            let disposition = if remaining == 0 {
                HoldDisposition::Released
            } else {
                HoldDisposition::Open
            };
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                remaining,
                disposition,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
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
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

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
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReconcileSpend,
            capability_id,
            grant_index,
            hold_id,
            authority,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle more exposure than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - exposed_cost_units;
        let new_total_cost_realized_spend = total_cost_realized_spend
            .checked_add(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_cost_units overflowed u64".to_string(),
                )
            })?;

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
                new_total_cost_realized_spend as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reconciled,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReconcileSpend,
            None,
            seq,
            Some(seq),
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            new_total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit as i64], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.connection()?
            .query_row(
                r#"
                SELECT
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch
            FROM budget_mutation_events
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                grant_index.map(|value| value as i64),
                limit as i64
            ],
            mutation_record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let summary = self.reap_holds_by_map(realized_by_hold)?;
        Ok((summary.reconciled, summary.reversed))
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(self.list_open_holds()?.len())
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        // SQLite persists the delegation depth on each reserved hold, so it can
        // enumerate the open delegated reservations precisely. Returning Some(..)
        // switches the mediation kernel onto the precise restart gate that drains
        // only the affected delegated admission, rather than the coarse gate that
        // denies all mediation until every open hold closes.
        Ok(Some(self.list_open_delegated_reserved_holds()?))
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        // SQLite persists every hold under its full id, so it can answer the
        // durable prefix probe precisely; Some(..) switches the mediation gate
        // onto the capability-agnostic reuse check instead of the per-capability
        // exact-id fallback.
        Ok(Some(self.hold_exists_for_request_id(request_id)?))
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        self.budget_hold_snapshot(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.mark_hold_reserved_until(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.reserve_invocation_hold(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.reap_expired_reserved_holds(now_unix_secs)
    }
}

impl SqliteBudgetStore {
    /// The single-transaction charge path, optionally committing a
    /// payment-journal row inside the SAME Immediate transaction as the
    /// hold write, so the money path's recoverable record is durable
    /// exactly when the hold is. Idempotent hold retries tolerate their
    /// own journal row; any other request-id reuse fails closed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn charge_cost_with_optional_journal(
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
        journal: Option<&chio_kernel::payment::PaymentJournalRecord>,
    ) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing_allowed) = SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::AuthorizeExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        )? {
            transaction.rollback()?;
            return Ok(existing_allowed.unwrap_or(false));
        }

        let row: Option<(u32, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;
        let (current_count, current_exposed, current_realized) = row.unwrap_or((0, 0, 0));

        if let Some(hold_id) = hold_id {
            let retry_follows_rollback = match event_id {
                Some(event_id) => Self::rollback_event_exists(&transaction, event_id)?,
                None => false,
            };
            if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                if hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && hold.authorized_exposure_units == cost_units
                    && hold.remaining_exposure_units == cost_units
                    && hold.invocation_count_debited
                    && hold.disposition == HoldDisposition::Open
                    && current_exposed >= cost_units
                {
                    let current = transaction
                        .query_row(
                            r#"
                            SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                            FROM capability_grant_budgets
                            WHERE capability_id = ?1 AND grant_index = ?2
                            "#,
                            params![capability_id, grant_index as i64],
                            |row| {
                                Ok((
                                    budget_u64_from_row(row, 0, "seq")?,
                                    budget_u32_from_row(row, 1, "invocation_count")?,
                                    budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                    budget_u64_from_row(
                                        row,
                                        3,
                                        "total_cost_realized_spend",
                                    )?,
                                ))
                            },
                        )
                        .optional()?;
                    if let Some((
                        usage_seq,
                        invocation_count_after,
                        total_cost_exposed_after,
                        total_cost_realized_spend_after,
                    )) = current
                    {
                        let event_seq = allocate_budget_replication_seq(&transaction)?;
                        if retry_follows_rollback {
                            SqliteBudgetStore::upsert_hold(
                                &transaction,
                                hold_id,
                                capability_id,
                                grant_index,
                                cost_units,
                                cost_units,
                                HoldDisposition::Open,
                                authority,
                            )?;
                        }
                        SqliteBudgetStore::append_mutation_event(
                            &transaction,
                            event_id,
                            Some(hold_id),
                            authority,
                            capability_id,
                            grant_index,
                            BudgetMutationKind::AuthorizeExposure,
                            Some(true),
                            event_seq,
                            Some(usage_seq),
                            cost_units,
                            0,
                            max_invocations,
                            max_cost_per_invocation,
                            max_total_cost_units,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )?;
                        if let Some(journal) = journal {
                            insert_payment_journal_tx(&transaction, journal, true)?;
                        }
                        transaction.commit()?;
                        return Ok(true);
                    }
                }
            }
            if retry_follows_rollback {
                Self::delete_hold_if_exists(&transaction, hold_id)?;
            }
        }

        let mut allowed = true;

        if let Some(max) = max_invocations {
            if current_count >= max {
                allowed = false;
            }
        }
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        if let Some(max_total) = max_total_cost_units {
            let current_total = checked_committed_cost_units(current_exposed, current_realized)?;
            let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                allowed = false;
            }
        }

        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            event_seq,
            usage_seq,
        );
        if allowed {
            if let Some(hold_id) = hold_id {
                let retry_follows_rollback = match event_id {
                    Some(event_id) => Self::rollback_event_exists(&transaction, event_id)?,
                    None => false,
                };
                if retry_follows_rollback {
                    if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                        if hold.capability_id == capability_id
                            && hold.grant_index == grant_index
                            && hold.authorized_exposure_units == cost_units
                            && hold.remaining_exposure_units == cost_units
                            && hold.invocation_count_debited
                            && hold.disposition == HoldDisposition::Open
                            && current_exposed >= cost_units
                        {
                            let current = transaction
                                .query_row(
                                    r#"
                                    SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                    FROM capability_grant_budgets
                                    WHERE capability_id = ?1 AND grant_index = ?2
                                    "#,
                                    params![capability_id, grant_index as i64],
                                    |row| {
                                        Ok((
                                            budget_u64_from_row(row, 0, "seq")?,
                                            budget_u32_from_row(row, 1, "invocation_count")?,
                                            budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                            budget_u64_from_row(
                                                row,
                                                3,
                                                "total_cost_realized_spend",
                                            )?,
                                        ))
                                    },
                                )
                                .optional()?;
                            if let Some((
                                usage_seq,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )) = current
                            {
                                let event_seq = allocate_budget_replication_seq(&transaction)?;
                                SqliteBudgetStore::upsert_hold(
                                    &transaction,
                                    hold_id,
                                    capability_id,
                                    grant_index,
                                    cost_units,
                                    cost_units,
                                    HoldDisposition::Open,
                                    authority,
                                )?;
                                SqliteBudgetStore::append_mutation_event(
                                    &transaction,
                                    event_id,
                                    Some(hold_id),
                                    authority,
                                    capability_id,
                                    grant_index,
                                    BudgetMutationKind::AuthorizeExposure,
                                    Some(true),
                                    event_seq,
                                    Some(usage_seq),
                                    cost_units,
                                    0,
                                    max_invocations,
                                    max_cost_per_invocation,
                                    max_total_cost_units,
                                    invocation_count_after,
                                    total_cost_exposed_after,
                                    total_cost_realized_spend_after,
                                )?;
                                if let Some(journal) = journal {
                                    insert_payment_journal_tx(&transaction, journal, true)?;
                                }
                                transaction.commit()?;
                                return Ok(true);
                            }
                        }
                    }
                    Self::delete_hold_if_exists(&transaction, hold_id)?;
                } else if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                    if hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == cost_units
                        && hold.remaining_exposure_units == cost_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                    {
                        let current = transaction
                            .query_row(
                                r#"
                                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                FROM capability_grant_budgets
                                WHERE capability_id = ?1 AND grant_index = ?2
                                "#,
                                params![capability_id, grant_index as i64],
                                |row| {
                                    Ok((
                                        budget_u64_from_row(row, 0, "seq")?,
                                        budget_u32_from_row(row, 1, "invocation_count")?,
                                        budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                        budget_u64_from_row(
                                            row,
                                            3,
                                            "total_cost_realized_spend",
                                        )?,
                                    ))
                                },
                            )
                            .optional()?;
                        if let Some((
                            seq,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )) = current
                        {
                            if total_cost_exposed_after < cost_units {
                                transaction.rollback()?;
                                return Err(BudgetStoreError::Invariant(format!(
                                    "budget hold `{hold_id}` is not reflected in usage totals"
                                )));
                            }
                            SqliteBudgetStore::append_mutation_event(
                                &transaction,
                                event_id,
                                Some(hold_id),
                                authority,
                                capability_id,
                                grant_index,
                                BudgetMutationKind::AuthorizeExposure,
                                Some(true),
                                seq,
                                Some(seq),
                                cost_units,
                                0,
                                max_invocations,
                                max_cost_per_invocation,
                                max_total_cost_units,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )?;
                            if let Some(journal) = journal {
                                insert_payment_journal_tx(&transaction, journal, true)?;
                            }
                            transaction.commit()?;
                            return Ok(true);
                        }
                    }
                    transaction.rollback()?;
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` already exists"
                    )));
                }
            }
            let new_total_cost_exposed =
                current_exposed.checked_add(cost_units).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            let updated_at = unix_now();
            let seq = allocate_budget_replication_seq(&transaction)?;
            transaction.execute(
                r#"
                INSERT INTO capability_grant_budgets (
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                    invocation_count = excluded.invocation_count,
                    updated_at = excluded.updated_at,
                    seq = excluded.seq,
                    total_cost_exposed = excluded.total_cost_exposed,
                    total_cost_realized_spend = excluded.total_cost_realized_spend
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    (current_count.saturating_add(1)) as i64,
                    updated_at,
                    seq as i64,
                    new_total_cost_exposed as i64,
                    current_realized as i64,
                ],
            )?;
            if let Some(hold_id) = hold_id {
                SqliteBudgetStore::create_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                    cost_units,
                    authority,
                )?;
            }
            invocation_count_after = current_count.saturating_add(1);
            total_cost_exposed_after = new_total_cost_exposed;
            total_cost_realized_spend_after = current_realized;
            event_seq = seq;
            usage_seq = Some(seq);
        } else {
            event_seq = allocate_budget_replication_seq(&transaction)?;
            invocation_count_after = current_count;
            total_cost_exposed_after = current_exposed;
            total_cost_realized_spend_after = current_realized;
            usage_seq = None;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::AuthorizeExposure,
            Some(allowed),
            event_seq,
            usage_seq,
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        if allowed {
            if let Some(journal) = journal {
                insert_payment_journal_tx(&transaction, journal, true)?;
            }
        }
        transaction.commit()?;
        Ok(allowed)
    }
}

fn journal_state_str(state: chio_kernel::payment::PaymentJournalState) -> &'static str {
    use chio_kernel::payment::PaymentJournalState as State;
    match state {
        State::HoldPlaced => "hold_placed",
        State::Authorized => "authorized",
        State::Settling => "settling",
        State::Settled => "settled",
        State::Closed => "closed",
        State::ReconcileFailed => "reconcile_failed",
    }
}

fn parse_journal_state(
    value: &str,
) -> Result<chio_kernel::payment::PaymentJournalState, BudgetStoreError> {
    use chio_kernel::payment::PaymentJournalState as State;
    match value {
        "hold_placed" => Ok(State::HoldPlaced),
        "authorized" => Ok(State::Authorized),
        "settling" => Ok(State::Settling),
        "settled" => Ok(State::Settled),
        "closed" => Ok(State::Closed),
        "reconcile_failed" => Ok(State::ReconcileFailed),
        other => Err(BudgetStoreError::Invariant(format!(
            "unknown payment journal state `{other}`"
        ))),
    }
}

fn settle_action_str(action: chio_kernel::payment::PaymentSettleAction) -> &'static str {
    match action {
        chio_kernel::payment::PaymentSettleAction::Capture => "capture",
        chio_kernel::payment::PaymentSettleAction::Release => "release",
    }
}

fn parse_settle_action(
    value: &str,
) -> Result<chio_kernel::payment::PaymentSettleAction, BudgetStoreError> {
    match value {
        "capture" => Ok(chio_kernel::payment::PaymentSettleAction::Capture),
        "release" => Ok(chio_kernel::payment::PaymentSettleAction::Release),
        other => Err(BudgetStoreError::Invariant(format!(
            "unknown payment settle action `{other}`"
        ))),
    }
}

/// Column shape shared by every `payment_journal` point and range query,
/// in the fixed order every `SELECT` below projects.
type PaymentJournalRow = (
    String,
    String,
    i64,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<i64>,
    String,
    String,
    i64,
    Option<String>,
);

/// Decode one `payment_journal` row into the kernel-owned record type.
fn payment_journal_row_to_record(
    row: PaymentJournalRow,
) -> Result<chio_kernel::payment::PaymentJournalRecord, BudgetStoreError> {
    let (
        request_id,
        capability_id,
        grant_index,
        hold_id,
        rail,
        authorization_id,
        transaction_id,
        amount_units,
        settle_action,
        settle_amount_units,
        currency,
        state,
        created_at,
        tenant_id,
    ) = row;
    Ok(chio_kernel::payment::PaymentJournalRecord {
        request_id,
        capability_id,
        grant_index: grant_index.clamp(0, i64::from(u32::MAX)) as u32,
        hold_id,
        rail,
        authorization_id,
        transaction_id,
        amount_units: amount_units.max(0) as u64,
        settle_action: settle_action
            .as_deref()
            .map(parse_settle_action)
            .transpose()?,
        settle_amount_units: settle_amount_units.map(|units| units.max(0) as u64),
        currency,
        state: parse_journal_state(&state)?,
        created_at_unix_ms: created_at.max(0) as u64,
        tenant_id,
    })
}

fn journal_now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Insert a payment-journal row inside an open transaction. A reused
/// request id fails closed, except that an idempotent hold retry may
/// re-encounter the row it wrote on a prior attempt (same request id and
/// hold id).
fn insert_payment_journal_tx(
    transaction: &rusqlite::Transaction<'_>,
    entry: &chio_kernel::payment::PaymentJournalRecord,
    allow_idempotent_retry: bool,
) -> Result<(), BudgetStoreError> {
    let changed = transaction.execute(
        "INSERT INTO payment_journal (request_id, capability_id, grant_index, hold_id, rail, \
         authorization_id, transaction_id, amount_units, settle_action, settle_amount_units, \
         currency, state, created_at, updated_at, tenant_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
         ON CONFLICT(request_id) DO NOTHING",
        params![
            entry.request_id,
            entry.capability_id,
            i64::from(entry.grant_index),
            entry.hold_id,
            entry.rail,
            entry.authorization_id,
            entry.transaction_id,
            entry.amount_units.min(i64::MAX as u64) as i64,
            entry.settle_action.map(settle_action_str),
            entry
                .settle_amount_units
                .map(|units| units.min(i64::MAX as u64) as i64),
            entry.currency,
            journal_state_str(entry.state),
            entry.created_at_unix_ms.min(i64::MAX as u64) as i64,
            journal_now_unix_ms(),
            entry.tenant_id,
        ],
    )?;
    if changed == 0 {
        if allow_idempotent_retry {
            let existing_hold: Option<Option<String>> = transaction
                .query_row(
                    "SELECT hold_id FROM payment_journal WHERE request_id = ?1",
                    params![entry.request_id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing_hold
                .as_ref()
                .is_some_and(|hold| *hold == entry.hold_id)
            {
                return Ok(());
            }
        }
        return Err(BudgetStoreError::Invariant(format!(
            "payment journal request_id already recorded: {}",
            entry.request_id
        )));
    }
    Ok(())
}
