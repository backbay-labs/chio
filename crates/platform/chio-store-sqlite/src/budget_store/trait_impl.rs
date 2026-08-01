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

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        request.validate()?;
        if !request.invocation_quotas.is_empty()
            || request.cumulative_approval.is_some()
            || request.admission_binding.is_some()
        {
            return self.authorize_composite_hold(request);
        }
        self.require_standalone_mutation("unbound authorization")?;
        self.authorize_budget_hold_atomic(&request)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        validate_budget_grant_index(request.grant_index)?;
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.capture_composite_invocation(request);
        }
        self.require_standalone_mutation("unbound invocation capture")?;
        if request.trusted_time.is_some() {
            return Err(BudgetStoreError::Invariant(
                "trusted capture time is not supported by the sqlite budget store".to_string(),
            ));
        }
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_legacy_writer(
            &transaction,
            Some(&request.hold_id),
            "invocation capture",
        )?;

        let existing_event =
            SqliteBudgetStore::load_mutation_event(&transaction, &request.event_id)?;
        let existing = SqliteBudgetStore::existing_event_allowed(
            &transaction,
            Some(&request.event_id),
            BudgetMutationKind::CaptureInvocation,
            &request.capability_id,
            request.grant_index,
            Some(&request.hold_id),
            request.authority.as_ref(),
            existing_event
                .as_ref()
                .map_or(0, |event| event.exposure_units),
            0,
            None,
            None,
            None,
        )?;
        let usage = transaction
            .query_row(
                r#"
                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![&request.capability_id, request.grant_index as i64],
                |row| {
                    Ok((
                        budget_u64_from_row(row, 0, "seq")?,
                        budget_u32_from_row(row, 1, "invocation_count")?,
                        budget_u64_from_row(row, 2, "total_cost_exposed")?,
                        budget_u64_from_row(row, 3, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;
        let mutation = |event_id: String,
                        event_seq,
                        authority: Option<BudgetEventAuthority>,
                        invocation_count_after,
                        total_cost_exposed_after,
                        total_cost_realized_spend_after,
                        exposure_units|
         -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
            Ok(BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id.clone()),
                admission_binding: None,
                exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                )?,
                invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Captured,
                monetary_state: if exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                },
                metadata: BudgetCommitMetadata {
                    authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(event_seq),
                    event_id: Some(event_id),
                    recorded_at_unix_seconds: None,
                },
            })
        };

        if existing.is_some() {
            let hold =
                SqliteBudgetStore::load_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "captured budget hold `{}` disappeared",
                        request.hold_id
                    ))
                })?;
            if !hold.invocation_captured {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation capture is no longer current",
                    request.hold_id
                )));
            }
            let original =
                SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
            if original.event_id != request.event_id {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation capture is no longer current",
                    request.hold_id
                )));
            }
            transaction.rollback()?;
            return Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation(
                original.event_id,
                original.event_seq,
                original.authority,
                original.invocation_count_after,
                original.total_cost_exposed_after,
                original.total_cost_realized_spend_after,
                original.exposure_units,
            )?));
        }

        let hold = SqliteBudgetStore::ensure_open_hold(
            &transaction,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if !hold.invocation_count_debited {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no invocation reservation to capture",
                request.hold_id
            )));
        }
        if hold.invocation_captured {
            let original =
                SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
            if original.event_id != request.event_id {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation was captured by a different event",
                    request.hold_id
                )));
            }
            transaction.rollback()?;
            return Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation(
                original.event_id,
                original.event_seq,
                original.authority,
                original.invocation_count_after,
                original.total_cost_exposed_after,
                original.total_cost_realized_spend_after,
                original.exposure_units,
            )?));
        }

        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET invocation_captured = 1,
                disposition = CASE
                    WHEN remaining_exposure_units = 0 THEN 'reconciled'
                    ELSE disposition
                END,
                updated_at = ?2
            WHERE hold_id = ?1
              AND invocation_count_debited = 1
              AND invocation_captured = 0
            "#,
            params![&request.hold_id, unix_now()],
        )?;
        if changed != 1 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation capture compare-and-set failed",
                request.hold_id
            )));
        }

        SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureInvocation,
            Some(true),
            event_seq,
            Some(usage.0),
            hold.remaining_exposure_units,
            0,
            None,
            None,
            None,
            usage.1,
            usage.2,
            usage.3,
        )?;
        transaction.commit()?;
        Ok(BudgetInvocationCaptureDecision::Captured(mutation(
            request.event_id,
            event_seq,
            request.authority,
            usage.1,
            usage.2,
            usage.3,
            hold.remaining_exposure_units,
        )?))
    }

    fn authorize_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        self.authorize_composite_cumulative_approval(request)
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        validate_budget_grant_index(request.grant_index)?;
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.cancel_captured_composite_hold(request);
        }
        self.require_standalone_mutation("captured invocation cancellation")?;
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_legacy_writer(
            &transaction,
            Some(&request.hold_id),
            "captured invocation cancellation",
        )?;

        if let Some(existing) =
            SqliteBudgetStore::load_mutation_event(&transaction, &request.event_id)?
        {
            SqliteBudgetStore::validate_replay_authority(
                &request.event_id,
                existing.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            let matches = existing.kind == BudgetMutationKind::CancelCapturedBeforeDispatch
                && existing.hold_id.as_deref() == Some(request.hold_id.as_str())
                && existing.capability_id == request.capability_id
                && existing.grant_index == request.grant_index as u32
                && existing.allowed == Some(true)
                && existing.realized_spend_units == 0
                && existing.max_invocations.is_none()
                && existing.max_cost_per_invocation.is_none()
                && existing.max_total_cost_units.is_none();
            if !matches {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{}` was reused for a different mutation",
                    request.event_id
                )));
            }
            let mutation = BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id),
                admission_binding: None,
                exposure_units: existing.exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    existing.total_cost_exposed_after,
                    existing.total_cost_realized_spend_after,
                )?,
                invocation_count_after: existing.invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Reversed,
                monetary_state: if existing.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                },
                metadata: BudgetCommitMetadata {
                    authority: existing.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(existing.event_seq),
                    event_id: Some(existing.event_id),
                    recorded_at_unix_seconds: u64::try_from(existing.recorded_at).ok(),
                },
            };
            transaction.rollback()?;
            return Ok(
                BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation),
            );
        }

        let hold = SqliteBudgetStore::ensure_open_hold(
            &transaction,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if !hold.invocation_count_debited || !hold.invocation_captured {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no captured invocation to cancel before dispatch",
                request.hold_id
            )));
        }
        let capture =
            SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
        if capture.capability_id != request.capability_id
            || capture.grant_index != request.grant_index as u32
            || capture.allowed != Some(true)
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "captured budget hold `{}` has mismatched capture evidence",
                request.hold_id
            )));
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![&request.capability_id, request.grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;
        if hold.remaining_exposure_units != hold.authorized_exposure_units
            || current.0 == 0
            || current.1 < hold.authorized_exposure_units
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` does not match captured-before-dispatch cancellation",
                request.hold_id
            )));
        }

        let total_cost_exposed_after = current.1 - hold.authorized_exposure_units;
        let event_seq = allocate_budget_replication_seq(&transaction)?;
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
                &request.capability_id,
                request.grant_index as i64,
                current.0 - 1,
                unix_now(),
                budget_u64_to_sqlite(event_seq, "seq")?,
                budget_u64_to_sqlite(total_cost_exposed_after, "total_cost_exposed")?,
            ],
        )?;
        SqliteBudgetStore::update_hold(
            &transaction,
            &request.hold_id,
            0,
            HoldDisposition::Reversed,
            request.authority.as_ref().or(hold.authority.as_ref()),
        )?;
        transaction.execute(
            "UPDATE budget_authorization_holds SET invocation_captured = 0 WHERE hold_id = ?1",
            params![&request.hold_id],
        )?;
        SqliteBudgetStore::append_mutation_event(
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
            hold.authorized_exposure_units,
            0,
            None,
            None,
            None,
            current.0 - 1,
            total_cost_exposed_after,
            current.2,
        )?;
        transaction.commit()?;

        Ok(BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(
            BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id),
                admission_binding: None,
                exposure_units: hold.authorized_exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    total_cost_exposed_after,
                    current.2,
                )?,
                invocation_count_after: current.0 - 1,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Reversed,
                monetary_state: if hold.authorized_exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                },
                metadata: BudgetCommitMetadata {
                    authority: request.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(event_seq),
                    event_id: Some(request.event_id),
                    recorded_at_unix_seconds: None,
                },
            },
        ))
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget release requires a durable hold identity".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget release requires a durable event identity".to_string(),
            )
        })?;
        if self.is_structured_hold(hold_id)? {
            return self.release_composite_hold(request);
        }
        self.require_standalone_mutation("legacy exposure release")?;
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            Some(hold_id),
            Some(event_id),
            request.authority.as_ref(),
        )?;
        recorded_sqlite_hold_mutation(self, hold_id, event_id, BudgetMutationKind::ReleaseExposure)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget reversal requires a durable hold identity".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget reversal requires a durable event identity".to_string(),
            )
        })?;
        if self.is_structured_hold(hold_id)? {
            return self.reverse_composite_hold(request);
        }
        self.require_standalone_mutation("legacy hold reversal")?;
        if request.expected_cumulative_approval_state.is_some() {
            return Err(BudgetStoreError::Invariant(
                "legacy sqlite budget holds do not support cumulative approval state fencing"
                    .to_string(),
            ));
        }
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            Some(hold_id),
            Some(event_id),
            request.authority.as_ref(),
        )?;
        recorded_sqlite_hold_mutation(self, hold_id, event_id, BudgetMutationKind::ReverseExposure)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget reconciliation requires a durable hold identity".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite rich budget reconciliation requires a durable event identity".to_string(),
            )
        })?;
        if self.is_structured_hold(hold_id)? {
            return self.reconcile_composite_hold(request);
        }
        self.require_standalone_mutation("legacy spend reconciliation")?;
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            Some(hold_id),
            Some(event_id),
            request.authority.as_ref(),
        )?;
        recorded_sqlite_hold_mutation(self, hold_id, event_id, BudgetMutationKind::ReconcileSpend)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite monetary capture requires a durable hold identity".to_string(),
            )
        })?;
        if !self.is_structured_hold(hold_id)? {
            return Err(BudgetStoreError::Invariant(
                "legacy sqlite budget holds do not support distinct monetary capture".to_string(),
            ));
        }
        self.capture_composite_hold(request)
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
        self.require_standalone_mutation("unbound charge")?;
        validate_budget_grant_index(grant_index)?;
        let request = BudgetAuthorizeHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index,
            max_invocations,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id: hold_id.map(ToOwned::to_owned),
            event_id: event_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
        };
        Ok(matches!(
            self.authorize_budget_hold_atomic(&request)?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ))
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
        self.require_standalone_mutation("legacy charge reversal")?;
        validate_budget_grant_index(grant_index)?;
        budget_u64_to_sqlite(cost_units, "exposure_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_legacy_writer(&transaction, hold_id, "charge reversal")?;

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
        if hold_id.is_none()
            && SqliteBudgetStore::has_live_hold(&transaction, capability_id, grant_index)?
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "live budget hold blocks generic reverse".to_string(),
            ));
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != cost_units
                || !hold.invocation_count_debited
                || hold.invocation_captured
            {
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
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
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
        self.require_standalone_mutation("legacy charge reduction")?;
        validate_budget_grant_index(grant_index)?;
        budget_u64_to_sqlite(cost_units, "exposure_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_legacy_writer(&transaction, hold_id, "charge reduction")?;

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
        if hold_id.is_none()
            && SqliteBudgetStore::has_live_hold(&transaction, capability_id, grant_index)?
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "live budget hold blocks generic release".to_string(),
            ));
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.invocation_captured {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` invocation was already captured"
                )));
            }
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
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
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
        self.require_standalone_mutation("legacy charge settlement")?;
        validate_budget_grant_index(grant_index)?;
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        budget_u64_to_sqlite(exposed_cost_units, "exposure_units")?;
        budget_u64_to_sqlite(realized_cost_units, "realized_spend_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_legacy_writer(
            &transaction,
            hold_id,
            "charge settlement",
        )?;

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
        if hold_id.is_none()
            && SqliteBudgetStore::has_live_hold(&transaction, capability_id, grant_index)?
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "live budget hold blocks generic reconciliation".to_string(),
            ));
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if !hold.invocation_captured {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` invocation was not captured before reconciliation"
                )));
            }
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
        budget_u64_to_sqlite(new_total_cost_realized_spend, "total_cost_realized_spend")?;

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
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
                budget_u64_to_sqlite(new_total_cost_realized_spend, "total_cost_realized_spend",)?,
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
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
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
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        validate_budget_grant_index(grant_index)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
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
            .optional()?;
        transaction.rollback()?;
        Ok(row)
    }

    fn get_invocation_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        self.composite_quota_usage(key)
    }

    fn get_cumulative_approval_account_usage(
        &self,
        key: &BudgetCumulativeApprovalAccountKey,
    ) -> Result<Option<BudgetCumulativeApprovalAccountUsage>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .query_row(
                r#"
                SELECT root_grant_hash, delegation_root_id, root_binding_digest,
                       currency, authority_threshold_units,
                       reserved_authorized_units, captured_authorized_units, version
                FROM budget_cumulative_approval_accounts
                WHERE authority_id = ?1 AND owner_id = ?2
                  AND approval_budget_id = ?3 AND approval_budget_epoch = ?4
                "#,
                params![
                    &key.authority_id,
                    &key.owner_id,
                    &key.approval_budget_id,
                    budget_u64_to_sqlite(key.approval_budget_epoch, "approval_budget_epoch")?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        budget_u64_from_row(row, 4, "authority_threshold_units")?,
                        budget_u64_from_row(row, 5, "reserved_authorized_units")?,
                        budget_u64_from_row(row, 6, "captured_authorized_units")?,
                        budget_u64_from_row(row, 7, "version")?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            transaction.rollback()?;
            return Ok(None);
        };
        if row.0 != key.root_grant_hash
            || row.1 != key.delegation_root_id
            || row.2 != key.root_binding_digest
            || row.3 != key.currency
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval account immutable identity changed".to_string(),
            ));
        }
        let amount = |units| MonetaryAmount {
            units,
            currency: key.currency.clone(),
        };
        let usage = BudgetCumulativeApprovalAccountUsage {
            account_key: key.clone(),
            authority_threshold: amount(row.4),
            reserved_authorized: amount(row.5),
            captured_authorized: amount(row.6),
            version: row.7,
        };
        transaction.rollback()?;
        Ok(Some(usage))
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        self.composite_cumulative_operation_usage(operation_id)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        if let Some(grant_index) = grant_index {
            validate_budget_grant_index(grant_index)?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            r#"
            SELECT event_id
            FROM budget_mutation_events
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let event_ids = statement
            .query_map(
                params![
                    capability_id,
                    grant_index.map(|value| value as i64),
                    limit as i64
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let events = event_ids
            .iter()
            .map(|event_id| {
                Self::load_projected_mutation_event(&transaction, event_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget mutation event `{event_id}` disappeared while listing"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.rollback()?;
        Ok(events)
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
        Ok(Some(self.list_open_delegated_reserved_holds()?))
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
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
        SqliteBudgetStore::reserve_invocation_hold(
            self,
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        SqliteBudgetStore::reap_expired_reserved_holds(self, now_unix_secs)
    }
}

fn recorded_sqlite_hold_mutation(
    store: &SqliteBudgetStore,
    hold_id: &str,
    event_id: &str,
    expected_kind: BudgetMutationKind,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_read(&mut connection)?;
    let event =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "sqlite budget mutation event `{event_id}` disappeared"
            ))
        })?;
    if event.kind != expected_kind || event.hold_id.as_deref() != Some(hold_id) {
        return Err(BudgetStoreError::Invariant(format!(
            "sqlite budget mutation event `{event_id}` changed identity"
        )));
    }
    let (authorization_seq, authorized_exposure_units) = transaction
        .query_row(
            r#"
            SELECT event_seq, exposure_units
            FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND allowed = 1
              AND event_seq < ?3
            ORDER BY event_seq DESC LIMIT 1
            "#,
            params![
                hold_id,
                BudgetMutationKind::AuthorizeExposure.as_str(),
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| {
                Ok((
                    budget_u64_from_row(row, 0, "event_seq")?,
                    budget_u64_from_row(row, 1, "exposure_units")?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "sqlite budget hold `{hold_id}` has no authorization generation"
            ))
        })?;
    let invocation_captured = transaction.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND event_seq > ?3
              AND event_seq <= ?4
        )
        "#,
        params![
            hold_id,
            BudgetMutationKind::CaptureInvocation.as_str(),
            budget_u64_to_sqlite(authorization_seq, "authorization_seq")?,
            budget_u64_to_sqlite(event.event_seq, "event_seq")?,
        ],
        |row| Ok(row.get::<_, i64>(0)? != 0),
    )?;
    let invocation_state = if expected_kind == BudgetMutationKind::ReverseExposure {
        BudgetInvocationState::Reversed
    } else if invocation_captured {
        BudgetInvocationState::Captured
    } else {
        BudgetInvocationState::Authorized
    };
    let monetary_state = if expected_kind == BudgetMutationKind::ReverseExposure {
        if event.exposure_units == 0 {
            BudgetMonetaryState::None
        } else {
            BudgetMonetaryState::Reversed
        }
    } else if expected_kind == BudgetMutationKind::ReleaseExposure {
        let released_exposure_units = transaction.query_row(
            r#"
            SELECT COALESCE(SUM(exposure_units), 0)
            FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND event_seq > ?3
              AND event_seq <= ?4
            "#,
            params![
                hold_id,
                BudgetMutationKind::ReleaseExposure.as_str(),
                budget_u64_to_sqlite(authorization_seq, "authorization_seq")?,
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| budget_u64_from_row(row, 0, "released_exposure_units"),
        )?;
        let remaining_exposure_units = authorized_exposure_units
            .checked_sub(released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "sqlite budget hold `{hold_id}` release history exceeds authorization"
                ))
            })?;
        if authorized_exposure_units == 0 {
            BudgetMonetaryState::None
        } else if remaining_exposure_units == 0 {
            BudgetMonetaryState::Released
        } else {
            BudgetMonetaryState::Exposed
        }
    } else if event.exposure_units == 0 && event.realized_spend_units == 0 {
        BudgetMonetaryState::None
    } else {
        BudgetMonetaryState::Reconciled
    };
    let decision = BudgetHoldMutationDecision {
        hold_id: Some(hold_id.to_string()),
        admission_binding: None,
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?,
        invocation_count_after: event.invocation_count_after,
        invocation_quota_usages: Vec::new(),
        cumulative_approval: None,
        invocation_state,
        monetary_state,
        metadata: BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: Some(event.event_seq),
            event_id: Some(event.event_id),
            recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
        },
    };
    transaction.rollback()?;
    Ok(decision)
}
