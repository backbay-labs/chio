use super::*;

impl SqliteBudgetStore {
    pub(super) fn authorize_budget_hold_atomic(
        &self,
        request: &BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        validate_budget_grant_index(request.grant_index)?;
        budget_u64_to_sqlite(request.requested_exposure_units, "requested_exposure_units")?;
        optional_budget_u64_to_sqlite(
            request.max_cost_per_invocation,
            "max_exposure_per_invocation",
        )?;
        optional_budget_u64_to_sqlite(request.max_total_cost_units, "max_total_exposure_units")?;
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_legacy_admission_after_composite_history(
            &transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        let request_event = match request.event_id.as_deref() {
            Some(event_id) => Self::load_mutation_event(&transaction, event_id)?,
            None => None,
        };
        let existing = Self::existing_event_allowed(
            &transaction,
            request.event_id.as_deref(),
            BudgetMutationKind::AuthorizeExposure,
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.requested_exposure_units,
            0,
            request.max_invocations,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
        )?;
        if existing.is_none() {
            if let Some(hold_id) = request.hold_id.as_deref() {
                if Self::load_hold(&transaction, hold_id)?.is_some() {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` exists without the requested authorization event"
                    )));
                }
            }
        }

        if let Some(hold_id) = request.hold_id.as_deref() {
            if let Some(hold) = Self::load_hold(&transaction, hold_id)? {
                Self::validate_authorize_hold(
                    &transaction,
                    request,
                    &hold,
                    request_event.as_ref(),
                )?;
                if hold.invocation_captured {
                    let current_authorize_event_id = transaction
                        .query_row(
                            r#"
                            SELECT event_id FROM budget_mutation_events
                            WHERE hold_id = ?1 AND kind = ?2
                            ORDER BY event_seq DESC LIMIT 1
                            "#,
                            params![hold_id, BudgetMutationKind::AuthorizeExposure.as_str()],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(format!(
                                "captured budget hold `{hold_id}` has no authorization event"
                            ))
                        })?;
                    if request.event_id.as_deref() != Some(current_authorize_event_id.as_str()) {
                        transaction.rollback()?;
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` authorization event is not current"
                        )));
                    }
                    let capture = Self::load_current_capture_event(&transaction, hold_id)?;
                    let decision = Self::captured_authorize_decision(self, hold, capture)?;
                    transaction.commit()?;
                    return Ok(decision);
                }
                if hold.disposition != HoldDisposition::Open {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` cannot be reopened by authorization"
                    )));
                }
            }
        }

        if existing.is_some() {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "idempotent budget authorization is missing its event id".to_string(),
                )
            })?;
            let event = Self::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget authorization event disappeared during transaction".to_string(),
                )
            })?;
            let decision = Self::authorize_event_decision(self, event)?;
            transaction.commit()?;
            return Ok(decision);
        }

        let current = transaction
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
            .unwrap_or((0, 0, 0, 0));

        let allowed = Self::authorize_limits_allow(request, current.1, current.2, current.3)?;
        let authorized_usage = if allowed {
            let exposed_after = current
                .2
                .checked_add(request.requested_exposure_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + requested exposure overflowed u64".to_string(),
                    )
                })?;
            let invocation_count_after = current.1.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation count overflowed u32".to_string())
            })?;
            budget_u64_to_sqlite(exposed_after, "total_cost_exposed")?;
            Some((invocation_count_after, exposed_after))
        } else {
            None
        };
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let (usage_seq, invocation_count_after, exposed_after, realized_after) =
            if let Some((invocation_count_after, exposed_after)) = authorized_usage {
                transaction.execute(
                    r#"
                INSERT INTO capability_grant_budgets (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                    invocation_count = excluded.invocation_count,
                    updated_at = excluded.updated_at,
                    seq = excluded.seq,
                    total_cost_exposed = excluded.total_cost_exposed,
                    total_cost_realized_spend = excluded.total_cost_realized_spend
                "#,
                    params![
                        &request.capability_id,
                        request.grant_index as i64,
                        i64::from(invocation_count_after),
                        unix_now(),
                        budget_u64_to_sqlite(event_seq, "seq")?,
                        budget_u64_to_sqlite(exposed_after, "total_cost_exposed")?,
                        budget_u64_to_sqlite(current.3, "total_cost_realized_spend")?,
                    ],
                )?;
                if let Some(hold_id) = request.hold_id.as_deref() {
                    Self::create_hold(
                        &transaction,
                        hold_id,
                        &request.capability_id,
                        request.grant_index,
                        request.requested_exposure_units,
                        request.authority.as_ref(),
                    )?;
                }
                (
                    Some(event_seq),
                    invocation_count_after,
                    exposed_after,
                    current.3,
                )
            } else {
                (None, current.1, current.2, current.3)
            };
        let event = Self::append_mutation_event(
            &transaction,
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::AuthorizeExposure,
            Some(allowed),
            event_seq,
            usage_seq,
            request.requested_exposure_units,
            0,
            request.max_invocations,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            invocation_count_after,
            exposed_after,
            realized_after,
        )?;
        let decision = Self::authorize_event_decision(self, event)?;
        transaction.commit()?;
        Ok(decision)
    }

    fn validate_authorize_hold(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetAuthorizeHoldRequest,
        hold: &SqliteBudgetHold,
        request_event: Option<&BudgetMutationRecord>,
    ) -> Result<(), BudgetStoreError> {
        if hold.capability_id != request.capability_id
            || hold.grant_index != request.grant_index
            || hold.authorized_exposure_units != request.requested_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` was reused for a different authorization",
                hold.hold_id
            )));
        }
        let original = match request_event {
            Some(event) => event.clone(),
            None => {
                let original = transaction
                    .query_row(
                        r#"
                    SELECT event_id FROM budget_mutation_events
                    WHERE hold_id = ?1 AND kind = ?2
                    ORDER BY event_seq ASC LIMIT 1
                    "#,
                        params![
                            &hold.hold_id,
                            BudgetMutationKind::AuthorizeExposure.as_str()
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let Some(original) = original else {
                    return Ok(());
                };
                Self::load_mutation_event(transaction, &original)?.ok_or_else(|| {
                    BudgetStoreError::Invariant("budget authorize event disappeared".to_string())
                })?
            }
        };
        if original.kind != BudgetMutationKind::AuthorizeExposure
            || original.capability_id != request.capability_id
            || original.grant_index != request.grant_index as u32
            || original.exposure_units != request.requested_exposure_units
            || original.max_invocations != request.max_invocations
            || original.max_cost_per_invocation != request.max_cost_per_invocation
            || original.max_total_cost_units != request.max_total_cost_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` authorization parameters changed",
                hold.hold_id
            )));
        }
        Ok(())
    }

    pub(super) fn load_current_capture_event(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let event_id = transaction
            .query_row(
                r#"
                SELECT event_id FROM budget_mutation_events
                WHERE hold_id = ?1
                  AND kind = ?2
                  AND event_seq > COALESCE((
                      SELECT MAX(event_seq) FROM budget_mutation_events
                      WHERE hold_id = ?1 AND kind = ?3
                  ), 0)
                ORDER BY event_seq DESC LIMIT 1
                "#,
                params![
                    hold_id,
                    BudgetMutationKind::CaptureInvocation.as_str(),
                    BudgetMutationKind::AuthorizeExposure.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "captured budget hold `{hold_id}` has no capture event and is quarantined"
                ))
            })?;
        Self::load_mutation_event(transaction, &event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "captured invocation event disappeared during authorization".to_string(),
            )
        })
    }

    fn authorize_limits_allow(
        request: &BudgetAuthorizeHoldRequest,
        invocation_count: u32,
        exposed: u64,
        realized: u64,
    ) -> Result<bool, BudgetStoreError> {
        if request
            .max_invocations
            .is_some_and(|max| invocation_count >= max)
            || request
                .max_cost_per_invocation
                .is_some_and(|max| request.requested_exposure_units > max)
        {
            return Ok(false);
        }
        let committed = checked_committed_cost_units(exposed, realized)?;
        let requested = committed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        Ok(request
            .max_total_cost_units
            .is_none_or(|max| requested <= max))
    }

    fn authorize_event_decision(
        &self,
        event: BudgetMutationRecord,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let committed_cost_units_after = checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?;
        let metadata = BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: self.budget_guarantee_level(),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: event
                .allowed
                .and_then(|allowed| allowed.then_some(event.event_seq)),
            event_id: Some(event.event_id),
            recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
        };
        if event.allowed == Some(true) {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: event.hold_id,
                    admission_binding: None,
                    authorized_exposure_units: event.exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: event.invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Authorized,
                    monetary_state: if event.exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: event.hold_id,
                admission_binding: None,
                attempted_exposure_units: event.exposure_units,
                committed_cost_units_after,
                invocation_count_after: event.invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Denied,
                monetary_state: BudgetMonetaryState::None,
                metadata,
            }))
        }
    }

    fn captured_authorize_decision(
        &self,
        hold: SqliteBudgetHold,
        capture: BudgetMutationRecord,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        Ok(BudgetAuthorizeHoldDecision::AlreadyCaptured(
            BudgetHoldMutationDecision {
                hold_id: Some(hold.hold_id),
                admission_binding: None,
                exposure_units: capture.exposure_units,
                realized_spend_units: capture.realized_spend_units,
                committed_cost_units_after: checked_committed_cost_units(
                    capture.total_cost_exposed_after,
                    capture.total_cost_realized_spend_after,
                )?,
                invocation_count_after: capture.invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Captured,
                monetary_state: if capture.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                },
                metadata: BudgetCommitMetadata {
                    authority: capture.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(capture.event_seq),
                    event_id: Some(capture.event_id),
                    recorded_at_unix_seconds: u64::try_from(capture.recorded_at).ok(),
                },
            },
        ))
    }
}
