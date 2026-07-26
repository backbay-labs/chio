use super::*;

impl SqliteBudgetStore {
    pub(super) fn validate_import_hold_frontier(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            return Ok(());
        };
        type Frontier = (String, u64, Option<BudgetEventAuthority>);
        let frontier: Option<Frontier> = transaction
            .query_row(
                r#"
                SELECT event_id, event_seq, authority_id, lease_id, lease_epoch
                FROM budget_mutation_events
                WHERE hold_id = ?1
                ORDER BY event_seq DESC LIMIT 1
                "#,
                params![hold_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        budget_u64_from_row(row, 1, "event_seq")?,
                        sqlite_budget_event_authority(row.get(2)?, row.get(3)?, row.get(4)?)?,
                    ))
                },
            )
            .optional()?;
        let Some((frontier_id, frontier_seq, frontier_authority)) = frontier else {
            return Ok(());
        };
        if record.kind == BudgetMutationKind::AuthorizeExposure {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` authorization identity already has durable history"
            )));
        }
        if record.event_seq <= frontier_seq {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` import sequence {} does not advance frontier `{frontier_id}` at {frontier_seq}",
                record.event_seq
            )));
        }
        match (frontier_authority.as_ref(), record.authority.as_ref()) {
            (Some(_), None) => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` import changed authority presence"
                )));
            }
            (None, Some(_)) => {}
            (Some(frontier), Some(incoming))
                if incoming.lease_epoch < frontier.lease_epoch
                    || (incoming.lease_epoch == frontier.lease_epoch
                        && (incoming.authority_id != frontier.authority_id
                            || incoming.lease_id != frontier.lease_id)) =>
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` import changed or regressed authority"
                )));
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn apply_imported_hold_state(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            if matches!(
                record.kind,
                BudgetMutationKind::ReverseExposure | BudgetMutationKind::ReleaseExposure
            ) && Self::has_captured_hold(
                transaction,
                &record.capability_id,
                record.grant_index as usize,
            )? {
                return Err(BudgetStoreError::Invariant(format!(
                    "captured budget hold blocks generic `{}` mutation",
                    record.kind.as_str()
                )));
            }
            return Ok(());
        };

        let existing = Self::load_hold(transaction, hold_id)?;
        if record.kind == BudgetMutationKind::AuthorizeExposure {
            if existing.is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` authorization identity already exists"
                )));
            }
        } else {
            Self::validate_imported_hold_predecessor(record, existing.as_ref())?;
        }

        let applied = match record.kind {
            BudgetMutationKind::IncrementInvocation => Ok(()),
            BudgetMutationKind::AuthorizeExposure => {
                if record.allowed == Some(true) {
                    Self::upsert_hold(
                        transaction,
                        hold_id,
                        &record.capability_id,
                        record.grant_index as usize,
                        record.exposure_units,
                        record.exposure_units,
                        false,
                        HoldDisposition::Open,
                        record.authority.as_ref(),
                    )
                } else {
                    Self::delete_hold_if_exists(transaction, hold_id)
                }
            }
            BudgetMutationKind::ReleaseExposure => {
                let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing release event"
                    ))
                })?;
                if hold.capability_id != record.capability_id
                    || hold.grant_index != record.grant_index as usize
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match capability/grant"
                    )));
                }
                if hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured"
                    )));
                }
                let remaining = hold
                    .remaining_exposure_units
                    .checked_sub(record.exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` cannot release more than remaining exposure"
                        ))
                    })?;
                let disposition = if remaining == 0 {
                    HoldDisposition::Released
                } else {
                    HoldDisposition::Open
                };
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    remaining,
                    hold.invocation_captured,
                    disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::CancelCapturedBeforeDispatch => {
                if record.allowed != Some(true) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget captured-before-dispatch cancellation event `{}` was not allowed",
                        record.event_id
                    )));
                }
                let hold = Self::ensure_open_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                )?;
                if !hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was not captured"
                    )));
                }
                if record.exposure_units != hold.authorized_exposure_units
                    || hold.remaining_exposure_units != hold.authorized_exposure_units
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match captured cancellation exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    0,
                    false,
                    HoldDisposition::Reversed,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::CaptureInvocation => {
                if record.allowed != Some(true) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget invocation capture event `{}` was not allowed",
                        record.event_id
                    )));
                }
                let hold = Self::ensure_open_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                )?;
                if !hold.invocation_count_debited {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` has no invocation reservation to capture"
                    )));
                }
                if hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured by another event"
                    )));
                }
                if record.exposure_units != hold.remaining_exposure_units {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match invocation capture exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    hold.remaining_exposure_units,
                    true,
                    hold.disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::ReverseExposure => {
                let existing = existing.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing reversal event"
                    ))
                })?;
                if existing.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured"
                    )));
                }
                if record.exposure_units != existing.remaining_exposure_units {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` imported reversal does not match live exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    existing.authorized_exposure_units,
                    0,
                    false,
                    HoldDisposition::Reversed,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReconcileSpend => {
                let existing = existing.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing reconciliation event"
                    ))
                })?;
                if !existing.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was not captured before reconciliation"
                    )));
                }
                if record.exposure_units != existing.remaining_exposure_units
                    || record.realized_spend_units > record.exposure_units
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` imported reconciliation does not match live exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    existing.authorized_exposure_units,
                    0,
                    true,
                    HoldDisposition::Reconciled,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReserveInvocation
            | BudgetMutationKind::AuthorizeCumulativeApproval
            | BudgetMutationKind::ReverseInvocation
            | BudgetMutationKind::CaptureSpend => Err(BudgetStoreError::Invariant(format!(
                "budget mutation `{}` uses state unsupported by the sqlite budget store",
                record.kind.as_str()
            ))),
        };
        applied?;
        if Self::load_hold(transaction, hold_id)?.is_some() {
            let changed = transaction.execute(
                r#"
                UPDATE budget_authorization_holds
                SET authorization_outcome = COALESCE(?2, authorization_outcome),
                    invocation_state = ?3,
                    monetary_state = ?4
                WHERE hold_id = ?1
                "#,
                params![
                    hold_id,
                    record
                        .authorization_outcome
                        .map(budget_authorization_outcome_text),
                    budget_invocation_state_text(record.invocation_state_after),
                    budget_monetary_state_text(record.monetary_state_after),
                ],
            )?;
            if changed != 1 {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget mutation `{}` did not persist its hold lifecycle",
                    record.event_id
                )));
            }
        }
        Self::validate_imported_hold_successor(
            transaction,
            record,
            Self::load_hold(transaction, hold_id)?.as_ref(),
        )
    }

    fn validate_imported_hold_predecessor(
        record: &BudgetMutationRecord,
        hold: Option<&SqliteBudgetHold>,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold) = hold else {
            if matches!(record.kind, BudgetMutationKind::IncrementInvocation) {
                return Ok(());
            }
            return Err(BudgetStoreError::Invariant(format!(
                "missing budget hold `{}` while importing `{}` event",
                record.hold_id.as_deref().unwrap_or(""),
                record.kind.as_str()
            )));
        };
        if hold.capability_id != record.capability_id
            || hold.grant_index != record.grant_index as usize
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` does not match imported capability/grant",
                hold.hold_id
            )));
        }
        let (invocation, monetary) = Self::legacy_hold_lifecycle(hold);
        if record.invocation_state_before != invocation || record.monetary_state_before != monetary
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` imported `{}` predecessor does not match durable state",
                hold.hold_id,
                record.kind.as_str()
            )));
        }
        Ok(())
    }

    fn validate_imported_hold_successor(
        _transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
        hold: Option<&SqliteBudgetHold>,
    ) -> Result<(), BudgetStoreError> {
        if record.kind == BudgetMutationKind::IncrementInvocation
            || (record.kind == BudgetMutationKind::AuthorizeExposure
                && record.allowed == Some(false))
        {
            return Ok(());
        }
        let hold = hold.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget mutation `{}` did not persist its hold successor",
                record.event_id
            ))
        })?;
        let (invocation, monetary) = Self::legacy_hold_lifecycle(hold);
        if record.invocation_state_after != invocation || record.monetary_state_after != monetary {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` imported `{}` successor does not match durable state",
                hold.hold_id,
                record.kind.as_str()
            )));
        }
        Ok(())
    }

    fn legacy_hold_lifecycle(
        hold: &SqliteBudgetHold,
    ) -> (BudgetInvocationState, BudgetMonetaryState) {
        let invocation = if hold.disposition == HoldDisposition::Reversed {
            BudgetInvocationState::Reversed
        } else if hold.invocation_captured {
            BudgetInvocationState::Captured
        } else if hold.invocation_count_debited {
            BudgetInvocationState::Authorized
        } else {
            BudgetInvocationState::Absent
        };
        let monetary = if hold.remaining_exposure_units > 0 {
            BudgetMonetaryState::Exposed
        } else {
            match hold.disposition {
                HoldDisposition::Open => BudgetMonetaryState::None,
                HoldDisposition::Released if hold.authorized_exposure_units > 0 => {
                    BudgetMonetaryState::Released
                }
                HoldDisposition::Reversed if hold.authorized_exposure_units > 0 => {
                    BudgetMonetaryState::Reversed
                }
                HoldDisposition::Reconciled => BudgetMonetaryState::Reconciled,
                HoldDisposition::Released | HoldDisposition::Reversed => BudgetMonetaryState::None,
            }
        };
        (invocation, monetary)
    }
}
