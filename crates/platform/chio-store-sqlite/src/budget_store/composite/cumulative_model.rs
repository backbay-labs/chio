use super::*;

fn canonical_approval_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_cumulative_approval_history(
    transaction: &Transaction<'_>,
    request: &BudgetCumulativeApprovalRequest,
    state: BudgetCumulativeApprovalState,
    approval_set_digest: Option<&str>,
) -> Result<(), BudgetStoreError> {
    type InitialRow = (
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
        i64,
        i64,
    );
    let initial: InitialRow = transaction
        .query_row(
            r#"
            SELECT event.kind, event.authorization_outcome,
                   cumulative.state_before, cumulative.state_after,
                   cumulative.reserved_authorized_before,
                   cumulative.captured_authorized_before,
                   cumulative.requested_authorized_units,
                   cumulative.effective_threshold_units
            FROM budget_event_cumulative_approval AS cumulative
            JOIN budget_mutation_events AS event
              ON event.event_id = cumulative.event_id
            WHERE cumulative.operation_id = ?1
            ORDER BY event.event_seq
            LIMIT 1
            "#,
            params![&request.operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "cumulative approval operation `{}` lost its reservation history: {error}",
                request.operation_id
            ))
        })?;
    let units = |value: i64, field: &str| {
        u64::try_from(value).map_err(|_| {
            BudgetStoreError::Invariant(format!(
                "cumulative approval operation `{}` has negative {field}",
                request.operation_id
            ))
        })
    };
    let reserved_before = units(initial.4, "reserved units")?;
    let captured_before = units(initial.5, "captured units")?;
    let requested_authorized = units(initial.6, "requested units")?;
    let effective_threshold = units(initial.7, "effective threshold")?;
    let prospective = reserved_before
        .checked_add(captured_before)
        .and_then(|value| value.checked_add(requested_authorized))
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "cumulative approval operation `{}` overflows its reservation history",
                request.operation_id
            ))
        })?;
    let approval_required = prospective >= effective_threshold;
    let expected_initial_state = if approval_required {
        "pending_approval"
    } else {
        "authorized"
    };
    if initial.0 != "reserve_invocation"
        || initial.1.as_deref()
            != Some(if approval_required {
                "approval_required"
            } else {
                "authorized"
            })
        || initial.2.is_some()
        || initial.3 != expected_initial_state
        || requested_authorized != request.requested_authorized.units
        || effective_threshold != request.effective_threshold.units
    {
        return Err(BudgetStoreError::Invariant(format!(
            "cumulative approval operation `{}` has invalid reservation history",
            request.operation_id
        )));
    }

    let approval_digests = {
        let mut statement = transaction.prepare(
            r#"
            SELECT event.cumulative_approval_set_digest
            FROM budget_event_cumulative_approval AS cumulative
            JOIN budget_mutation_events AS event
              ON event.event_id = cumulative.event_id
            WHERE cumulative.operation_id = ?1
              AND event.kind = 'authorize_cumulative_approval'
            ORDER BY event.event_seq
            "#,
        )?;
        let rows = statement
            .query_map(params![&request.operation_id], |row| {
                row.get::<_, Option<String>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let exact_approval = match approval_set_digest {
        Some(digest) if canonical_approval_digest(digest) => {
            approval_digests.as_slice() == [Some(digest.to_string())]
        }
        Some(_) => false,
        None => approval_digests.is_empty(),
    };
    let valid_state = match state {
        BudgetCumulativeApprovalState::PendingApproval => {
            approval_required && approval_set_digest.is_none()
        }
        BudgetCumulativeApprovalState::Authorized | BudgetCumulativeApprovalState::Captured => {
            approval_required == approval_set_digest.is_some()
        }
        BudgetCumulativeApprovalState::ReversedBeforeDispatch => {
            approval_required || approval_set_digest.is_none()
        }
    };
    if !exact_approval || !valid_state {
        return Err(BudgetStoreError::Invariant(format!(
            "cumulative approval operation `{}` has invalid approval history",
            request.operation_id
        )));
    }
    Ok(())
}

pub(super) fn load_hold_cumulative(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<
    Option<(
        BudgetCumulativeApprovalRequest,
        BudgetCumulativeApprovalState,
        Option<String>,
    )>,
    BudgetStoreError,
> {
    type Row = (
        String,
        String,
        String,
        i64,
        i64,
        i64,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
    );
    let row: Option<Row> = transaction
        .query_row(
            r#"
            SELECT operation.operation_id, operation.authority_id,
                   operation.owner_id, operation.approval_budget_epoch,
                   operation.effective_threshold_units,
                   operation.requested_authorized_units, operation.state,
                   operation.approval_set_digest, operation.approval_budget_id,
                   account.delegation_root_id, account.root_binding_digest,
                   account.root_grant_hash, account.authority_threshold_units
            FROM budget_cumulative_approval_operations AS operation
            JOIN budget_cumulative_approval_accounts AS account
              ON account.authority_id = operation.authority_id
             AND account.owner_id = operation.owner_id
             AND account.approval_budget_id = operation.approval_budget_id
             AND account.approval_budget_epoch = operation.approval_budget_epoch
            WHERE operation.hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
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
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let currency: String = transaction.query_row(
        r#"
        SELECT account.currency
        FROM budget_cumulative_approval_operations AS operation
        JOIN budget_cumulative_approval_accounts AS account
          ON account.authority_id = operation.authority_id
         AND account.owner_id = operation.owner_id
         AND account.approval_budget_id = operation.approval_budget_id
         AND account.approval_budget_epoch = operation.approval_budget_epoch
        WHERE operation.hold_id = ?1
        "#,
        params![hold_id],
        |row| row.get(0),
    )?;
    let units = |value: i64| {
        u64::try_from(value).map_err(|_| {
            BudgetStoreError::Invariant("negative cumulative approval units".to_string())
        })
    };
    let request = BudgetCumulativeApprovalRequest {
        operation_id: row.0,
        account_key: BudgetCumulativeApprovalAccountKey {
            authority_id: row.1,
            owner_id: row.2,
            approval_budget_id: row.8,
            approval_budget_epoch: units(row.3)?,
            root_grant_hash: row.11,
            delegation_root_id: row.9,
            root_binding_digest: row.10,
            currency: currency.clone(),
        },
        authority_threshold: MonetaryAmount {
            units: units(row.12)?,
            currency: currency.clone(),
        },
        effective_threshold: MonetaryAmount {
            units: units(row.4)?,
            currency: currency.clone(),
        },
        requested_authorized: MonetaryAmount {
            units: units(row.5)?,
            currency,
        },
    };
    validate_cumulative_request(&request)?;
    let state = cumulative_state(&row.6)?;
    validate_cumulative_approval_history(transaction, &request, state, row.7.as_deref())?;
    Ok(Some((request, state, row.7)))
}
