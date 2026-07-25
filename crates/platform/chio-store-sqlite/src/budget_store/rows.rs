use super::*;

pub(super) fn budget_authorization_outcome_text(value: BudgetAuthorizationOutcome) -> &'static str {
    match value {
        BudgetAuthorizationOutcome::Authorized => "authorized",
        BudgetAuthorizationOutcome::ApprovalRequired => "approval_required",
        BudgetAuthorizationOutcome::Denied => "denied",
    }
}

pub(super) fn budget_authorization_outcome(
    value: &str,
) -> Result<BudgetAuthorizationOutcome, BudgetStoreError> {
    match value {
        "authorized" => Ok(BudgetAuthorizationOutcome::Authorized),
        "approval_required" => Ok(BudgetAuthorizationOutcome::ApprovalRequired),
        "denied" => Ok(BudgetAuthorizationOutcome::Denied),
        _ => Err(BudgetStoreError::Invariant(format!(
            "unknown budget authorization outcome `{value}`"
        ))),
    }
}

pub(super) fn budget_invocation_state_text(value: BudgetInvocationState) -> &'static str {
    match value {
        BudgetInvocationState::Absent => "absent",
        BudgetInvocationState::Authorized => "authorized",
        BudgetInvocationState::Captured => "captured",
        BudgetInvocationState::Reversed => "reversed",
        BudgetInvocationState::Denied => "denied",
    }
}

pub(super) fn budget_invocation_state(
    value: &str,
) -> Result<BudgetInvocationState, BudgetStoreError> {
    match value {
        "absent" => Ok(BudgetInvocationState::Absent),
        "authorized" => Ok(BudgetInvocationState::Authorized),
        "captured" => Ok(BudgetInvocationState::Captured),
        "reversed" => Ok(BudgetInvocationState::Reversed),
        "denied" => Ok(BudgetInvocationState::Denied),
        _ => Err(BudgetStoreError::Invariant(format!(
            "unknown budget invocation state `{value}`"
        ))),
    }
}

pub(super) fn budget_monetary_state_text(value: BudgetMonetaryState) -> &'static str {
    match value {
        BudgetMonetaryState::None => "none",
        BudgetMonetaryState::Exposed => "exposed",
        BudgetMonetaryState::Released => "released",
        BudgetMonetaryState::Reconciled => "reconciled",
        BudgetMonetaryState::Captured => "captured",
        BudgetMonetaryState::Reversed => "reversed",
    }
}

pub(super) fn budget_monetary_state(value: &str) -> Result<BudgetMonetaryState, BudgetStoreError> {
    match value {
        "none" => Ok(BudgetMonetaryState::None),
        "exposed" => Ok(BudgetMonetaryState::Exposed),
        "released" => Ok(BudgetMonetaryState::Released),
        "reconciled" => Ok(BudgetMonetaryState::Reconciled),
        "captured" => Ok(BudgetMonetaryState::Captured),
        "reversed" => Ok(BudgetMonetaryState::Reversed),
        _ => Err(BudgetStoreError::Invariant(format!(
            "unknown budget monetary state `{value}`"
        ))),
    }
}

pub(super) type BudgetEventLifecycle = (
    Option<BudgetAuthorizationOutcome>,
    BudgetInvocationState,
    BudgetInvocationState,
    BudgetMonetaryState,
    BudgetMonetaryState,
);

pub(super) fn appended_event_lifecycle(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: Option<&str>,
    kind: BudgetMutationKind,
    allowed: Option<bool>,
    exposure_units: u64,
) -> Result<BudgetEventLifecycle, BudgetStoreError> {
    type HoldState = (bool, u64, u64, Option<String>, Option<String>, String);
    let hold: Option<HoldState> = hold_id
        .map(|hold_id| {
            transaction
                .query_row(
                    r#"
                    SELECT invocation_captured, remaining_exposure_units,
                           authorized_exposure_units, invocation_state, monetary_state
                           , projection_kind
                    FROM budget_authorization_holds WHERE hold_id = ?1
                    "#,
                    params![hold_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            budget_u64_from_row(row, 1, "remaining_exposure_units")?,
                            budget_u64_from_row(row, 2, "authorized_exposure_units")?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
        })
        .transpose()?
        .flatten();
    let live_money = if exposure_units == 0 {
        BudgetMonetaryState::None
    } else {
        BudgetMonetaryState::Exposed
    };
    let current_invocation = match hold.as_ref() {
        None => BudgetInvocationState::Absent,
        Some(hold) if hold.5 == "legacy" && hold.0 => BudgetInvocationState::Captured,
        Some(hold) if hold.5 == "legacy" => BudgetInvocationState::Authorized,
        Some(hold) => match hold.3.as_deref() {
            Some(value) => budget_invocation_state(value)?,
            None if hold.0 => BudgetInvocationState::Captured,
            None => BudgetInvocationState::Authorized,
        },
    };
    let current_money = match hold.as_ref() {
        None => live_money,
        Some(hold) if hold.5 == "legacy" && hold.2 == 0 => BudgetMonetaryState::None,
        Some(hold) if hold.5 == "legacy" && hold.1 == 0 => BudgetMonetaryState::Released,
        Some(hold) if hold.5 == "legacy" => BudgetMonetaryState::Exposed,
        Some(hold) => match hold.4.as_deref() {
            Some(value) => budget_monetary_state(value)?,
            None if hold.2 == 0 => BudgetMonetaryState::None,
            None if hold.1 == 0 => BudgetMonetaryState::Released,
            None => BudgetMonetaryState::Exposed,
        },
    };
    let authorization_outcome = allowed.map(|allowed| {
        if allowed {
            BudgetAuthorizationOutcome::Authorized
        } else {
            BudgetAuthorizationOutcome::Denied
        }
    });
    Ok(match kind {
        BudgetMutationKind::IncrementInvocation => (
            authorization_outcome,
            BudgetInvocationState::Absent,
            if allowed == Some(true) {
                BudgetInvocationState::Captured
            } else {
                BudgetInvocationState::Denied
            },
            BudgetMonetaryState::None,
            BudgetMonetaryState::None,
        ),
        BudgetMutationKind::AuthorizeExposure | BudgetMutationKind::ReserveInvocation => (
            authorization_outcome,
            BudgetInvocationState::Absent,
            if allowed == Some(false) {
                BudgetInvocationState::Denied
            } else {
                BudgetInvocationState::Authorized
            },
            BudgetMonetaryState::None,
            if allowed == Some(false) {
                BudgetMonetaryState::None
            } else {
                live_money
            },
        ),
        BudgetMutationKind::CaptureInvocation => (
            None,
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Captured,
            live_money,
            live_money,
        ),
        BudgetMutationKind::AuthorizeCumulativeApproval => (
            Some(BudgetAuthorizationOutcome::Authorized),
            current_invocation,
            current_invocation,
            current_money,
            current_money,
        ),
        BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::CancelCapturedBeforeDispatch => (
            None,
            if kind == BudgetMutationKind::CancelCapturedBeforeDispatch {
                BudgetInvocationState::Captured
            } else {
                BudgetInvocationState::Authorized
            },
            BudgetInvocationState::Reversed,
            hold.as_ref().map_or(live_money, |hold| {
                if hold.2 == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                }
            }),
            if exposure_units == 0 {
                current_money
            } else {
                BudgetMonetaryState::Reversed
            },
        ),
        BudgetMutationKind::ReleaseExposure => {
            let invocation = if current_invocation == BudgetInvocationState::Absent {
                BudgetInvocationState::Absent
            } else {
                current_invocation
            };
            let after = hold.as_ref().map_or(BudgetMonetaryState::Released, |hold| {
                if hold.1 == 0 {
                    BudgetMonetaryState::Released
                } else {
                    BudgetMonetaryState::Exposed
                }
            });
            let before = hold.as_ref().map_or(BudgetMonetaryState::Exposed, |hold| {
                if hold.2 == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                }
            });
            (None, invocation, invocation, before, after)
        }
        BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureSpend => (
            None,
            current_invocation,
            current_invocation,
            live_money,
            if kind == BudgetMutationKind::CaptureSpend {
                BudgetMonetaryState::Captured
            } else {
                BudgetMonetaryState::Reconciled
            },
        ),
    })
}

pub(super) fn validate_legacy_event_lifecycle(
    record: &BudgetMutationRecord,
) -> Result<(), BudgetStoreError> {
    let money_for_exposure = if record.exposure_units == 0 {
        BudgetMonetaryState::None
    } else {
        BudgetMonetaryState::Exposed
    };
    let expected_outcome = record.allowed.map(|allowed| {
        if allowed {
            BudgetAuthorizationOutcome::Authorized
        } else {
            BudgetAuthorizationOutcome::Denied
        }
    });
    let valid = match record.kind {
        BudgetMutationKind::IncrementInvocation => {
            record.allowed.is_some()
                && record.authorization_outcome == expected_outcome
                && record.invocation_state_before == BudgetInvocationState::Absent
                && record.invocation_state_after
                    == if record.allowed == Some(true) {
                        BudgetInvocationState::Captured
                    } else {
                        BudgetInvocationState::Denied
                    }
                && record.monetary_state_before == BudgetMonetaryState::None
                && record.monetary_state_after == BudgetMonetaryState::None
        }
        BudgetMutationKind::AuthorizeExposure => {
            record.allowed.is_some()
                && record.authorization_outcome == expected_outcome
                && record.invocation_state_before == BudgetInvocationState::Absent
                && record.invocation_state_after
                    == if record.allowed == Some(false) {
                        BudgetInvocationState::Denied
                    } else {
                        BudgetInvocationState::Authorized
                    }
                && record.monetary_state_before == BudgetMonetaryState::None
                && record.monetary_state_after
                    == if record.allowed == Some(false) {
                        BudgetMonetaryState::None
                    } else {
                        money_for_exposure
                    }
        }
        BudgetMutationKind::CaptureInvocation => {
            record.allowed == Some(true)
                && record.authorization_outcome.is_none()
                && record.invocation_state_before == BudgetInvocationState::Authorized
                && record.invocation_state_after == BudgetInvocationState::Captured
                && record.monetary_state_before == money_for_exposure
                && record.monetary_state_after == money_for_exposure
        }
        BudgetMutationKind::CancelCapturedBeforeDispatch => {
            record.allowed == Some(true)
                && record.authorization_outcome.is_none()
                && record.invocation_state_before == BudgetInvocationState::Captured
                && record.invocation_state_after == BudgetInvocationState::Reversed
                && record.monetary_state_before == money_for_exposure
                && record.monetary_state_after
                    == if record.exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Reversed
                    }
        }
        BudgetMutationKind::ReverseExposure => {
            record.allowed.is_none()
                && record.authorization_outcome.is_none()
                && record.invocation_state_before == BudgetInvocationState::Authorized
                && record.invocation_state_after == BudgetInvocationState::Reversed
                && record.monetary_state_before == money_for_exposure
                && record.monetary_state_after
                    == if record.exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Reversed
                    }
        }
        BudgetMutationKind::ReleaseExposure => {
            record.allowed.is_none()
                && record.authorization_outcome.is_none()
                && record.invocation_state_before == record.invocation_state_after
                && matches!(
                    record.invocation_state_after,
                    BudgetInvocationState::Absent | BudgetInvocationState::Authorized
                )
                && matches!(
                    record.monetary_state_before,
                    BudgetMonetaryState::None | BudgetMonetaryState::Exposed
                )
                && matches!(
                    record.monetary_state_after,
                    BudgetMonetaryState::None
                        | BudgetMonetaryState::Exposed
                        | BudgetMonetaryState::Released
                )
        }
        BudgetMutationKind::ReconcileSpend => {
            record.allowed.is_none()
                && record.authorization_outcome.is_none()
                && record.invocation_state_before == record.invocation_state_after
                && matches!(
                    record.invocation_state_after,
                    BudgetInvocationState::Absent | BudgetInvocationState::Captured
                )
                && matches!(
                    record.monetary_state_before,
                    BudgetMonetaryState::None | BudgetMonetaryState::Exposed
                )
                && record.monetary_state_after == BudgetMonetaryState::Reconciled
        }
        BudgetMutationKind::ReserveInvocation
        | BudgetMutationKind::AuthorizeCumulativeApproval
        | BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::CaptureSpend => false,
    };
    if !valid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget mutation `{}` has an invalid legacy lifecycle projection",
            record.event_id
        )));
    }
    Ok(())
}

pub(super) fn legacy_event_lifecycle_is_unset(record: &BudgetMutationRecord) -> bool {
    record.authorization_outcome.is_none()
        && record.invocation_state_before == BudgetInvocationState::Absent
        && record.invocation_state_after == BudgetInvocationState::Absent
        && record.monetary_state_before == BudgetMonetaryState::None
        && record.monetary_state_after == BudgetMonetaryState::None
}

pub(super) fn imported_event_lifecycle(
    transaction: &rusqlite::Transaction<'_>,
    record: &BudgetMutationRecord,
) -> Result<BudgetEventLifecycle, BudgetStoreError> {
    let mut lifecycle = appended_event_lifecycle(
        transaction,
        record.hold_id.as_deref(),
        record.kind,
        record.allowed,
        record.exposure_units,
    )?;
    if record.kind != BudgetMutationKind::ReleaseExposure {
        return Ok(lifecycle);
    }
    let Some(hold_id) = record.hold_id.as_deref() else {
        return Ok(lifecycle);
    };
    let hold = transaction
        .query_row(
            r#"
            SELECT invocation_captured, remaining_exposure_units,
                   authorized_exposure_units
            FROM budget_authorization_holds WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    budget_u64_from_row(row, 1, "remaining_exposure_units")?,
                    budget_u64_from_row(row, 2, "authorized_exposure_units")?,
                ))
            },
        )
        .optional()?;
    if let Some((captured, remaining, authorized)) = hold {
        if record.exposure_units > remaining {
            return Err(BudgetStoreError::Invariant(format!(
                "imported release `{}` exceeds held exposure",
                record.event_id
            )));
        }
        let invocation = if captured {
            BudgetInvocationState::Captured
        } else {
            BudgetInvocationState::Authorized
        };
        let before = if authorized == 0 {
            BudgetMonetaryState::None
        } else {
            BudgetMonetaryState::Exposed
        };
        let after = if authorized == 0 {
            BudgetMonetaryState::None
        } else if remaining == record.exposure_units {
            BudgetMonetaryState::Released
        } else {
            BudgetMonetaryState::Exposed
        };
        lifecycle = (None, invocation, invocation, before, after);
    }
    Ok(lifecycle)
}

pub(super) fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

pub(super) fn budget_u64_to_sqlite(
    value: u64,
    field_name: &'static str,
) -> Result<i64, BudgetStoreError> {
    i64::try_from(value).map_err(|_| {
        BudgetStoreError::Overflow(format!(
            "budget field `{field_name}` exceeds SQLite INTEGER range: {value}"
        ))
    })
}

pub(super) fn optional_budget_u64_to_sqlite(
    value: Option<u64>,
    field_name: &'static str,
) -> Result<Option<i64>, BudgetStoreError> {
    value
        .map(|value| budget_u64_to_sqlite(value, field_name))
        .transpose()
}

pub(super) fn validate_budget_grant_index(grant_index: usize) -> Result<(), BudgetStoreError> {
    u32::try_from(grant_index)
        .map(|_| ())
        .map_err(|_| BudgetStoreError::Overflow("grant_index exceeds u32 range".to_string()))
}

pub(super) fn record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BudgetUsageRecord> {
    let total_cost_exposed = budget_u64_from_row(row, 5, "total_cost_exposed")?;
    let total_cost_realized_spend = budget_u64_from_row(row, 6, "total_cost_realized_spend")?;
    Ok(BudgetUsageRecord {
        capability_id: row.get(0)?,
        grant_index: budget_u32_from_row(row, 1, "grant_index")?,
        invocation_count: budget_u32_from_row(row, 2, "invocation_count")?,
        updated_at: row.get(3)?,
        seq: budget_u64_from_row(row, 4, "seq")?,
        total_cost_exposed,
        total_cost_realized_spend,
    })
}

pub(super) fn mutation_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<BudgetMutationRecord> {
    let kind = row.get::<_, String>(4)?;
    let kind = BudgetMutationKind::parse(&kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown budget mutation kind `{kind}`"),
            )),
        )
    })?;
    let authority = sqlite_budget_event_authority(row.get(17)?, row.get(18)?, row.get(19)?)?;
    let exposure_units = budget_u64_from_row(row, 9, "exposure_units")?;
    let authorization_outcome = row
        .get::<_, Option<String>>(20)?
        .map(|value| {
            budget_authorization_outcome(&value)
                .map_err(|error| lifecycle_conversion_error(20, error))
        })
        .transpose()?;
    let invocation_state_before = budget_invocation_state(&row.get::<_, String>(21)?)
        .map_err(|error| lifecycle_conversion_error(21, error))?;
    let invocation_state_after = budget_invocation_state(&row.get::<_, String>(22)?)
        .map_err(|error| lifecycle_conversion_error(22, error))?;
    let monetary_state_before = budget_monetary_state(&row.get::<_, String>(23)?)
        .map_err(|error| lifecycle_conversion_error(23, error))?;
    let monetary_state_after = budget_monetary_state(&row.get::<_, String>(24)?)
        .map_err(|error| lifecycle_conversion_error(24, error))?;
    Ok(BudgetMutationRecord {
        event_id: row.get(0)?,
        hold_id: row.get(1)?,
        admission_binding: None,
        capability_id: row.get(2)?,
        grant_index: budget_u32_from_row(row, 3, "grant_index")?,
        kind,
        allowed: row.get::<_, Option<i64>>(5)?.map(|value| value > 0),
        authorization_outcome,
        invocation_state_before,
        invocation_state_after,
        monetary_state_before,
        monetary_state_after,
        recorded_at: row.get(6)?,
        event_seq: budget_u64_from_row(row, 7, "event_seq")?,
        usage_seq: optional_budget_u64_from_row(row, 8, "usage_seq")?,
        exposure_units,
        realized_spend_units: budget_u64_from_row(row, 10, "realized_spend_units")?,
        max_invocations: optional_budget_u32_from_row(row, 11, "max_invocations")?,
        max_cost_per_invocation: optional_budget_u64_from_row(
            row,
            12,
            "max_exposure_per_invocation",
        )?,
        max_total_cost_units: optional_budget_u64_from_row(row, 13, "max_total_exposure_units")?,
        invocation_count_after: budget_u32_from_row(row, 14, "invocation_count_after")?,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: budget_u64_from_row(row, 15, "total_cost_exposed_after")?,
        total_cost_realized_spend_after: budget_u64_from_row(
            row,
            16,
            "total_cost_realized_spend_after",
        )?,
        authority,
    })
}

fn lifecycle_conversion_error(index: usize, error: BudgetStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn budget_i64_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<i64> {
    let value = row.get::<_, i64>(index)?;
    if value < 0 {
        return Err(negative_budget_field_error(index, field_name, value));
    }
    Ok(value)
}

pub(super) fn budget_u64_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<u64> {
    Ok(budget_i64_from_row(row, index, field_name)? as u64)
}

pub(super) fn budget_u32_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<u32> {
    let value = budget_i64_from_row(row, index, field_name)?;
    u32::try_from(value).map_err(|_| budget_field_overflow_error(index, field_name, value))
}

pub(super) fn budget_usize_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<usize> {
    let value = budget_i64_from_row(row, index, field_name)?;
    usize::try_from(value).map_err(|_| budget_field_overflow_error(index, field_name, value))
}

fn optional_budget_i64_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<Option<i64>> {
    let Some(value) = row.get::<_, Option<i64>>(index)? else {
        return Ok(None);
    };
    if value < 0 {
        return Err(negative_budget_field_error(index, field_name, value));
    }
    Ok(Some(value))
}

pub(super) fn optional_budget_u64_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<Option<u64>> {
    Ok(optional_budget_i64_from_row(row, index, field_name)?.map(|value| value as u64))
}

pub(super) fn optional_budget_u32_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    field_name: &'static str,
) -> rusqlite::Result<Option<u32>> {
    optional_budget_i64_from_row(row, index, field_name)?
        .map(|value| {
            u32::try_from(value).map_err(|_| budget_field_overflow_error(index, field_name, value))
        })
        .transpose()
}

fn negative_budget_field_error(
    index: usize,
    field_name: &'static str,
    value: i64,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("budget field `{field_name}` was negative: {value}"),
        )),
    )
}

fn budget_field_overflow_error(
    index: usize,
    field_name: &'static str,
    value: i64,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("budget field `{field_name}` exceeded target integer range: {value}"),
        )),
    )
}

pub(super) fn sqlite_budget_event_authority(
    authority_id: Option<String>,
    lease_id: Option<String>,
    lease_epoch: Option<i64>,
) -> rusqlite::Result<Option<BudgetEventAuthority>> {
    match (authority_id, lease_id, lease_epoch) {
        (None, None, None) => Ok(None),
        (Some(authority_id), Some(lease_id), Some(lease_epoch)) if lease_epoch >= 0 => {
            Ok(Some(BudgetEventAuthority {
                authority_id,
                lease_id,
                lease_epoch: lease_epoch as u64,
            }))
        }
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid budget authority lease columns",
            )),
        )),
    }
}
