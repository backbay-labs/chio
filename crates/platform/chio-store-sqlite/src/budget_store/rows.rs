use super::*;

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
    Ok(BudgetMutationRecord {
        event_id: row.get(0)?,
        hold_id: row.get(1)?,
        capability_id: row.get(2)?,
        grant_index: budget_u32_from_row(row, 3, "grant_index")?,
        kind,
        allowed: row.get::<_, Option<i64>>(5)?.map(|value| value > 0),
        recorded_at: row.get(6)?,
        event_seq: budget_u64_from_row(row, 7, "event_seq")?,
        usage_seq: optional_budget_u64_from_row(row, 8, "usage_seq")?,
        exposure_units: budget_u64_from_row(row, 9, "exposure_units")?,
        realized_spend_units: budget_u64_from_row(row, 10, "realized_spend_units")?,
        max_invocations: optional_budget_u32_from_row(row, 11, "max_invocations")?,
        max_cost_per_invocation: optional_budget_u64_from_row(
            row,
            12,
            "max_exposure_per_invocation",
        )?,
        max_total_cost_units: optional_budget_u64_from_row(row, 13, "max_total_exposure_units")?,
        invocation_count_after: budget_u32_from_row(row, 14, "invocation_count_after")?,
        total_cost_exposed_after: budget_u64_from_row(row, 15, "total_cost_exposed_after")?,
        total_cost_realized_spend_after: budget_u64_from_row(
            row,
            16,
            "total_cost_realized_spend_after",
        )?,
        authority,
    })
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
