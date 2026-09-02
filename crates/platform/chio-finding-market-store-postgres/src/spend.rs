use sqlx::Row as _;

use super::{
    checked_i64, stored_u64, unavailable, validate_identifier, HostedJobWriteOutcome,
    HostedMarketStoreError, HostedTenantId, PostgresFindingMarketStore, MAX_I_JSON_INTEGER,
    MAX_JOB_ID_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedSpendState {
    Reserved,
    Committed,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedSpendReservation {
    pub tenant_id: HostedTenantId,
    pub reservation_id: String,
    pub billing_period: String,
    pub units: u64,
    pub state: HostedSpendState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl PostgresFindingMarketStore {
    /// Reserve tenant spend inside a closed UTC calendar-month bucket.
    /// Reservation identity is immutable and exact retries never spend twice.
    pub async fn reserve_monthly_spend(
        &self,
        tenant: &HostedTenantId,
        reservation_id: &str,
        units: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(reservation_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("spend_reservation_id"))?;
        if !(1..=MAX_I_JSON_INTEGER).contains(&units) {
            return Err(HostedMarketStoreError::Invalid("spend_units"));
        }
        let units = checked_i64(units, "spend units")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        if let Some(row) = sqlx::query(
            "SELECT units, state FROM chio_finding_market_spend_reservations WHERE tenant_id = $1 AND reservation_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(reservation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?
        {
            let same_units = row.try_get::<i64, _>(0).map_err(unavailable)? == units;
            let state = parse_spend_state(&row.try_get::<String, _>(1).map_err(unavailable)?)?;
            if !same_units || state != HostedSpendState::Reserved {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction
                .commit()
                .await
                .map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        let (billing_period, now): (String, i64) = sqlx::query_as(
            "SELECT to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM'), FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        validate_billing_period(&billing_period)
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        // The spend-period accumulator and the tenant ceiling are
        // maintained by a trigger on this table, so every writer keeps them
        // correct and the ceiling denies inside the same statement.
        let inserted = sqlx::query(
            "INSERT INTO chio_finding_market_spend_reservations (tenant_id, reservation_id, billing_period, units, state, created_at, updated_at) VALUES ($1, $2, $3, $4, 'reserved', $5, $5) ON CONFLICT (tenant_id, reservation_id) DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(reservation_id)
        .bind(&billing_period)
        .bind(units)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_spend_insert_error)?
        .rows_affected();
        if inserted != 1 {
            // A concurrent reserve won the identity after the replay check.
            // Drop this attempt's period increment and answer from the
            // winner's durable row.
            transaction.rollback().await.map_err(unavailable)?;
            let existing = self
                .monthly_spend_reservation(tenant, reservation_id)
                .await?
                .ok_or(HostedMarketStoreError::Unavailable)?;
            let same_units = checked_i64(existing.units, "spend units")? == units;
            if same_units && existing.state == HostedSpendState::Reserved {
                return Ok(HostedJobWriteOutcome::ExactReplay);
            }
            return Err(HostedMarketStoreError::Conflict);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(HostedJobWriteOutcome::Inserted)
    }

    pub async fn commit_monthly_spend(
        &self,
        tenant: &HostedTenantId,
        reservation_id: &str,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.finish_monthly_spend(tenant, reservation_id, HostedSpendState::Committed)
            .await
    }

    /// Release an uncommitted reservation. Committed gross spend is immutable.
    pub async fn release_monthly_spend(
        &self,
        tenant: &HostedTenantId,
        reservation_id: &str,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.finish_monthly_spend(tenant, reservation_id, HostedSpendState::Released)
            .await
    }

    async fn finish_monthly_spend(
        &self,
        tenant: &HostedTenantId,
        reservation_id: &str,
        desired: HostedSpendState,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome = self
            .finish_monthly_spend_in_transaction(
                &mut transaction,
                tenant,
                reservation_id,
                desired,
                None,
            )
            .await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub(crate) async fn finish_monthly_spend_in_transaction(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &HostedTenantId,
        reservation_id: &str,
        desired: HostedSpendState,
        expected_units: Option<u64>,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(reservation_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("spend_reservation_id"))?;
        if !matches!(
            desired,
            HostedSpendState::Committed | HostedSpendState::Released
        ) {
            return Err(HostedMarketStoreError::Invalid("spend_state"));
        }
        let now: i64 =
            sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT")
                .fetch_one(&mut **transaction)
                .await
                .map_err(unavailable)?;
        let row = sqlx::query(
            "SELECT state, created_at, units FROM chio_finding_market_spend_reservations WHERE tenant_id = $1 AND reservation_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(reservation_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(unavailable)?
        .ok_or(HostedMarketStoreError::NotFound)?;
        let stored = parse_spend_state(&row.try_get::<String, _>(0).map_err(unavailable)?)?;
        let created_at: i64 = row.try_get(1).map_err(unavailable)?;
        let units: i64 = row.try_get(2).map_err(unavailable)?;
        if let Some(expected_units) = expected_units {
            if units != checked_i64(expected_units, "spend units")? {
                return Err(HostedMarketStoreError::Conflict);
            }
        }
        if now < created_at {
            return Err(HostedMarketStoreError::Invalid("spend time"));
        }
        if stored == desired {
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        if stored != HostedSpendState::Reserved {
            return Err(HostedMarketStoreError::Conflict);
        }
        let updated = sqlx::query(
            "UPDATE chio_finding_market_spend_reservations SET state = $3, updated_at = $4 WHERE tenant_id = $1 AND reservation_id = $2 AND state = 'reserved'",
        )
        .bind(tenant.as_str())
        .bind(reservation_id)
        .bind(spend_state_name(desired))
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?
        .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::Conflict);
        }
        Ok(HostedJobWriteOutcome::Inserted)
    }

    pub async fn monthly_spend_reservation(
        &self,
        tenant: &HostedTenantId,
        reservation_id: &str,
    ) -> Result<Option<HostedSpendReservation>, HostedMarketStoreError> {
        validate_identifier(reservation_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("spend_reservation_id"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT reservation_id, billing_period, units, state, created_at, updated_at FROM chio_finding_market_spend_reservations WHERE tenant_id = $1 AND reservation_id = $2",
        )
        .bind(tenant.as_str())
        .bind(reservation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| spend_reservation_from_row(tenant, &row))
            .transpose()
    }
}

const SPEND_PERIOD_CEILING_CONSTRAINT: &str = "chio_finding_market_spend_period_ceiling_v1";

/// The spend-period trigger denies a reservation that would carry the
/// tenant past its monthly ceiling. Every other insert failure stays
/// opaque.
fn map_spend_insert_error(error: sqlx::Error) -> HostedMarketStoreError {
    match &error {
        sqlx::Error::Database(database_error)
            if database_error.constraint() == Some(SPEND_PERIOD_CEILING_CONSTRAINT) =>
        {
            HostedMarketStoreError::Capacity
        }
        _ => unavailable(error),
    }
}

fn spend_reservation_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedSpendReservation, HostedMarketStoreError> {
    let reservation_id: String = row.try_get(0).map_err(unavailable)?;
    let billing_period: String = row.try_get(1).map_err(unavailable)?;
    validate_identifier(&reservation_id, MAX_JOB_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_billing_period(&billing_period).map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let units = stored_u64(row.try_get(2).map_err(unavailable)?)?;
    if units == 0 || units > MAX_I_JSON_INTEGER {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(HostedSpendReservation {
        tenant_id: tenant.clone(),
        reservation_id,
        billing_period,
        units,
        state: parse_spend_state(&row.try_get::<String, _>(3).map_err(unavailable)?)?,
        created_at: stored_u64(row.try_get(4).map_err(unavailable)?)?,
        updated_at: stored_u64(row.try_get(5).map_err(unavailable)?)?,
    })
}

fn validate_billing_period(value: &str) -> Result<(), HostedMarketStoreError> {
    let bytes = value.as_bytes();
    if bytes.len() != 7
        || bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return Err(HostedMarketStoreError::Invalid("billing_period"));
    }
    let year = value[..4]
        .parse::<u16>()
        .map_err(|_| HostedMarketStoreError::Invalid("billing_period"))?;
    let month = value[5..]
        .parse::<u8>()
        .map_err(|_| HostedMarketStoreError::Invalid("billing_period"))?;
    if year < 1970 || !(1..=12).contains(&month) {
        return Err(HostedMarketStoreError::Invalid("billing_period"));
    }
    Ok(())
}

const fn spend_state_name(state: HostedSpendState) -> &'static str {
    match state {
        HostedSpendState::Reserved => "reserved",
        HostedSpendState::Committed => "committed",
        HostedSpendState::Released => "released",
    }
}

fn parse_spend_state(value: &str) -> Result<HostedSpendState, HostedMarketStoreError> {
    match value {
        "reserved" => Ok(HostedSpendState::Reserved),
        "committed" => Ok(HostedSpendState::Committed),
        "released" => Ok(HostedSpendState::Released),
        _ => Err(HostedMarketStoreError::Decode("spend state label")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_periods_are_closed() {
        assert!(validate_billing_period("2026-08").is_ok());
        assert!(validate_billing_period("2026-13").is_err());
        assert!(validate_billing_period("1969-12").is_err());
    }
}
