use sqlx::Row as _;

use super::{
    checked_i64, stored_u64, unavailable, validate_identifier, HostedJobWriteOutcome,
    HostedMarketStoreError, HostedTenantId, PostgresFindingMarketStore, MAX_I_JSON_INTEGER,
    MAX_TENANT_JOBS,
};

/// Durable tenant limits bound to one hosted configuration revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedTenantLimits {
    pub(super) max_concurrent_jobs: u32,
    pub(super) max_queued_jobs: u64,
    pub(super) max_monthly_spend_units: u64,
    pub(super) configuration_revision: String,
}

impl HostedTenantLimits {
    pub fn new(
        max_concurrent_jobs: u32,
        max_queued_jobs: u64,
        max_monthly_spend_units: u64,
        configuration_revision: impl Into<String>,
    ) -> Result<Self, HostedMarketStoreError> {
        let configuration_revision = configuration_revision.into();
        if !(1..=1_024).contains(&max_concurrent_jobs)
            || !(1..=MAX_TENANT_JOBS).contains(&max_queued_jobs)
            || !(1..=MAX_I_JSON_INTEGER).contains(&max_monthly_spend_units)
            || validate_identifier(&configuration_revision, 256).is_err()
        {
            return Err(HostedMarketStoreError::Invalid("tenant_limits"));
        }
        Ok(Self {
            max_concurrent_jobs,
            max_queued_jobs,
            max_monthly_spend_units,
            configuration_revision,
        })
    }

    #[must_use]
    pub const fn max_concurrent_jobs(&self) -> u32 {
        self.max_concurrent_jobs
    }

    #[must_use]
    pub const fn max_queued_jobs(&self) -> u64 {
        self.max_queued_jobs
    }

    #[must_use]
    pub const fn max_monthly_spend_units(&self) -> u64 {
        self.max_monthly_spend_units
    }

    #[must_use]
    pub fn configuration_revision(&self) -> &str {
        &self.configuration_revision
    }
}

impl PostgresFindingMarketStore {
    pub async fn register_tenant(
        &self,
        tenant: &HostedTenantId,
        limits: &HostedTenantLimits,
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let now = checked_i64(now, "tenant time")?;
        let max_queued_jobs = checked_i64(limits.max_queued_jobs, "tenant max queued jobs")?;
        let max_monthly_spend_units = checked_i64(
            limits.max_monthly_spend_units,
            "tenant max monthly spend units",
        )?;
        let mut transaction = self.begin_tenant_scope(tenant).await?;
        let existing = sqlx::query(
            "SELECT max_concurrent_jobs, max_queued_jobs, max_monthly_spend_units, configuration_revision FROM chio_finding_market_tenants WHERE tenant_id = $1 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(row) = existing {
            let matches = row.try_get::<i32, _>(0).map_err(unavailable)?
                == i32::try_from(limits.max_concurrent_jobs)
                    .map_err(|_| HostedMarketStoreError::Invalid("tenant_limits"))?
                && row.try_get::<i64, _>(1).map_err(unavailable)? == max_queued_jobs
                && row.try_get::<i64, _>(2).map_err(unavailable)? == max_monthly_spend_units
                && row.try_get::<String, _>(3).map_err(unavailable)?.as_str()
                    == limits.configuration_revision.as_str();
            if !matches {
                return Err(HostedMarketStoreError::Conflict);
            }
            let authority_matches: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chio_finding_market_authority_state WHERE tenant_id = $1 AND configuration_revision = $2)",
            )
            .bind(tenant.as_str())
            .bind(&limits.configuration_revision)
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
            if !authority_matches {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        sqlx::query(
            "INSERT INTO chio_finding_market_tenants (tenant_id, enabled, created_at, max_concurrent_jobs, max_queued_jobs, max_monthly_spend_units, configuration_revision) VALUES ($1, TRUE, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_str())
        .bind(now)
        .bind(i32::try_from(limits.max_concurrent_jobs).map_err(|_| {
            HostedMarketStoreError::Invalid("tenant max concurrent jobs")
        })?)
        .bind(max_queued_jobs)
        .bind(max_monthly_spend_units)
        .bind(&limits.configuration_revision)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(HostedJobWriteOutcome::Inserted)
    }

    /// Verify that durable tenant admission uses the exact deployed profile.
    pub async fn verify_tenant_limits(
        &self,
        tenant: &HostedTenantId,
        expected: &HostedTenantLimits,
    ) -> Result<(), HostedMarketStoreError> {
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT max_concurrent_jobs, max_queued_jobs, max_monthly_spend_units, configuration_revision FROM chio_finding_market_tenants WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let stored = tenant_limits_from_row(&row)?;
        transaction.commit().await.map_err(unavailable)?;
        if stored != *expected {
            return Err(HostedMarketStoreError::Configuration);
        }
        Ok(())
    }

    /// Changes tenant admission without deleting durable state. Disabling a
    /// tenant makes every subsequent tenant-scoped operation fail closed.
    pub async fn set_tenant_enabled(
        &self,
        tenant: &HostedTenantId,
        enabled: bool,
    ) -> Result<(), HostedMarketStoreError> {
        let mut transaction = self.begin_tenant_scope(tenant).await?;
        let updated =
            sqlx::query("UPDATE chio_finding_market_tenants SET enabled = $2 WHERE tenant_id = $1")
                .bind(tenant.as_str())
                .bind(enabled)
                .execute(&mut *transaction)
                .await
                .map_err(unavailable)?
                .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::NotFound);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(())
    }
}

fn tenant_limits_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<HostedTenantLimits, HostedMarketStoreError> {
    let max_concurrent_jobs = u32::try_from(row.try_get::<i32, _>(0).map_err(unavailable)?)
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let max_queued_jobs = stored_u64(row.try_get(1).map_err(unavailable)?)?;
    let max_monthly_spend_units = stored_u64(row.try_get(2).map_err(unavailable)?)?;
    let configuration_revision: String = row.try_get(3).map_err(unavailable)?;
    HostedTenantLimits::new(
        max_concurrent_jobs,
        max_queued_jobs,
        max_monthly_spend_units,
        configuration_revision,
    )
    .map_err(|_| HostedMarketStoreError::DigestMismatch)
}
