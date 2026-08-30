use sqlx::Row as _;

use super::*;

impl PostgresFindingMarketStore {
    /// Claim a bounded batch without exceeding the tenant's configured active
    /// lease ceiling across all worker replicas. `limit` bounds only this
    /// caller's batch.
    pub async fn claim_due_jobs(
        &self,
        tenant: &HostedTenantId,
        worker_id: &str,
        lease_duration_secs: u64,
        limit: u32,
    ) -> Result<Vec<HostedMarketJob>, HostedMarketStoreError> {
        validate_identifier(worker_id, MAX_LEASE_OWNER_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("worker_id"))?;
        if lease_duration_secs == 0
            || lease_duration_secs > 3_600
            || limit == 0
            || limit > MAX_CLAIM_BATCH
        {
            return Err(HostedMarketStoreError::Invalid("lease"));
        }
        let lease_duration = checked_i64(lease_duration_secs, "lease_duration_secs")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let configured_limit: i32 = sqlx::query_scalar(
            "SELECT max_concurrent_jobs FROM chio_finding_market_tenants WHERE tenant_id = $1 FOR SHARE",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let active_leases: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chio_finding_market_jobs WHERE tenant_id = $1 AND state = 'leased' AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let available_slots = i64::from(configured_limit)
            .checked_sub(active_leases)
            .ok_or(HostedMarketStoreError::DigestMismatch)?;
        if available_slots <= 0 {
            transaction
                .commit()
                .await
                .map_err(|_| HostedMarketStoreError::Unavailable)?;
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            WITH clock AS (
                SELECT floor(extract(epoch from clock_timestamp()))::bigint AS now_secs
            ), due AS (
                SELECT tenant_id, job_id
                FROM chio_finding_market_jobs CROSS JOIN clock
                WHERE tenant_id = $1
                  AND available_at <= clock.now_secs
                  AND (
                      state = 'pending'
                      OR state = 'failed'
                      OR (state = 'leased' AND lease_expires_at <= clock.now_secs)
                  )
                ORDER BY available_at, created_at, job_id
                FOR UPDATE SKIP LOCKED
                LIMIT $4
            )
            UPDATE chio_finding_market_jobs AS jobs
            SET state = 'leased', lease_owner = $2,
                lease_expires_at = clock.now_secs + $3,
                attempt_count = jobs.attempt_count + 1,
                lease_fence = jobs.lease_fence + 1,
                updated_at = clock.now_secs,
                last_error_code = NULL
            FROM due CROSS JOIN clock
            WHERE jobs.tenant_id = due.tenant_id AND jobs.job_id = due.job_id
            RETURNING jobs.tenant_id, jobs.job_id, jobs.job_kind, jobs.request_sha256,
                      jobs.payload_sha256, jobs.payload_json, jobs.state,
                      jobs.attempt_count, jobs.available_at, jobs.lease_owner,
                      jobs.lease_expires_at, jobs.lease_fence, jobs.result_sha256,
                      jobs.result_json, jobs.last_error_code, jobs.created_at,
                      jobs.updated_at
            "#,
        )
        .bind(tenant.as_str())
        .bind(worker_id)
        .bind(lease_duration)
        .bind(available_slots.min(i64::from(limit)))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        rows.iter().map(|row| job_from_row(tenant, row)).collect()
    }

    /// Extend one live lease using the database clock and the existing fence.
    pub async fn renew_job_lease(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
        lease_duration_secs: u64,
    ) -> Result<HostedLeaseRenewal, HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        if lease_duration_secs == 0 || lease_duration_secs > 3_600 {
            return Err(HostedMarketStoreError::Invalid("lease"));
        }
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        let lease_duration = checked_i64(lease_duration_secs, "lease_duration_secs")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let expires_at: Option<i64> = sqlx::query_scalar(
            r#"
            UPDATE chio_finding_market_jobs
            SET lease_expires_at =
                    floor(extract(epoch from clock_timestamp()))::bigint + $3,
                updated_at = floor(extract(epoch from clock_timestamp()))::bigint
            WHERE tenant_id = $1 AND job_id = $2
              AND state = 'leased' AND lease_owner = $4 AND lease_fence = $5
              AND lease_expires_at >
                  floor(extract(epoch from clock_timestamp()))::bigint
            RETURNING lease_expires_at
            "#,
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(lease_duration)
        .bind(lease.worker_id())
        .bind(lease_fence)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let expires_at = expires_at.ok_or(HostedMarketStoreError::LeaseLost)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(HostedLeaseRenewal {
            expires_at: stored_u64(expires_at)?,
        })
    }

    pub async fn complete_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
        result_json: &[u8],
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        validate_canonical_json(result_json, "result_json")?;
        let result_sha256 = sha256_hex(result_json);
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT state, lease_owner, lease_expires_at, lease_fence, result_sha256, result_json FROM chio_finding_market_jobs WHERE tenant_id = $1 AND job_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .ok_or(HostedMarketStoreError::NotFound)?;
        let state: String = row.try_get(0).map_err(unavailable)?;
        if state == "completed" {
            let stored_sha: Option<String> = row.try_get(4).map_err(unavailable)?;
            let stored_json: Option<Vec<u8>> = row.try_get(5).map_err(unavailable)?;
            if stored_sha.as_deref() == Some(result_sha256.as_str())
                && stored_json.as_deref() == Some(result_json)
            {
                transaction
                    .commit()
                    .await
                    .map_err(|_| HostedMarketStoreError::Unavailable)?;
                return Ok(HostedJobWriteOutcome::ExactReplay);
            }
            return Err(HostedMarketStoreError::Conflict);
        }
        let lease_owner: Option<String> = row.try_get(1).map_err(unavailable)?;
        let stored_lease_fence: i64 = row.try_get(3).map_err(unavailable)?;
        if state != "leased"
            || lease_owner.as_deref() != Some(lease.worker_id())
            || stored_lease_fence != lease_fence
        {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'completed', lease_owner = NULL, lease_expires_at = NULL, result_sha256 = $3, result_json = $4, updated_at = floor(extract(epoch from clock_timestamp()))::bigint WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $5 AND lease_fence = $6 AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(result_sha256)
        .bind(result_json)
        .bind(lease.worker_id())
        .bind(lease_fence)
        .execute(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(HostedJobWriteOutcome::Inserted)
    }

    pub async fn fail_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
        error_code: &str,
        retry_delay_secs: u64,
    ) -> Result<(), HostedMarketStoreError> {
        validate_identifier(error_code, MAX_ERROR_CODE_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("error_code"))?;
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        if retry_delay_secs == 0 || retry_delay_secs > 3_600 {
            return Err(HostedMarketStoreError::Invalid("retry_delay_secs"));
        }
        let retry_delay = checked_i64(retry_delay_secs, "retry_delay_secs")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'failed', lease_owner = NULL, lease_expires_at = NULL, last_error_code = $3, available_at = floor(extract(epoch from clock_timestamp()))::bigint + $4, updated_at = floor(extract(epoch from clock_timestamp()))::bigint WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $5 AND lease_fence = $6 AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(error_code)
        .bind(retry_delay)
        .bind(lease.worker_id())
        .bind(lease_fence)
        .execute(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(())
    }

    /// Return a matching, unreclaimed lease to the pending queue during
    /// cooperative shutdown.
    ///
    /// A claim reserves one execution attempt. Shutdown occurs outside the
    /// job's control, so this fenced transition gives that attempt back while
    /// preserving the monotonically increasing lease fence.
    pub async fn relinquish_job_lease(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
    ) -> Result<(), HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        // Expiry alone does not transfer ownership. A successful reclaim
        // changes both owner and fence, so the exact fence remains the
        // authoritative exclusion boundary while delayed cleanup refunds the
        // interrupted attempt.
        let updated = sqlx::query(
            r#"
            UPDATE chio_finding_market_jobs
            SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,
                attempt_count = attempt_count - 1,
                available_at = floor(extract(epoch from clock_timestamp()))::bigint,
                last_error_code = NULL,
                updated_at = floor(extract(epoch from clock_timestamp()))::bigint
            WHERE tenant_id = $1 AND job_id = $2
              AND state = 'leased' AND lease_owner = $3 AND lease_fence = $4
              AND attempt_count > 0
            "#,
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(lease.worker_id())
        .bind(lease_fence)
        .execute(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(())
    }

    /// Permanently fail a leased job after its bounded attempt budget.
    pub async fn exhaust_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
        error_code: &str,
    ) -> Result<(), HostedMarketStoreError> {
        validate_identifier(error_code, MAX_ERROR_CODE_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("error_code"))?;
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'exhausted', lease_owner = NULL, lease_expires_at = NULL, last_error_code = $3, updated_at = floor(extract(epoch from clock_timestamp()))::bigint WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $4 AND lease_fence = $5 AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(error_code)
        .bind(lease.worker_id())
        .bind(lease_fence)
        .execute(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(())
    }
}
