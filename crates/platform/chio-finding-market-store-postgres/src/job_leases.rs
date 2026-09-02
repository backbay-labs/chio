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
        let rows = sqlx::query(
            r#"
            SELECT tenant_id, job_id, job_kind, request_sha256, payload_sha256,
                   payload_json, state, attempt_count, available_at, lease_owner,
                   lease_expires_at, lease_fence, result_sha256, result_json,
                   last_error_code, created_at, updated_at
            FROM chio_finding_market_claim_jobs($1, $2, $3, $4)
            "#,
        )
        .bind(tenant.as_str())
        .bind(worker_id)
        .bind(lease_duration)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
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
        let expires_at: Option<i64> =
            sqlx::query_scalar("SELECT chio_finding_market_renew_job_lease($1, $2, $3, $4, $5)")
                .bind(tenant.as_str())
                .bind(job_id)
                .bind(lease.worker_id())
                .bind(lease_fence)
                .bind(lease_duration)
                .fetch_one(&mut *transaction)
                .await
                .map_err(unavailable)?;
        let expires_at = expires_at.ok_or(HostedMarketStoreError::LeaseLost)?;
        transaction.commit().await.map_err(unavailable)?;
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
        let outcome: i16 =
            sqlx::query_scalar("SELECT chio_finding_market_complete_job($1, $2, $3, $4, $5, $6)")
                .bind(tenant.as_str())
                .bind(job_id)
                .bind(lease.worker_id())
                .bind(lease_fence)
                .bind(result_sha256)
                .bind(result_json)
                .fetch_one(&mut *transaction)
                .await
                .map_err(unavailable)?;
        let outcome = match outcome {
            0 => Ok(HostedJobWriteOutcome::Inserted),
            1 => Ok(HostedJobWriteOutcome::ExactReplay),
            2 => Err(HostedMarketStoreError::Conflict),
            3 => Err(HostedMarketStoreError::NotFound),
            4 => Err(HostedMarketStoreError::LeaseLost),
            _ => Err(HostedMarketStoreError::Decode(
                "job transition outcome code",
            )),
        }?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
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
        let updated: bool =
            sqlx::query_scalar("SELECT chio_finding_market_fail_job($1, $2, $3, $4, $5, $6)")
                .bind(tenant.as_str())
                .bind(job_id)
                .bind(lease.worker_id())
                .bind(lease_fence)
                .bind(error_code)
                .bind(retry_delay)
                .fetch_one(&mut *transaction)
                .await
                .map_err(unavailable)?;
        if !updated {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction.commit().await.map_err(unavailable)?;
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
        let updated: bool =
            sqlx::query_scalar("SELECT chio_finding_market_relinquish_job_lease($1, $2, $3, $4)")
                .bind(tenant.as_str())
                .bind(job_id)
                .bind(lease.worker_id())
                .bind(lease_fence)
                .fetch_one(&mut *transaction)
                .await
                .map_err(unavailable)?;
        if !updated {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction.commit().await.map_err(unavailable)?;
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
        let updated: bool =
            sqlx::query_scalar("SELECT chio_finding_market_exhaust_job($1, $2, $3, $4, $5)")
                .bind(tenant.as_str())
                .bind(job_id)
                .bind(lease.worker_id())
                .bind(lease_fence)
                .bind(error_code)
                .fetch_one(&mut *transaction)
                .await
                .map_err(unavailable)?;
        if !updated {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(())
    }
}
