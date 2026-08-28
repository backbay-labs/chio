//! PostgreSQL durability for the hosted cognition-market control loop.
//!
//! Every tenant-scoped operation sets `chio.tenant_id` transaction-locally
//! before touching a row. PostgreSQL row-level security is enabled and forced,
//! so a missing or mismatched tenant context returns no rows and admits no
//! writes. Job creation additionally takes a tenant-keyed transaction advisory
//! lock, making the per-tenant capacity check linearizable.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::time::Duration;

use chio_core_types::{canonical_json_bytes_from_str, sha256_hex};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Postgres, Row as _, Transaction};

const MIGRATION_SQL: &str = include_str!("../migrations/0001_hosted_market.sql");
const TERMINAL_JOB_MIGRATION_SQL: &str = include_str!("../migrations/0002_terminal_jobs.sql");
const LEASE_FENCING_MIGRATION_SQL: &str = include_str!("../migrations/0003_lease_fencing.sql");
const MAX_TENANT_ID_BYTES: usize = 128;
const MAX_JOB_ID_BYTES: usize = 256;
const MAX_JOB_KIND_BYTES: usize = 96;
const MAX_LEASE_OWNER_BYTES: usize = 256;
const MAX_ERROR_CODE_BYTES: usize = 128;
const MAX_JOB_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_CLAIM_BATCH: u32 = 100;
const DEFAULT_MAX_JOBS_PER_TENANT: i64 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum HostedMarketStoreError {
    #[error("hosted market PostgreSQL configuration is invalid")]
    Configuration,
    #[error("hosted market tenant identity is invalid")]
    Tenant,
    #[error("hosted market tenant is disabled")]
    TenantDisabled,
    #[error("hosted market job input is invalid: {0}")]
    Invalid(&'static str),
    #[error("hosted market job conflicts with durable state")]
    Conflict,
    #[error("hosted market tenant job capacity is exhausted")]
    Capacity,
    #[error("hosted market job was not found")]
    NotFound,
    #[error("hosted market job lease is not held by this worker")]
    LeaseLost,
    #[error("hosted market durable state failed its digest check")]
    DigestMismatch,
    #[error("hosted market PostgreSQL operation is unavailable")]
    Unavailable,
}

/// A validated opaque tenant identity. It is always bound separately from
/// caller-provided object identifiers in database primary keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostedTenantId(String);

impl HostedTenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, HostedMarketStoreError> {
        let value = value.into();
        validate_identifier(&value, MAX_TENANT_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Tenant)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// TLS-required PostgreSQL pool configuration. The DSN is redacted from
/// `Debug`, because it may carry a password even when deployments normally
/// resolve it from a secret manager.
#[derive(Clone)]
pub struct HostedPostgresConfig {
    database_url: String,
    ca_certificate_path: Option<PathBuf>,
    max_connections: u32,
    acquire_timeout: Duration,
    max_jobs_per_tenant: i64,
}

impl fmt::Debug for HostedPostgresConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedPostgresConfig")
            .field("database_url", &"[REDACTED]")
            .field("ca_certificate_path", &self.ca_certificate_path)
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("max_jobs_per_tenant", &self.max_jobs_per_tenant)
            .finish()
    }
}

impl HostedPostgresConfig {
    pub fn new(database_url: impl Into<String>) -> Result<Self, HostedMarketStoreError> {
        let database_url = database_url.into();
        let parsed = PgConnectOptions::from_str(&database_url)
            .map_err(|_| HostedMarketStoreError::Configuration)?;
        if database_url.is_empty() || parsed.get_host().is_empty() {
            return Err(HostedMarketStoreError::Configuration);
        }
        Ok(Self {
            database_url,
            ca_certificate_path: None,
            max_connections: 16,
            acquire_timeout: Duration::from_secs(5),
            max_jobs_per_tenant: DEFAULT_MAX_JOBS_PER_TENANT,
        })
    }

    pub fn with_ca_certificate(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, HostedMarketStoreError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(HostedMarketStoreError::Configuration);
        }
        self.ca_certificate_path = Some(path);
        Ok(self)
    }

    pub fn with_max_connections(mut self, value: u32) -> Result<Self, HostedMarketStoreError> {
        if value == 0 || value > 256 {
            return Err(HostedMarketStoreError::Configuration);
        }
        self.max_connections = value;
        Ok(self)
    }

    pub fn with_max_jobs_per_tenant(mut self, value: i64) -> Result<Self, HostedMarketStoreError> {
        if !(1..=10_000_000).contains(&value) {
            return Err(HostedMarketStoreError::Configuration);
        }
        self.max_jobs_per_tenant = value;
        Ok(self)
    }

    fn connect_options(&self) -> Result<PgConnectOptions, HostedMarketStoreError> {
        let mut options = PgConnectOptions::from_str(&self.database_url)
            .map_err(|_| HostedMarketStoreError::Configuration)?
            .ssl_mode(PgSslMode::VerifyFull);
        if let Some(path) = self.ca_certificate_path.as_ref() {
            options = options.ssl_root_cert(path);
        }
        Ok(options)
    }
}

#[derive(Clone)]
pub struct PostgresFindingMarketStore {
    pool: PgPool,
    max_jobs_per_tenant: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedJobWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedJobState {
    Pending,
    Leased,
    Completed,
    Failed,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedMarketJob {
    pub tenant_id: HostedTenantId,
    pub job_id: String,
    pub job_kind: String,
    pub request_sha256: String,
    pub payload_sha256: String,
    pub payload_json: Vec<u8>,
    pub state: HostedJobState,
    pub attempt_count: u64,
    pub available_at: u64,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<u64>,
    pub lease_fence: u64,
    pub result_sha256: Option<String>,
    pub result_json: Option<Vec<u8>>,
    pub last_error_code: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Fenced ownership proof returned by a successful job claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedJobLease {
    worker_id: String,
    fence: u64,
}

impl HostedJobLease {
    pub fn new(worker_id: impl Into<String>, fence: u64) -> Result<Self, HostedMarketStoreError> {
        let worker_id = worker_id.into();
        validate_identifier(&worker_id, MAX_LEASE_OWNER_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("worker_id"))?;
        if fence == 0 {
            return Err(HostedMarketStoreError::Invalid("lease_fence"));
        }
        Ok(Self { worker_id, fence })
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub fn fence(&self) -> u64 {
        self.fence
    }
}

impl PostgresFindingMarketStore {
    pub async fn connect(config: &HostedPostgresConfig) -> Result<Self, HostedMarketStoreError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options()?)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        verify_runtime_role(&pool).await?;
        Ok(Self {
            pool,
            max_jobs_per_tenant: config.max_jobs_per_tenant,
        })
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_pool_for_integration_tests(pool: PgPool, max_jobs_per_tenant: i64) -> Self {
        Self {
            pool,
            max_jobs_per_tenant,
        }
    }

    pub async fn migrate(&self) -> Result<(), HostedMarketStoreError> {
        sqlx::raw_sql(MIGRATION_SQL)
            .execute(&self.pool)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        sqlx::raw_sql(TERMINAL_JOB_MIGRATION_SQL)
            .execute(&self.pool)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        sqlx::raw_sql(LEASE_FENCING_MIGRATION_SQL)
            .execute(&self.pool)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(())
    }

    pub async fn register_tenant(
        &self,
        tenant: &HostedTenantId,
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let now = checked_i64(now, "tenant time")?;
        let inserted = sqlx::query(
            "INSERT INTO chio_finding_market_tenants (tenant_id, created_at) VALUES ($1, $2) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .rows_affected();
        Ok(if inserted == 1 {
            HostedJobWriteOutcome::Inserted
        } else {
            HostedJobWriteOutcome::ExactReplay
        })
    }

    /// Changes tenant admission without deleting durable state. Disabling a
    /// tenant makes every subsequent tenant-scoped operation fail closed.
    pub async fn set_tenant_enabled(
        &self,
        tenant: &HostedTenantId,
        enabled: bool,
    ) -> Result<(), HostedMarketStoreError> {
        let updated =
            sqlx::query("UPDATE chio_finding_market_tenants SET enabled = $2 WHERE tenant_id = $1")
                .bind(tenant.as_str())
                .bind(enabled)
                .execute(&self.pool)
                .await
                .map_err(|_| HostedMarketStoreError::Unavailable)?
                .rows_affected();
        if updated != 1 {
            return Err(HostedMarketStoreError::NotFound);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        job_kind: &str,
        request_sha256: &str,
        payload_json: &[u8],
        available_at: u64,
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        validate_identifier(job_kind, MAX_JOB_KIND_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_kind"))?;
        validate_digest(request_sha256, "request_sha256")?;
        validate_canonical_json(payload_json, "payload_json")?;
        let payload_sha256 = sha256_hex(payload_json);
        let available_at = checked_i64(available_at, "available_at")?;
        let now = checked_i64(now, "now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;

        if let Some(row) = sqlx::query(
            "SELECT job_kind, request_sha256, payload_sha256, payload_json FROM chio_finding_market_jobs WHERE tenant_id = $1 AND job_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        {
            let stored_kind: String = row.try_get(0).map_err(unavailable)?;
            let stored_request: String = row.try_get(1).map_err(unavailable)?;
            let stored_payload_sha: String = row.try_get(2).map_err(unavailable)?;
            let stored_payload: Vec<u8> = row.try_get(3).map_err(unavailable)?;
            verify_payload(&stored_payload_sha, &stored_payload)?;
            if stored_kind != job_kind
                || stored_request != request_sha256
                || stored_payload_sha != payload_sha256
                || stored_payload != payload_json
            {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| HostedMarketStoreError::Unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chio_finding_market_jobs WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        if count >= self.max_jobs_per_tenant {
            return Err(HostedMarketStoreError::Capacity);
        }
        sqlx::query(
            "INSERT INTO chio_finding_market_jobs (tenant_id, job_id, job_kind, request_sha256, payload_sha256, payload_json, state, available_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $8)",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(job_kind)
        .bind(request_sha256)
        .bind(payload_sha256)
        .bind(payload_json)
        .bind(available_at)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        Ok(HostedJobWriteOutcome::Inserted)
    }

    pub async fn get_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
    ) -> Result<Option<HostedMarketJob>, HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(JOB_SELECT)
            .bind(tenant.as_str())
            .bind(job_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        row.map(|row| job_from_row(tenant, &row)).transpose()
    }

    pub async fn claim_due_jobs(
        &self,
        tenant: &HostedTenantId,
        worker_id: &str,
        now: u64,
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
        let now_i64 = checked_i64(now, "now")?;
        let lease_expires = checked_i64(
            now.checked_add(lease_duration_secs)
                .ok_or(HostedMarketStoreError::Invalid("lease"))?,
            "lease_expires_at",
        )?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            r#"
            WITH due AS (
                SELECT tenant_id, job_id
                FROM chio_finding_market_jobs
                WHERE tenant_id = $1
                  AND available_at <= $3
                  AND (
                      state = 'pending'
                      OR state = 'failed'
                      OR (state = 'leased' AND lease_expires_at <= $3)
                  )
                ORDER BY available_at, created_at, job_id
                FOR UPDATE SKIP LOCKED
                LIMIT $5
            )
            UPDATE chio_finding_market_jobs AS jobs
            SET state = 'leased', lease_owner = $2, lease_expires_at = $4,
                attempt_count = jobs.attempt_count + 1,
                lease_fence = jobs.lease_fence + 1, updated_at = $3,
                last_error_code = NULL
            FROM due
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
        .bind(now_i64)
        .bind(lease_expires)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        rows.iter().map(|row| job_from_row(tenant, row)).collect()
    }

    pub async fn complete_job(
        &self,
        tenant: &HostedTenantId,
        job_id: &str,
        lease: &HostedJobLease,
        result_json: &[u8],
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        validate_canonical_json(result_json, "result_json")?;
        let result_sha256 = sha256_hex(result_json);
        let now = checked_i64(now, "now")?;
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
        let lease_expires: Option<i64> = row.try_get(2).map_err(unavailable)?;
        let stored_lease_fence: i64 = row.try_get(3).map_err(unavailable)?;
        if state != "leased"
            || lease_owner.as_deref() != Some(lease.worker_id())
            || stored_lease_fence != lease_fence
            || lease_expires.is_none_or(|expiry| expiry <= now)
        {
            return Err(HostedMarketStoreError::LeaseLost);
        }
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'completed', lease_owner = NULL, lease_expires_at = NULL, result_sha256 = $3, result_json = $4, updated_at = $5 WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $6 AND lease_fence = $7",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(result_sha256)
        .bind(result_json)
        .bind(now)
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
        retry_at: u64,
        now: u64,
    ) -> Result<(), HostedMarketStoreError> {
        validate_identifier(error_code, MAX_ERROR_CODE_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("error_code"))?;
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        let retry_at = checked_i64(retry_at, "retry_at")?;
        let now = checked_i64(now, "now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'failed', lease_owner = NULL, lease_expires_at = NULL, last_error_code = $3, available_at = $4, updated_at = $5 WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $6 AND lease_fence = $7 AND lease_expires_at > $5",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(error_code)
        .bind(retry_at)
        .bind(now)
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
        now: u64,
    ) -> Result<(), HostedMarketStoreError> {
        validate_identifier(error_code, MAX_ERROR_CODE_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("error_code"))?;
        validate_identifier(job_id, MAX_JOB_ID_BYTES)
            .map_err(|_| HostedMarketStoreError::Invalid("job_id"))?;
        let lease_fence = checked_i64(lease.fence(), "lease_fence")?;
        let now = checked_i64(now, "now")?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let updated = sqlx::query(
            "UPDATE chio_finding_market_jobs SET state = 'exhausted', lease_owner = NULL, lease_expires_at = NULL, last_error_code = $3, updated_at = $4 WHERE tenant_id = $1 AND job_id = $2 AND state = 'leased' AND lease_owner = $5 AND lease_fence = $6 AND lease_expires_at > $4",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .bind(error_code)
        .bind(now)
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

    async fn begin_tenant(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let enabled = sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?
        .ok_or(HostedMarketStoreError::NotFound)?;
        if !enabled {
            return Err(HostedMarketStoreError::TenantDisabled);
        }
        Ok(transaction)
    }
}

const JOB_SELECT: &str = r#"
SELECT tenant_id, job_id, job_kind, request_sha256, payload_sha256,
       payload_json, state, attempt_count, available_at, lease_owner,
       lease_expires_at, lease_fence, result_sha256, result_json,
       last_error_code, created_at, updated_at
FROM chio_finding_market_jobs
WHERE tenant_id = $1 AND job_id = $2
"#;

fn job_from_row(
    tenant: &HostedTenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedMarketJob, HostedMarketStoreError> {
    let stored_tenant: String = row.try_get(0).map_err(unavailable)?;
    if stored_tenant != tenant.as_str() {
        return Err(HostedMarketStoreError::Tenant);
    }
    let job_id: String = row.try_get(1).map_err(unavailable)?;
    let job_kind: String = row.try_get(2).map_err(unavailable)?;
    let request_sha256: String = row.try_get(3).map_err(unavailable)?;
    validate_identifier(&job_id, MAX_JOB_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_identifier(&job_kind, MAX_JOB_KIND_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_digest(&request_sha256, "durable request digest")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let payload_sha256: String = row.try_get(4).map_err(unavailable)?;
    let payload_json: Vec<u8> = row.try_get(5).map_err(unavailable)?;
    verify_payload(&payload_sha256, &payload_json)?;
    let attempt_count = stored_u64(row.try_get(7).map_err(unavailable)?)?;
    let lease_fence = stored_u64(row.try_get(11).map_err(unavailable)?)?;
    let result_sha256: Option<String> = row.try_get(12).map_err(unavailable)?;
    let result_json: Option<Vec<u8>> = row.try_get(13).map_err(unavailable)?;
    match (result_sha256.as_deref(), result_json.as_deref()) {
        (Some(digest), Some(bytes)) => verify_payload(digest, bytes)?,
        (None, None) => {}
        _ => return Err(HostedMarketStoreError::DigestMismatch),
    }
    let state = parse_state(&row.try_get::<String, _>(6).map_err(unavailable)?)?;
    let lease_owner: Option<String> = row.try_get(9).map_err(unavailable)?;
    if let Some(owner) = lease_owner.as_deref() {
        validate_identifier(owner, MAX_LEASE_OWNER_BYTES)
            .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    }
    let lease_expires_at = row
        .try_get::<Option<i64>, _>(10)
        .map_err(unavailable)?
        .map(stored_u64)
        .transpose()?;
    let last_error_code: Option<String> = row.try_get(14).map_err(unavailable)?;
    if let Some(code) = last_error_code.as_deref() {
        validate_identifier(code, MAX_ERROR_CODE_BYTES)
            .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    }
    if matches!(state, HostedJobState::Leased) != lease_owner.is_some()
        || matches!(state, HostedJobState::Leased) != lease_expires_at.is_some()
        || matches!(state, HostedJobState::Completed) != result_json.is_some()
        || (matches!(state, HostedJobState::Pending | HostedJobState::Completed)
            && last_error_code.is_some())
        || (matches!(state, HostedJobState::Failed | HostedJobState::Exhausted)
            && last_error_code.is_none())
        || (matches!(state, HostedJobState::Pending) && (attempt_count != 0 || lease_fence != 0))
        || (!matches!(state, HostedJobState::Pending) && (attempt_count == 0 || lease_fence == 0))
    {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(HostedMarketJob {
        tenant_id: tenant.clone(),
        job_id,
        job_kind,
        request_sha256,
        payload_sha256,
        payload_json,
        state,
        attempt_count,
        available_at: stored_u64(row.try_get(8).map_err(unavailable)?)?,
        lease_owner,
        lease_expires_at,
        lease_fence,
        result_sha256,
        result_json,
        last_error_code,
        created_at: stored_u64(row.try_get(15).map_err(unavailable)?)?,
        updated_at: stored_u64(row.try_get(16).map_err(unavailable)?)?,
    })
}

async fn verify_runtime_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row =
        sqlx::query("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_optional(pool)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?
            .ok_or(HostedMarketStoreError::Configuration)?;
    let is_superuser: bool = row.try_get(0).map_err(unavailable)?;
    let bypasses_rls: bool = row.try_get(1).map_err(unavailable)?;
    if is_superuser || bypasses_rls {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(());
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), HostedMarketStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(HostedMarketStoreError::Invalid(field))
}

fn validate_canonical_json(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), HostedMarketStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_JOB_JSON_BYTES {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    let raw = std::str::from_utf8(bytes).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    let canonical =
        canonical_json_bytes_from_str(raw).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    if canonical != bytes {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    Ok(())
}

fn verify_payload(digest: &str, bytes: &[u8]) -> Result<(), HostedMarketStoreError> {
    validate_digest(digest, "durable digest")?;
    validate_canonical_json(bytes, "durable JSON")?;
    if sha256_hex(bytes) != digest {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(())
}

fn checked_i64(value: u64, field: &'static str) -> Result<i64, HostedMarketStoreError> {
    if value == 0 {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    i64::try_from(value).map_err(|_| HostedMarketStoreError::Invalid(field))
}

fn stored_u64(value: i64) -> Result<u64, HostedMarketStoreError> {
    u64::try_from(value).map_err(|_| HostedMarketStoreError::DigestMismatch)
}

fn parse_state(value: &str) -> Result<HostedJobState, HostedMarketStoreError> {
    match value {
        "pending" => Ok(HostedJobState::Pending),
        "leased" => Ok(HostedJobState::Leased),
        "completed" => Ok(HostedJobState::Completed),
        "failed" => Ok(HostedJobState::Failed),
        "exhausted" => Ok(HostedJobState::Exhausted),
        _ => Err(HostedMarketStoreError::DigestMismatch),
    }
}

fn unavailable(_error: sqlx::Error) -> HostedMarketStoreError {
    HostedMarketStoreError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_ids_are_closed_and_bounded() {
        assert!(HostedTenantId::new("tenant:acme-1").is_ok());
        assert!(HostedTenantId::new("").is_err());
        assert!(HostedTenantId::new("tenant with spaces").is_err());
        assert!(HostedTenantId::new("x".repeat(MAX_TENANT_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn postgres_dsn_is_redacted_and_tls_is_forced() {
        let config =
            HostedPostgresConfig::new("postgres://market-user:super-secret@db.example/chio")
                .unwrap_or_else(|error| panic!("valid PostgreSQL config: {error}"));
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
        let options = config
            .connect_options()
            .unwrap_or_else(|error| panic!("connect options: {error}"));
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
    }

    #[test]
    fn canonical_payload_validation_fails_closed() {
        assert!(validate_canonical_json(br#"{"a":1,"b":2}"#, "payload").is_ok());
        assert!(validate_canonical_json(br#"{ "b": 2, "a": 1 }"#, "payload").is_err());
        assert!(validate_canonical_json(&[], "payload").is_err());
    }
}
