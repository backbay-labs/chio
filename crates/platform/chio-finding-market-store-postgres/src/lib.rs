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

use chio_core_types::sha256_hex;
pub use chio_finding_market_port::{
    HostedApiKeyRecord, HostedCapabilityAdmissionOutcome, HostedPrincipal, HostedPrincipalRole,
    HostedTenantId,
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use zeroize::Zeroize as _;

mod aggregates;
mod auth;
mod catalog;
mod checkpoints;
mod domain;
mod http;
mod import;
mod job_leases;
mod ports;
mod replication;
mod retention;
mod runtime_boundary;
mod spend;
mod tenant;
mod transactions;
mod validation;

pub(crate) use validation::{
    checked_i64, checked_nonnegative_i64, stored_u64, unavailable, validate_canonical_json,
    validate_digest, validate_identifier, verify_payload,
};

pub use aggregates::{HostedAggregateEvent, HostedAggregateHead, HostedAggregateHistoryPage};
pub use auth::{
    HostedPrincipalLifecycleBody, HostedPrincipalLifecycleOperation, HostedSecurityEventOutcome,
    SignedHostedPrincipalLifecycleEvent, HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA,
};
pub use catalog::{HostedDomainPage, HostedDomainWrite};
pub use checkpoints::{
    HostedAggregateCheckpointBody, HostedAggregateCheckpointRecord,
    SignedHostedAggregateCheckpoint, HOSTED_AGGREGATE_CHECKPOINT_SCHEMA,
};
pub use chio_finding_market_port::{HostedAggregateKind, HostedMarketDomainEventKind};
pub use domain::{
    HostedCommerceSettlementPacket, HostedCommerceSettlementStatus, HostedMarketDomainArtifact,
    HostedMarketDomainEvent, HostedMarketDomainProjection,
};
pub use import::{
    HostedSqliteImportBatchBody, HostedSqliteImportEntry, HostedSqliteImportOutcome,
    SignedHostedSqliteImportBatch, HOSTED_SQLITE_IMPORT_BATCH_SCHEMA,
};
pub use replication::{
    HostedAuthorityMode, HostedAuthorityState, HostedAuthorityTransitionBody,
    HostedAuthorityTransitionOperation, HostedMarketAuthority, HostedPrincipalReplicationEventBody,
    HostedPrincipalRollbackOutboxRecord, HostedReplicationCheckBody, HostedReplicationEventBody,
    HostedRollbackOutboxEntry, HostedRollbackOutboxRecord, PostgresFindingMarketReplicator,
    SignedHostedAuthorityTransition, SignedHostedPrincipalReplicationEvent,
    SignedHostedReplicationCheck, SignedHostedReplicationEvent, HOSTED_AUTHORITY_TRANSITION_SCHEMA,
    HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA, HOSTED_REPLICATION_CHECK_SCHEMA,
    HOSTED_REPLICATION_EVENT_SCHEMA,
};
pub use retention::{
    HostedArchiveManifestBody, HostedGcReceiptBody, HostedJournalCheckpointBody,
    HostedJournalCommitment, HostedLegalHoldAction, HostedLegalHoldBody, HostedQuotaAlertBody,
    HostedRestoreVerificationBody, HostedRetentionResourceKind, HostedRetentionTarget,
    PostgresFindingMarketRetention, SignedHostedArchiveManifest, SignedHostedGcReceipt,
    SignedHostedJournalCheckpoint, SignedHostedLegalHold, SignedHostedQuotaAlert,
    SignedHostedRestoreVerification, HOSTED_ARCHIVE_MANIFEST_SCHEMA, HOSTED_GC_RECEIPT_SCHEMA,
    HOSTED_JOURNAL_CHECKPOINT_SCHEMA, HOSTED_LEGAL_HOLD_SCHEMA, HOSTED_QUOTA_ALERT_SCHEMA,
    HOSTED_RESTORE_VERIFICATION_SCHEMA,
};
pub use spend::{HostedSpendReservation, HostedSpendState};
pub use tenant::HostedTenantLimits;
pub use transactions::HostedPurchaseRecoveryOutcome;

const MIGRATION_LOCK_NAME: &str = "chio.finding.market.migrations.v1";
const LEGACY_MIGRATIONS: &[(i64, &str, &str)] = &[
    (
        1,
        "hosted_market",
        include_str!("../migrations/0001_hosted_market.sql"),
    ),
    (
        2,
        "terminal_jobs",
        include_str!("../migrations/0002_terminal_jobs.sql"),
    ),
    (
        3,
        "lease_fencing",
        include_str!("../migrations/0003_lease_fencing.sql"),
    ),
    (
        4,
        "hosted_auth",
        include_str!("../migrations/0004_hosted_auth.sql"),
    ),
    (
        5,
        "market_aggregates",
        include_str!("../migrations/0005_market_aggregates.sql"),
    ),
    (
        6,
        "tenant_registry_rls",
        include_str!("../migrations/0006_tenant_registry_rls.sql"),
    ),
    (
        7,
        "tenant_limits",
        include_str!("../migrations/0007_tenant_limits.sql"),
    ),
    (
        8,
        "append_only_aggregates",
        include_str!("../migrations/0008_append_only_aggregates.sql"),
    ),
    (
        9,
        "aggregate_checkpoints",
        include_str!("../migrations/0009_aggregate_checkpoints.sql"),
    ),
];
const MAX_JOB_ID_BYTES: usize = 256;
const MAX_JOB_KIND_BYTES: usize = 96;
const GC_JOB_TOMBSTONE_CONSTRAINT: &str = "chio_finding_market_jobs_gc_tombstone_v1";
const MAX_LEASE_OWNER_BYTES: usize = 256;
const MAX_ERROR_CODE_BYTES: usize = 128;
const MAX_CLAIM_BATCH: u32 = 100;
const DEFAULT_MAX_JOBS_PER_TENANT: i64 = 100_000;
const MAX_TENANT_JOBS: u64 = 10_000_000;
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum HostedMarketStoreError {
    #[error("hosted market PostgreSQL configuration is invalid")]
    Configuration,
    #[error("hosted market tenant identity is invalid")]
    Tenant,
    #[error("hosted market tenant was not found")]
    TenantNotFound,
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
    #[error("hosted market durable state failed to decode: {0}")]
    Decode(&'static str),
    #[error("hosted market retention target is protected by an active hold")]
    RetentionHeld,
    #[error("hosted market PostgreSQL migration ledger drifted")]
    MigrationDrift,
    #[error("hosted market PostgreSQL operation is unavailable")]
    Unavailable,
}

async fn verify_schema_current(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let rows =
        sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .map_err(|_| HostedMarketStoreError::MigrationDrift)?;
    let expected = chio_finding_market_migrations::MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect::<Vec<_>>();
    if rows.len() != expected.len() {
        return Err(HostedMarketStoreError::MigrationDrift);
    }
    for (row, expected) in rows.iter().zip(expected) {
        let version: i64 = row.try_get(0).map_err(unavailable)?;
        let checksum: Vec<u8> = row.try_get(1).map_err(unavailable)?;
        let success: bool = row.try_get(2).map_err(unavailable)?;
        let expected_checksum: &[u8] = expected.checksum.as_ref();
        if version != expected.version || checksum != expected_checksum || !success {
            return Err(HostedMarketStoreError::MigrationDrift);
        }
    }
    Ok(())
}

async fn bridge_legacy_migration_ledger(
    connection: &mut sqlx::pool::PoolConnection<Postgres>,
) -> Result<(), HostedMarketStoreError> {
    let sqlx_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
            .fetch_one(&mut **connection)
            .await
            .map_err(unavailable)?;
    if sqlx_table.is_some() {
        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&mut **connection)
            .await
            .map_err(unavailable)?;
        if applied > 0 {
            return Ok(());
        }
    }

    sqlx::raw_sql(
        r#"CREATE TABLE IF NOT EXISTS chio_finding_market_schema_migrations (
            version BIGINT PRIMARY KEY CHECK (version > 0),
            name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
            checksum_sha256 CHAR(64) NOT NULL CHECK (
                checksum_sha256 !~ '[^0-9a-f]'
            ),
            applied_at BIGINT NOT NULL CHECK (applied_at > 0)
        )"#,
    )
    .execute(&mut **connection)
    .await
    .map_err(unavailable)?;
    let rows = sqlx::query(
        "SELECT version, name, checksum_sha256 FROM chio_finding_market_schema_migrations ORDER BY version",
    )
    .fetch_all(&mut **connection)
    .await
    .map_err(unavailable)?;
    if rows.len() > LEGACY_MIGRATIONS.len() {
        return Err(HostedMarketStoreError::MigrationDrift);
    }
    for (index, row) in rows.iter().enumerate() {
        let (version, name, sql) = LEGACY_MIGRATIONS
            .get(index)
            .ok_or(HostedMarketStoreError::MigrationDrift)?;
        if row.try_get::<i64, _>(0).map_err(unavailable)? != *version
            || row.try_get::<String, _>(1).map_err(unavailable)? != *name
            || row.try_get::<String, _>(2).map_err(unavailable)? != sha256_hex(sql.as_bytes())
        {
            return Err(HostedMarketStoreError::MigrationDrift);
        }
    }
    if rows.is_empty() {
        return Ok(());
    }

    sqlx::raw_sql(
        r#"CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
            success BOOLEAN NOT NULL,
            checksum BYTEA NOT NULL,
            execution_time BIGINT NOT NULL
        )"#,
    )
    .execute(&mut **connection)
    .await
    .map_err(unavailable)?;
    let embedded = chio_finding_market_migrations::MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect::<Vec<_>>();
    for (legacy, migration) in rows.iter().zip(embedded) {
        let version: i64 = legacy.try_get(0).map_err(unavailable)?;
        if migration.version != version {
            return Err(HostedMarketStoreError::MigrationDrift);
        }
        let description: &str = migration.description.as_ref();
        let checksum: &[u8] = migration.checksum.as_ref();
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES ($1, $2, TRUE, $3, 0)",
        )
        .bind(version)
        .bind(description)
        .bind(checksum)
        .execute(&mut **connection)
        .await
        .map_err(unavailable)?;
    }
    Ok(())
}

/// TLS-required PostgreSQL pool configuration. The DSN is redacted from
/// `Debug`, because it may carry a password even when deployments normally
/// resolve it from a secret manager.
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

    pub fn with_acquire_timeout(mut self, value: Duration) -> Result<Self, HostedMarketStoreError> {
        if !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&value) {
            return Err(HostedMarketStoreError::Configuration);
        }
        self.acquire_timeout = value;
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

impl Drop for HostedPostgresConfig {
    fn drop(&mut self) {
        self.database_url.zeroize();
    }
}

#[derive(Clone)]
pub struct PostgresFindingMarketStore {
    pool: PgPool,
    max_jobs_per_tenant: i64,
}

/// Schema-only connection holder for the separately credentialed migrator.
pub struct PostgresFindingMarketMigrator {
    pool: PgPool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedJobWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Authoritative expiry returned by PostgreSQL after a fenced renewal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedLeaseRenewal {
    pub expires_at: u64,
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
            .map_err(unavailable)?;
        runtime_boundary::verify_runtime_role(&pool).await?;
        verify_schema_current(&pool).await?;
        Ok(Self {
            pool,
            max_jobs_per_tenant: config.max_jobs_per_tenant,
        })
    }

    pub async fn connect_worker(
        config: &HostedPostgresConfig,
    ) -> Result<Self, HostedMarketStoreError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options()?)
            .await
            .map_err(unavailable)?;
        runtime_boundary::verify_worker_role(&pool).await?;
        verify_schema_current(&pool).await?;
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

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    pub async fn verify_runtime_boundary_for_integration_tests(
        &self,
    ) -> Result<(), HostedMarketStoreError> {
        runtime_boundary::verify_runtime_role(&self.pool).await
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    pub async fn verify_worker_boundary_for_integration_tests(
        &self,
    ) -> Result<(), HostedMarketStoreError> {
        runtime_boundary::verify_worker_role(&self.pool).await
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    pub async fn begin_tenant_write_for_integration_tests(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        self.begin_tenant(tenant).await
    }
}

impl PostgresFindingMarketMigrator {
    pub async fn connect(config: &HostedPostgresConfig) -> Result<Self, HostedMarketStoreError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options()?)
            .await
            .map_err(unavailable)?;
        runtime_boundary::verify_migrator_role(&pool).await?;
        Ok(Self { pool })
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_pool_for_integration_tests(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), HostedMarketStoreError> {
        let mut connection = self.pool.acquire().await.map_err(unavailable)?;
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind(MIGRATION_LOCK_NAME)
            .execute(&mut *connection)
            .await
            .map_err(unavailable)?;
        let migrated = match bridge_legacy_migration_ledger(&mut connection).await {
            Ok(()) => chio_finding_market_migrations::MIGRATOR
                .run_direct(&mut *connection)
                .await
                .map_err(|_| HostedMarketStoreError::MigrationDrift),
            Err(error) => Err(error),
        };
        let unlocked = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
            .bind(MIGRATION_LOCK_NAME)
            .execute(&mut *connection)
            .await
            .map_err(unavailable);
        match (migrated, unlocked) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }
}

impl PostgresFindingMarketStore {
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
        // Tenant-wide lock guarding the queued-job quota check below: the
        // count-then-insert pair must not interleave. This serializes job
        // inserts per tenant, so a tenant's insert throughput is bounded by
        // one quota-check transaction at a time; admission (DPoP) and spend
        // reservations are row-scoped and do not share this ceiling.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;

        if let Some(row) = sqlx::query(
            "SELECT job_kind, request_sha256, payload_sha256, payload_json FROM chio_finding_market_jobs WHERE tenant_id = $1 AND job_id = $2 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?
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
                .map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }

        let quota: i64 = sqlx::query_scalar(
            "SELECT max_queued_jobs FROM chio_finding_market_tenants WHERE tenant_id = $1 FOR SHARE",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let counts = sqlx::query(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE state IN ('pending', 'leased', 'failed')) FROM chio_finding_market_jobs WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let retained_count: i64 = counts.try_get(0).map_err(unavailable)?;
        let queued_count: i64 = counts.try_get(1).map_err(unavailable)?;
        if retained_count >= self.max_jobs_per_tenant || queued_count >= quota {
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
        .map_err(map_job_insert_error)?;
        transaction.commit().await.map_err(unavailable)?;
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
            .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| job_from_row(tenant, &row)).transpose()
    }

    /// Count work that can still execute for one tenant. Qualification uses
    /// this before provisioning so an unrelated retained job cannot satisfy
    /// an exact canary.
    pub async fn nonterminal_job_count(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<u64, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chio_finding_market_jobs WHERE tenant_id = $1 AND state IN ('pending', 'leased', 'failed')",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        stored_u64(count)
    }

    /// Count every retained job for one tenant. Exact-job qualification uses
    /// this to reject stale terminal rows as well as runnable work.
    pub async fn job_count(&self, tenant: &HostedTenantId) -> Result<u64, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chio_finding_market_jobs WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        stored_u64(count)
    }

    /// Prove that the runtime role can enter one configured tenant boundary
    /// before a worker advertises readiness or claims a lease.
    pub async fn probe_tenant(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<(), HostedMarketStoreError> {
        let transaction = self.begin_tenant(tenant).await?;
        transaction.commit().await.map_err(unavailable)
    }

    pub(crate) async fn begin_tenant(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant_scope(tenant).await?;
        self.require_enabled_tenant(&mut transaction, tenant, true)
            .await?;
        Ok(transaction)
    }

    pub(crate) async fn begin_tenant_snapshot(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        self.require_enabled_tenant(&mut transaction, tenant, false)
            .await?;
        Ok(transaction)
    }

    async fn require_enabled_tenant(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &HostedTenantId,
        lock_for_scoped_write: bool,
    ) -> Result<(), HostedMarketStoreError> {
        let query = if lock_for_scoped_write {
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1 FOR SHARE"
        } else {
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1"
        };
        let enabled = sqlx::query_scalar::<_, bool>(query)
            .bind(tenant.as_str())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(unavailable)?
            .ok_or(HostedMarketStoreError::TenantNotFound)?;
        if !enabled {
            return Err(HostedMarketStoreError::TenantDisabled);
        }
        Ok(())
    }

    async fn begin_tenant_scope(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        Ok(transaction)
    }
}

fn map_job_insert_error(error: sqlx::Error) -> HostedMarketStoreError {
    match &error {
        sqlx::Error::Database(database_error)
            if database_error.constraint() == Some(GC_JOB_TOMBSTONE_CONSTRAINT) =>
        {
            HostedMarketStoreError::Conflict
        }
        _ => HostedMarketStoreError::Unavailable,
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
        || lease_fence < attempt_count
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

#[cfg(test)]
mod tests;
