use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection as _, PgConnection, PgPool, Postgres, Row as _, Transaction};

use super::{
    checked_i64, checked_nonnegative_i64, runtime_boundary, stored_u64, unavailable,
    validate_digest, validate_identifier, HostedAggregateKind, HostedJobWriteOutcome,
    HostedMarketStoreError, HostedPostgresConfig, HostedTenantId,
};

pub const HOSTED_JOURNAL_CHECKPOINT_SCHEMA: &str = "chio.finding.hosted-journal-checkpoint.v1";
pub const HOSTED_ARCHIVE_MANIFEST_SCHEMA: &str = "chio.finding.hosted-archive-manifest.v1";
pub const HOSTED_LEGAL_HOLD_SCHEMA: &str = "chio.finding.hosted-legal-hold.v1";
pub const HOSTED_RESTORE_VERIFICATION_SCHEMA: &str = "chio.finding.hosted-restore-verification.v1";
pub const HOSTED_QUOTA_ALERT_SCHEMA: &str = "chio.finding.hosted-quota-alert.v1";
pub const HOSTED_GC_RECEIPT_SCHEMA: &str = "chio.finding.hosted-gc-receipt.v1";

const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_FAMILY_BYTES: usize = 96;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const MAX_CONFIGURATION_REVISION_BYTES: usize = 256;
const MAX_OBJECT_URI_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedRetentionResourceKind {
    Aggregate,
    Job,
}

impl HostedRetentionResourceKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Aggregate => "aggregate",
            Self::Job => "job",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedRetentionTarget {
    pub resource_kind: HostedRetentionResourceKind,
    pub resource_family: String,
    pub resource_id: String,
    pub resource_revision: u64,
    pub resource_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedJournalCheckpointBody {
    pub schema: String,
    pub tenant_id: String,
    pub aggregate_heads_sha256: String,
    pub terminal_jobs_sha256: String,
    pub previous_checkpoint_sha256: Option<String>,
    pub migration_version: u64,
    pub configuration_revision: String,
    pub created_at: u64,
}

pub type SignedHostedJournalCheckpoint = SignedExportEnvelope<HostedJournalCheckpointBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedJournalCommitment {
    pub aggregate_heads_sha256: String,
    pub terminal_jobs_sha256: String,
    pub previous_checkpoint_sha256: Option<String>,
    pub migration_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedArchiveManifestBody {
    pub schema: String,
    pub tenant_id: String,
    pub target: HostedRetentionTarget,
    pub covered_checkpoint_sha256: String,
    pub object_uri: String,
    pub object_sha256: String,
    pub object_size: u64,
    pub configuration_revision: String,
    pub previous_archive_sha256: Option<String>,
    pub created_at: u64,
}

pub type SignedHostedArchiveManifest = SignedExportEnvelope<HostedArchiveManifestBody>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedLegalHoldAction {
    Placed,
    Released,
}

impl HostedLegalHoldAction {
    const fn label(self) -> &'static str {
        match self {
            Self::Placed => "placed",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedLegalHoldBody {
    pub schema: String,
    pub tenant_id: String,
    pub hold_id: String,
    pub target: HostedRetentionTarget,
    pub action: HostedLegalHoldAction,
    pub previous_hold_event_sha256: Option<String>,
    pub created_at: u64,
}

pub type SignedHostedLegalHold = SignedExportEnvelope<HostedLegalHoldBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedRestoreVerificationBody {
    pub schema: String,
    pub tenant_id: String,
    pub archive_sha256: String,
    pub restored_resource_sha256: String,
    pub verified_at: u64,
}

pub type SignedHostedRestoreVerification = SignedExportEnvelope<HostedRestoreVerificationBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedQuotaAlertBody {
    pub schema: String,
    pub tenant_id: String,
    pub quota_kind: String,
    pub observed_value: u64,
    pub limit_value: u64,
    pub created_at: u64,
}

pub type SignedHostedQuotaAlert = SignedExportEnvelope<HostedQuotaAlertBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedGcReceiptBody {
    pub schema: String,
    pub tenant_id: String,
    pub archive_sha256: String,
    pub target: HostedRetentionTarget,
    pub completed_at: u64,
}

pub type SignedHostedGcReceipt = SignedExportEnvelope<HostedGcReceiptBody>;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AggregateCheckpointMember {
    aggregate_kind: HostedAggregateKind,
    aggregate_id: String,
    revision: u64,
    event_sha256: String,
    updated_at: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TerminalJobCheckpointMember {
    job_id: String,
    job_kind: String,
    state: String,
    result_sha256: String,
    updated_at: u64,
}

#[derive(Serialize)]
struct CheckpointMemberInsert<'a> {
    member_kind: &'static str,
    member_family: &'a str,
    member_id: &'a str,
    member_revision: u64,
    member_sha256: String,
}

/// Separately credentialed retention and checkpoint writer. It never owns
/// schema objects and receives no direct mutation privilege on market state.
#[derive(Clone)]
pub struct PostgresFindingMarketRetention {
    pool: PgPool,
}

impl PostgresFindingMarketRetention {
    pub async fn connect(config: &HostedPostgresConfig) -> Result<Self, HostedMarketStoreError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections.min(4))
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options()?)
            .await
            .map_err(unavailable)?;
        runtime_boundary::verify_retention_role(&pool).await?;
        super::verify_schema_current(&pool).await?;
        Ok(Self { pool })
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_pool_for_integration_tests(pool: PgPool) -> Self {
        Self { pool }
    }

    #[cfg(feature = "postgres-integration")]
    #[doc(hidden)]
    pub async fn verify_retention_boundary_for_integration_tests(
        &self,
    ) -> Result<(), HostedMarketStoreError> {
        runtime_boundary::verify_retention_role(&self.pool).await
    }

    pub async fn append_journal_checkpoint(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        checkpoint: &SignedHostedJournalCheckpoint,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            checkpoint,
            HOSTED_JOURNAL_CHECKPOINT_SCHEMA,
            &checkpoint.body.schema,
        )?;
        validate_digest(
            &checkpoint.body.aggregate_heads_sha256,
            "journal aggregate heads",
        )?;
        validate_digest(
            &checkpoint.body.terminal_jobs_sha256,
            "journal terminal jobs",
        )?;
        if let Some(previous) = checkpoint.body.previous_checkpoint_sha256.as_deref() {
            validate_digest(previous, "journal checkpoint predecessor")?;
        }
        validate_identifier(
            &checkpoint.body.configuration_revision,
            MAX_CONFIGURATION_REVISION_BYTES,
        )
        .map_err(|()| HostedMarketStoreError::Invalid("configuration revision"))?;
        if checkpoint.body.migration_version == 0 || checkpoint.body.created_at == 0 {
            return Err(HostedMarketStoreError::Invalid("journal checkpoint"));
        }
        let envelope = signed_bytes(checkpoint, "journal checkpoint")?;
        let checkpoint_sha256 = sha256_hex(&envelope);
        let checkpoint_lock = format!("journal-checkpoint:{}", tenant.as_str());
        let mut connection = self.pool.acquire().await.map_err(unavailable)?;
        // A session advisory lock survives transaction rollback. Closing this
        // dedicated connection on cancellation prevents a locked session from
        // returning to the pool.
        connection.close_on_drop();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 10))")
            .bind(&checkpoint_lock)
            .execute(&mut *connection)
            .await
            .map_err(unavailable)?;
        let result = async {
            let mut transaction = Self::begin_snapshot_on(&mut connection, tenant).await?;
            if let Some(retained) = sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT checkpoint_envelope_json FROM chio_finding_market_journal_checkpoints WHERE tenant_id = $1 AND checkpoint_sha256 = $2",
            )
            .bind(tenant.as_str())
            .bind(&checkpoint_sha256)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(unavailable)?
            {
                if retained != envelope {
                    return Err(HostedMarketStoreError::Conflict);
                }
                transaction
                    .commit()
                    .await
                    .map_err(unavailable)?;
                return Ok(HostedJobWriteOutcome::ExactReplay);
            }
            let previous = sqlx::query(
                "SELECT checkpoint_sha256, created_at FROM chio_finding_market_journal_checkpoints WHERE tenant_id = $1 ORDER BY created_at DESC, checkpoint_sha256 DESC LIMIT 1",
            )
            .bind(tenant.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(unavailable)?;
            match previous {
                Some(row) => {
                    let previous_sha256: String = row.try_get(0).map_err(unavailable)?;
                    let previous_created_at = stored_u64(row.try_get(1).map_err(unavailable)?)?;
                    if checkpoint.body.previous_checkpoint_sha256.as_deref()
                        != Some(previous_sha256.as_str())
                        || checkpoint.body.created_at <= previous_created_at
                    {
                        return Err(HostedMarketStoreError::Conflict);
                    }
                }
                None if checkpoint.body.previous_checkpoint_sha256.is_none() => {}
                None => return Err(HostedMarketStoreError::Conflict),
            }
            let migration_version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
            if stored_u64(migration_version)? != checkpoint.body.migration_version {
                return Err(HostedMarketStoreError::MigrationDrift);
            }
            let configuration_revision: String = sqlx::query_scalar(
                "SELECT configuration_revision FROM chio_finding_market_tenants WHERE tenant_id = $1",
            )
            .bind(tenant.as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
            if configuration_revision != checkpoint.body.configuration_revision {
                return Err(HostedMarketStoreError::Conflict);
            }
            let aggregates = load_aggregate_members(&mut transaction, tenant).await?;
            let terminal_jobs = load_terminal_job_members(&mut transaction, tenant).await?;
            let latest_member_time = aggregates
                .iter()
                .map(|member| member.updated_at)
                .chain(terminal_jobs.iter().map(|member| member.updated_at))
                .max()
                .unwrap_or(0);
            if checkpoint.body.created_at < latest_member_time {
                return Err(HostedMarketStoreError::Conflict);
            }
            if canonical_digest(&aggregates, "journal aggregate heads")?
                != checkpoint.body.aggregate_heads_sha256
                || canonical_digest(&terminal_jobs, "journal terminal jobs")?
                    != checkpoint.body.terminal_jobs_sha256
            {
                return Err(HostedMarketStoreError::Conflict);
            }
            let mut members = Vec::with_capacity(aggregates.len() + terminal_jobs.len());
            for member in &aggregates {
                members.push(CheckpointMemberInsert {
                    member_kind: HostedRetentionResourceKind::Aggregate.label(),
                    member_family: member.aggregate_kind.label(),
                    member_id: &member.aggregate_id,
                    member_revision: member.revision,
                    member_sha256: member.event_sha256.clone(),
                });
            }
            for member in &terminal_jobs {
                members.push(CheckpointMemberInsert {
                    member_kind: HostedRetentionResourceKind::Job.label(),
                    member_family: &member.job_kind,
                    member_id: &member.job_id,
                    member_revision: 0,
                    member_sha256: canonical_digest(member, "terminal job member")?,
                });
            }
            let members_json = serde_json::to_string(&members)
                .map_err(|_| HostedMarketStoreError::Invalid("checkpoint members"))?;
            let outcome: i16 = sqlx::query_scalar(
                r#"SELECT chio_finding_market_append_journal_checkpoint(
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb
                )"#,
            )
            .bind(tenant.as_str())
            .bind(&checkpoint_sha256)
            .bind(&checkpoint.body.aggregate_heads_sha256)
            .bind(&checkpoint.body.terminal_jobs_sha256)
            .bind(checkpoint.body.previous_checkpoint_sha256.as_deref())
            .bind(migration_version)
            .bind(&checkpoint.body.configuration_revision)
            .bind(checkpoint.signer_key.to_hex())
            .bind(&envelope)
            .bind(checked_i64(checkpoint.body.created_at, "checkpoint time")?)
            .bind(members_json)
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
            let outcome = retention_write_outcome(outcome)?;
            transaction
                .commit()
                .await
                .map_err(unavailable)?;
            Ok(outcome)
        }
        .await;
        let unlocked: Result<bool, HostedMarketStoreError> =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 10))")
                .bind(&checkpoint_lock)
                .fetch_one(&mut *connection)
                .await
                .map_err(unavailable);
        let closed = connection.close().await.map_err(unavailable);
        match (unlocked, closed) {
            (Ok(true), Ok(())) => result,
            _ => Err(HostedMarketStoreError::Unavailable),
        }
    }

    pub async fn journal_commitment(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<HostedJournalCommitment, HostedMarketStoreError> {
        let mut transaction = self.begin_snapshot(tenant).await?;
        let aggregates = load_aggregate_members(&mut transaction, tenant).await?;
        let terminal_jobs = load_terminal_job_members(&mut transaction, tenant).await?;
        let previous_checkpoint_sha256 = sqlx::query_scalar(
            "SELECT checkpoint_sha256 FROM chio_finding_market_journal_checkpoints WHERE tenant_id = $1 ORDER BY created_at DESC, checkpoint_sha256 DESC LIMIT 1",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let migration_version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let commitment = HostedJournalCommitment {
            aggregate_heads_sha256: canonical_digest(&aggregates, "journal aggregate heads")?,
            terminal_jobs_sha256: canonical_digest(&terminal_jobs, "journal terminal jobs")?,
            previous_checkpoint_sha256,
            migration_version: stored_u64(migration_version)?,
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(commitment)
    }

    pub async fn append_archive_manifest(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        manifest: &SignedHostedArchiveManifest,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            manifest,
            HOSTED_ARCHIVE_MANIFEST_SCHEMA,
            &manifest.body.schema,
        )?;
        validate_target(&manifest.body.target)?;
        validate_digest(
            &manifest.body.covered_checkpoint_sha256,
            "archive checkpoint",
        )?;
        validate_digest(&manifest.body.object_sha256, "archive object")?;
        if manifest.body.object_size == 0
            || manifest.body.created_at == 0
            || manifest.body.object_uri.len() > MAX_OBJECT_URI_BYTES
            || !is_external_object_uri(&manifest.body.object_uri)
        {
            return Err(HostedMarketStoreError::Invalid("archive manifest"));
        }
        validate_identifier(
            &manifest.body.configuration_revision,
            MAX_CONFIGURATION_REVISION_BYTES,
        )
        .map_err(|()| HostedMarketStoreError::Invalid("configuration revision"))?;
        if let Some(previous) = manifest.body.previous_archive_sha256.as_deref() {
            validate_digest(previous, "archive predecessor")?;
        }
        let envelope = signed_bytes(manifest, "archive manifest")?;
        let archive_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin(tenant).await?;
        let replay = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT archive_envelope_json FROM chio_finding_market_archive_manifests WHERE tenant_id = $1 AND archive_sha256 = $2",
        )
        .bind(tenant.as_str())
        .bind(&archive_sha256)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(retained) = replay {
            if retained != envelope {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        require_checkpoint_member(
            &mut transaction,
            tenant,
            &manifest.body.covered_checkpoint_sha256,
            &manifest.body.target,
        )
        .await?;
        let checkpoint_row = sqlx::query(
            "SELECT configuration_revision, created_at FROM chio_finding_market_journal_checkpoints WHERE tenant_id = $1 AND checkpoint_sha256 = $2",
        )
        .bind(tenant.as_str())
        .bind(&manifest.body.covered_checkpoint_sha256)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let checkpoint_configuration_revision: String =
            checkpoint_row.try_get(0).map_err(unavailable)?;
        let checkpoint_created_at = stored_u64(checkpoint_row.try_get(1).map_err(unavailable)?)?;
        if checkpoint_configuration_revision != manifest.body.configuration_revision
            || manifest.body.created_at < checkpoint_created_at
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        let previous = sqlx::query(
            "SELECT archive_sha256, created_at FROM chio_finding_market_archive_manifests WHERE tenant_id = $1 AND resource_kind = $2 AND resource_family = $3 AND resource_id = $4 ORDER BY created_at DESC, archive_sha256 DESC LIMIT 1",
        )
        .bind(tenant.as_str())
        .bind(manifest.body.target.resource_kind.label())
        .bind(&manifest.body.target.resource_family)
        .bind(&manifest.body.target.resource_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match previous {
            Some(row) => {
                let previous_sha256: String = row.try_get(0).map_err(unavailable)?;
                let previous_created_at = stored_u64(row.try_get(1).map_err(unavailable)?)?;
                if manifest.body.previous_archive_sha256.as_deref()
                    != Some(previous_sha256.as_str())
                    || manifest.body.created_at <= previous_created_at
                {
                    return Err(HostedMarketStoreError::Conflict);
                }
            }
            None if manifest.body.previous_archive_sha256.is_none() => {}
            None => return Err(HostedMarketStoreError::Conflict),
        }
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_archive_manifest(
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14, $15, $16
            )"#,
        )
        .bind(tenant.as_str())
        .bind(&archive_sha256)
        .bind(manifest.body.target.resource_kind.label())
        .bind(&manifest.body.target.resource_family)
        .bind(&manifest.body.target.resource_id)
        .bind(checked_nonnegative_i64(
            manifest.body.target.resource_revision,
            "archive revision",
        )?)
        .bind(&manifest.body.target.resource_sha256)
        .bind(&manifest.body.covered_checkpoint_sha256)
        .bind(&manifest.body.object_uri)
        .bind(&manifest.body.object_sha256)
        .bind(checked_i64(manifest.body.object_size, "archive size")?)
        .bind(&manifest.body.configuration_revision)
        .bind(manifest.body.previous_archive_sha256.as_deref())
        .bind(manifest.signer_key.to_hex())
        .bind(&envelope)
        .bind(checked_i64(manifest.body.created_at, "archive time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = retention_write_outcome(outcome)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn append_legal_hold(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        hold: &SignedHostedLegalHold,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            hold,
            HOSTED_LEGAL_HOLD_SCHEMA,
            &hold.body.schema,
        )?;
        validate_identifier(&hold.body.hold_id, MAX_RESOURCE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("legal hold"))?;
        validate_target(&hold.body.target)?;
        if hold.body.created_at == 0 {
            return Err(HostedMarketStoreError::Invalid("legal hold"));
        }
        if let Some(previous) = hold.body.previous_hold_event_sha256.as_deref() {
            validate_digest(previous, "legal hold predecessor")?;
        }
        let envelope = signed_bytes(hold, "legal hold")?;
        let event_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin(tenant).await?;
        let replay = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT hold_envelope_json FROM chio_finding_market_legal_hold_events WHERE tenant_id = $1 AND hold_event_sha256 = $2",
        )
        .bind(tenant.as_str())
        .bind(&event_sha256)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(retained) = replay {
            if retained != envelope {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        let previous = sqlx::query(
            "SELECT hold_event_sha256, action, resource_kind, resource_family, resource_id, created_at FROM chio_finding_market_legal_hold_events WHERE tenant_id = $1 AND hold_id = $2 ORDER BY created_at DESC, hold_event_sha256 DESC LIMIT 1",
        )
        .bind(tenant.as_str())
        .bind(&hold.body.hold_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match previous {
            Some(row) => {
                let previous_sha: String = row.try_get(0).map_err(unavailable)?;
                let previous_action: String = row.try_get(1).map_err(unavailable)?;
                let previous_kind: String = row.try_get(2).map_err(unavailable)?;
                let previous_family: String = row.try_get(3).map_err(unavailable)?;
                let previous_id: String = row.try_get(4).map_err(unavailable)?;
                let previous_created_at = stored_u64(row.try_get(5).map_err(unavailable)?)?;
                if hold.body.previous_hold_event_sha256.as_deref() != Some(&previous_sha)
                    || previous_kind != hold.body.target.resource_kind.label()
                    || previous_family != hold.body.target.resource_family
                    || previous_id != hold.body.target.resource_id
                    || previous_action == hold.body.action.label()
                    || hold.body.created_at <= previous_created_at
                {
                    return Err(HostedMarketStoreError::Conflict);
                }
            }
            None if hold.body.action == HostedLegalHoldAction::Placed
                && hold.body.previous_hold_event_sha256.is_none() => {}
            None => return Err(HostedMarketStoreError::Conflict),
        }
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_legal_hold_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )"#,
        )
        .bind(tenant.as_str())
        .bind(event_sha256)
        .bind(&hold.body.hold_id)
        .bind(hold.body.target.resource_kind.label())
        .bind(&hold.body.target.resource_family)
        .bind(&hold.body.target.resource_id)
        .bind(hold.body.action.label())
        .bind(hold.body.previous_hold_event_sha256.as_deref())
        .bind(hold.signer_key.to_hex())
        .bind(&envelope)
        .bind(checked_i64(hold.body.created_at, "legal hold time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = retention_write_outcome(outcome)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn append_restore_verification(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        verification: &SignedHostedRestoreVerification,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            verification,
            HOSTED_RESTORE_VERIFICATION_SCHEMA,
            &verification.body.schema,
        )?;
        validate_digest(&verification.body.archive_sha256, "restore archive")?;
        validate_digest(
            &verification.body.restored_resource_sha256,
            "restored resource",
        )?;
        if verification.body.verified_at == 0 {
            return Err(HostedMarketStoreError::Invalid("restore verification"));
        }
        let envelope = signed_bytes(verification, "restore verification")?;
        let verification_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin(tenant).await?;
        let archive = sqlx::query(
            "SELECT resource_sha256, created_at FROM chio_finding_market_archive_manifests WHERE tenant_id = $1 AND archive_sha256 = $2",
        )
        .bind(tenant.as_str())
        .bind(&verification.body.archive_sha256)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let Some(archive) = archive else {
            return Err(HostedMarketStoreError::Conflict);
        };
        let archive_digest: String = archive.try_get(0).map_err(unavailable)?;
        let archive_created_at = stored_u64(archive.try_get(1).map_err(unavailable)?)?;
        if archive_digest != verification.body.restored_resource_sha256
            || verification.body.verified_at < archive_created_at
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_restore_verification(
                $1, $2, $3, $4, $5, $6, $7
            )"#,
        )
        .bind(tenant.as_str())
        .bind(&verification_sha256)
        .bind(&verification.body.archive_sha256)
        .bind(&verification.body.restored_resource_sha256)
        .bind(verification.signer_key.to_hex())
        .bind(&envelope)
        .bind(checked_i64(verification.body.verified_at, "restore time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = retention_write_outcome(outcome)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn append_quota_alert(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        alert: &SignedHostedQuotaAlert,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            alert,
            HOSTED_QUOTA_ALERT_SCHEMA,
            &alert.body.schema,
        )?;
        validate_identifier(&alert.body.quota_kind, MAX_RESOURCE_FAMILY_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("quota alert"))?;
        if alert.body.limit_value == 0
            || alert.body.observed_value < alert.body.limit_value
            || alert.body.created_at == 0
        {
            return Err(HostedMarketStoreError::Invalid("quota alert"));
        }
        let envelope = signed_bytes(alert, "quota alert")?;
        let alert_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin(tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_quota_alert(
                $1, $2, $3, $4, $5, $6, $7, $8
            )"#,
        )
        .bind(tenant.as_str())
        .bind(&alert_sha256)
        .bind(&alert.body.quota_kind)
        .bind(checked_i64(alert.body.observed_value, "quota value")?)
        .bind(checked_i64(alert.body.limit_value, "quota limit")?)
        .bind(alert.signer_key.to_hex())
        .bind(&envelope)
        .bind(checked_i64(alert.body.created_at, "quota alert time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = retention_write_outcome(outcome)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn garbage_collect(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        receipt: &SignedHostedGcReceipt,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            receipt,
            HOSTED_GC_RECEIPT_SCHEMA,
            &receipt.body.schema,
        )?;
        validate_digest(&receipt.body.archive_sha256, "GC archive")?;
        validate_target(&receipt.body.target)?;
        if receipt.body.completed_at == 0 {
            return Err(HostedMarketStoreError::Invalid("GC receipt"));
        }
        let envelope = signed_bytes(receipt, "GC receipt")?;
        let receipt_sha256 = sha256_hex(&envelope);
        let mut transaction = self.begin(tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_gc_retained_resource(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )"#,
        )
        .bind(tenant.as_str())
        .bind(&receipt.body.archive_sha256)
        .bind(receipt.body.target.resource_kind.label())
        .bind(&receipt.body.target.resource_family)
        .bind(&receipt.body.target.resource_id)
        .bind(checked_nonnegative_i64(
            receipt.body.target.resource_revision,
            "GC revision",
        )?)
        .bind(&receipt.body.target.resource_sha256)
        .bind(receipt_sha256)
        .bind(receipt.signer_key.to_hex())
        .bind(envelope)
        .bind(checked_i64(receipt.body.completed_at, "GC time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            3 => return Err(HostedMarketStoreError::RetentionHeld),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    async fn begin(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let enabled: Option<bool> = sqlx::query_scalar(
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match enabled {
            Some(true) => Ok(transaction),
            Some(false) => Err(HostedMarketStoreError::TenantDisabled),
            None => Err(HostedMarketStoreError::NotFound),
        }
    }

    async fn begin_snapshot(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'_, Postgres>, HostedMarketStoreError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let enabled: Option<bool> = sqlx::query_scalar(
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match enabled {
            Some(true) => Ok(transaction),
            Some(false) => Err(HostedMarketStoreError::TenantDisabled),
            None => Err(HostedMarketStoreError::NotFound),
        }
    }

    async fn begin_snapshot_on<'connection>(
        connection: &'connection mut PgConnection,
        tenant: &HostedTenantId,
    ) -> Result<Transaction<'connection, Postgres>, HostedMarketStoreError> {
        let mut transaction = connection.begin().await.map_err(unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let enabled: Option<bool> = sqlx::query_scalar(
            "SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match enabled {
            Some(true) => Ok(transaction),
            Some(false) => Err(HostedMarketStoreError::TenantDisabled),
            None => Err(HostedMarketStoreError::NotFound),
        }
    }
}

async fn load_aggregate_members(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
) -> Result<Vec<AggregateCheckpointMember>, HostedMarketStoreError> {
    let rows = sqlx::query(
        "SELECT aggregate_kind, aggregate_id, revision, event_sha256, updated_at FROM chio_finding_market_aggregate_heads WHERE tenant_id = $1 ORDER BY aggregate_kind, aggregate_id",
    )
    .bind(tenant.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    rows.into_iter()
        .map(|row| {
            Ok(AggregateCheckpointMember {
                aggregate_kind: crate::aggregates::parse_aggregate_kind(
                    &row.try_get::<String, _>(0).map_err(unavailable)?,
                )?,
                aggregate_id: row.try_get(1).map_err(unavailable)?,
                revision: stored_u64(row.try_get(2).map_err(unavailable)?)?,
                event_sha256: row.try_get(3).map_err(unavailable)?,
                updated_at: stored_u64(row.try_get(4).map_err(unavailable)?)?,
            })
        })
        .collect()
}

async fn load_terminal_job_members(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
) -> Result<Vec<TerminalJobCheckpointMember>, HostedMarketStoreError> {
    let rows = sqlx::query(
        "SELECT job_id, job_kind, state, result_sha256, updated_at FROM chio_finding_market_jobs WHERE tenant_id = $1 AND state IN ('completed', 'exhausted') ORDER BY job_kind, job_id",
    )
    .bind(tenant.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    rows.into_iter()
        .map(|row| {
            let result_sha256: Option<String> = row.try_get(3).map_err(unavailable)?;
            Ok(TerminalJobCheckpointMember {
                job_id: row.try_get(0).map_err(unavailable)?,
                job_kind: row.try_get(1).map_err(unavailable)?,
                state: row.try_get(2).map_err(unavailable)?,
                result_sha256: result_sha256.unwrap_or_else(|| "0".repeat(64)),
                updated_at: stored_u64(row.try_get(4).map_err(unavailable)?)?,
            })
        })
        .collect()
}

async fn require_checkpoint_member(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    checkpoint_sha256: &str,
    target: &HostedRetentionTarget,
) -> Result<(), HostedMarketStoreError> {
    let exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM chio_finding_market_journal_checkpoint_members
            WHERE tenant_id = $1 AND checkpoint_sha256 = $2
              AND member_kind = $3 AND member_family = $4
              AND member_id = $5 AND member_revision = $6
              AND member_sha256 = $7
        )"#,
    )
    .bind(tenant.as_str())
    .bind(checkpoint_sha256)
    .bind(target.resource_kind.label())
    .bind(&target.resource_family)
    .bind(&target.resource_id)
    .bind(checked_nonnegative_i64(
        target.resource_revision,
        "resource revision",
    )?)
    .bind(&target.resource_sha256)
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if !exists {
        return Err(HostedMarketStoreError::Conflict);
    }
    Ok(())
}

fn retention_write_outcome(outcome: i16) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
    match outcome {
        0 => Ok(HostedJobWriteOutcome::Inserted),
        1 => Ok(HostedJobWriteOutcome::ExactReplay),
        2 => Err(HostedMarketStoreError::Conflict),
        _ => Err(HostedMarketStoreError::Unavailable),
    }
}

fn validate_target(target: &HostedRetentionTarget) -> Result<(), HostedMarketStoreError> {
    validate_identifier(&target.resource_family, MAX_RESOURCE_FAMILY_BYTES)
        .map_err(|()| HostedMarketStoreError::Invalid("retention target"))?;
    validate_identifier(&target.resource_id, MAX_RESOURCE_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::Invalid("retention target"))?;
    validate_digest(&target.resource_sha256, "retention target")?;
    match target.resource_kind {
        HostedRetentionResourceKind::Aggregate if target.resource_revision == 0 => {
            Err(HostedMarketStoreError::Invalid("retention target"))
        }
        HostedRetentionResourceKind::Job if target.resource_revision != 0 => {
            Err(HostedMarketStoreError::Invalid("retention target"))
        }
        _ => Ok(()),
    }
}

fn validate_signed<T: Serialize + Clone>(
    tenant: &HostedTenantId,
    expected_signer: &PublicKey,
    envelope: &SignedExportEnvelope<T>,
    expected_schema: &str,
    actual_schema: &str,
) -> Result<(), HostedMarketStoreError> {
    if actual_schema != expected_schema
        || expected_signer.is_weak_ed25519()
        || envelope.signer_key != *expected_signer
        || !matches!(envelope.verify_signature(), Ok(true))
    {
        return Err(HostedMarketStoreError::Invalid("signed retention artifact"));
    }
    let value = serde_json::to_value(&envelope.body)
        .map_err(|_| HostedMarketStoreError::Invalid("signed retention artifact"))?;
    if value.get("tenantId").and_then(serde_json::Value::as_str) != Some(tenant.as_str()) {
        return Err(HostedMarketStoreError::Tenant);
    }
    Ok(())
}

fn signed_bytes<T: Serialize + Clone>(
    value: &SignedExportEnvelope<T>,
    field: &'static str,
) -> Result<Vec<u8>, HostedMarketStoreError> {
    let bytes = canonical_json_bytes(value).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    Ok(bytes)
}

fn canonical_digest<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, HostedMarketStoreError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| HostedMarketStoreError::Invalid(field))
}

fn is_external_object_uri(value: &str) -> bool {
    value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
        && ["s3://", "gs://", "https://"]
            .iter()
            .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}
