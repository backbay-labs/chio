use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use super::{
    aggregates::aggregate_event_digest, checked_i64, checked_nonnegative_i64, runtime_boundary,
    stored_u64, unavailable, validate_digest, validate_identifier, HostedJobWriteOutcome,
    HostedMarketDomainEvent, HostedMarketDomainEventKind, HostedMarketStoreError,
    HostedPostgresConfig, HostedTenantId, PostgresFindingMarketStore,
    SignedHostedPrincipalLifecycleEvent,
};

pub const HOSTED_REPLICATION_EVENT_SCHEMA: &str = "chio.finding.hosted-replication-event.v1";
pub const HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA: &str =
    "chio.finding.hosted-principal-replication-event.v1";
pub const HOSTED_REPLICATION_CHECK_SCHEMA: &str = "chio.finding.hosted-replication-check.v1";
pub const HOSTED_AUTHORITY_TRANSITION_SCHEMA: &str = "chio.finding.hosted-authority-transition.v1";

const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedMarketAuthority {
    Sqlite,
    Postgres,
}

impl HostedMarketAuthority {
    const fn label(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }

    fn parse(value: &str) -> Result<Self, HostedMarketStoreError> {
        match value {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            _ => Err(HostedMarketStoreError::Decode("authority label")),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedAuthorityMode {
    Shadow,
    Frozen,
    RollbackWindow,
    Authoritative,
    Retired,
}

impl HostedAuthorityMode {
    fn parse(value: &str) -> Result<Self, HostedMarketStoreError> {
        match value {
            "shadow" => Ok(Self::Shadow),
            "frozen" => Ok(Self::Frozen),
            "rollback_window" => Ok(Self::RollbackWindow),
            "authoritative" => Ok(Self::Authoritative),
            "retired" => Ok(Self::Retired),
            _ => Err(HostedMarketStoreError::Decode("authority mode label")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAuthorityState {
    pub tenant_id: HostedTenantId,
    pub authority: HostedMarketAuthority,
    pub authority_epoch: u64,
    pub mode: HostedAuthorityMode,
    pub mutations_enabled: bool,
    pub last_replication_sequence: u64,
    pub last_outbox_sequence: u64,
    pub rollback_window_ends_at: Option<u64>,
    pub configuration_revision: String,
    pub transition_sha256: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedReplicationEventBody {
    pub schema: String,
    pub tenant_id: String,
    pub source_authority: HostedMarketAuthority,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub event_kind: HostedMarketDomainEventKind,
    pub aggregate_id: String,
    pub event_id: String,
    pub expected_revision: u64,
    pub expected_event_sha256: Option<String>,
    pub artifact_signer_key: Option<PublicKey>,
    pub payload: serde_json::Value,
    pub committed_at: u64,
}

pub type SignedHostedReplicationEvent = SignedExportEnvelope<HostedReplicationEventBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPrincipalReplicationEventBody {
    pub schema: String,
    pub tenant_id: String,
    pub source_authority: HostedMarketAuthority,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub lifecycle_event: SignedHostedPrincipalLifecycleEvent,
    pub committed_at: u64,
}

pub type SignedHostedPrincipalReplicationEvent =
    SignedExportEnvelope<HostedPrincipalReplicationEventBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedReplicationCheckBody {
    pub schema: String,
    pub tenant_id: String,
    pub source_authority: HostedMarketAuthority,
    pub authority_epoch: u64,
    pub through_sequence: u64,
    pub source_projection_sha256: String,
    pub target_projection_sha256: String,
    pub lag_seconds: u64,
    pub projection_difference_count: u64,
    pub security_counter_count: u64,
    pub checked_at: u64,
}

pub type SignedHostedReplicationCheck = SignedExportEnvelope<HostedReplicationCheckBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedRollbackOutboxRecord {
    pub tenant_id: String,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub expected_revision: u64,
    pub expected_event_sha256: Option<String>,
    pub event_id: String,
    pub event_kind: String,
    pub artifact_schema: String,
    pub payload_sha256: String,
    pub payload_json: Vec<u8>,
    pub event_sha256: String,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPrincipalRollbackOutboxRecord {
    pub tenant_id: String,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub principal_event_sha256: String,
    pub principal_id: String,
    pub operation: super::HostedPrincipalLifecycleOperation,
    pub role: super::HostedPrincipalRole,
    pub capability_public_key_hex: Option<String>,
    pub overlap_expires_at: Option<u64>,
    pub previous_event_sha256: Option<String>,
    pub signer_key_hex: String,
    pub event_envelope_json: Vec<u8>,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HostedRollbackOutboxEntry {
    Domain(HostedRollbackOutboxRecord),
    Principal(HostedPrincipalRollbackOutboxRecord),
}

impl HostedRollbackOutboxEntry {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Domain(record) => record.sequence,
            Self::Principal(record) => record.sequence,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostedProjectionCommitmentEntry {
    aggregate_kind: String,
    aggregate_id: String,
    revision: u64,
    event_sha256: String,
    event_kind: String,
    artifact_schema: String,
    payload_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostedPrincipalProjectionCommitmentEntry {
    principal_id: String,
    role: String,
    capability_public_key_hex: Option<String>,
    enabled: bool,
    lifecycle_event_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostedPrincipalKeyOverlapCommitmentEntry {
    principal_id: String,
    capability_public_key_hex: String,
    valid_through: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostedProjectionCommitment {
    schema: &'static str,
    domain: Vec<HostedProjectionCommitmentEntry>,
    principals: Vec<HostedPrincipalProjectionCommitmentEntry>,
    principal_key_overlaps: Vec<HostedPrincipalKeyOverlapCommitmentEntry>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedAuthorityTransitionOperation {
    Freeze,
    Cutover,
    Rollback,
    RetireSqlite,
}

impl HostedAuthorityTransitionOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Freeze => "freeze",
            Self::Cutover => "cutover",
            Self::Rollback => "rollback",
            Self::RetireSqlite => "retire_sqlite",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedAuthorityTransitionBody {
    pub schema: String,
    pub tenant_id: String,
    pub operation: HostedAuthorityTransitionOperation,
    pub from_authority: HostedMarketAuthority,
    pub to_authority: HostedMarketAuthority,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub through_sequence: u64,
    pub source_checkpoint_sha256: String,
    pub target_checkpoint_sha256: String,
    pub configuration_revision: String,
    pub rollback_window_ends_at: Option<u64>,
    pub created_at: u64,
}

pub type SignedHostedAuthorityTransition = SignedExportEnvelope<HostedAuthorityTransitionBody>;

/// Separate replication credential. It can append verified mirror records and
/// apply signed authority barriers, but cannot invoke public market commands.
#[derive(Clone)]
pub struct PostgresFindingMarketReplicator {
    pool: PgPool,
}

impl PostgresFindingMarketReplicator {
    pub async fn connect(config: &HostedPostgresConfig) -> Result<Self, HostedMarketStoreError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections.min(8))
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options()?)
            .await
            .map_err(unavailable)?;
        runtime_boundary::verify_replicator_role(&pool).await?;
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
    pub async fn verify_replicator_boundary_for_integration_tests(
        &self,
    ) -> Result<(), HostedMarketStoreError> {
        runtime_boundary::verify_replicator_role(&self.pool).await
    }

    pub async fn apply_replication_event(
        &self,
        tenant: &HostedTenantId,
        expected_source_signer: &PublicKey,
        event: &SignedHostedReplicationEvent,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_source_signer,
            event,
            HOSTED_REPLICATION_EVENT_SCHEMA,
            &event.body.schema,
        )?;
        let body = &event.body;
        if body.source_authority != HostedMarketAuthority::Sqlite
            || body.authority_epoch == 0
            || body.sequence == 0
            || body.committed_at == 0
        {
            return Err(HostedMarketStoreError::Invalid("replication event"));
        }
        if let Some(expected) = body.expected_event_sha256.as_deref() {
            validate_digest(expected, "replication expected head")?;
        }
        let payload_json = canonical_json_bytes(&body.payload)
            .map_err(|_| HostedMarketStoreError::Invalid("replication payload"))?;
        let artifact_authority_id =
            if body.event_kind == HostedMarketDomainEventKind::PenaltyAssessed {
                body.payload
                    .get("body")
                    .and_then(|value| value.get("issuedBy"))
                    .and_then(serde_json::Value::as_str)
            } else {
                None
            };
        let domain_event = HostedMarketDomainEvent::from_canonical_payload(
            body.event_kind,
            body.aggregate_id.clone(),
            body.event_id.clone(),
            payload_json,
            body.artifact_signer_key.as_ref(),
            artifact_authority_id,
        )?;
        let payload_sha256 = sha256_hex(domain_event.payload_json());
        let revision = body
            .expected_revision
            .checked_add(1)
            .ok_or(HostedMarketStoreError::Invalid("replication revision"))?;
        let domain_event_sha256 = aggregate_event_digest(
            tenant,
            body.event_kind.aggregate_kind(),
            &body.aggregate_id,
            revision,
            &body.event_id,
            body.event_kind.event_kind(),
            body.expected_event_sha256.as_deref(),
            &payload_sha256,
            body.committed_at,
        )?;
        let envelope = signed_bytes(event, "replication event")?;
        let replication_event_sha256 = sha256_hex(&envelope);
        let mut transaction = begin(&self.pool, tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_apply_replication_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17, $18
            )"#,
        )
        .bind(tenant.as_str())
        .bind(replication_event_sha256)
        .bind(body.source_authority.label())
        .bind(checked_i64(body.authority_epoch, "authority epoch")?)
        .bind(checked_i64(body.sequence, "replication sequence")?)
        .bind(body.event_kind.aggregate_kind().label())
        .bind(&body.aggregate_id)
        .bind(checked_nonnegative_i64(
            body.expected_revision,
            "replication revision",
        )?)
        .bind(body.expected_event_sha256.as_deref())
        .bind(&body.event_id)
        .bind(body.event_kind.event_kind())
        .bind(body.event_kind.artifact_schema())
        .bind(&payload_sha256)
        .bind(domain_event.payload_json())
        .bind(domain_event_sha256)
        .bind(event.signer_key.to_hex())
        .bind(envelope)
        .bind(checked_i64(body.committed_at, "replication time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn apply_principal_replication_event(
        &self,
        tenant: &HostedTenantId,
        expected_source_signer: &PublicKey,
        expected_principal_signer: &PublicKey,
        event: &SignedHostedPrincipalReplicationEvent,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_source_signer,
            event,
            HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA,
            &event.body.schema,
        )?;
        let body = &event.body;
        if body.source_authority != HostedMarketAuthority::Sqlite
            || body.authority_epoch == 0
            || body.sequence == 0
            || body.committed_at == 0
            || body.committed_at != body.lifecycle_event.body.created_at
        {
            return Err(HostedMarketStoreError::Invalid(
                "principal replication event",
            ));
        }
        let principal_envelope = super::auth::validate_principal_lifecycle_event(
            tenant,
            expected_principal_signer,
            &body.lifecycle_event,
        )?;
        let principal_event_sha256 = sha256_hex(&principal_envelope);
        let replication_envelope = signed_bytes(event, "principal replication event")?;
        let replication_event_sha256 = sha256_hex(&replication_envelope);
        let lifecycle = &body.lifecycle_event.body;
        let mut transaction = begin(&self.pool, tenant).await?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_apply_principal_replication_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17
            )"#,
        )
        .bind(tenant.as_str())
        .bind(replication_event_sha256)
        .bind(body.source_authority.label())
        .bind(checked_i64(body.authority_epoch, "authority epoch")?)
        .bind(checked_i64(body.sequence, "replication sequence")?)
        .bind(principal_event_sha256)
        .bind(&lifecycle.principal_id)
        .bind(lifecycle.operation.as_str())
        .bind(lifecycle.role.as_str())
        .bind(lifecycle.capability_public_key_hex.as_deref())
        .bind(
            lifecycle
                .overlap_expires_at
                .map(|value| checked_i64(value, "principal key overlap"))
                .transpose()?,
        )
        .bind(lifecycle.previous_event_sha256.as_deref())
        .bind(body.lifecycle_event.signer_key.to_hex())
        .bind(principal_envelope)
        .bind(event.signer_key.to_hex())
        .bind(replication_envelope)
        .bind(checked_i64(body.committed_at, "replication time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn append_replication_check(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        check: &SignedHostedReplicationCheck,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            check,
            HOSTED_REPLICATION_CHECK_SCHEMA,
            &check.body.schema,
        )?;
        let body = &check.body;
        for digest in [
            body.source_projection_sha256.as_str(),
            body.target_projection_sha256.as_str(),
        ] {
            validate_digest(digest, "replication projection")?;
        }
        if body.authority_epoch == 0 || body.checked_at == 0 {
            return Err(HostedMarketStoreError::Invalid("replication check"));
        }
        let mut transaction = begin(&self.pool, tenant).await?;
        let state = load_authority_state(&mut transaction, tenant).await?;
        let expected_sequence = match body.source_authority {
            HostedMarketAuthority::Sqlite => state.last_replication_sequence,
            HostedMarketAuthority::Postgres => state.last_outbox_sequence,
        };
        if state.authority_epoch != body.authority_epoch
            || expected_sequence != body.through_sequence
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        let postgres_projection_sha256 = projection_sha256(&mut transaction, tenant).await?;
        let recorded_postgres_sha256 = match body.source_authority {
            HostedMarketAuthority::Sqlite => &body.target_projection_sha256,
            HostedMarketAuthority::Postgres => &body.source_projection_sha256,
        };
        if recorded_postgres_sha256 != &postgres_projection_sha256 {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
        let envelope = signed_bytes(check, "replication check")?;
        let check_sha256 = sha256_hex(&envelope);
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_replication_check(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            )"#,
        )
        .bind(tenant.as_str())
        .bind(&check_sha256)
        .bind(body.source_authority.label())
        .bind(checked_i64(body.authority_epoch, "authority epoch")?)
        .bind(checked_nonnegative_i64(
            body.through_sequence,
            "replication sequence",
        )?)
        .bind(&body.source_projection_sha256)
        .bind(&body.target_projection_sha256)
        .bind(checked_nonnegative_i64(
            body.lag_seconds,
            "replication lag",
        )?)
        .bind(checked_nonnegative_i64(
            body.projection_difference_count,
            "projection differences",
        )?)
        .bind(checked_nonnegative_i64(
            body.security_counter_count,
            "security counters",
        )?)
        .bind(check.signer_key.to_hex())
        .bind(&envelope)
        .bind(checked_i64(body.checked_at, "replication check time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub async fn pending_rollback_outbox(
        &self,
        tenant: &HostedTenantId,
        authority_epoch: u64,
        after_sequence: u64,
        limit: u16,
    ) -> Result<Vec<HostedRollbackOutboxRecord>, HostedMarketStoreError> {
        if authority_epoch == 0 || limit == 0 || limit > 1_000 {
            return Err(HostedMarketStoreError::Invalid("rollback outbox cursor"));
        }
        let mut transaction = begin(&self.pool, tenant).await?;
        let state = load_authority_state(&mut transaction, tenant).await?;
        if state.authority != HostedMarketAuthority::Postgres
            || state.mode != HostedAuthorityMode::RollbackWindow
            || state.authority_epoch != authority_epoch
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        let rows = sqlx::query(
            r#"SELECT sequence, aggregate_kind, aggregate_id, expected_revision,
                      expected_event_sha256, event_id, event_kind, artifact_schema,
                      payload_sha256, payload_json, event_sha256, committed_at
               FROM chio_finding_market_replication_outbox
               WHERE tenant_id = $1 AND authority_epoch = $2 AND sequence > $3
               ORDER BY sequence
               LIMIT $4"#,
        )
        .bind(tenant.as_str())
        .bind(checked_i64(authority_epoch, "authority epoch")?)
        .bind(checked_nonnegative_i64(after_sequence, "outbox cursor")?)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let payload_sha256: String = row.try_get(8).map_err(unavailable)?;
            let payload_json: Vec<u8> = row.try_get(9).map_err(unavailable)?;
            let event_sha256: String = row.try_get(10).map_err(unavailable)?;
            if sha256_hex(&payload_json) != payload_sha256 {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            validate_digest(&event_sha256, "outbox event")?;
            records.push(HostedRollbackOutboxRecord {
                tenant_id: tenant.as_str().to_owned(),
                authority_epoch,
                sequence: stored_u64(row.try_get(0).map_err(unavailable)?)?,
                aggregate_kind: row.try_get(1).map_err(unavailable)?,
                aggregate_id: row.try_get(2).map_err(unavailable)?,
                expected_revision: stored_u64(row.try_get(3).map_err(unavailable)?)?,
                expected_event_sha256: row.try_get(4).map_err(unavailable)?,
                event_id: row.try_get(5).map_err(unavailable)?,
                event_kind: row.try_get(6).map_err(unavailable)?,
                artifact_schema: row.try_get(7).map_err(unavailable)?,
                payload_sha256,
                payload_json,
                event_sha256,
                committed_at: stored_u64(row.try_get(11).map_err(unavailable)?)?,
            });
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(records)
    }

    pub async fn pending_rollback_batch(
        &self,
        tenant: &HostedTenantId,
        authority_epoch: u64,
        after_sequence: u64,
        limit: u16,
    ) -> Result<Vec<HostedRollbackOutboxEntry>, HostedMarketStoreError> {
        if authority_epoch == 0 || limit == 0 || limit > 1_000 {
            return Err(HostedMarketStoreError::Invalid("rollback outbox cursor"));
        }
        let mut transaction = begin(&self.pool, tenant).await?;
        let state = load_authority_state(&mut transaction, tenant).await?;
        if state.authority != HostedMarketAuthority::Postgres
            || state.mode != HostedAuthorityMode::RollbackWindow
            || state.authority_epoch != authority_epoch
        {
            return Err(HostedMarketStoreError::Conflict);
        }
        let domain_rows = sqlx::query(
            r#"SELECT sequence, aggregate_kind, aggregate_id, expected_revision,
                      expected_event_sha256, event_id, event_kind, artifact_schema,
                      payload_sha256, payload_json, event_sha256, committed_at
               FROM chio_finding_market_replication_outbox
               WHERE tenant_id = $1 AND authority_epoch = $2 AND sequence > $3
               ORDER BY sequence
               LIMIT $4"#,
        )
        .bind(tenant.as_str())
        .bind(checked_i64(authority_epoch, "authority epoch")?)
        .bind(checked_nonnegative_i64(after_sequence, "outbox cursor")?)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let principal_rows = sqlx::query(
            r#"SELECT sequence, principal_event_sha256, principal_id, operation,
                      role, capability_public_key_hex, overlap_expires_at,
                      previous_event_sha256, signer_key_hex,
                      event_envelope_json, committed_at
               FROM chio_finding_market_principal_replication_outbox
               WHERE tenant_id = $1 AND authority_epoch = $2 AND sequence > $3
               ORDER BY sequence
               LIMIT $4"#,
        )
        .bind(tenant.as_str())
        .bind(checked_i64(authority_epoch, "authority epoch")?)
        .bind(checked_nonnegative_i64(after_sequence, "outbox cursor")?)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let mut entries = Vec::with_capacity(domain_rows.len() + principal_rows.len());
        for row in domain_rows {
            let payload_sha256: String = row.try_get(8).map_err(unavailable)?;
            let payload_json: Vec<u8> = row.try_get(9).map_err(unavailable)?;
            let event_sha256: String = row.try_get(10).map_err(unavailable)?;
            if sha256_hex(&payload_json) != payload_sha256 {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            validate_digest(&event_sha256, "outbox event")?;
            entries.push(HostedRollbackOutboxEntry::Domain(
                HostedRollbackOutboxRecord {
                    tenant_id: tenant.as_str().to_owned(),
                    authority_epoch,
                    sequence: stored_u64(row.try_get(0).map_err(unavailable)?)?,
                    aggregate_kind: row.try_get(1).map_err(unavailable)?,
                    aggregate_id: row.try_get(2).map_err(unavailable)?,
                    expected_revision: stored_u64(row.try_get(3).map_err(unavailable)?)?,
                    expected_event_sha256: row.try_get(4).map_err(unavailable)?,
                    event_id: row.try_get(5).map_err(unavailable)?,
                    event_kind: row.try_get(6).map_err(unavailable)?,
                    artifact_schema: row.try_get(7).map_err(unavailable)?,
                    payload_sha256,
                    payload_json,
                    event_sha256,
                    committed_at: stored_u64(row.try_get(11).map_err(unavailable)?)?,
                },
            ));
        }
        for row in principal_rows {
            entries.push(HostedRollbackOutboxEntry::Principal(
                principal_rollback_record(tenant, authority_epoch, &row)?,
            ));
        }
        entries.sort_unstable_by_key(HostedRollbackOutboxEntry::sequence);
        entries.truncate(usize::from(limit));
        transaction.commit().await.map_err(unavailable)?;
        Ok(entries)
    }

    pub async fn target_projection_sha256(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<String, HostedMarketStoreError> {
        let mut transaction = begin(&self.pool, tenant).await?;
        let digest = projection_sha256(&mut transaction, tenant).await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(digest)
    }

    pub async fn authority_state(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<HostedAuthorityState, HostedMarketStoreError> {
        let mut transaction = begin(&self.pool, tenant).await?;
        let state = load_authority_state(&mut transaction, tenant).await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(state)
    }

    pub async fn apply_authority_transition(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        transition: &SignedHostedAuthorityTransition,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_signer,
            transition,
            HOSTED_AUTHORITY_TRANSITION_SCHEMA,
            &transition.body.schema,
        )?;
        let body = &transition.body;
        if body.from_epoch == 0
            || body.to_epoch != body.from_epoch.saturating_add(1)
            || body.created_at == 0
        {
            return Err(HostedMarketStoreError::Invalid("authority transition"));
        }
        validate_identifier(&body.configuration_revision, 256)
            .map_err(|()| HostedMarketStoreError::Invalid("configuration revision"))?;
        validate_digest(&body.source_checkpoint_sha256, "source checkpoint")?;
        validate_digest(&body.target_checkpoint_sha256, "target checkpoint")?;
        if body.source_checkpoint_sha256 != body.target_checkpoint_sha256 {
            return Err(HostedMarketStoreError::Conflict);
        }
        match body.operation {
            HostedAuthorityTransitionOperation::Cutover
                if body.from_authority != HostedMarketAuthority::Sqlite
                    || body.to_authority != HostedMarketAuthority::Postgres
                    || body.rollback_window_ends_at != body.created_at.checked_add(604_800) =>
            {
                return Err(HostedMarketStoreError::Invalid("authority cutover"));
            }
            HostedAuthorityTransitionOperation::Rollback
                if body.from_authority != HostedMarketAuthority::Postgres
                    || body.to_authority != HostedMarketAuthority::Sqlite
                    || body.rollback_window_ends_at.is_some() =>
            {
                return Err(HostedMarketStoreError::Invalid("authority rollback"));
            }
            HostedAuthorityTransitionOperation::Freeze
            | HostedAuthorityTransitionOperation::RetireSqlite
                if body.from_authority != body.to_authority
                    || body.rollback_window_ends_at.is_some() =>
            {
                return Err(HostedMarketStoreError::Invalid("authority transition"));
            }
            _ => {}
        }
        let envelope = signed_bytes(transition, "authority transition")?;
        let transition_sha256 = sha256_hex(&envelope);
        let mut transaction = begin(&self.pool, tenant).await?;
        let target_projection_sha256 = projection_sha256(&mut transaction, tenant).await?;
        if body.target_checkpoint_sha256 != target_projection_sha256 {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_apply_authority_transition(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15
            )"#,
        )
        .bind(tenant.as_str())
        .bind(transition_sha256)
        .bind(body.operation.label())
        .bind(body.from_authority.label())
        .bind(body.to_authority.label())
        .bind(checked_i64(body.from_epoch, "authority epoch")?)
        .bind(checked_i64(body.to_epoch, "authority epoch")?)
        .bind(checked_nonnegative_i64(
            body.through_sequence,
            "replication sequence",
        )?)
        .bind(&body.source_checkpoint_sha256)
        .bind(&body.target_checkpoint_sha256)
        .bind(&body.configuration_revision)
        .bind(
            body.rollback_window_ends_at
                .map(|value| checked_i64(value, "rollback window"))
                .transpose()?,
        )
        .bind(transition.signer_key.to_hex())
        .bind(envelope)
        .bind(checked_i64(body.created_at, "authority transition time")?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => return Err(HostedMarketStoreError::Conflict),
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }
}

fn principal_rollback_record(
    tenant: &HostedTenantId,
    authority_epoch: u64,
    row: &PgRow,
) -> Result<HostedPrincipalRollbackOutboxRecord, HostedMarketStoreError> {
    let principal_event_sha256: String = row.try_get(1).map_err(unavailable)?;
    let principal_id: String = row.try_get(2).map_err(unavailable)?;
    let operation = super::HostedPrincipalLifecycleOperation::parse(
        &row.try_get::<String, _>(3).map_err(unavailable)?,
    )?;
    let role = row
        .try_get::<String, _>(4)
        .map_err(unavailable)?
        .parse::<super::HostedPrincipalRole>()
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let capability_public_key_hex: Option<String> = row.try_get(5).map_err(unavailable)?;
    let overlap_expires_at = row
        .try_get::<Option<i64>, _>(6)
        .map_err(unavailable)?
        .map(stored_u64)
        .transpose()?;
    let previous_event_sha256: Option<String> = row.try_get(7).map_err(unavailable)?;
    let signer_key_hex: String = row.try_get(8).map_err(unavailable)?;
    let event_envelope_json: Vec<u8> = row.try_get(9).map_err(unavailable)?;
    let committed_at = stored_u64(row.try_get(10).map_err(unavailable)?)?;
    validate_digest(&principal_event_sha256, "principal outbox event")?;
    if let Some(previous) = previous_event_sha256.as_deref() {
        validate_digest(previous, "principal outbox predecessor")?;
    }
    let envelope: SignedHostedPrincipalLifecycleEvent =
        serde_json::from_slice(&event_envelope_json)
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    let canonical =
        canonical_json_bytes(&envelope).map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    if canonical != event_envelope_json
        || sha256_hex(&canonical) != principal_event_sha256
        || envelope.signer_key.to_hex() != signer_key_hex
        || envelope.body.tenant_id != tenant.as_str()
        || envelope.body.principal_id != principal_id
        || envelope.body.operation != operation
        || envelope.body.role != role
        || envelope.body.capability_public_key_hex != capability_public_key_hex
        || envelope.body.overlap_expires_at != overlap_expires_at
        || envelope.body.previous_event_sha256 != previous_event_sha256
        || envelope.body.created_at != committed_at
    {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    super::auth::validate_principal_lifecycle_event(tenant, &envelope.signer_key, &envelope)
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    Ok(HostedPrincipalRollbackOutboxRecord {
        tenant_id: tenant.as_str().to_owned(),
        authority_epoch,
        sequence: stored_u64(row.try_get(0).map_err(unavailable)?)?,
        principal_event_sha256,
        principal_id,
        operation,
        role,
        capability_public_key_hex,
        overlap_expires_at,
        previous_event_sha256,
        signer_key_hex,
        event_envelope_json,
        committed_at,
    })
}

async fn projection_sha256(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
) -> Result<String, HostedMarketStoreError> {
    let rows = sqlx::query(
        r#"SELECT aggregate_kind, aggregate_id, revision, event_sha256,
                  event_kind, artifact_schema, payload_sha256, payload_json
           FROM chio_finding_market_domain_projections
           WHERE tenant_id = $1
           ORDER BY aggregate_kind, aggregate_id"#,
    )
    .bind(tenant.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let mut domain = Vec::with_capacity(rows.len());
    for row in rows {
        let payload_sha256: String = row.try_get(6).map_err(unavailable)?;
        let payload_json: Vec<u8> = row.try_get(7).map_err(unavailable)?;
        if sha256_hex(&payload_json) != payload_sha256 {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
        domain.push(HostedProjectionCommitmentEntry {
            aggregate_kind: row.try_get(0).map_err(unavailable)?,
            aggregate_id: row.try_get(1).map_err(unavailable)?,
            revision: stored_u64(row.try_get(2).map_err(unavailable)?)?,
            event_sha256: row.try_get(3).map_err(unavailable)?,
            event_kind: row.try_get(4).map_err(unavailable)?,
            artifact_schema: row.try_get(5).map_err(unavailable)?,
            payload_sha256,
        });
    }
    let principal_rows = sqlx::query(
        r#"SELECT principal.principal_id, principal.role,
                  principal.capability_public_key_hex, principal.enabled,
                  lifecycle.event_sha256
           FROM chio_finding_market_principals AS principal
           JOIN LATERAL (
               SELECT event_sha256
               FROM chio_finding_market_principal_events AS event
               WHERE event.tenant_id = principal.tenant_id
                 AND event.principal_id = principal.principal_id
               ORDER BY event.created_at DESC, event.event_sha256 DESC
               LIMIT 1
           ) AS lifecycle ON TRUE
           WHERE principal.tenant_id = $1
           ORDER BY principal.principal_id"#,
    )
    .bind(tenant.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let mut principals = Vec::with_capacity(principal_rows.len());
    for row in principal_rows {
        let lifecycle_event_sha256: String = row.try_get(4).map_err(unavailable)?;
        validate_digest(&lifecycle_event_sha256, "principal projection event")?;
        principals.push(HostedPrincipalProjectionCommitmentEntry {
            principal_id: row.try_get(0).map_err(unavailable)?,
            role: row.try_get(1).map_err(unavailable)?,
            capability_public_key_hex: row.try_get(2).map_err(unavailable)?,
            enabled: row.try_get(3).map_err(unavailable)?,
            lifecycle_event_sha256,
        });
    }
    let principal_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_principals WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if usize::try_from(principal_count).ok() != Some(principals.len()) {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    let overlap_rows = sqlx::query(
        r#"SELECT principal_id, capability_public_key_hex, valid_through
           FROM chio_finding_market_principal_key_overlaps
           WHERE tenant_id = $1
           ORDER BY principal_id, capability_public_key_hex, valid_through,
                    lifecycle_event_sha256"#,
    )
    .bind(tenant.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let mut principal_key_overlaps = Vec::with_capacity(overlap_rows.len());
    for row in overlap_rows {
        principal_key_overlaps.push(HostedPrincipalKeyOverlapCommitmentEntry {
            principal_id: row.try_get(0).map_err(unavailable)?,
            capability_public_key_hex: row.try_get(1).map_err(unavailable)?,
            valid_through: stored_u64(row.try_get(2).map_err(unavailable)?)?,
        });
    }
    let commitment = HostedProjectionCommitment {
        schema: "chio.finding.hosted-projection-commitment.v1",
        domain,
        principals,
        principal_key_overlaps,
    };
    let bytes = canonical_json_bytes(&commitment)
        .map_err(|_| HostedMarketStoreError::Invalid("projection commitment"))?;
    Ok(sha256_hex(&bytes))
}

impl PostgresFindingMarketStore {
    pub async fn authority_state(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<HostedAuthorityState, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let state = load_authority_state(&mut transaction, tenant).await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(state)
    }
}

async fn begin<'a>(
    pool: &'a PgPool,
    tenant: &HostedTenantId,
) -> Result<Transaction<'a, Postgres>, HostedMarketStoreError> {
    let mut transaction = pool.begin().await.map_err(unavailable)?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
    let enabled: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM chio_finding_market_tenants WHERE tenant_id = $1")
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

async fn load_authority_state(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
) -> Result<HostedAuthorityState, HostedMarketStoreError> {
    let row = sqlx::query(
        r#"SELECT authority, authority_epoch, mode, mutations_enabled,
                  last_replication_sequence, last_outbox_sequence, rollback_window_ends_at,
                  configuration_revision, transition_sha256, updated_at
           FROM chio_finding_market_authority_state WHERE tenant_id = $1"#,
    )
    .bind(tenant.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::NotFound)?;
    let transition_sha256: Option<String> = row.try_get(8).map_err(unavailable)?;
    if let Some(digest) = transition_sha256.as_deref() {
        validate_digest(digest, "authority transition")
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    }
    Ok(HostedAuthorityState {
        tenant_id: tenant.clone(),
        authority: HostedMarketAuthority::parse(
            &row.try_get::<String, _>(0).map_err(unavailable)?,
        )?,
        authority_epoch: stored_u64(row.try_get(1).map_err(unavailable)?)?,
        mode: HostedAuthorityMode::parse(&row.try_get::<String, _>(2).map_err(unavailable)?)?,
        mutations_enabled: row.try_get(3).map_err(unavailable)?,
        last_replication_sequence: stored_u64(row.try_get(4).map_err(unavailable)?)?,
        last_outbox_sequence: stored_u64(row.try_get(5).map_err(unavailable)?)?,
        rollback_window_ends_at: row
            .try_get::<Option<i64>, _>(6)
            .map_err(unavailable)?
            .map(stored_u64)
            .transpose()?,
        configuration_revision: row.try_get(7).map_err(unavailable)?,
        transition_sha256,
        updated_at: stored_u64(row.try_get(9).map_err(unavailable)?)?,
    })
}

pub(crate) fn validate_signed<T: Serialize + Clone>(
    tenant: &HostedTenantId,
    expected_signer: &PublicKey,
    envelope: &SignedExportEnvelope<T>,
    expected_schema: &str,
    actual_schema: &str,
) -> Result<(), HostedMarketStoreError> {
    if actual_schema != expected_schema
        || envelope.signer_key != *expected_signer
        || expected_signer.is_weak_ed25519()
        || !matches!(envelope.verify_signature(), Ok(true))
    {
        return Err(HostedMarketStoreError::Invalid(
            "signed replication artifact",
        ));
    }
    let body = serde_json::to_value(&envelope.body)
        .map_err(|_| HostedMarketStoreError::Invalid("signed replication artifact"))?;
    if body.get("tenantId").and_then(serde_json::Value::as_str) != Some(tenant.as_str()) {
        return Err(HostedMarketStoreError::Tenant);
    }
    Ok(())
}

fn signed_bytes<T: Serialize + Clone>(
    envelope: &SignedExportEnvelope<T>,
    field: &'static str,
) -> Result<Vec<u8>, HostedMarketStoreError> {
    let bytes =
        canonical_json_bytes(envelope).map_err(|_| HostedMarketStoreError::Invalid(field))?;
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    Ok(bytes)
}
