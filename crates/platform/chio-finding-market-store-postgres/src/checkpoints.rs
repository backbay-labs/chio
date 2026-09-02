use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use super::{
    checked_i64, stored_u64, unavailable, validate_digest, validate_identifier,
    HostedAggregateKind, HostedJobWriteOutcome, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};

pub const HOSTED_AGGREGATE_CHECKPOINT_SCHEMA: &str = "chio.finding.hosted.aggregate-checkpoint.v1";
const CHECKPOINT_LOCK_DOMAIN: &str = "chio.finding.hosted.checkpoint-lock.v1";
const MAX_CHECKPOINT_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
const MAX_AGGREGATE_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedAggregateCheckpointBody {
    pub schema: String,
    pub tenant_id: String,
    pub aggregate_kind: HostedAggregateKind,
    pub aggregate_id: String,
    pub revision: u64,
    pub event_sha256: String,
    pub previous_checkpoint_sha256: Option<String>,
    pub created_at: u64,
}

pub type SignedHostedAggregateCheckpoint = SignedExportEnvelope<HostedAggregateCheckpointBody>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAggregateCheckpointRecord {
    pub checkpoint_sha256: String,
    pub checkpoint: SignedHostedAggregateCheckpoint,
}

impl PostgresFindingMarketStore {
    pub async fn append_aggregate_checkpoint(
        &self,
        tenant: &HostedTenantId,
        expected_signer: &PublicKey,
        checkpoint: &SignedHostedAggregateCheckpoint,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        validate_checkpoint(tenant, expected_signer, checkpoint)?;
        let envelope_json = canonical_json_bytes(checkpoint)
            .map_err(|_| HostedMarketStoreError::Invalid("aggregate checkpoint"))?;
        if envelope_json.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
            return Err(HostedMarketStoreError::Invalid("aggregate checkpoint"));
        }
        let checkpoint_sha256 = sha256_hex(&envelope_json);
        let body = &checkpoint.body;
        let revision = checked_i64(body.revision, "aggregate checkpoint revision")?;
        let created_at = checked_i64(body.created_at, "aggregate checkpoint time")?;
        let lock_key = canonical_json_bytes(&(
            CHECKPOINT_LOCK_DOMAIN,
            tenant.as_str(),
            body.aggregate_kind.label(),
            body.aggregate_id.as_str(),
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| HostedMarketStoreError::Invalid("aggregate checkpoint lock"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 6))")
            .bind(lock_key)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;

        let replay: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT checkpoint_envelope_json FROM chio_finding_market_aggregate_checkpoints WHERE tenant_id = $1 AND checkpoint_sha256 = $2",
        )
        .bind(tenant.as_str())
        .bind(&checkpoint_sha256)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(retained) = replay {
            if retained != envelope_json {
                return Err(HostedMarketStoreError::Conflict);
            }
            transaction.commit().await.map_err(unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }

        let previous = sqlx::query(
            r#"SELECT revision, checkpoint_sha256
               FROM chio_finding_market_aggregate_checkpoints
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3
               ORDER BY revision DESC LIMIT 1"#,
        )
        .bind(tenant.as_str())
        .bind(body.aggregate_kind.label())
        .bind(&body.aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        match previous {
            Some(row) => {
                let previous_revision = stored_u64(row.try_get(0).map_err(unavailable)?)?;
                let previous_sha256: String = row.try_get(1).map_err(unavailable)?;
                if body.revision <= previous_revision
                    || body.previous_checkpoint_sha256.as_deref() != Some(previous_sha256.as_str())
                {
                    return Err(HostedMarketStoreError::Conflict);
                }
            }
            None if body.previous_checkpoint_sha256.is_none() => {}
            None => return Err(HostedMarketStoreError::Conflict),
        }
        let event_matches: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                SELECT 1 FROM chio_finding_market_aggregate_events
                WHERE tenant_id = $1 AND aggregate_kind = $2
                  AND aggregate_id = $3 AND revision = $4 AND event_sha256 = $5
            )"#,
        )
        .bind(tenant.as_str())
        .bind(body.aggregate_kind.label())
        .bind(&body.aggregate_id)
        .bind(revision)
        .bind(&body.event_sha256)
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if !event_matches {
            return Err(HostedMarketStoreError::Conflict);
        }
        sqlx::query(
            r#"INSERT INTO chio_finding_market_aggregate_checkpoints (
                tenant_id, checkpoint_sha256, aggregate_kind, aggregate_id,
                revision, event_sha256, previous_checkpoint_sha256,
                signer_key_hex, checkpoint_envelope_json, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(tenant.as_str())
        .bind(&checkpoint_sha256)
        .bind(body.aggregate_kind.label())
        .bind(&body.aggregate_id)
        .bind(revision)
        .bind(&body.event_sha256)
        .bind(body.previous_checkpoint_sha256.as_deref())
        .bind(checkpoint.signer_key.to_hex())
        .bind(&envelope_json)
        .bind(created_at)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(HostedJobWriteOutcome::Inserted)
    }

    pub async fn latest_aggregate_checkpoint(
        &self,
        tenant: &HostedTenantId,
        aggregate_kind: HostedAggregateKind,
        aggregate_id: &str,
        expected_signer: &PublicKey,
    ) -> Result<Option<HostedAggregateCheckpointRecord>, HostedMarketStoreError> {
        validate_identifier(aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            r#"SELECT checkpoint_sha256, checkpoint_envelope_json
               FROM chio_finding_market_aggregate_checkpoints
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3
               ORDER BY revision DESC LIMIT 1"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| {
            let checkpoint_sha256: String = row.try_get(0).map_err(unavailable)?;
            let envelope_json: Vec<u8> = row.try_get(1).map_err(unavailable)?;
            validate_digest(&checkpoint_sha256, "durable aggregate checkpoint")
                .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
            if sha256_hex(&envelope_json) != checkpoint_sha256 {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            let checkpoint: SignedHostedAggregateCheckpoint =
                serde_json::from_slice(&envelope_json)
                    .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
            if canonical_json_bytes(&checkpoint).ok().as_deref() != Some(envelope_json.as_slice())
                || checkpoint.body.aggregate_kind != aggregate_kind
                || checkpoint.body.aggregate_id != aggregate_id
            {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            validate_checkpoint(tenant, expected_signer, &checkpoint)
                .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
            Ok(HostedAggregateCheckpointRecord {
                checkpoint_sha256,
                checkpoint,
            })
        })
        .transpose()
    }
}

fn validate_checkpoint(
    tenant: &HostedTenantId,
    expected_signer: &PublicKey,
    checkpoint: &SignedHostedAggregateCheckpoint,
) -> Result<(), HostedMarketStoreError> {
    let body = &checkpoint.body;
    if body.schema != HOSTED_AGGREGATE_CHECKPOINT_SCHEMA
        || body.tenant_id != tenant.as_str()
        || checkpoint.signer_key != *expected_signer
        || expected_signer.is_weak_ed25519()
        || !matches!(checkpoint.verify_signature(), Ok(true))
        || body.revision == 0
        || body.created_at == 0
    {
        return Err(HostedMarketStoreError::Invalid("aggregate checkpoint"));
    }
    validate_identifier(&body.aggregate_id, MAX_AGGREGATE_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::Invalid("aggregate checkpoint"))?;
    validate_digest(&body.event_sha256, "aggregate checkpoint event")?;
    if let Some(previous) = body.previous_checkpoint_sha256.as_deref() {
        validate_digest(previous, "aggregate checkpoint predecessor")?;
    }
    Ok(())
}
