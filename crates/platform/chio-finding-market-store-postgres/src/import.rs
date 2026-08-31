use std::collections::BTreeMap;

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{
    replication::validate_signed, HostedJobWriteOutcome, HostedMarketAuthority,
    HostedMarketStoreError, HostedTenantId, PostgresFindingMarketReplicator,
    SignedHostedPrincipalReplicationEvent, SignedHostedReplicationEvent,
};

pub const HOSTED_SQLITE_IMPORT_BATCH_SCHEMA: &str = "chio.finding.hosted-sqlite-import-batch.v1";
const MAX_IMPORT_BATCH: usize = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "entry_kind", content = "event")]
pub enum HostedSqliteImportEntry {
    Domain(SignedHostedReplicationEvent),
    Principal(SignedHostedPrincipalReplicationEvent),
}

impl HostedSqliteImportEntry {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Domain(event) => event.body.sequence,
            Self::Principal(event) => event.body.sequence,
        }
    }

    fn tenant_id(&self) -> &str {
        match self {
            Self::Domain(event) => &event.body.tenant_id,
            Self::Principal(event) => &event.body.tenant_id,
        }
    }

    const fn authority_epoch(&self) -> u64 {
        match self {
            Self::Domain(event) => event.body.authority_epoch,
            Self::Principal(event) => event.body.authority_epoch,
        }
    }

    const fn source_authority(&self) -> HostedMarketAuthority {
        match self {
            Self::Domain(event) => event.body.source_authority,
            Self::Principal(event) => event.body.source_authority,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedSqliteImportBatchBody {
    pub schema: String,
    pub tenant_id: String,
    pub authority_epoch: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub source_projection_sha256: String,
    pub entries: Vec<HostedSqliteImportEntry>,
    pub exported_at: u64,
}

pub type SignedHostedSqliteImportBatch = SignedExportEnvelope<HostedSqliteImportBatchBody>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedSqliteImportOutcome {
    pub inserted: u64,
    pub exact_replays: u64,
    pub through_sequence: u64,
    pub target_projection_sha256: String,
}

impl HostedSqliteImportBatchBody {
    fn validate(&self, tenant: &HostedTenantId) -> Result<(), HostedMarketStoreError> {
        if self.schema != HOSTED_SQLITE_IMPORT_BATCH_SCHEMA
            || self.tenant_id != tenant.as_str()
            || self.authority_epoch == 0
            || self.first_sequence == 0
            || self.exported_at == 0
            || self.entries.is_empty()
            || self.entries.len() > MAX_IMPORT_BATCH
        {
            return Err(HostedMarketStoreError::Invalid("SQLite import batch"));
        }
        crate::validate_digest(&self.source_projection_sha256, "SQLite projection")?;
        let mut expected_sequence = self.first_sequence;
        for entry in &self.entries {
            if entry.tenant_id() != self.tenant_id
                || entry.authority_epoch() != self.authority_epoch
                || entry.source_authority() != HostedMarketAuthority::Sqlite
                || entry.sequence() != expected_sequence
            {
                return Err(HostedMarketStoreError::Invalid("SQLite import sequence"));
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(HostedMarketStoreError::Invalid("SQLite import sequence"))?;
        }
        if expected_sequence.checked_sub(1) != Some(self.last_sequence) {
            return Err(HostedMarketStoreError::Invalid("SQLite import sequence"));
        }
        Ok(())
    }
}

impl PostgresFindingMarketReplicator {
    /// Import one signed, contiguous source batch. The operation is safely
    /// resumable because each contained event has its own exact-replay fence.
    /// A source/target projection mismatch leaves PostgreSQL in shadow mode
    /// and blocks the caller from constructing a valid cutover transition.
    pub async fn apply_sqlite_import_batch(
        &self,
        tenant: &HostedTenantId,
        expected_source_signer: &PublicKey,
        principal_authorities: &BTreeMap<String, PublicKey>,
        batch: &SignedHostedSqliteImportBatch,
    ) -> Result<HostedSqliteImportOutcome, HostedMarketStoreError> {
        validate_signed(
            tenant,
            expected_source_signer,
            batch,
            HOSTED_SQLITE_IMPORT_BATCH_SCHEMA,
            &batch.body.schema,
        )?;
        batch.body.validate(tenant)?;

        let mut inserted = 0_u64;
        let mut exact_replays = 0_u64;
        for entry in &batch.body.entries {
            let outcome = match entry {
                HostedSqliteImportEntry::Domain(event) => {
                    self.apply_replication_event(tenant, expected_source_signer, event)
                        .await?
                }
                HostedSqliteImportEntry::Principal(event) => {
                    let expected_principal_signer = principal_authorities
                        .get(&event.body.lifecycle_event.body.principal_id)
                        .ok_or(HostedMarketStoreError::Invalid("principal authority"))?;
                    self.apply_principal_replication_event(
                        tenant,
                        expected_source_signer,
                        expected_principal_signer,
                        event,
                    )
                    .await?
                }
            };
            match outcome {
                HostedJobWriteOutcome::Inserted => inserted = inserted.saturating_add(1),
                HostedJobWriteOutcome::ExactReplay => {
                    exact_replays = exact_replays.saturating_add(1);
                }
            }
        }

        let target_projection_sha256 = self.target_projection_sha256(tenant).await?;
        if target_projection_sha256 != batch.body.source_projection_sha256 {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
        Ok(HostedSqliteImportOutcome {
            inserted,
            exact_replays,
            through_sequence: batch.body.last_sequence,
            target_projection_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use chio_core_types::crypto::Keypair;

    use super::*;
    use crate::{
        HostedMarketDomainEventKind, HostedReplicationEventBody, HOSTED_REPLICATION_EVENT_SCHEMA,
    };

    fn signed_domain_entry(
        tenant: &HostedTenantId,
        sequence: u64,
        source: &Keypair,
    ) -> HostedSqliteImportEntry {
        HostedSqliteImportEntry::Domain(
            SignedExportEnvelope::sign(
                HostedReplicationEventBody {
                    schema: HOSTED_REPLICATION_EVENT_SCHEMA.to_owned(),
                    tenant_id: tenant.as_str().to_owned(),
                    source_authority: HostedMarketAuthority::Sqlite,
                    authority_epoch: 1,
                    sequence,
                    event_kind: HostedMarketDomainEventKind::FindingPublished,
                    aggregate_id: "a".repeat(64),
                    event_id: format!("import-{sequence}"),
                    expected_revision: 0,
                    expected_event_sha256: None,
                    artifact_signer_key: Some(source.public_key()),
                    payload: serde_json::json!({"invalid": true}),
                    committed_at: 1_700_000_000,
                },
                source,
            )
            .unwrap_or_else(|error| panic!("test envelope failed: {error}")),
        )
    }

    #[test]
    fn import_batch_requires_a_contiguous_closed_sequence() {
        let tenant = HostedTenantId::new("tenant:import")
            .unwrap_or_else(|error| panic!("test tenant failed: {error}"));
        let source = Keypair::from_seed(&[33_u8; 32]);
        let mut body = HostedSqliteImportBatchBody {
            schema: HOSTED_SQLITE_IMPORT_BATCH_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            authority_epoch: 1,
            first_sequence: 1,
            last_sequence: 2,
            source_projection_sha256: "a".repeat(64),
            entries: vec![
                signed_domain_entry(&tenant, 1, &source),
                signed_domain_entry(&tenant, 2, &source),
            ],
            exported_at: 1_700_000_001,
        };
        assert!(body.validate(&tenant).is_ok());
        body.entries.swap(0, 1);
        assert!(body.validate(&tenant).is_err());
        body.entries.swap(0, 1);
        body.last_sequence = 3;
        assert!(body.validate(&tenant).is_err());
    }
}
