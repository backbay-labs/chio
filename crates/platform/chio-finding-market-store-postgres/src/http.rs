use std::collections::BTreeSet;

use async_trait::async_trait;
use chio_core_types::canonical_json_bytes;
use chio_finding_market_port::{
    HostedDomainMutation, HostedHttpPage, HostedHttpProjection, HostedMarketBackend,
    HostedMarketBackendError, HostedMarketBackendOutcome,
};

use crate::{
    HostedJobWriteOutcome, HostedMarketDomainEvent, HostedMarketDomainEventKind,
    HostedMarketDomainProjection, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};

#[async_trait]
impl HostedMarketBackend for PostgresFindingMarketStore {
    async fn ready(&self) -> Result<(), HostedMarketBackendError> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(|_| HostedMarketBackendError::Unavailable)
    }

    async fn append(
        &self,
        tenant: &HostedTenantId,
        event_kind: &str,
        aggregate_kind: &str,
        mutation: &HostedDomainMutation,
        committed_at: u64,
    ) -> Result<HostedMarketBackendOutcome, HostedMarketBackendError> {
        let event_kind = HostedMarketDomainEventKind::from_event_kind(event_kind)
            .ok_or(HostedMarketBackendError::Invalid)?;
        if event_kind.aggregate_kind().label() != aggregate_kind {
            return Err(HostedMarketBackendError::Invalid);
        }
        let payload_json = canonical_json_bytes(&mutation.payload)
            .map_err(|_| HostedMarketBackendError::Invalid)?;
        let event = HostedMarketDomainEvent::from_canonical_payload(
            event_kind,
            &mutation.aggregate_id,
            &mutation.event_id,
            payload_json,
            mutation.artifact_signer_key.as_ref(),
            mutation.artifact_authority_id.as_deref(),
        )
        .map_err(map_store_error)?;
        self.append_domain_event(
            tenant,
            &event,
            mutation.expected_revision,
            mutation.expected_event_sha256.as_deref(),
            committed_at,
        )
        .await
        .map(map_outcome)
        .map_err(map_store_error)
    }

    async fn finding(
        &self,
        tenant: &HostedTenantId,
        finding_id: &str,
    ) -> Result<Option<HostedHttpProjection>, HostedMarketBackendError> {
        self.domain_projection(
            tenant,
            HostedMarketDomainEventKind::FindingPublished,
            finding_id,
        )
        .await
        .map_err(map_store_error)?
        .map(http_projection)
        .transpose()
    }

    async fn findings(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedHttpPage, HostedMarketBackendError> {
        let page = self
            .catalog_findings(tenant, after, limit)
            .await
            .map_err(map_store_error)?;
        let items = page
            .items
            .into_iter()
            .map(http_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(HostedHttpPage {
            items,
            next_cursor: page.next_cursor,
        })
    }

    async fn non_live_findings(
        &self,
        tenant: &HostedTenantId,
        finding_ids: &[String],
    ) -> Result<BTreeSet<String>, HostedMarketBackendError> {
        self.catalog_non_live_finding_ids(tenant, finding_ids)
            .await
            .map_err(map_store_error)
    }
}

fn map_outcome(outcome: HostedJobWriteOutcome) -> HostedMarketBackendOutcome {
    match outcome {
        HostedJobWriteOutcome::Inserted => HostedMarketBackendOutcome::Inserted,
        HostedJobWriteOutcome::ExactReplay => HostedMarketBackendOutcome::ExactReplay,
    }
}

fn http_projection(
    projection: HostedMarketDomainProjection,
) -> Result<HostedHttpProjection, HostedMarketBackendError> {
    let payload = serde_json::from_slice(&projection.payload_json)
        .map_err(|_| HostedMarketBackendError::Integrity)?;
    Ok(HostedHttpProjection {
        event_kind: projection.event_kind.event_kind().to_owned(),
        aggregate_kind: projection.event_kind.aggregate_kind().label().to_owned(),
        aggregate_id: projection.aggregate_id,
        event_id: projection.event_id,
        revision: projection.revision,
        previous_event_sha256: projection.previous_event_sha256,
        event_sha256: projection.event_sha256,
        artifact_schema: projection.event_kind.artifact_schema().to_owned(),
        artifact_sha256: projection.payload_sha256,
        payload,
        committed_at: projection.committed_at,
    })
}

fn map_store_error(error: HostedMarketStoreError) -> HostedMarketBackendError {
    match error {
        HostedMarketStoreError::Invalid(_)
        | HostedMarketStoreError::Tenant
        | HostedMarketStoreError::TenantNotFound
        | HostedMarketStoreError::TenantDisabled => HostedMarketBackendError::Invalid,
        HostedMarketStoreError::NotFound => HostedMarketBackendError::NotFound,
        HostedMarketStoreError::Conflict | HostedMarketStoreError::LeaseLost => {
            HostedMarketBackendError::Conflict
        }
        HostedMarketStoreError::Capacity => HostedMarketBackendError::Capacity,
        HostedMarketStoreError::DigestMismatch
        | HostedMarketStoreError::Decode(_)
        | HostedMarketStoreError::MigrationDrift
        | HostedMarketStoreError::RetentionHeld => HostedMarketBackendError::Integrity,
        HostedMarketStoreError::Configuration | HostedMarketStoreError::Unavailable => {
            HostedMarketBackendError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_never_leak_database_details() {
        assert_eq!(
            map_store_error(HostedMarketStoreError::MigrationDrift),
            HostedMarketBackendError::Integrity
        );
        assert_eq!(
            map_store_error(HostedMarketStoreError::Unavailable),
            HostedMarketBackendError::Unavailable
        );
    }
}
