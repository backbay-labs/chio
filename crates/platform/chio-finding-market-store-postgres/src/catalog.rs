use std::collections::BTreeSet;

use chio_core_types::sha256_hex;
use chio_finding::{
    Finding, FindingEffectIntentKind, SignedFindingAdmission, SignedFindingChallengeEnforcement,
    SignedFindingMarketTerms, SignedFindingStatusEpoch, SignedFindingVerifiedFixSubmission,
    SignedFindingVoluntaryRetraction,
};
use sqlx::Row as _;

use crate::{
    aggregates::aggregate_event_digest, domain::validate_persisted_domain_payload, stored_u64,
    unavailable, validate_digest, validate_identifier, HostedJobWriteOutcome,
    HostedMarketDomainArtifact, HostedMarketDomainEvent, HostedMarketDomainEventKind,
    HostedMarketDomainProjection, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};

const MAX_CATALOG_PAGE: u32 = 100;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_AGGREGATE_ID_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedDomainPage {
    pub items: Vec<HostedMarketDomainProjection>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedDomainWrite {
    pub event_id: String,
    pub expected_revision: u64,
    pub expected_event_sha256: Option<String>,
    pub committed_at: u64,
}

impl HostedDomainWrite {
    pub fn new(
        event_id: impl Into<String>,
        expected_revision: u64,
        expected_event_sha256: Option<String>,
        committed_at: u64,
    ) -> Result<Self, HostedMarketStoreError> {
        let write = Self {
            event_id: event_id.into(),
            expected_revision,
            expected_event_sha256,
            committed_at,
        };
        validate_identifier(&write.event_id, MAX_EVENT_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("event_id"))?;
        if write.committed_at == 0
            || (write.expected_revision == 0 && write.expected_event_sha256.is_some())
            || (write.expected_revision > 0
                && write
                    .expected_event_sha256
                    .as_deref()
                    .is_none_or(|digest| validate_digest(digest, "expected event").is_err()))
        {
            return Err(HostedMarketStoreError::Invalid("domain write"));
        }
        Ok(write)
    }
}

impl PostgresFindingMarketStore {
    pub async fn catalog_findings(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::FindingPublished,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_listings(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::ListingActivated,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_admissions(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::AdmissionAdmitted,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_status_epochs(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::StatusPublished,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_verified_fixes(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::VerifiedFixSubmitted,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_retractions(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::RetractionVoluntary,
            after,
            limit,
        )
        .await
    }

    /// Resolve non-live Findings for one bounded catalog page. Sticky
    /// voluntary and enforcement-pending retractions suppress their exact
    /// Finding. A status epoch is only a signed sparse-map root, so this
    /// PostgreSQL journal cannot derive per-Finding liveness without a
    /// retained sparse proof. Once any epoch exists, the whole requested page
    /// therefore fails closed until a proof-aware catalog backend is wired.
    /// Every returned retraction row is revalidated against its signed
    /// artifact and append-only event digest.
    pub async fn catalog_non_live_finding_ids(
        &self,
        tenant: &HostedTenantId,
        finding_ids: &[String],
    ) -> Result<BTreeSet<String>, HostedMarketStoreError> {
        if finding_ids.is_empty() {
            return Ok(BTreeSet::new());
        }
        if finding_ids.len() > MAX_CATALOG_PAGE as usize {
            return Err(HostedMarketStoreError::Invalid("status query limit"));
        }
        let requested = finding_ids.iter().collect::<BTreeSet<_>>();
        if requested.len() != finding_ids.len()
            || finding_ids
                .iter()
                .any(|finding_id| validate_identifier(finding_id, MAX_AGGREGATE_ID_BYTES).is_err())
        {
            return Err(HostedMarketStoreError::Invalid("status query"));
        }
        let maximum_rows = finding_ids
            .len()
            .checked_mul(2)
            .ok_or(HostedMarketStoreError::Invalid("status query limit"))?;
        let fetch_limit = i64::try_from(maximum_rows)
            .map_err(|_| HostedMarketStoreError::Invalid("status query limit"))?
            .checked_add(1)
            .ok_or(HostedMarketStoreError::Invalid("status query limit"))?;
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let has_status_epoch: bool = sqlx::query_scalar(
            r#"SELECT EXISTS (
                   SELECT 1
                   FROM chio_finding_market_domain_projections
                   WHERE tenant_id = $1 AND aggregate_kind = 'status_epoch'
               )"#,
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if has_status_epoch {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(finding_ids.iter().cloned().collect());
        }
        let rows = sqlx::query(
            r#"SELECT DISTINCT ON (
                         projection.subject_finding_id,
                         projection.aggregate_kind
                     )
                      projection.aggregate_id, projection.revision,
                      projection.event_sha256, projection.event_kind,
                      projection.artifact_schema, projection.payload_sha256,
                      projection.payload_json, projection.updated_at,
                      event.event_id, event.previous_event_sha256,
                      event.committed_at
               FROM chio_finding_market_domain_projections AS projection
               JOIN chio_finding_market_aggregate_events AS event
                 ON event.tenant_id = projection.tenant_id
                AND event.aggregate_kind = projection.aggregate_kind
                AND event.aggregate_id = projection.aggregate_id
                AND event.revision = projection.revision
                AND event.event_sha256 = projection.event_sha256
               WHERE projection.tenant_id = $1
                 AND projection.aggregate_kind IN ('retraction', 'enforcement')
                 AND projection.subject_finding_id = ANY($2::TEXT[])
               ORDER BY projection.subject_finding_id ASC,
                        projection.aggregate_kind ASC,
                        projection.aggregate_id ASC
               LIMIT $3"#,
        )
        .bind(tenant.as_str())
        .bind(finding_ids.to_vec())
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        if rows.len() > maximum_rows {
            return Err(HostedMarketStoreError::DigestMismatch);
        }
        let mut retracted = BTreeSet::new();
        for row in &rows {
            let stored_event_kind: String = row.try_get(3).map_err(unavailable)?;
            let event_kind = HostedMarketDomainEventKind::from_event_kind(&stored_event_kind)
                .filter(|kind| {
                    matches!(
                        kind,
                        HostedMarketDomainEventKind::RetractionVoluntary
                            | HostedMarketDomainEventKind::EnforcementFinalized
                    )
                })
                .ok_or(HostedMarketStoreError::DigestMismatch)?;
            let projection = projection_from_catalog_row(tenant, event_kind, row)?;
            if projection.revision != 1 || projection.previous_event_sha256.is_some() {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            let finding_id = match event_kind {
                HostedMarketDomainEventKind::RetractionVoluntary => {
                    let artifact: SignedFindingVoluntaryRetraction =
                        serde_json::from_slice(&projection.payload_json)
                            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
                    artifact.body.finding_id
                }
                HostedMarketDomainEventKind::EnforcementFinalized => {
                    let artifact: SignedFindingChallengeEnforcement =
                        serde_json::from_slice(&projection.payload_json)
                            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
                    if !artifact
                        .body
                        .effect_intents
                        .iter()
                        .any(|intent| intent.kind == FindingEffectIntentKind::Retraction)
                    {
                        return Err(HostedMarketStoreError::DigestMismatch);
                    }
                    artifact.body.finding_id
                }
                _ => return Err(HostedMarketStoreError::DigestMismatch),
            };
            if !requested.contains(&finding_id) {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            retracted.insert(finding_id);
        }
        Ok(retracted)
    }

    pub async fn list_domain_projections(
        &self,
        tenant: &HostedTenantId,
        event_kind: HostedMarketDomainEventKind,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        if limit == 0 || limit > MAX_CATALOG_PAGE {
            return Err(HostedMarketStoreError::Invalid("catalog limit"));
        }
        if let Some(after) = after {
            validate_identifier(after, MAX_AGGREGATE_ID_BYTES)
                .map_err(|()| HostedMarketStoreError::Invalid("catalog cursor"))?;
        }
        let fetch_limit = i64::from(limit) + 1;
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let rows = sqlx::query(
            r#"SELECT projection.aggregate_id, projection.revision,
                      projection.event_sha256, projection.event_kind,
                      projection.artifact_schema, projection.payload_sha256,
                      projection.payload_json, projection.updated_at,
                      event.event_id, event.previous_event_sha256,
                      event.committed_at
               FROM chio_finding_market_domain_projections AS projection
               JOIN chio_finding_market_aggregate_events AS event
                 ON event.tenant_id = projection.tenant_id
                AND event.aggregate_kind = projection.aggregate_kind
                AND event.aggregate_id = projection.aggregate_id
                AND event.revision = projection.revision
                AND event.event_sha256 = projection.event_sha256
               WHERE projection.tenant_id = $1
                 AND projection.aggregate_kind = $2
                 AND ($3::TEXT IS NULL OR projection.aggregate_id > $3)
               ORDER BY projection.aggregate_id ASC
               LIMIT $4"#,
        )
        .bind(tenant.as_str())
        .bind(event_kind.aggregate_kind().label())
        .bind(after)
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;

        let has_more = rows.len() > limit as usize;
        let mut items = rows
            .iter()
            .take(limit as usize)
            .map(|row| projection_from_catalog_row(tenant, event_kind, row))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            items.last().map(|item| item.aggregate_id.clone())
        } else {
            None
        };
        items.shrink_to_fit();
        Ok(HostedDomainPage { items, next_cursor })
    }

    pub async fn publish_finding(
        &self,
        tenant: &HostedTenantId,
        artifact: &Finding,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.finding_id,
            &HostedMarketDomainArtifact::Finding(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn activate_listing(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingMarketTerms,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.listing_id,
            &HostedMarketDomainArtifact::MarketTerms(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn admit_finding(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingAdmission,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.admission_id,
            &HostedMarketDomainArtifact::Admission(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn publish_status_epoch(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingStatusEpoch,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.status_epoch_id,
            &HostedMarketDomainArtifact::StatusEpoch(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn submit_verified_fix(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingVerifiedFixSubmission,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.submission_id,
            &HostedMarketDomainArtifact::VerifiedFix(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn record_voluntary_retraction(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingVoluntaryRetraction,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.intent_id,
            &HostedMarketDomainArtifact::Retraction(artifact.clone()),
            write,
        )
        .await
    }

    pub(crate) async fn append_typed_artifact(
        &self,
        tenant: &HostedTenantId,
        aggregate_id: &str,
        artifact: &HostedMarketDomainArtifact,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let event =
            HostedMarketDomainEvent::from_artifact(aggregate_id, &write.event_id, artifact)?;
        self.append_domain_event(
            tenant,
            &event,
            write.expected_revision,
            write.expected_event_sha256.as_deref(),
            write.committed_at,
        )
        .await
    }
}

fn projection_from_catalog_row(
    tenant: &HostedTenantId,
    event_kind: HostedMarketDomainEventKind,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedMarketDomainProjection, HostedMarketStoreError> {
    let aggregate_id: String = row.try_get(0).map_err(unavailable)?;
    let revision = stored_u64(row.try_get(1).map_err(unavailable)?)?;
    let event_sha256: String = row.try_get(2).map_err(unavailable)?;
    let stored_event_kind: String = row.try_get(3).map_err(unavailable)?;
    let stored_schema: String = row.try_get(4).map_err(unavailable)?;
    let payload_sha256: String = row.try_get(5).map_err(unavailable)?;
    let payload_json: Vec<u8> = row.try_get(6).map_err(unavailable)?;
    let event_id: String = row.try_get(8).map_err(unavailable)?;
    let previous_event_sha256: Option<String> = row.try_get(9).map_err(unavailable)?;
    let committed_at = stored_u64(row.try_get(10).map_err(unavailable)?)?;
    validate_identifier(&aggregate_id, MAX_AGGREGATE_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    validate_digest(&event_sha256, "catalog event")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    validate_digest(&payload_sha256, "catalog payload")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    validate_identifier(&event_id, MAX_EVENT_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    if let Some(previous) = previous_event_sha256.as_deref() {
        validate_digest(previous, "catalog predecessor")
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    }
    if revision == 0
        || stored_event_kind != event_kind.event_kind()
        || stored_schema != event_kind.artifact_schema()
        || sha256_hex(&payload_json) != payload_sha256
    {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    let expected_event_sha256 = aggregate_event_digest(
        tenant,
        event_kind.aggregate_kind(),
        &aggregate_id,
        revision,
        &event_id,
        event_kind.event_kind(),
        previous_event_sha256.as_deref(),
        &payload_sha256,
        committed_at,
    )?;
    if expected_event_sha256 != event_sha256 {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    validate_persisted_domain_payload(event_kind, &aggregate_id, &payload_json)?;
    Ok(HostedMarketDomainProjection {
        tenant_id: tenant.clone(),
        event_kind,
        aggregate_id,
        revision,
        event_id,
        previous_event_sha256,
        event_sha256,
        payload_sha256,
        payload_json,
        committed_at,
        updated_at: stored_u64(row.try_get(7).map_err(unavailable)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_expectation_requires_a_coherent_head() {
        assert!(HostedDomainWrite::new("event-a", 0, None, 1).is_ok());
        assert!(HostedDomainWrite::new("event-a", 0, Some("a".repeat(64)), 1).is_err());
        assert!(HostedDomainWrite::new("event-a", 1, None, 1).is_err());
        assert!(HostedDomainWrite::new("event-a", 1, Some("a".repeat(64)), 1).is_ok());
    }
}
