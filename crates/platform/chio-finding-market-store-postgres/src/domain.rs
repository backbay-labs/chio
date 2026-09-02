use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::metadata::{FindingDelivery, FINDING_DELIVERY_METADATA_KEY};
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    Finding, FindingReplayRecipeInput, SignedFindingAdmission, SignedFindingAuditReport,
    SignedFindingBondBacking, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingChallengeOutcome, SignedFindingChallengeVerifierProfile,
    SignedFindingClaimAllocation, SignedFindingFailedDelivery, SignedFindingLiability,
    SignedFindingMarketTerms, SignedFindingPurchaseRecord, SignedFindingPurchaseResult,
    SignedFindingStatusEpoch, SignedFindingVerifiedFixSubmission, SignedFindingVoluntaryRetraction,
};
use chio_finding_market_port::{
    HostedAuthenticatedFindingDelivery, HostedMarketDomainEventKind,
    HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
};
use chio_open_market::penalty::SignedOpenMarketPenalty;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row as _, Transaction};

use super::{
    aggregates::aggregate_event_digest, checked_i64, checked_nonnegative_i64, stored_u64,
    unavailable, validate_canonical_json, validate_digest, validate_identifier,
    HostedAggregateKind, HostedJobWriteOutcome, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};

const MAX_AGGREGATE_ID_BYTES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SETTLEMENT_TEXT_BYTES: usize = 512;
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedCommerceSettlementStatus {
    Dispatched,
    Reconciled,
    Settled,
}

/// Closed unsigned commerce packet. Authenticity is carried by its bound
/// dispatch and reconciliation receipt references; hosted authorization is
/// responsible for resolving those references before append.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedCommerceSettlementPacket {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub order_id: String,
    pub merchant_subject: String,
    pub psp: String,
    pub payment_intent_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub quote_sha256: String,
    pub settlement_rail: String,
    pub settlement_account_ref: String,
    pub dispatch_receipt_ref: String,
    pub reconciliation_ref: String,
    pub status: HostedCommerceSettlementStatus,
}

impl HostedCommerceSettlementPacket {
    fn validate(&self) -> Result<(), HostedMarketStoreError> {
        if self.schema != "chio.commerce.settlement-packet.v1"
            || self.amount_minor == 0
            || self.amount_minor > MAX_I_JSON_INTEGER
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(HostedMarketStoreError::Invalid("settlement packet"));
        }
        for value in [
            self.id.as_str(),
            self.issued_at.as_str(),
            self.order_id.as_str(),
            self.merchant_subject.as_str(),
            self.psp.as_str(),
            self.payment_intent_id.as_str(),
            self.settlement_rail.as_str(),
            self.settlement_account_ref.as_str(),
            self.dispatch_receipt_ref.as_str(),
            self.reconciliation_ref.as_str(),
        ] {
            if value.is_empty()
                || value.len() > MAX_SETTLEMENT_TEXT_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(HostedMarketStoreError::Invalid("settlement packet"));
            }
        }
        validate_digest(&self.quote_sha256, "settlement quote")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedMarketDomainEvent {
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: String,
    event_id: String,
    payload_json: Vec<u8>,
    expected_signer: Option<PublicKey>,
    expected_authority_id: Option<String>,
}

#[derive(Clone, Debug)]
pub enum HostedMarketDomainArtifact {
    Finding(Finding),
    ReplayRecipe(FindingReplayRecipeInput),
    VerifierProfile(SignedFindingChallengeVerifierProfile),
    BondBacking(SignedFindingBondBacking),
    MarketTerms(SignedFindingMarketTerms),
    Admission(SignedFindingAdmission),
    Participation(SignedFindingClaimAllocation),
    Purchase(SignedFindingPurchaseRecord),
    Reveal(SignedFindingPurchaseResult),
    Delivery(HostedAuthenticatedFindingDelivery),
    PurchaseSettlement(SignedFindingPurchaseResult),
    FailedDelivery(SignedFindingFailedDelivery),
    Challenge(SignedFindingChallenge),
    ChallengeOutcome(SignedFindingChallengeOutcome),
    VerifiedFix(SignedFindingVerifiedFixSubmission),
    Retraction(SignedFindingVoluntaryRetraction),
    Liability(SignedFindingLiability),
    Appeal(SignedFindingChallengeEnforcement),
    Penalty(SignedOpenMarketPenalty),
    Enforcement(SignedFindingChallengeEnforcement),
    Settlement(HostedCommerceSettlementPacket),
    StatusEpoch(SignedFindingStatusEpoch),
    AuditReport(SignedFindingAuditReport),
}

impl HostedMarketDomainEvent {
    /// Build an event whose signer is self-contained in a validated artifact.
    /// Delivery receipts and penalties require an external tenant or authority
    /// pin and must use their dedicated store operations instead.
    pub fn from_artifact(
        aggregate_id: impl Into<String>,
        event_id: impl Into<String>,
        artifact: &HostedMarketDomainArtifact,
    ) -> Result<Self, HostedMarketStoreError> {
        if matches!(
            artifact,
            HostedMarketDomainArtifact::Delivery(_) | HostedMarketDomainArtifact::Penalty(_)
        ) {
            return Err(HostedMarketStoreError::Invalid("domain artifact authority"));
        }
        let payload_json = artifact.canonical_payload()?;
        Self::from_canonical_payload(
            artifact.event_kind(),
            aggregate_id,
            event_id,
            payload_json,
            artifact.signer(),
            None,
        )
    }

    /// Construct a validated event from canonical bytes received through a
    /// store-neutral edge. The typed artifact, signer, schema, aggregate
    /// identity, and canonical representation are all revalidated here.
    pub fn from_canonical_payload(
        event_kind: HostedMarketDomainEventKind,
        aggregate_id: impl Into<String>,
        event_id: impl Into<String>,
        payload_json: Vec<u8>,
        expected_signer: Option<&PublicKey>,
        expected_authority_id: Option<&str>,
    ) -> Result<Self, HostedMarketStoreError> {
        let event = Self {
            event_kind,
            aggregate_id: aggregate_id.into(),
            event_id: event_id.into(),
            payload_json,
            expected_signer: expected_signer.cloned(),
            expected_authority_id: expected_authority_id.map(str::to_owned),
        };
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<(), HostedMarketStoreError> {
        validate_identifier(&self.aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        validate_identifier(&self.event_id, MAX_EVENT_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("event_id"))?;
        validate_canonical_json(&self.payload_json, "domain payload")?;
        if self.payload_json.len() > MAX_PAYLOAD_BYTES {
            return Err(HostedMarketStoreError::Invalid("domain payload"));
        }
        validate_domain_payload(
            self.event_kind,
            &self.aggregate_id,
            &self.payload_json,
            self.expected_signer.as_ref(),
            self.expected_authority_id.as_deref(),
        )
    }

    pub(crate) fn payload_json(&self) -> &[u8] {
        &self.payload_json
    }
}

impl HostedMarketDomainArtifact {
    fn event_kind(&self) -> HostedMarketDomainEventKind {
        match self {
            Self::Finding(_) => HostedMarketDomainEventKind::FindingPublished,
            Self::ReplayRecipe(_) => HostedMarketDomainEventKind::RecipeRegistered,
            Self::VerifierProfile(_) => HostedMarketDomainEventKind::ProfileRegistered,
            Self::BondBacking(_) => HostedMarketDomainEventKind::CollateralRegistered,
            Self::MarketTerms(_) => HostedMarketDomainEventKind::ListingActivated,
            Self::Admission(_) => HostedMarketDomainEventKind::AdmissionAdmitted,
            Self::Participation(_) => HostedMarketDomainEventKind::ParticipationAdmitted,
            Self::Purchase(_) => HostedMarketDomainEventKind::PurchaseAuthorized,
            Self::Reveal(_) => HostedMarketDomainEventKind::RevealCommitted,
            Self::Delivery(_) => HostedMarketDomainEventKind::DeliveryAccepted,
            Self::PurchaseSettlement(_) => HostedMarketDomainEventKind::PurchaseSettled,
            Self::FailedDelivery(_) => HostedMarketDomainEventKind::DeliveryFailed,
            Self::Challenge(_) => HostedMarketDomainEventKind::ChallengeSubmitted,
            Self::ChallengeOutcome(_) => HostedMarketDomainEventKind::ChallengeFinalized,
            Self::VerifiedFix(_) => HostedMarketDomainEventKind::VerifiedFixSubmitted,
            Self::Retraction(_) => HostedMarketDomainEventKind::RetractionVoluntary,
            Self::Liability(_) => HostedMarketDomainEventKind::LiabilityAssessed,
            Self::Appeal(_) => HostedMarketDomainEventKind::AppealFinalized,
            Self::Penalty(_) => HostedMarketDomainEventKind::PenaltyAssessed,
            Self::Enforcement(_) => HostedMarketDomainEventKind::EnforcementFinalized,
            Self::Settlement(_) => HostedMarketDomainEventKind::SettlementTerminal,
            Self::StatusEpoch(_) => HostedMarketDomainEventKind::StatusPublished,
            Self::AuditReport(_) => HostedMarketDomainEventKind::AuditFinalized,
        }
    }

    fn signer(&self) -> Option<&PublicKey> {
        match self {
            Self::Finding(finding) => Some(&finding.issuer),
            Self::ReplayRecipe(_) => None,
            Self::Delivery(artifact) => Some(&artifact.receipt.kernel_key),
            Self::VerifierProfile(envelope) => Some(&envelope.signer_key),
            Self::BondBacking(envelope) => Some(&envelope.signer_key),
            Self::MarketTerms(envelope) => Some(&envelope.signer_key),
            Self::Admission(envelope) => Some(&envelope.signer_key),
            Self::Participation(envelope) => Some(&envelope.signer_key),
            Self::Purchase(envelope) => Some(&envelope.signer_key),
            Self::Reveal(envelope) | Self::PurchaseSettlement(envelope) => {
                Some(&envelope.signer_key)
            }
            Self::FailedDelivery(envelope) => Some(&envelope.signer_key),
            Self::Challenge(envelope) => Some(&envelope.signer_key),
            Self::ChallengeOutcome(envelope) => Some(&envelope.signer_key),
            Self::VerifiedFix(envelope) => Some(&envelope.signer_key),
            Self::Retraction(envelope) => Some(&envelope.signer_key),
            Self::Liability(envelope) => Some(&envelope.signer_key),
            Self::Appeal(envelope) | Self::Enforcement(envelope) => Some(&envelope.signer_key),
            Self::Penalty(envelope) => Some(&envelope.signer_key),
            Self::Settlement(_) => None,
            Self::StatusEpoch(envelope) => Some(&envelope.signer_key),
            Self::AuditReport(envelope) => Some(&envelope.signer_key),
        }
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, HostedMarketStoreError> {
        let bytes = match self {
            Self::Finding(artifact) => canonical_json_bytes(artifact),
            Self::ReplayRecipe(artifact) => canonical_json_bytes(artifact),
            Self::VerifierProfile(artifact) => canonical_json_bytes(artifact),
            Self::BondBacking(artifact) => canonical_json_bytes(artifact),
            Self::MarketTerms(artifact) => canonical_json_bytes(artifact),
            Self::Admission(artifact) => canonical_json_bytes(artifact),
            Self::Participation(artifact) => canonical_json_bytes(artifact),
            Self::Purchase(artifact) => canonical_json_bytes(artifact),
            Self::Reveal(artifact) => canonical_json_bytes(artifact),
            Self::Delivery(artifact) => canonical_json_bytes(artifact),
            Self::PurchaseSettlement(artifact) => canonical_json_bytes(artifact),
            Self::FailedDelivery(artifact) => canonical_json_bytes(artifact),
            Self::Challenge(artifact) => canonical_json_bytes(artifact),
            Self::ChallengeOutcome(artifact) => canonical_json_bytes(artifact),
            Self::VerifiedFix(artifact) => canonical_json_bytes(artifact),
            Self::Retraction(artifact) => canonical_json_bytes(artifact),
            Self::Liability(artifact) => canonical_json_bytes(artifact),
            Self::Appeal(artifact) | Self::Enforcement(artifact) => canonical_json_bytes(artifact),
            Self::Penalty(artifact) => canonical_json_bytes(artifact),
            Self::Settlement(artifact) => canonical_json_bytes(artifact),
            Self::StatusEpoch(artifact) => canonical_json_bytes(artifact),
            Self::AuditReport(artifact) => canonical_json_bytes(artifact),
        };
        bytes.map_err(|_| HostedMarketStoreError::Invalid("domain artifact"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedMarketDomainProjection {
    pub tenant_id: HostedTenantId,
    pub event_kind: HostedMarketDomainEventKind,
    pub aggregate_id: String,
    pub revision: u64,
    pub event_id: String,
    pub previous_event_sha256: Option<String>,
    pub event_sha256: String,
    pub payload_sha256: String,
    pub payload_json: Vec<u8>,
    pub committed_at: u64,
    pub updated_at: u64,
}

impl PostgresFindingMarketStore {
    pub async fn append_domain_event(
        &self,
        tenant: &HostedTenantId,
        event: &HostedMarketDomainEvent,
        expected_revision: u64,
        expected_event_sha256: Option<&str>,
        committed_at: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        let mut transaction = self.begin_tenant(tenant).await?;
        let outcome = self
            .append_domain_event_in_transaction(
                &mut transaction,
                tenant,
                event,
                expected_revision,
                expected_event_sha256,
                committed_at,
            )
            .await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub(crate) async fn append_domain_event_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &HostedTenantId,
        event: &HostedMarketDomainEvent,
        expected_revision: u64,
        expected_event_sha256: Option<&str>,
        committed_at: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        event.validate()?;
        validate_domain_tenant_binding(event, tenant)?;
        validate_retraction_finding_binding(transaction, tenant, event).await?;
        if expected_revision == 0 {
            if expected_event_sha256.is_some() {
                return Err(HostedMarketStoreError::Invalid("expected domain head"));
            }
        } else {
            validate_digest(
                expected_event_sha256
                    .ok_or(HostedMarketStoreError::Invalid("expected domain head"))?,
                "expected domain head",
            )?;
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(HostedMarketStoreError::Invalid("domain revision"))?;
        let payload_sha256 = sha256_hex(&event.payload_json);
        let aggregate_kind = event.event_kind.aggregate_kind();
        let event_sha256 = aggregate_event_digest(
            tenant,
            aggregate_kind,
            &event.aggregate_id,
            revision,
            &event.event_id,
            event.event_kind.event_kind(),
            expected_event_sha256,
            &payload_sha256,
            committed_at,
        )?;
        if let Some(exact) = retained_event_matches(
            transaction,
            tenant,
            aggregate_kind,
            event,
            revision,
            expected_event_sha256,
            &payload_sha256,
        )
        .await?
        {
            if !exact {
                return Err(HostedMarketStoreError::Conflict);
            }
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
        validate_fresh_domain_event(event, committed_at)?;
        let outcome: i16 = sqlx::query_scalar(
            r#"SELECT chio_finding_market_append_domain_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
            )"#,
        )
        .bind(tenant.as_str())
        .bind(aggregate_kind.label())
        .bind(&event.aggregate_id)
        .bind(checked_nonnegative_i64(
            expected_revision,
            "expected domain revision",
        )?)
        .bind(expected_event_sha256)
        .bind(&event.event_id)
        .bind(event.event_kind.event_kind())
        .bind(event.event_kind.artifact_schema())
        .bind(&payload_sha256)
        .bind(&event.payload_json)
        .bind(&event_sha256)
        .bind(checked_i64(committed_at, "domain event time")?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => {
                match retained_event_matches(
                    transaction,
                    tenant,
                    aggregate_kind,
                    event,
                    revision,
                    expected_event_sha256,
                    &payload_sha256,
                )
                .await?
                {
                    Some(true) => HostedJobWriteOutcome::ExactReplay,
                    Some(false) | None => return Err(HostedMarketStoreError::Conflict),
                }
            }
            _ => return Err(HostedMarketStoreError::Unavailable),
        };
        Ok(outcome)
    }

    pub async fn domain_projection(
        &self,
        tenant: &HostedTenantId,
        event_kind: HostedMarketDomainEventKind,
        aggregate_id: &str,
    ) -> Result<Option<HostedMarketDomainProjection>, HostedMarketStoreError> {
        validate_identifier(aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        let mut transaction = self.begin_tenant_snapshot(tenant).await?;
        let row = sqlx::query(
            r#"SELECT projection.revision, projection.event_sha256,
                      projection.event_kind, projection.artifact_schema,
                      projection.payload_sha256, projection.payload_json,
                      projection.updated_at, event.event_id,
                      event.previous_event_sha256, event.committed_at
               FROM chio_finding_market_domain_projections AS projection
               JOIN chio_finding_market_aggregate_events AS event
                 ON event.tenant_id = projection.tenant_id
                AND event.aggregate_kind = projection.aggregate_kind
                AND event.aggregate_id = projection.aggregate_id
                AND event.revision = projection.revision
                AND event.event_sha256 = projection.event_sha256
               WHERE projection.tenant_id = $1
                 AND projection.aggregate_kind = $2
                 AND projection.aggregate_id = $3"#,
        )
        .bind(tenant.as_str())
        .bind(event_kind.aggregate_kind().label())
        .bind(aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        row.map(|row| domain_projection_from_row(tenant, event_kind, aggregate_id, &row))
            .transpose()
    }
}

async fn validate_retraction_finding_binding(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    event: &HostedMarketDomainEvent,
) -> Result<(), HostedMarketStoreError> {
    let (finding_id, seller, status_feed_ref) = match event.event_kind {
        HostedMarketDomainEventKind::RetractionVoluntary => {
            let artifact: SignedFindingVoluntaryRetraction =
                parse_canonical(&event.payload_json, "voluntary retraction artifact")?;
            (
                artifact.body.finding_id,
                artifact.body.seller,
                artifact.body.status_feed_ref,
            )
        }
        _ => return Ok(()),
    };
    let row = sqlx::query(
        r#"SELECT projection.revision, projection.event_sha256,
                  projection.event_kind, projection.artifact_schema,
                  projection.payload_sha256, projection.payload_json,
                  projection.updated_at, event.event_id,
                  event.previous_event_sha256, event.committed_at
           FROM chio_finding_market_domain_projections AS projection
           JOIN chio_finding_market_aggregate_events AS event
             ON event.tenant_id = projection.tenant_id
            AND event.aggregate_kind = projection.aggregate_kind
            AND event.aggregate_id = projection.aggregate_id
            AND event.revision = projection.revision
            AND event.event_sha256 = projection.event_sha256
           WHERE projection.tenant_id = $1
             AND projection.aggregate_kind = 'finding'
             AND projection.aggregate_id = $2"#,
    )
    .bind(tenant.as_str())
    .bind(&finding_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let row = row.ok_or(HostedMarketStoreError::Invalid("subject finding binding"))?;
    let projection = domain_projection_from_row(
        tenant,
        HostedMarketDomainEventKind::FindingPublished,
        &finding_id,
        &row,
    )?;
    let finding: Finding = serde_json::from_slice(&projection.payload_json)
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    if finding.issuer != seller || finding.status_feed_ref != status_feed_ref {
        return Err(HostedMarketStoreError::Invalid("subject finding binding"));
    }
    Ok(())
}

fn domain_projection_from_row(
    tenant: &HostedTenantId,
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: &str,
    row: &sqlx::postgres::PgRow,
) -> Result<HostedMarketDomainProjection, HostedMarketStoreError> {
    let stored_event_kind: String = row.try_get(2).map_err(unavailable)?;
    let stored_schema: String = row.try_get(3).map_err(unavailable)?;
    let payload_sha256: String = row.try_get(4).map_err(unavailable)?;
    let payload_json: Vec<u8> = row.try_get(5).map_err(unavailable)?;
    let revision = stored_u64(row.try_get(0).map_err(unavailable)?)?;
    let event_sha256: String = row.try_get(1).map_err(unavailable)?;
    let event_id: String = row.try_get(7).map_err(unavailable)?;
    let previous_event_sha256: Option<String> = row.try_get(8).map_err(unavailable)?;
    let committed_at = stored_u64(row.try_get(9).map_err(unavailable)?)?;
    if stored_event_kind != event_kind.event_kind()
        || stored_schema != event_kind.artifact_schema()
        || sha256_hex(&payload_json) != payload_sha256
        || revision == 0
    {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    validate_digest(&event_sha256, "domain projection event")
        .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    validate_identifier(&event_id, MAX_EVENT_ID_BYTES)
        .map_err(|()| HostedMarketStoreError::DigestMismatch)?;
    if let Some(previous) = previous_event_sha256.as_deref() {
        validate_digest(previous, "domain projection predecessor")
            .map_err(|_| HostedMarketStoreError::DigestMismatch)?;
    }
    let expected_event_sha256 = aggregate_event_digest(
        tenant,
        event_kind.aggregate_kind(),
        aggregate_id,
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
    validate_persisted_domain_payload(event_kind, aggregate_id, &payload_json)?;
    Ok(HostedMarketDomainProjection {
        tenant_id: tenant.clone(),
        event_kind,
        aggregate_id: aggregate_id.to_owned(),
        revision,
        event_id,
        previous_event_sha256,
        event_sha256,
        payload_sha256,
        payload_json,
        committed_at,
        updated_at: stored_u64(row.try_get(6).map_err(unavailable)?)?,
    })
}

#[allow(clippy::too_many_arguments)]
async fn retained_event_matches(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &HostedTenantId,
    aggregate_kind: HostedAggregateKind,
    event: &HostedMarketDomainEvent,
    revision: u64,
    expected_event_sha256: Option<&str>,
    payload_sha256: &str,
) -> Result<Option<bool>, HostedMarketStoreError> {
    let row = sqlx::query(
        r#"SELECT aggregate_kind, aggregate_id, revision, event_kind,
                  previous_event_sha256, payload_sha256, payload_json
           FROM chio_finding_market_aggregate_events
           WHERE tenant_id = $1 AND event_id = $2"#,
    )
    .bind(tenant.as_str())
    .bind(&event.event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let retained_kind: String = row.try_get("aggregate_kind").map_err(unavailable)?;
    let retained_id: String = row.try_get("aggregate_id").map_err(unavailable)?;
    let retained_revision: i64 = row.try_get("revision").map_err(unavailable)?;
    let retained_event_kind: String = row.try_get("event_kind").map_err(unavailable)?;
    let retained_previous: Option<String> =
        row.try_get("previous_event_sha256").map_err(unavailable)?;
    let retained_payload_sha256: String = row.try_get("payload_sha256").map_err(unavailable)?;
    let retained_payload: Vec<u8> = row.try_get("payload_json").map_err(unavailable)?;
    let expected_revision = checked_nonnegative_i64(revision, "domain revision")?;
    Ok(Some(
        retained_kind == aggregate_kind.label()
            && retained_id == event.aggregate_id
            && retained_revision == expected_revision
            && retained_event_kind == event.event_kind.event_kind()
            && retained_previous.as_deref() == expected_event_sha256
            && retained_payload_sha256 == payload_sha256
            && retained_payload == event.payload_json,
    ))
}

fn validate_fresh_domain_event(
    event: &HostedMarketDomainEvent,
    committed_at: u64,
) -> Result<(), HostedMarketStoreError> {
    if event.event_kind != HostedMarketDomainEventKind::FindingPublished {
        return Ok(());
    }
    let finding: Finding = parse_canonical(&event.payload_json, "finding artifact")?;
    if finding.issued_at > committed_at || finding.expires_at <= committed_at {
        return Err(HostedMarketStoreError::Invalid(
            "finding artifact freshness",
        ));
    }
    Ok(())
}

pub(crate) fn validate_persisted_domain_payload(
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: &str,
    payload_json: &[u8],
) -> Result<(), HostedMarketStoreError> {
    let signer = match event_kind {
        HostedMarketDomainEventKind::FindingPublished => {
            Some(parse_canonical::<Finding>(payload_json, "finding artifact")?.issuer)
        }
        HostedMarketDomainEventKind::RecipeRegistered
        | HostedMarketDomainEventKind::SettlementTerminal => None,
        HostedMarketDomainEventKind::DeliveryAccepted => Some(
            parse_canonical::<HostedAuthenticatedFindingDelivery>(
                payload_json,
                "authenticated delivery artifact",
            )?
            .receipt
            .kernel_key,
        ),
        _ => Some(
            parse_canonical::<SignedExportEnvelope<serde_json::Value>>(
                payload_json,
                "signed domain artifact",
            )?
            .signer_key,
        ),
    };
    let authority_id = if event_kind == HostedMarketDomainEventKind::PenaltyAssessed {
        Some(
            parse_canonical::<SignedOpenMarketPenalty>(payload_json, "market penalty artifact")?
                .body
                .issued_by,
        )
    } else {
        None
    };
    validate_domain_payload(
        event_kind,
        aggregate_id,
        payload_json,
        signer.as_ref(),
        authority_id.as_deref(),
    )
}

fn validate_domain_payload(
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: &str,
    payload_json: &[u8],
    expected_signer: Option<&PublicKey>,
    expected_authority_id: Option<&str>,
) -> Result<(), HostedMarketStoreError> {
    use chio_finding::{
        Finding, FindingAdmission, FindingAuditReport, FindingBondBacking, FindingChallenge,
        FindingChallengeEnforcement, FindingChallengeOutcome, FindingChallengeVerifierProfile,
        FindingClaimAllocation, FindingFailedDelivery, FindingLiability, FindingMarketTerms,
        FindingPurchaseRecord, FindingPurchaseResult, FindingReplayRecipeInput, FindingStatusEpoch,
        FindingVerifiedFixSubmission, FindingVoluntaryRetraction,
    };

    match event_kind {
        HostedMarketDomainEventKind::FindingPublished => {
            let signer = required_signer(expected_signer)?;
            let finding: Finding = parse_canonical(payload_json, "finding artifact")?;
            if finding.issuer != *signer {
                return Err(HostedMarketStoreError::Invalid("finding artifact signer"));
            }
            chio_finding::verify_finding(&finding)
                .map_err(|_| HostedMarketStoreError::Invalid("finding artifact"))?;
            require_aggregate_identity(aggregate_id, &finding.finding_id)
        }
        HostedMarketDomainEventKind::RecipeRegistered => {
            require_unsigned(expected_signer)?;
            let recipe: FindingReplayRecipeInput =
                parse_canonical(payload_json, "replay recipe artifact")?;
            recipe
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("replay recipe artifact"))?;
            let recipe_sha256 = recipe
                .canonical_sha256()
                .map_err(|_| HostedMarketStoreError::Invalid("replay recipe artifact"))?;
            require_aggregate_identity(aggregate_id, &recipe_sha256)
        }
        HostedMarketDomainEventKind::ProfileRegistered => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingChallengeVerifierProfile>(payload_json, signer)?;
            chio_finding::verify_signed_profile(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("verifier profile artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.profile_id)
        }
        HostedMarketDomainEventKind::CollateralRegistered => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingBondBacking>(payload_json, signer)?;
            chio_finding::verify_signed_bond_backing(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("bond backing artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.allocation_id)
        }
        HostedMarketDomainEventKind::ListingActivated => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingMarketTerms>(payload_json, signer)?;
            chio_finding::verify_signed_market_terms(&artifact)
                .map_err(|_| HostedMarketStoreError::Invalid("market terms artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.listing_id)
        }
        HostedMarketDomainEventKind::AdmissionAdmitted => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingAdmission>(payload_json, signer)?;
            let venue_id = artifact.body.venue_id.clone();
            chio_finding::verify_signed_admission(&artifact, signer, &venue_id)
                .map_err(|_| HostedMarketStoreError::Invalid("admission artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.admission_id)
        }
        HostedMarketDomainEventKind::ParticipationAdmitted => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingClaimAllocation>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("claim allocation artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.allocation_id)
        }
        HostedMarketDomainEventKind::PurchaseAuthorized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingPurchaseRecord>(payload_json, signer)?;
            chio_finding::verify_signed_purchase_record(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("purchase artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.purchase_key)
        }
        HostedMarketDomainEventKind::RevealCommitted
        | HostedMarketDomainEventKind::PurchaseSettled => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingPurchaseResult>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("purchase result artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.result_id)
        }
        HostedMarketDomainEventKind::DeliveryAccepted => {
            let signer = required_signer(expected_signer)?;
            let (_, delivery) = parse_authenticated_delivery(payload_json, signer)?;
            require_aggregate_identity(aggregate_id, &delivery.purchase_intent_id)
        }
        HostedMarketDomainEventKind::DeliveryFailed => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingFailedDelivery>(payload_json, signer)?;
            chio_finding::verify_signed_failed_delivery(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("failed delivery artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.failed_delivery_id)
        }
        HostedMarketDomainEventKind::ChallengeSubmitted => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingChallenge>(payload_json, signer)?;
            chio_finding::verify_signed_challenge(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("challenge artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.challenge_id)
        }
        HostedMarketDomainEventKind::ChallengeFinalized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingChallengeOutcome>(payload_json, signer)?;
            chio_finding::verify_signed_challenge_outcome(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("challenge outcome artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.outcome_id)
        }
        HostedMarketDomainEventKind::VerifiedFixSubmitted => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingVerifiedFixSubmission>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("verified fix artifact"))?;
            if artifact.body.seller != *signer {
                return Err(HostedMarketStoreError::Invalid(
                    "verified fix artifact signer",
                ));
            }
            require_aggregate_identity(aggregate_id, &artifact.body.submission_id)
        }
        HostedMarketDomainEventKind::RetractionVoluntary => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingVoluntaryRetraction>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("voluntary retraction artifact"))?;
            if artifact.body.seller != *signer {
                return Err(HostedMarketStoreError::Invalid(
                    "voluntary retraction artifact signer",
                ));
            }
            require_aggregate_identity(aggregate_id, &artifact.body.intent_id)
        }
        HostedMarketDomainEventKind::LiabilityAssessed => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingLiability>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("liability artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.liability_key)
        }
        HostedMarketDomainEventKind::AppealFinalized
        | HostedMarketDomainEventKind::EnforcementFinalized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingChallengeEnforcement>(payload_json, signer)?;
            chio_finding::verify_signed_challenge_enforcement(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("challenge enforcement artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.enforcement_id)
        }
        HostedMarketDomainEventKind::PenaltyAssessed => {
            let signer = required_signer(expected_signer)?;
            let authority_id = expected_authority_id
                .ok_or(HostedMarketStoreError::Invalid("market penalty authority"))?;
            let artifact = parse_signed::<chio_open_market::penalty::OpenMarketPenaltyArtifact>(
                payload_json,
                signer,
            )?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("market penalty artifact"))?;
            if artifact.body.issued_by != authority_id
                || artifact.body.governing_operator_id != authority_id
            {
                return Err(HostedMarketStoreError::Invalid("market penalty authority"));
            }
            require_aggregate_identity(aggregate_id, &artifact.body.penalty_id)
        }
        HostedMarketDomainEventKind::SettlementTerminal => {
            require_unsigned(expected_signer)?;
            let artifact: HostedCommerceSettlementPacket =
                parse_canonical(payload_json, "settlement packet artifact")?;
            artifact.validate()?;
            require_aggregate_identity(aggregate_id, &artifact.id)
        }
        HostedMarketDomainEventKind::StatusPublished => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingStatusEpoch>(payload_json, signer)?;
            if artifact.body.operator_key != *signer {
                return Err(HostedMarketStoreError::Invalid(
                    "status epoch artifact signer",
                ));
            }
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("status epoch artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.status_epoch_id)
        }
        HostedMarketDomainEventKind::AuditFinalized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingAuditReport>(payload_json, signer)?;
            chio_finding::verify_signed_audit_report(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("audit report artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.audit_report_id)
        }
    }
}

fn parse_authenticated_delivery(
    payload_json: &[u8],
    expected_kernel_key: &PublicKey,
) -> Result<(HostedAuthenticatedFindingDelivery, FindingDelivery), HostedMarketStoreError> {
    let artifact: HostedAuthenticatedFindingDelivery =
        parse_canonical(payload_json, "authenticated delivery artifact")?;
    if artifact.schema != HOSTED_AUTHENTICATED_DELIVERY_SCHEMA
        || artifact.receipt.kernel_key != *expected_kernel_key
        || expected_kernel_key.is_weak_ed25519()
        || !matches!(artifact.receipt.decision, Some(Decision::Allow))
        || !artifact
            .receipt
            .action
            .verify_hash()
            .map_err(|_| HostedMarketStoreError::Invalid("delivery receipt"))?
        || !artifact
            .receipt
            .verify_signature()
            .map_err(|_| HostedMarketStoreError::Invalid("delivery receipt"))?
    {
        return Err(HostedMarketStoreError::Invalid("delivery receipt"));
    }
    let delivery = artifact
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .cloned()
        .ok_or(HostedMarketStoreError::Invalid("delivery receipt"))?;
    let delivery: FindingDelivery = serde_json::from_value(delivery)
        .map_err(|_| HostedMarketStoreError::Invalid("delivery receipt"))?;
    delivery
        .validate()
        .map_err(|_| HostedMarketStoreError::Invalid("delivery receipt"))?;
    Ok((artifact, delivery))
}

fn validate_domain_tenant_binding(
    event: &HostedMarketDomainEvent,
    tenant: &HostedTenantId,
) -> Result<(), HostedMarketStoreError> {
    if event.event_kind != HostedMarketDomainEventKind::DeliveryAccepted {
        return Ok(());
    }
    let expected_kernel_key = required_signer(event.expected_signer.as_ref())?;
    let (artifact, _) = parse_authenticated_delivery(&event.payload_json, expected_kernel_key)?;
    if artifact.receipt.tenant_id.as_deref() != Some(tenant.as_str()) {
        return Err(HostedMarketStoreError::Invalid("delivery receipt tenant"));
    }
    Ok(())
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    payload_json: &[u8],
    label: &'static str,
) -> Result<T, HostedMarketStoreError> {
    let artifact: T =
        serde_json::from_slice(payload_json).map_err(|_| HostedMarketStoreError::Invalid(label))?;
    let canonical =
        canonical_json_bytes(&artifact).map_err(|_| HostedMarketStoreError::Invalid(label))?;
    if canonical != payload_json {
        return Err(HostedMarketStoreError::Invalid(label));
    }
    Ok(artifact)
}

fn parse_signed<T: DeserializeOwned + Serialize>(
    payload_json: &[u8],
    expected_signer: &PublicKey,
) -> Result<SignedExportEnvelope<T>, HostedMarketStoreError> {
    let envelope: SignedExportEnvelope<T> =
        parse_canonical(payload_json, "signed domain artifact")?;
    chio_finding::verify_pinned_envelope(&envelope, expected_signer, "hosted_domain")
        .map_err(|_| HostedMarketStoreError::Invalid("signed domain artifact"))?;
    Ok(envelope)
}

fn required_signer(
    expected_signer: Option<&PublicKey>,
) -> Result<&PublicKey, HostedMarketStoreError> {
    expected_signer.ok_or(HostedMarketStoreError::Invalid("domain artifact signer"))
}

fn require_unsigned(expected_signer: Option<&PublicKey>) -> Result<(), HostedMarketStoreError> {
    if expected_signer.is_some() {
        Err(HostedMarketStoreError::Invalid("domain artifact signer"))
    } else {
        Ok(())
    }
}

fn require_aggregate_identity(
    aggregate_id: &str,
    artifact_id: &str,
) -> Result<(), HostedMarketStoreError> {
    if aggregate_id == artifact_id {
        Ok(())
    } else {
        Err(HostedMarketStoreError::Invalid("domain aggregate identity"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use chio_core_types::capability::scope::MonetaryAmount;
    use chio_core_types::crypto::Keypair;
    use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core_types::receipt::decision::ToolCallAction;
    use chio_core_types::receipt::kinds::{
        BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core_types::receipt::metadata::{
        DeliveryResult, FindingDeliverySettlementMode, FindingMediaTypeCheck,
        FindingTransformProfile, FINDING_DELIVERY_SCHEMA,
    };
    use chio_finding::{
        FindingClaimAllocation, FindingClaimAllocationEntry, FindingClaimBeneficiaryKind,
        FindingHostedPurchaseVerdict, FindingHostedSettlementTerminal, FindingLiability,
        FindingLiabilityLifecycleState, FindingPurchaseResult, FindingVerifiedFixSubmission,
        FindingVoluntaryRetraction, FindingVoluntaryRetractionReason,
        FINDING_CLAIM_ALLOCATION_SCHEMA_V1, FINDING_LIABILITY_SCHEMA_V1,
        FINDING_PURCHASE_RESULT_SCHEMA_V1, FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA_V1,
        FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1,
    };
    use chio_open_market::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference};
    use chio_open_market::fee_schedule::OpenMarketBondClass;
    use chio_open_market::penalty::{
        OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyArtifact,
        OpenMarketPenaltyState, OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
    };
    use chio_test_support::prelude::*;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn authenticated_delivery(
        signer: &Keypair,
        tenant_id: &str,
    ) -> HostedAuthenticatedFindingDelivery {
        let delivery = FindingDelivery {
            schema: FINDING_DELIVERY_SCHEMA.to_owned(),
            finding_id: digest('a'),
            listing_id: "listing-a".to_owned(),
            transform_profile: FindingTransformProfile::Identity,
            digest_check: DeliveryResult::Matched,
            media_type_check: FindingMediaTypeCheck::Matched,
            settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
            accepted_bid_envelope_sha256: digest('b'),
            venue_admission_envelope_sha256: digest('c'),
            reservation_id: "reservation-a".to_owned(),
            purchase_intent_id: "purchase-intent-a".to_owned(),
            authoritative_payment_operation_id: "payment-a".to_owned(),
            status_proof: None,
        };
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "findingId": delivery.finding_id.clone()
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "pending".to_owned(),
                timestamp: 1_700_000_000,
                capability_id: "capability-a".to_owned(),
                tool_server: "finding-market".to_owned(),
                tool_name: "read_finding".to_owned(),
                action,
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: digest('d'),
                policy_hash: digest('e'),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    FINDING_DELIVERY_METADATA_KEY: delivery
                })),
                trust_level: TrustLevel::Mediated,
                tenant_id: Some(tenant_id.to_owned()),
                kernel_key: signer.public_key(),
                bbs_projection_version: None,
            },
            signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        HostedAuthenticatedFindingDelivery {
            schema: HOSTED_AUTHENTICATED_DELIVERY_SCHEMA.to_owned(),
            receipt,
        }
    }

    fn validate_schema(path: &str, document: serde_json::Value) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("spec/schemas");
        let schema_path = root.join(path);
        let schema = chio_spec_validate::load_json(&schema_path).test_unwrap();
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            Path::new("<hosted-domain-artifact>"),
            &document,
        )
        .test_unwrap();
    }

    #[test]
    fn domain_event_validation_cannot_be_bypassed_at_append_input() {
        let event = HostedMarketDomainEvent {
            event_kind: HostedMarketDomainEventKind::FindingPublished,
            aggregate_id: "finding-a".to_owned(),
            event_id: "event-a".to_owned(),
            payload_json: b"{}".to_vec(),
            expected_signer: None,
            expected_authority_id: None,
        };
        assert!(event.validate().is_err());

        let mut noncanonical = event;
        noncanonical.event_kind = HostedMarketDomainEventKind::RecipeRegistered;
        noncanonical.aggregate_id = sha256_hex(b"{}");
        noncanonical.payload_json = b"{ \"schema\": \"invalid\" }".to_vec();
        assert!(noncanonical.validate().is_err());
    }

    #[test]
    fn delivery_requires_a_pinned_valid_receipt_and_exact_tenant() {
        let signer = Keypair::from_seed(&[50_u8; 32]);
        let artifact = authenticated_delivery(&signer, "tenant:test");
        let payload = canonical_json_bytes(&artifact)
            .unwrap_or_else(|error| panic!("test delivery payload failed: {error}"));
        let event = HostedMarketDomainEvent::from_canonical_payload(
            HostedMarketDomainEventKind::DeliveryAccepted,
            "purchase-intent-a",
            "delivery-a",
            payload,
            Some(&signer.public_key()),
            None,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let tenant = HostedTenantId::new("tenant:test")
            .unwrap_or_else(|error| panic!("test tenant failed: {error}"));
        assert!(validate_domain_tenant_binding(&event, &tenant).is_ok());
        let other_tenant = HostedTenantId::new("tenant:other")
            .unwrap_or_else(|error| panic!("test tenant failed: {error}"));
        assert!(validate_domain_tenant_binding(&event, &other_tenant).is_err());
        assert!(parse_authenticated_delivery(event.payload_json(), &signer.public_key()).is_ok());
        assert!(parse_authenticated_delivery(
            event.payload_json(),
            &Keypair::from_seed(&[51_u8; 32]).public_key()
        )
        .is_err());

        let mut tampered = artifact;
        tampered.receipt.content_hash = digest('f');
        let tampered_payload = canonical_json_bytes(&tampered)
            .unwrap_or_else(|error| panic!("test delivery payload failed: {error}"));
        assert!(HostedMarketDomainEvent::from_canonical_payload(
            HostedMarketDomainEventKind::DeliveryAccepted,
            "purchase-intent-a",
            "delivery-tampered",
            tampered_payload,
            Some(&signer.public_key()),
            None,
        )
        .is_err());
    }

    #[test]
    fn every_declared_domain_family_has_a_typed_validated_artifact() {
        let signer = Keypair::from_seed(&[31_u8; 32]);
        let public_key = signer.public_key();
        let allocation_id = digest('a');
        let claim = SignedExportEnvelope::sign(
            FindingClaimAllocation {
                schema: FINDING_CLAIM_ALLOCATION_SCHEMA_V1.to_owned(),
                allocation_id: allocation_id.clone(),
                liability_key: digest('b'),
                purchase_snapshot_sha256: digest('c'),
                deterministic_allocation_sha256: allocation_id.clone(),
                cutoff_slot: 10,
                total_realized_spend_units: 7,
                slash: MonetaryAmount {
                    units: 9,
                    currency: "USD".to_owned(),
                },
                buyer_pool_units: 7,
                community_fund_units: 2,
                entries: vec![
                    FindingClaimAllocationEntry {
                        beneficiary_kind: FindingClaimBeneficiaryKind::Buyer,
                        destination: "buyer:destination".to_owned(),
                        amount_units: 7,
                    },
                    FindingClaimAllocationEntry {
                        beneficiary_kind: FindingClaimBeneficiaryKind::CommunityFund,
                        destination: "community:destination".to_owned(),
                        amount_units: 2,
                    },
                ],
                recorded_at: 20,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let result_id = digest('d');
        let purchase = SignedExportEnvelope::sign(
            FindingPurchaseResult {
                schema: FINDING_PURCHASE_RESULT_SCHEMA_V1.to_owned(),
                result_id: result_id.clone(),
                request_id: result_id.clone(),
                finding_id: digest('e'),
                payer: public_key.clone(),
                reservation_id: "reservation-a".to_owned(),
                purchase_intent_id: "purchase-intent-a".to_owned(),
                authoritative_payment_operation_id: "payment-a".to_owned(),
                verdict: FindingHostedPurchaseVerdict::Allow,
                settlement: FindingHostedSettlementTerminal::Captured,
                accepted_price: MonetaryAmount {
                    units: 10,
                    currency: "USD".to_owned(),
                },
                realized_spend: MonetaryAmount {
                    units: 10,
                    currency: "USD".to_owned(),
                },
                delivery_receipt_sha256: digest('f'),
                purchase_record_sha256: Some(digest('1')),
                failed_delivery_sha256: None,
                output_sha256: Some(digest('2')),
                recorded_at: 21,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let submission_id = digest('3');
        let fix = SignedExportEnvelope::sign(
            FindingVerifiedFixSubmission {
                schema: FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA_V1.to_owned(),
                submission_id: submission_id.clone(),
                seller: public_key.clone(),
                finding_id: digest('4'),
                proof_bundle_sha256: digest('5'),
                activation_sha256: digest('6'),
                submitted_at: 22,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let intent_id = digest('7');
        let retraction = SignedExportEnvelope::sign(
            FindingVoluntaryRetraction {
                schema: FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1.to_owned(),
                intent_id: intent_id.clone(),
                finding_id: digest('8'),
                seller: public_key.clone(),
                status_feed_ref: "status:feed".to_owned(),
                reason: FindingVoluntaryRetractionReason::SellerVoluntaryRetraction,
                issued_at: 23,
                inclusion_deadline: 24,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut substituted_retraction_body = retraction.body.clone();
        substituted_retraction_body.seller = Keypair::from_seed(&[91_u8; 32]).public_key();
        let substituted_retraction =
            SignedExportEnvelope::sign(substituted_retraction_body, &signer)
                .unwrap_or_else(|error| panic!("{error}"));
        let substituted_intent_id = substituted_retraction.body.intent_id.clone();
        assert!(HostedMarketDomainEvent::from_artifact(
            &substituted_intent_id,
            "retraction-seller-substitution",
            &HostedMarketDomainArtifact::Retraction(substituted_retraction),
        )
        .is_err());
        let mut substituted_fix_body = fix.body.clone();
        substituted_fix_body.seller = Keypair::from_seed(&[92_u8; 32]).public_key();
        let substituted_fix = SignedExportEnvelope::sign(substituted_fix_body, &signer)
            .unwrap_or_else(|error| panic!("{error}"));
        let substituted_submission_id = substituted_fix.body.submission_id.clone();
        assert!(HostedMarketDomainEvent::from_artifact(
            &substituted_submission_id,
            "verified-fix-seller-substitution",
            &HostedMarketDomainArtifact::VerifiedFix(substituted_fix),
        )
        .is_err());

        let liability_key = digest('9');
        let liability = SignedExportEnvelope::sign(
            FindingLiability {
                schema: FINDING_LIABILITY_SCHEMA_V1.to_owned(),
                liability_key: liability_key.clone(),
                defect_key: digest('a'),
                finding_id: digest('b'),
                listing_id: "listing-a".to_owned(),
                backing_allocation_id: "backing-a".to_owned(),
                seller: public_key,
                venue_id: "venue-a".to_owned(),
                chain_id: "chain-a".to_owned(),
                vault_contract: "vault-contract-a".to_owned(),
                vault_id: "vault-a".to_owned(),
                state: FindingLiabilityLifecycleState::Open,
                upheld_challenge_id: None,
                purchase_snapshot_sha256: None,
                deterministic_allocation_sha256: None,
                opened_at: 25,
                updated_at: 25,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let penalty_id = "penalty-a".to_owned();
        let penalty = SignedExportEnvelope::sign(
            OpenMarketPenaltyArtifact {
                schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_owned(),
                penalty_id: penalty_id.clone(),
                fee_schedule_id: "fee-a".to_owned(),
                charter_id: "charter-a".to_owned(),
                case_id: "case-a".to_owned(),
                governing_operator_id: "operator-a".to_owned(),
                namespace: "finding".to_owned(),
                listing_id: "listing-a".to_owned(),
                activation_id: None,
                subject_operator_id: Some("seller-a".to_owned()),
                abuse_class: OpenMarketAbuseClass::FraudulentListing,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::HoldBond,
                state: OpenMarketPenaltyState::Proposed,
                penalty_amount: MonetaryAmount {
                    units: 1,
                    currency: "USD".to_owned(),
                },
                opened_at: 26,
                updated_at: 26,
                expires_at: None,
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::External,
                    reference_id: "evidence-a".to_owned(),
                    uri: None,
                    sha256: Some(digest('c')),
                }],
                supersedes_penalty_id: None,
                issued_by: "operator-a".to_owned(),
                note: None,
            },
            &signer,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut mismatched_penalty_body = penalty.body.clone();
        mismatched_penalty_body.governing_operator_id = "substituted-operator".to_owned();
        let mismatched_penalty = SignedExportEnvelope::sign(mismatched_penalty_body, &signer)
            .unwrap_or_else(|error| panic!("{error}"));
        let mismatched_penalty_id = mismatched_penalty.body.penalty_id.clone();
        let mismatched_payload = canonical_json_bytes(&mismatched_penalty)
            .unwrap_or_else(|error| panic!("test penalty payload failed: {error}"));
        assert!(HostedMarketDomainEvent::from_canonical_payload(
            HostedMarketDomainEventKind::PenaltyAssessed,
            &mismatched_penalty_id,
            "penalty-authority-substitution",
            mismatched_payload,
            Some(&signer.public_key()),
            Some("operator-a"),
        )
        .is_err());

        let settlement_id = "settlement-a".to_owned();
        let settlement = HostedCommerceSettlementPacket {
            schema: "chio.commerce.settlement-packet.v1".to_owned(),
            id: settlement_id.clone(),
            issued_at: "2026-08-31T12:00:00Z".to_owned(),
            order_id: "order-a".to_owned(),
            merchant_subject: "seller-a".to_owned(),
            psp: "psp-a".to_owned(),
            payment_intent_id: "payment-a".to_owned(),
            amount_minor: 100,
            currency: "USD".to_owned(),
            quote_sha256: digest('d'),
            settlement_rail: "rail-a".to_owned(),
            settlement_account_ref: "account-a".to_owned(),
            dispatch_receipt_ref: "dispatch-a".to_owned(),
            reconciliation_ref: "reconciliation-a".to_owned(),
            status: HostedCommerceSettlementStatus::Settled,
        };

        for (schema, value) in [
            (
                "chio-finding/v1/claim-allocation.schema.json",
                serde_json::to_value(&claim).test_unwrap(),
            ),
            (
                "chio-finding/v1/purchase-result.schema.json",
                serde_json::to_value(&purchase).test_unwrap(),
            ),
            (
                "chio-finding/v1/verified-fix-submission.schema.json",
                serde_json::to_value(&fix).test_unwrap(),
            ),
            (
                "chio-finding/v1/voluntary-retraction.schema.json",
                serde_json::to_value(&retraction).test_unwrap(),
            ),
            (
                "chio-finding/v1/liability.schema.json",
                serde_json::to_value(&liability).test_unwrap(),
            ),
            (
                "chio-finding/v1/market-penalty.schema.json",
                serde_json::to_value(&penalty).test_unwrap(),
            ),
            (
                "chio-commerce/v1/settlement-packet.schema.json",
                serde_json::to_value(&settlement).test_unwrap(),
            ),
        ] {
            validate_schema(schema, value);
        }

        let artifacts = [
            (
                allocation_id,
                HostedMarketDomainArtifact::Participation(claim),
            ),
            (
                result_id.clone(),
                HostedMarketDomainArtifact::Reveal(purchase.clone()),
            ),
            (
                result_id,
                HostedMarketDomainArtifact::PurchaseSettlement(purchase),
            ),
            (submission_id, HostedMarketDomainArtifact::VerifiedFix(fix)),
            (
                intent_id,
                HostedMarketDomainArtifact::Retraction(retraction),
            ),
            (
                liability_key,
                HostedMarketDomainArtifact::Liability(liability),
            ),
            (penalty_id, HostedMarketDomainArtifact::Penalty(penalty)),
            (
                settlement_id,
                HostedMarketDomainArtifact::Settlement(settlement),
            ),
        ];
        for (index, (aggregate_id, artifact)) in artifacts.iter().enumerate() {
            let event_id = format!("event-{index}");
            let result = if let HostedMarketDomainArtifact::Penalty(penalty) = artifact {
                HostedMarketDomainEvent::from_canonical_payload(
                    HostedMarketDomainEventKind::PenaltyAssessed,
                    aggregate_id,
                    event_id,
                    canonical_json_bytes(penalty).test_unwrap(),
                    Some(&penalty.signer_key),
                    Some(&penalty.body.issued_by),
                )
            } else {
                HostedMarketDomainEvent::from_artifact(aggregate_id, event_id, artifact)
            };
            assert!(result.is_ok());
        }
    }
}
