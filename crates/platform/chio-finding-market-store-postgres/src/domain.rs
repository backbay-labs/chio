use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    Finding, FindingReplayRecipeInput, SignedFindingAdmission, SignedFindingAuditReport,
    SignedFindingBondBacking, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingChallengeOutcome, SignedFindingChallengeVerifierProfile,
    SignedFindingClaimAllocation, SignedFindingFailedDelivery, SignedFindingLiability,
    SignedFindingMarketTerms, SignedFindingPurchaseRecord, SignedFindingPurchaseResult,
    SignedFindingStatusEpoch, SignedFindingVerifiedFixSubmission, SignedFindingVoluntaryRetraction,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedMarketDomainEventKind {
    FindingPublished,
    RecipeRegistered,
    ProfileRegistered,
    CollateralRegistered,
    ListingActivated,
    AdmissionAdmitted,
    ParticipationAdmitted,
    PurchaseAuthorized,
    RevealCommitted,
    DeliveryAccepted,
    PurchaseSettled,
    DeliveryFailed,
    ChallengeSubmitted,
    ChallengeFinalized,
    VerifiedFixSubmitted,
    RetractionVoluntary,
    LiabilityAssessed,
    AppealFinalized,
    PenaltyAssessed,
    EnforcementFinalized,
    SettlementTerminal,
    StatusPublished,
    AuditFinalized,
}

impl HostedMarketDomainEventKind {
    pub const ALL: [Self; 23] = [
        Self::FindingPublished,
        Self::RecipeRegistered,
        Self::ProfileRegistered,
        Self::CollateralRegistered,
        Self::ListingActivated,
        Self::AdmissionAdmitted,
        Self::ParticipationAdmitted,
        Self::PurchaseAuthorized,
        Self::RevealCommitted,
        Self::DeliveryAccepted,
        Self::PurchaseSettled,
        Self::DeliveryFailed,
        Self::ChallengeSubmitted,
        Self::ChallengeFinalized,
        Self::VerifiedFixSubmitted,
        Self::RetractionVoluntary,
        Self::LiabilityAssessed,
        Self::AppealFinalized,
        Self::PenaltyAssessed,
        Self::EnforcementFinalized,
        Self::SettlementTerminal,
        Self::StatusPublished,
        Self::AuditFinalized,
    ];

    pub fn from_event_kind(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.event_kind() == value)
    }

    pub const fn aggregate_kind(self) -> HostedAggregateKind {
        match self {
            Self::FindingPublished => HostedAggregateKind::Finding,
            Self::RecipeRegistered => HostedAggregateKind::Recipe,
            Self::ProfileRegistered => HostedAggregateKind::Profile,
            Self::CollateralRegistered => HostedAggregateKind::Collateral,
            Self::ListingActivated => HostedAggregateKind::Listing,
            Self::AdmissionAdmitted => HostedAggregateKind::Admission,
            Self::ParticipationAdmitted => HostedAggregateKind::Participation,
            Self::PurchaseAuthorized => HostedAggregateKind::Purchase,
            Self::RevealCommitted => HostedAggregateKind::Reveal,
            Self::DeliveryAccepted => HostedAggregateKind::Delivery,
            Self::PurchaseSettled => HostedAggregateKind::PurchaseTerminal,
            Self::DeliveryFailed => HostedAggregateKind::FailedDelivery,
            Self::ChallengeSubmitted => HostedAggregateKind::Challenge,
            Self::ChallengeFinalized => HostedAggregateKind::ChallengeOutcome,
            Self::VerifiedFixSubmitted => HostedAggregateKind::VerifiedFix,
            Self::RetractionVoluntary => HostedAggregateKind::Retraction,
            Self::LiabilityAssessed => HostedAggregateKind::Liability,
            Self::AppealFinalized => HostedAggregateKind::Appeal,
            Self::PenaltyAssessed => HostedAggregateKind::Penalty,
            Self::EnforcementFinalized => HostedAggregateKind::Enforcement,
            Self::SettlementTerminal => HostedAggregateKind::Settlement,
            Self::StatusPublished => HostedAggregateKind::StatusEpoch,
            Self::AuditFinalized => HostedAggregateKind::AuditRound,
        }
    }

    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::FindingPublished => "finding.published",
            Self::RecipeRegistered => "recipe.registered",
            Self::ProfileRegistered => "profile.registered",
            Self::CollateralRegistered => "collateral.registered",
            Self::ListingActivated => "listing.activated",
            Self::AdmissionAdmitted => "admission.admitted",
            Self::ParticipationAdmitted => "participation.admitted",
            Self::PurchaseAuthorized => "purchase.authorized",
            Self::RevealCommitted => "reveal.committed",
            Self::DeliveryAccepted => "delivery.accepted",
            Self::PurchaseSettled => "purchase.settled",
            Self::DeliveryFailed => "delivery.failed",
            Self::ChallengeSubmitted => "challenge.submitted",
            Self::ChallengeFinalized => "challenge.finalized",
            Self::VerifiedFixSubmitted => "verified_fix.submitted",
            Self::RetractionVoluntary => "retraction.voluntary",
            Self::LiabilityAssessed => "liability.assessed",
            Self::AppealFinalized => "appeal.finalized",
            Self::PenaltyAssessed => "penalty.assessed",
            Self::EnforcementFinalized => "enforcement.finalized",
            Self::SettlementTerminal => "settlement.terminal",
            Self::StatusPublished => "status.published",
            Self::AuditFinalized => "audit.finalized",
        }
    }

    pub const fn artifact_schema(self) -> &'static str {
        match self {
            Self::FindingPublished => "chio.finding.v1",
            Self::RecipeRegistered => "chio.finding.replay-recipe-input.v1",
            Self::ProfileRegistered => "chio.finding.challenge-verifier-profile.v1",
            Self::CollateralRegistered => "chio.finding.bond-backing.v1",
            Self::ListingActivated => "chio.finding.market-terms.v1",
            Self::AdmissionAdmitted => "chio.finding.admission.v1",
            Self::ParticipationAdmitted => "chio.finding.claim-allocation.v1",
            Self::PurchaseAuthorized => "chio.finding.purchase-record.v1",
            Self::RevealCommitted | Self::PurchaseSettled => "chio.finding.purchase-result.v1",
            Self::DeliveryAccepted => "chio.finding.delivery.v1",
            Self::DeliveryFailed => "chio.finding.failed-delivery.v1",
            Self::ChallengeSubmitted => "chio.finding.challenge.v1",
            Self::ChallengeFinalized => "chio.finding.challenge-outcome.v1",
            Self::VerifiedFixSubmitted => "chio.finding.verified-fix-submission.v1",
            Self::RetractionVoluntary => "chio.finding.voluntary-retraction.v1",
            Self::LiabilityAssessed => "chio.finding.liability.v1",
            Self::AppealFinalized | Self::EnforcementFinalized => {
                "chio.finding.challenge-enforcement.v1"
            }
            Self::PenaltyAssessed => "chio.registry.market-penalty.v1",
            Self::SettlementTerminal => "chio.commerce.settlement-packet.v1",
            Self::StatusPublished => "chio.finding.status-epoch.v1",
            Self::AuditFinalized => "chio.finding.audit-report.v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedMarketDomainEvent {
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: String,
    event_id: String,
    payload_json: Vec<u8>,
    expected_signer: Option<PublicKey>,
}

#[derive(Clone, Debug, PartialEq)]
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
    Delivery(chio_core_types::receipt::metadata::FindingDelivery),
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
    pub fn from_artifact(
        aggregate_id: impl Into<String>,
        event_id: impl Into<String>,
        artifact: &HostedMarketDomainArtifact,
    ) -> Result<Self, HostedMarketStoreError> {
        let payload_json = artifact.canonical_payload()?;
        Self::from_canonical_payload(
            artifact.event_kind(),
            aggregate_id,
            event_id,
            payload_json,
            artifact.signer(),
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
    ) -> Result<Self, HostedMarketStoreError> {
        let event = Self {
            event_kind,
            aggregate_id: aggregate_id.into(),
            event_id: event_id.into(),
            payload_json,
            expected_signer: expected_signer.cloned(),
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
            Self::ReplayRecipe(_) | Self::Delivery(_) => None,
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
        event.validate()?;
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
        let mut transaction = self.begin_tenant(tenant).await?;
        if let Some(exact) = retained_event_matches(
            &mut transaction,
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
            transaction
                .commit()
                .await
                .map_err(|_| HostedMarketStoreError::Unavailable)?;
            return Ok(HostedJobWriteOutcome::ExactReplay);
        }
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
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
        let outcome = match outcome {
            0 => HostedJobWriteOutcome::Inserted,
            1 => HostedJobWriteOutcome::ExactReplay,
            2 => {
                match retained_event_matches(
                    &mut transaction,
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
        transaction
            .commit()
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
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
        row.map(|row| {
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
        })
        .transpose()
    }
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
        | HostedMarketDomainEventKind::DeliveryAccepted
        | HostedMarketDomainEventKind::SettlementTerminal => None,
        _ => Some(
            parse_canonical::<SignedExportEnvelope<serde_json::Value>>(
                payload_json,
                "signed domain artifact",
            )?
            .signer_key,
        ),
    };
    validate_domain_payload(event_kind, aggregate_id, payload_json, signer.as_ref())
}

fn validate_domain_payload(
    event_kind: HostedMarketDomainEventKind,
    aggregate_id: &str,
    payload_json: &[u8],
    expected_signer: Option<&PublicKey>,
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
            require_unsigned(expected_signer)?;
            let artifact: chio_core_types::receipt::metadata::FindingDelivery =
                parse_canonical(payload_json, "delivery artifact")?;
            artifact
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("delivery artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.purchase_intent_id)
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
            require_aggregate_identity(aggregate_id, &artifact.body.submission_id)
        }
        HostedMarketDomainEventKind::RetractionVoluntary => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingVoluntaryRetraction>(payload_json, signer)?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("voluntary retraction artifact"))?;
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
            let artifact = parse_signed::<chio_open_market::penalty::OpenMarketPenaltyArtifact>(
                payload_json,
                signer,
            )?;
            artifact
                .body
                .validate()
                .map_err(|_| HostedMarketStoreError::Invalid("market penalty artifact"))?;
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
        };
        assert!(event.validate().is_err());

        let mut noncanonical = event;
        noncanonical.event_kind = HostedMarketDomainEventKind::RecipeRegistered;
        noncanonical.aggregate_id = sha256_hex(b"{}");
        noncanonical.payload_json = b"{ \"schema\": \"invalid\" }".to_vec();
        assert!(noncanonical.validate().is_err());
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
            assert!(HostedMarketDomainEvent::from_artifact(
                aggregate_id,
                format!("event-{index}"),
                artifact,
            )
            .is_ok());
        }
    }
}
