use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    Finding, FindingReplayRecipeInput, SignedFindingAdmission, SignedFindingAuditReport,
    SignedFindingBondBacking, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingChallengeOutcome, SignedFindingChallengeVerifierProfile,
    SignedFindingFailedDelivery, SignedFindingMarketTerms, SignedFindingPurchaseRecord,
    SignedFindingStatusEpoch,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use super::{
    aggregates::aggregate_event_digest, checked_i64, checked_nonnegative_i64, stored_u64,
    unavailable, validate_canonical_json, validate_digest, validate_identifier,
    HostedAggregateKind, HostedJobWriteOutcome, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};

const MAX_AGGREGATE_ID_BYTES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

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
    pub event_kind: HostedMarketDomainEventKind,
    pub aggregate_id: String,
    pub event_id: String,
    pub payload_json: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HostedMarketDomainArtifact {
    Finding(Finding),
    ReplayRecipe(FindingReplayRecipeInput),
    VerifierProfile(SignedFindingChallengeVerifierProfile),
    BondBacking(SignedFindingBondBacking),
    MarketTerms(SignedFindingMarketTerms),
    Admission(SignedFindingAdmission),
    Purchase(SignedFindingPurchaseRecord),
    Delivery(chio_core_types::receipt::metadata::FindingDelivery),
    FailedDelivery(SignedFindingFailedDelivery),
    Challenge(SignedFindingChallenge),
    ChallengeOutcome(SignedFindingChallengeOutcome),
    Appeal(SignedFindingChallengeEnforcement),
    Enforcement(SignedFindingChallengeEnforcement),
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

    pub(crate) fn from_canonical_payload(
        event_kind: HostedMarketDomainEventKind,
        aggregate_id: impl Into<String>,
        event_id: impl Into<String>,
        payload_json: Vec<u8>,
        expected_signer: Option<&PublicKey>,
    ) -> Result<Self, HostedMarketStoreError> {
        let aggregate_id = aggregate_id.into();
        let event_id = event_id.into();
        validate_identifier(&aggregate_id, MAX_AGGREGATE_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("aggregate_id"))?;
        validate_identifier(&event_id, MAX_EVENT_ID_BYTES)
            .map_err(|()| HostedMarketStoreError::Invalid("event_id"))?;
        validate_canonical_json(&payload_json, "domain payload")?;
        if payload_json.len() > MAX_PAYLOAD_BYTES {
            return Err(HostedMarketStoreError::Invalid("domain payload"));
        }
        validate_domain_payload(event_kind, &aggregate_id, &payload_json, expected_signer)?;
        Ok(Self {
            event_kind,
            aggregate_id,
            event_id,
            payload_json,
        })
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
            Self::Purchase(_) => HostedMarketDomainEventKind::PurchaseAuthorized,
            Self::Delivery(_) => HostedMarketDomainEventKind::DeliveryAccepted,
            Self::FailedDelivery(_) => HostedMarketDomainEventKind::DeliveryFailed,
            Self::Challenge(_) => HostedMarketDomainEventKind::ChallengeSubmitted,
            Self::ChallengeOutcome(_) => HostedMarketDomainEventKind::ChallengeFinalized,
            Self::Appeal(_) => HostedMarketDomainEventKind::AppealFinalized,
            Self::Enforcement(_) => HostedMarketDomainEventKind::EnforcementFinalized,
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
            Self::Purchase(envelope) => Some(&envelope.signer_key),
            Self::FailedDelivery(envelope) => Some(&envelope.signer_key),
            Self::Challenge(envelope) => Some(&envelope.signer_key),
            Self::ChallengeOutcome(envelope) => Some(&envelope.signer_key),
            Self::Appeal(envelope) | Self::Enforcement(envelope) => Some(&envelope.signer_key),
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
            Self::Purchase(artifact) => canonical_json_bytes(artifact),
            Self::Delivery(artifact) => canonical_json_bytes(artifact),
            Self::FailedDelivery(artifact) => canonical_json_bytes(artifact),
            Self::Challenge(artifact) => canonical_json_bytes(artifact),
            Self::ChallengeOutcome(artifact) => canonical_json_bytes(artifact),
            Self::Appeal(artifact) | Self::Enforcement(artifact) => canonical_json_bytes(artifact),
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
    pub event_sha256: String,
    pub payload_sha256: String,
    pub payload_json: Vec<u8>,
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
            2 => return Err(HostedMarketStoreError::Conflict),
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
            r#"SELECT revision, event_sha256, event_kind, artifact_schema,
                      payload_sha256, payload_json, updated_at
               FROM chio_finding_market_domain_projections
               WHERE tenant_id = $1 AND aggregate_kind = $2 AND aggregate_id = $3"#,
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
            if stored_event_kind != event_kind.event_kind()
                || stored_schema != event_kind.artifact_schema()
                || sha256_hex(&payload_json) != payload_sha256
            {
                return Err(HostedMarketStoreError::DigestMismatch);
            }
            Ok(HostedMarketDomainProjection {
                tenant_id: tenant.clone(),
                event_kind,
                aggregate_id: aggregate_id.to_owned(),
                revision: stored_u64(row.try_get(0).map_err(unavailable)?)?,
                event_sha256: row.try_get(1).map_err(unavailable)?,
                payload_sha256,
                payload_json,
                updated_at: stored_u64(row.try_get(6).map_err(unavailable)?)?,
            })
        })
        .transpose()
    }
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
        FindingFailedDelivery, FindingMarketTerms, FindingPurchaseRecord, FindingReplayRecipeInput,
        FindingStatusEpoch,
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
        HostedMarketDomainEventKind::PurchaseAuthorized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingPurchaseRecord>(payload_json, signer)?;
            chio_finding::verify_signed_purchase_record(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("purchase artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.purchase_key)
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
        HostedMarketDomainEventKind::AppealFinalized
        | HostedMarketDomainEventKind::EnforcementFinalized => {
            let signer = required_signer(expected_signer)?;
            let artifact = parse_signed::<FindingChallengeEnforcement>(payload_json, signer)?;
            chio_finding::verify_signed_challenge_enforcement(&artifact, signer)
                .map_err(|_| HostedMarketStoreError::Invalid("challenge enforcement artifact"))?;
            require_aggregate_identity(aggregate_id, &artifact.body.enforcement_id)
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
        HostedMarketDomainEventKind::ParticipationAdmitted
        | HostedMarketDomainEventKind::RevealCommitted
        | HostedMarketDomainEventKind::PurchaseSettled
        | HostedMarketDomainEventKind::VerifiedFixSubmitted
        | HostedMarketDomainEventKind::RetractionVoluntary
        | HostedMarketDomainEventKind::LiabilityAssessed
        | HostedMarketDomainEventKind::PenaltyAssessed
        | HostedMarketDomainEventKind::SettlementTerminal => Err(HostedMarketStoreError::Invalid(
            "unsupported hosted domain artifact",
        )),
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
