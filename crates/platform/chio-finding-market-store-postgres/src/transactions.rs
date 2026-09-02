use chio_core_types::{canonical_json_bytes, PublicKey};
use chio_finding::{
    FindingHostedSettlementTerminal, SignedFindingAuditReport, SignedFindingChallenge,
    SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome, SignedFindingClaimAllocation,
    SignedFindingFailedDelivery, SignedFindingLiability, SignedFindingPurchaseRecord,
    SignedFindingPurchaseResult,
};
use chio_finding_market_port::HostedAuthenticatedFindingDelivery;
use chio_open_market::penalty::SignedOpenMarketPenalty;

use crate::{
    unavailable, HostedCommerceSettlementPacket, HostedDomainPage, HostedDomainWrite,
    HostedJobWriteOutcome, HostedMarketDomainArtifact, HostedMarketDomainEvent,
    HostedMarketDomainEventKind, HostedMarketStoreError, HostedSpendState, HostedTenantId,
    PostgresFindingMarketStore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedPurchaseRecoveryOutcome {
    pub reveal: HostedJobWriteOutcome,
    pub spend: HostedJobWriteOutcome,
    pub terminal: HostedJobWriteOutcome,
}

impl PostgresFindingMarketStore {
    /// Converge a purchase result after a process crash. The terminal, reveal,
    /// and spend transition share one tenant transaction, so none can become
    /// visible unless every fence admits the same result.
    pub async fn recover_purchase_result(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingPurchaseResult,
        reveal_write: &HostedDomainWrite,
        terminal_write: &HostedDomainWrite,
    ) -> Result<HostedPurchaseRecoveryOutcome, HostedMarketStoreError> {
        let desired = match artifact.body.settlement {
            FindingHostedSettlementTerminal::Captured => HostedSpendState::Committed,
            FindingHostedSettlementTerminal::Released => HostedSpendState::Released,
        };
        let terminal_event = HostedMarketDomainEvent::from_artifact(
            &artifact.body.result_id,
            &terminal_write.event_id,
            &HostedMarketDomainArtifact::PurchaseSettlement(artifact.clone()),
        )?;
        let reveal_event = HostedMarketDomainEvent::from_artifact(
            &artifact.body.result_id,
            &reveal_write.event_id,
            &HostedMarketDomainArtifact::Reveal(artifact.clone()),
        )?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let terminal = self
            .append_domain_event_in_transaction(
                &mut transaction,
                tenant,
                &terminal_event,
                terminal_write.expected_revision,
                terminal_write.expected_event_sha256.as_deref(),
                terminal_write.committed_at,
            )
            .await?;
        let reveal = self
            .append_domain_event_in_transaction(
                &mut transaction,
                tenant,
                &reveal_event,
                reveal_write.expected_revision,
                reveal_write.expected_event_sha256.as_deref(),
                reveal_write.committed_at,
            )
            .await?;
        let spend = self
            .finish_monthly_spend_in_transaction(
                &mut transaction,
                tenant,
                &artifact.body.reservation_id,
                desired,
                Some(artifact.body.accepted_price.units),
            )
            .await?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(HostedPurchaseRecoveryOutcome {
            reveal,
            spend,
            terminal,
        })
    }

    pub async fn catalog_purchases(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::PurchaseAuthorized,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_reveals(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::RevealCommitted,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_purchase_terminals(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::PurchaseSettled,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_failed_deliveries(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::DeliveryFailed,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_challenges(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::ChallengeSubmitted,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_challenge_outcomes(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::ChallengeFinalized,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_liabilities(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::LiabilityAssessed,
            after,
            limit,
        )
        .await
    }

    pub async fn catalog_settlements(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedDomainPage, HostedMarketStoreError> {
        self.list_domain_projections(
            tenant,
            HostedMarketDomainEventKind::SettlementTerminal,
            after,
            limit,
        )
        .await
    }

    pub async fn authorize_purchase(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingPurchaseRecord,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.purchase_key,
            &HostedMarketDomainArtifact::Purchase(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn commit_reveal(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingPurchaseResult,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.result_id,
            &HostedMarketDomainArtifact::Reveal(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn accept_delivery(
        &self,
        tenant: &HostedTenantId,
        expected_kernel_key: &PublicKey,
        artifact: &HostedAuthenticatedFindingDelivery,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        if artifact.receipt.kernel_key != *expected_kernel_key {
            return Err(HostedMarketStoreError::Invalid("delivery receipt signer"));
        }
        let purchase_intent_id = artifact
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.get(chio_core_types::receipt::metadata::FINDING_DELIVERY_METADATA_KEY)
            })
            .and_then(|delivery| delivery.get("purchase_intent_id"))
            .and_then(serde_json::Value::as_str)
            .ok_or(HostedMarketStoreError::Invalid("delivery receipt"))?;
        let payload_json = canonical_json_bytes(artifact)
            .map_err(|_| HostedMarketStoreError::Invalid("delivery receipt"))?;
        let event = HostedMarketDomainEvent::from_canonical_payload(
            HostedMarketDomainEventKind::DeliveryAccepted,
            purchase_intent_id,
            &write.event_id,
            payload_json,
            Some(expected_kernel_key),
            None,
        )?;
        self.append_domain_event(
            tenant,
            &event,
            write.expected_revision,
            write.expected_event_sha256.as_deref(),
            write.committed_at,
        )
        .await
    }

    pub async fn settle_purchase(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingPurchaseResult,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.result_id,
            &HostedMarketDomainArtifact::PurchaseSettlement(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn fail_delivery(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingFailedDelivery,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.failed_delivery_id,
            &HostedMarketDomainArtifact::FailedDelivery(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn submit_challenge(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingChallenge,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.challenge_id,
            &HostedMarketDomainArtifact::Challenge(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn finalize_challenge(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingChallengeOutcome,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.outcome_id,
            &HostedMarketDomainArtifact::ChallengeOutcome(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn admit_participation(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingClaimAllocation,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.allocation_id,
            &HostedMarketDomainArtifact::Participation(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn assess_liability(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingLiability,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.liability_key,
            &HostedMarketDomainArtifact::Liability(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn finalize_appeal(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingChallengeEnforcement,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.enforcement_id,
            &HostedMarketDomainArtifact::Appeal(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn assess_penalty(
        &self,
        tenant: &HostedTenantId,
        authority_id: &str,
        artifact: &SignedOpenMarketPenalty,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        if artifact.body.issued_by != authority_id
            || artifact.body.governing_operator_id != authority_id
        {
            return Err(HostedMarketStoreError::Invalid("market penalty authority"));
        }
        let payload_json = canonical_json_bytes(artifact)
            .map_err(|_| HostedMarketStoreError::Invalid("market penalty artifact"))?;
        let event = HostedMarketDomainEvent::from_canonical_payload(
            HostedMarketDomainEventKind::PenaltyAssessed,
            &artifact.body.penalty_id,
            &write.event_id,
            payload_json,
            Some(&artifact.signer_key),
            Some(authority_id),
        )?;
        self.append_domain_event(
            tenant,
            &event,
            write.expected_revision,
            write.expected_event_sha256.as_deref(),
            write.committed_at,
        )
        .await
    }

    pub async fn finalize_enforcement(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingChallengeEnforcement,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.enforcement_id,
            &HostedMarketDomainArtifact::Enforcement(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn record_settlement(
        &self,
        tenant: &HostedTenantId,
        artifact: &HostedCommerceSettlementPacket,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.id,
            &HostedMarketDomainArtifact::Settlement(artifact.clone()),
            write,
        )
        .await
    }

    pub async fn finalize_audit(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingAuditReport,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.audit_report_id,
            &HostedMarketDomainArtifact::AuditReport(artifact.clone()),
            write,
        )
        .await
    }
}
