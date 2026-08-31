use chio_core_types::receipt::metadata::FindingDelivery;
use chio_finding::{
    FindingHostedSettlementTerminal, SignedFindingAuditReport, SignedFindingChallenge,
    SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome, SignedFindingClaimAllocation,
    SignedFindingFailedDelivery, SignedFindingLiability, SignedFindingPurchaseRecord,
    SignedFindingPurchaseResult,
};
use chio_open_market::penalty::SignedOpenMarketPenalty;

use crate::{
    HostedCommerceSettlementPacket, HostedDomainPage, HostedDomainWrite, HostedJobWriteOutcome,
    HostedMarketDomainArtifact, HostedMarketDomainEventKind, HostedMarketStoreError,
    HostedSpendState, HostedTenantId, PostgresFindingMarketStore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedPurchaseRecoveryOutcome {
    pub reveal: HostedJobWriteOutcome,
    pub spend: HostedJobWriteOutcome,
    pub terminal: HostedJobWriteOutcome,
}

impl PostgresFindingMarketStore {
    /// Converge a purchase result after a process crash. Every step is
    /// exact-replay stable, and incompatible spend state rejects before a new
    /// domain event is written.
    pub async fn recover_purchase_result(
        &self,
        tenant: &HostedTenantId,
        artifact: &SignedFindingPurchaseResult,
        reveal_write: &HostedDomainWrite,
        terminal_write: &HostedDomainWrite,
    ) -> Result<HostedPurchaseRecoveryOutcome, HostedMarketStoreError> {
        let reservation = self
            .monthly_spend_reservation(tenant, &artifact.body.reservation_id)
            .await?
            .ok_or(HostedMarketStoreError::NotFound)?;
        let desired = validate_purchase_recovery_state(
            artifact.body.settlement,
            reservation.state,
            reservation.units,
            artifact.body.accepted_price.units,
        )?;

        let reveal = self.commit_reveal(tenant, artifact, reveal_write).await?;
        let spend = match desired {
            HostedSpendState::Committed => {
                self.commit_monthly_spend(tenant, &artifact.body.reservation_id)
                    .await?
            }
            HostedSpendState::Released => {
                self.release_monthly_spend(tenant, &artifact.body.reservation_id)
                    .await?
            }
            HostedSpendState::Reserved => {
                return Err(HostedMarketStoreError::Invalid("purchase terminal"));
            }
        };
        let terminal = self
            .settle_purchase(tenant, artifact, terminal_write)
            .await?;
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
        artifact: &FindingDelivery,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.purchase_intent_id,
            &HostedMarketDomainArtifact::Delivery(artifact.clone()),
            write,
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
        artifact: &SignedOpenMarketPenalty,
        write: &HostedDomainWrite,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.append_typed_artifact(
            tenant,
            &artifact.body.penalty_id,
            &HostedMarketDomainArtifact::Penalty(artifact.clone()),
            write,
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

fn validate_purchase_recovery_state(
    settlement: FindingHostedSettlementTerminal,
    reservation_state: HostedSpendState,
    reserved_units: u64,
    accepted_units: u64,
) -> Result<HostedSpendState, HostedMarketStoreError> {
    let desired = match settlement {
        FindingHostedSettlementTerminal::Captured => HostedSpendState::Committed,
        FindingHostedSettlementTerminal::Released => HostedSpendState::Released,
    };
    if reserved_units != accepted_units
        || (!matches!(reservation_state, HostedSpendState::Reserved)
            && reservation_state != desired)
    {
        return Err(HostedMarketStoreError::Conflict);
    }
    Ok(desired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_only_converges_to_the_bound_terminal() {
        assert!(matches!(
            validate_purchase_recovery_state(
                FindingHostedSettlementTerminal::Captured,
                HostedSpendState::Reserved,
                10,
                10,
            ),
            Ok(HostedSpendState::Committed)
        ));
        assert!(matches!(
            validate_purchase_recovery_state(
                FindingHostedSettlementTerminal::Captured,
                HostedSpendState::Committed,
                10,
                10,
            ),
            Ok(HostedSpendState::Committed)
        ));
        assert!(validate_purchase_recovery_state(
            FindingHostedSettlementTerminal::Captured,
            HostedSpendState::Released,
            10,
            10,
        )
        .is_err());
        assert!(validate_purchase_recovery_state(
            FindingHostedSettlementTerminal::Released,
            HostedSpendState::Reserved,
            11,
            10,
        )
        .is_err());
    }
}
