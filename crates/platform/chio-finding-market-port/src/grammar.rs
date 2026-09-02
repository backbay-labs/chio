//! Canonical hosted-market domain event grammar.
//!
//! One table binds every event kind to its aggregate family and the exact
//! signed artifact schema its payload must verify against. The HTTP edge and
//! every storage adapter consult this table instead of carrying their own
//! copies; a write whose kind, aggregate, and schema do not agree here is
//! rejected before it reaches durable state.

use serde::{Deserialize, Serialize};

use crate::HOSTED_AUTHENTICATED_DELIVERY_SCHEMA;

/// Closed set of durable cognition-market aggregate families.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HostedAggregateKind {
    Finding,
    Recipe,
    Profile,
    Collateral,
    Listing,
    Admission,
    Participation,
    Purchase,
    Reveal,
    Delivery,
    PurchaseTerminal,
    FailedDelivery,
    Challenge,
    ChallengeOutcome,
    VerifiedFix,
    Retraction,
    Liability,
    Appeal,
    Penalty,
    Enforcement,
    Settlement,
    StatusEpoch,
    AuditRound,
}

impl HostedAggregateKind {
    /// Stable storage and wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Recipe => "recipe",
            Self::Profile => "profile",
            Self::Collateral => "collateral",
            Self::Listing => "listing",
            Self::Admission => "admission",
            Self::Participation => "participation",
            Self::Purchase => "purchase",
            Self::Reveal => "reveal",
            Self::Delivery => "delivery",
            Self::PurchaseTerminal => "purchase_terminal",
            Self::FailedDelivery => "failed_delivery",
            Self::Challenge => "challenge",
            Self::ChallengeOutcome => "challenge_outcome",
            Self::VerifiedFix => "verified_fix",
            Self::Retraction => "retraction",
            Self::Liability => "liability",
            Self::Appeal => "appeal",
            Self::Penalty => "penalty",
            Self::Enforcement => "enforcement",
            Self::Settlement => "settlement",
            Self::StatusEpoch => "status_epoch",
            Self::AuditRound => "audit_round",
        }
    }

    /// Parse a stored label. `None` is an integrity failure at the caller.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.label() == value)
    }

    const ALL: [Self; 23] = [
        Self::Finding,
        Self::Recipe,
        Self::Profile,
        Self::Collateral,
        Self::Listing,
        Self::Admission,
        Self::Participation,
        Self::Purchase,
        Self::Reveal,
        Self::Delivery,
        Self::PurchaseTerminal,
        Self::FailedDelivery,
        Self::Challenge,
        Self::ChallengeOutcome,
        Self::VerifiedFix,
        Self::Retraction,
        Self::Liability,
        Self::Appeal,
        Self::Penalty,
        Self::Enforcement,
        Self::Settlement,
        Self::StatusEpoch,
        Self::AuditRound,
    ];
}

/// Closed set of hosted-market domain events. Each variant fixes the wire
/// event kind, the aggregate family it mutates, and the signed artifact
/// schema its payload must carry.
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

    #[must_use]
    pub fn from_event_kind(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.event_kind() == value)
    }

    /// Stable wire event kind.
    #[must_use]
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

    /// Aggregate family this event mutates.
    #[must_use]
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

    /// Signed artifact schema the event payload must verify against.
    #[must_use]
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
            Self::DeliveryAccepted => HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kinds_round_trip_and_bind_unique_wire_names() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in HostedMarketDomainEventKind::ALL {
            assert_eq!(
                HostedMarketDomainEventKind::from_event_kind(kind.event_kind()),
                Some(kind)
            );
            assert!(seen.insert(kind.event_kind()), "duplicate wire event kind");
            assert!(!kind.artifact_schema().is_empty());
        }
    }

    #[test]
    fn aggregate_labels_round_trip() {
        for kind in HostedMarketDomainEventKind::ALL {
            let aggregate = kind.aggregate_kind();
            assert_eq!(
                HostedAggregateKind::parse(aggregate.label()),
                Some(aggregate)
            );
        }
    }
}
