//! Liability claim package, response, dispute, and adjudication artifacts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::credit::{SignedCreditBond, SignedCreditLossLifecycle, SignedExposureLedgerReport};
use crate::receipt::lineage::SignedExportEnvelope;

use crate::error::MarketError;
use crate::{validate_positive_money, verify_signed_artifact, SignedLiabilityBoundCoverage};

/// Evidence artifact families a claim reference may point at.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimEvidenceKind {
    BoundCoverage,
    ExposureLedger,
    CreditBond,
    CreditLossLifecycle,
    Receipt,
    ClaimResponse,
    ClaimDispute,
}

/// Pointer to one supporting evidence artifact by kind and reference id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimEvidenceReference {
    pub kind: LiabilityClaimEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

/// Provider disposition for a submitted claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimResponseDisposition {
    Acknowledged,
    Accepted,
    Denied,
}

/// Terminal adjudication outcome for a disputed claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimAdjudicationOutcome {
    ClaimUpheld,
    ProviderUpheld,
    PartialSettlement,
}

/// Claimant-signed claim over one bound coverage: the coverage, exposure,
/// bond, and loss evidence plus the claimed amount and receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPackageArtifact {
    pub schema: String,
    pub claim_id: String,
    pub issued_at: u64,
    pub bound_coverage: SignedLiabilityBoundCoverage,
    pub exposure: SignedExposureLedgerReport,
    pub bond: SignedCreditBond,
    pub loss_event: SignedCreditLossLifecycle,
    pub claimant: String,
    pub claim_event_at: u64,
    pub claim_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub narrative: String,
    pub receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimPackageArtifact {
    /// Fail closed on the claim shape: every embedded artifact must verify,
    /// the claim amount must fit inside the bound coverage and its currency,
    /// the event must fall inside the coverage window, and every evidence
    /// artifact must bind the same coverage subject and bond.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(&self.bound_coverage, "claim package bound_coverage")?;
        verify_signed_artifact(&self.exposure, "claim package exposure")?;
        verify_signed_artifact(&self.bond, "claim package bond")?;
        verify_signed_artifact(&self.loss_event, "claim package loss_event")?;
        if self.claimant.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim packages require a non-empty claimant",
            ));
        }
        if self.narrative.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim packages require a non-empty narrative",
            ));
        }
        if self.receipt_ids.is_empty() {
            return Err(MarketError::field_invalid(
                "claim packages require at least one receipt reference",
            ));
        }
        let mut deduped_receipts = BTreeSet::new();
        for receipt_id in &self.receipt_ids {
            if receipt_id.trim().is_empty() {
                return Err(MarketError::field_invalid(
                    "claim receipt references must be non-empty",
                ));
            }
            if !deduped_receipts.insert(receipt_id.trim().to_string()) {
                return Err(MarketError::field_invalid(
                    "claim receipt references must be unique",
                ));
            }
        }
        validate_positive_money(&self.claim_amount, "claim_amount")?;
        let coverage = &self.bound_coverage.body.coverage_amount;
        if self.claim_amount.currency != coverage.currency {
            return Err(MarketError::currency_mismatch(
                "claim_amount currency must match bound coverage currency",
            ));
        }
        if self.claim_amount.units > coverage.units {
            return Err(MarketError::amount_out_of_bounds(
                "claim_amount cannot exceed bound coverage amount",
            ));
        }
        if self.claim_event_at < self.bound_coverage.body.effective_from
            || self.claim_event_at > self.bound_coverage.body.effective_until
        {
            return Err(MarketError::window_invalid(
                "claim_event_at must fall within the bound coverage effective window",
            ));
        }
        if self.exposure.body.summary.mixed_currency_book {
            return Err(MarketError::state_invalid(
                "claim packages require exposure evidence without mixed-currency ambiguity",
            ));
        }
        let subject_key = &self
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if self
            .exposure
            .body
            .filters
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err(MarketError::binding_mismatch(
                "claim exposure evidence must match the bound coverage subject",
            ));
        }
        if self
            .bond
            .body
            .report
            .filters
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err(MarketError::binding_mismatch(
                "claim bond evidence must match the bound coverage subject",
            ));
        }
        if self.loss_event.body.bond_id != self.bond.body.bond_id {
            return Err(MarketError::binding_mismatch(
                "claim loss evidence must reference the same bond",
            ));
        }
        if self
            .loss_event
            .body
            .report
            .summary
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err(MarketError::binding_mismatch(
                "claim loss evidence must match the bound coverage subject",
            ));
        }
        Ok(())
    }
}

/// Signed claim package envelope.
pub type SignedLiabilityClaimPackage = SignedExportEnvelope<LiabilityClaimPackageArtifact>;

/// Provider response to a signed claim: acknowledged, accepted with a
/// covered amount, or denied with a reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimResponseArtifact {
    pub schema: String,
    pub claim_response_id: String,
    pub issued_at: u64,
    pub claim: SignedLiabilityClaimPackage,
    pub provider_response_ref: String,
    pub disposition: LiabilityClaimResponseDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimResponseArtifact {
    /// Fail closed on the response shape: the embedded claim must verify,
    /// and the disposition fixes which of covered_amount and denial_reason
    /// must be present.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(&self.claim, "claim response claim")?;
        self.claim.body.validate()?;
        if self.provider_response_ref.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim responses require a non-empty provider_response_ref",
            ));
        }
        match self.disposition {
            LiabilityClaimResponseDisposition::Acknowledged => {
                if self.covered_amount.is_some() {
                    return Err(MarketError::field_invalid(
                        "acknowledged claim responses cannot include covered_amount",
                    ));
                }
                if self.denial_reason.is_some() {
                    return Err(MarketError::field_invalid(
                        "acknowledged claim responses cannot include denial_reason",
                    ));
                }
            }
            LiabilityClaimResponseDisposition::Accepted => {
                let covered_amount = self.covered_amount.as_ref().ok_or_else(|| {
                    MarketError::field_invalid("accepted claim responses require covered_amount")
                })?;
                validate_positive_money(covered_amount, "covered_amount")?;
                if covered_amount.currency != self.claim.body.claim_amount.currency {
                    return Err(MarketError::currency_mismatch(
                        "covered_amount currency must match claim_amount currency",
                    ));
                }
                if covered_amount.units > self.claim.body.claim_amount.units {
                    return Err(MarketError::amount_out_of_bounds(
                        "covered_amount cannot exceed claim_amount",
                    ));
                }
                if self.denial_reason.is_some() {
                    return Err(MarketError::field_invalid(
                        "accepted claim responses cannot include denial_reason",
                    ));
                }
            }
            LiabilityClaimResponseDisposition::Denied => {
                if self.covered_amount.is_some() {
                    return Err(MarketError::field_invalid(
                        "denied claim responses cannot include covered_amount",
                    ));
                }
                if self
                    .denial_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    return Err(MarketError::field_invalid(
                        "denied claim responses require denial_reason",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Signed claim response envelope.
pub type SignedLiabilityClaimResponse = SignedExportEnvelope<LiabilityClaimResponseArtifact>;

/// Claimant dispute over a provider response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimDisputeArtifact {
    pub schema: String,
    pub dispute_id: String,
    pub issued_at: u64,
    pub provider_response: SignedLiabilityClaimResponse,
    pub opened_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimDisputeArtifact {
    /// Fail closed on the dispute shape: the embedded response must verify
    /// and the dispute narrative must be non-empty.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(&self.provider_response, "claim dispute provider_response")?;
        self.provider_response.body.validate()?;
        if self.opened_by.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim disputes require a non-empty opened_by",
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim disputes require a non-empty reason",
            ));
        }
        let partially_accepted = self.provider_response.body.disposition
            == LiabilityClaimResponseDisposition::Accepted
            && self
                .provider_response
                .body
                .covered_amount
                .as_ref()
                .is_some_and(|amount| {
                    amount.units < self.provider_response.body.claim.body.claim_amount.units
                });
        if self.provider_response.body.disposition != LiabilityClaimResponseDisposition::Denied
            && !partially_accepted
        {
            return Err(MarketError::field_invalid(
                "claim disputes require a denied or partially accepted provider response",
            ));
        }
        Ok(())
    }
}

/// Signed claim dispute envelope.
pub type SignedLiabilityClaimDispute = SignedExportEnvelope<LiabilityClaimDisputeArtifact>;

/// Adjudicator decision over a disputed claim, optionally recording the
/// predeclared decision rule and roster anchor it was checked against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimAdjudicationArtifact {
    pub schema: String,
    pub adjudication_id: String,
    pub issued_at: u64,
    pub dispute: SignedLiabilityClaimDispute,
    pub adjudicator: String,
    pub outcome: LiabilityClaimAdjudicationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awarded_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Predeclared decision rule or circuit-breaker condition id the
    /// adjudication applied (ADR-0015). Optional and omitted when
    /// absent so existing signed fixtures keep byte-stable canonical JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_rule_ref: Option<String>,
    /// Id or hash of the signed roster artifact the adjudicator was checked
    /// against (ADR-0015 anchoring). Records which ex-ante roster
    /// was applied so the check is auditable and not per-adjudication fabricable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_anchor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimAdjudicationArtifact {
    /// Fail closed on the adjudication shape: the embedded dispute must
    /// verify, the adjudicator must be named, and the awarded amount must
    /// respect the outcome (full award for upheld claims, a strictly
    /// smaller one for partial settlement, none for provider-upheld).
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(&self.dispute, "claim adjudication dispute")?;
        self.dispute.body.validate()?;
        if self.adjudicator.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim adjudications require a non-empty adjudicator",
            ));
        }
        if self
            .decision_rule_ref
            .as_ref()
            .is_some_and(|rule| rule.trim().is_empty())
        {
            return Err(MarketError::field_invalid(
                "claim adjudication decision_rule_ref must not be blank when present",
            ));
        }
        if self
            .roster_anchor_ref
            .as_ref()
            .is_some_and(|anchor| anchor.trim().is_empty())
        {
            return Err(MarketError::field_invalid(
                "claim adjudication roster_anchor_ref must not be blank when present",
            ));
        }
        let claim_amount = &self
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_amount;
        match self.outcome {
            LiabilityClaimAdjudicationOutcome::ClaimUpheld => {
                let awarded_amount = self.awarded_amount.as_ref().ok_or_else(|| {
                    MarketError::field_invalid("claim_upheld adjudications require awarded_amount")
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(MarketError::currency_mismatch(
                        "awarded_amount currency must match claim_amount currency",
                    ));
                }
                if awarded_amount.units > claim_amount.units {
                    return Err(MarketError::amount_out_of_bounds(
                        "awarded_amount cannot exceed claim_amount",
                    ));
                }
            }
            LiabilityClaimAdjudicationOutcome::ProviderUpheld => {
                if self.awarded_amount.is_some() {
                    return Err(MarketError::field_invalid(
                        "provider_upheld adjudications cannot include awarded_amount",
                    ));
                }
            }
            LiabilityClaimAdjudicationOutcome::PartialSettlement => {
                let awarded_amount = self.awarded_amount.as_ref().ok_or_else(|| {
                    MarketError::field_invalid(
                        "partial_settlement adjudications require awarded_amount",
                    )
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(MarketError::currency_mismatch(
                        "awarded_amount currency must match claim_amount currency",
                    ));
                }
                if awarded_amount.units >= claim_amount.units {
                    return Err(MarketError::amount_out_of_bounds(
                        "partial_settlement awarded_amount must be less than claim_amount",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Fail-closed adjudication policy gate (ADR-0015).
    ///
    /// Requires the adjudicator to be an exact (trimmed) member of the
    /// operator-supplied predeclared `roster`, requires `decision_rule_ref` to
    /// be present and a member of `allowed_decision_rules`, and requires the
    /// recorded `roster_anchor_ref` to equal `roster_anchor` (the id/hash of the
    /// signed roster artifact the `roster` was drawn from). Callers pass concrete
    /// values so `chio-market` needs no dependency on the roster's source crate.
    pub fn validate_against_roster(
        &self,
        roster: &[String],
        allowed_decision_rules: &[String],
        roster_anchor: &str,
    ) -> Result<(), MarketError> {
        let adjudicator = self.adjudicator.trim();
        if !roster.iter().any(|entry| entry.trim() == adjudicator) {
            return Err(MarketError::binding_mismatch(format!(
                "adjudicator \"{adjudicator}\" is not on the predeclared roster"
            )));
        }
        let rule = self
            .decision_rule_ref
            .as_ref()
            .map(|rule| rule.trim())
            .filter(|rule| !rule.is_empty())
            .ok_or_else(|| {
                MarketError::field_invalid("adjudication is missing a decision_rule_ref")
            })?;
        if !allowed_decision_rules
            .iter()
            .any(|allowed| allowed.trim() == rule)
        {
            return Err(MarketError::binding_mismatch(format!(
                "decision_rule_ref \"{rule}\" is not an allowed decision rule"
            )));
        }
        let recorded_anchor = self
            .roster_anchor_ref
            .as_ref()
            .map(|anchor| anchor.trim())
            .filter(|anchor| !anchor.is_empty())
            .ok_or_else(|| {
                MarketError::field_invalid("adjudication is missing a roster_anchor_ref")
            })?;
        if recorded_anchor != roster_anchor.trim() {
            return Err(MarketError::binding_mismatch(format!("roster_anchor_ref \"{recorded_anchor}\" does not match the applied roster anchor \"{}\"",
                roster_anchor.trim())));
        }
        Ok(())
    }
}

/// Signed claim adjudication envelope.
pub type SignedLiabilityClaimAdjudication =
    SignedExportEnvelope<LiabilityClaimAdjudicationArtifact>;
