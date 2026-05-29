//! Liability claim package, response, dispute, and adjudication artifacts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::MonetaryAmount;
use crate::credit::{SignedCreditBond, SignedCreditLossLifecycle, SignedExposureLedgerReport};
use crate::receipt::SignedExportEnvelope;

use crate::{validate_positive_money, verify_signed_artifact, SignedLiabilityBoundCoverage};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimResponseDisposition {
    Acknowledged,
    Accepted,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimAdjudicationOutcome {
    ClaimUpheld,
    ProviderUpheld,
    PartialSettlement,
}

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
    pub fn validate(&self) -> Result<(), String> {
        verify_signed_artifact(&self.bound_coverage, "claim package bound_coverage")?;
        verify_signed_artifact(&self.exposure, "claim package exposure")?;
        verify_signed_artifact(&self.bond, "claim package bond")?;
        verify_signed_artifact(&self.loss_event, "claim package loss_event")?;
        if self.claimant.trim().is_empty() {
            return Err("claim packages require a non-empty claimant".to_string());
        }
        if self.narrative.trim().is_empty() {
            return Err("claim packages require a non-empty narrative".to_string());
        }
        if self.receipt_ids.is_empty() {
            return Err("claim packages require at least one receipt reference".to_string());
        }
        let mut deduped_receipts = BTreeSet::new();
        for receipt_id in &self.receipt_ids {
            if receipt_id.trim().is_empty() {
                return Err("claim receipt references must be non-empty".to_string());
            }
            if !deduped_receipts.insert(receipt_id.trim().to_string()) {
                return Err("claim receipt references must be unique".to_string());
            }
        }
        validate_positive_money(&self.claim_amount, "claim_amount")?;
        let coverage = &self.bound_coverage.body.coverage_amount;
        if self.claim_amount.currency != coverage.currency {
            return Err("claim_amount currency must match bound coverage currency".to_string());
        }
        if self.claim_amount.units > coverage.units {
            return Err("claim_amount cannot exceed bound coverage amount".to_string());
        }
        if self.claim_event_at < self.bound_coverage.body.effective_from
            || self.claim_event_at > self.bound_coverage.body.effective_until
        {
            return Err(
                "claim_event_at must fall within the bound coverage effective window".to_string(),
            );
        }
        if self.exposure.body.summary.mixed_currency_book {
            return Err(
                "claim packages require exposure evidence without mixed-currency ambiguity"
                    .to_string(),
            );
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
            return Err(
                "claim exposure evidence must match the bound coverage subject".to_string(),
            );
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
            return Err("claim bond evidence must match the bound coverage subject".to_string());
        }
        if self.loss_event.body.bond_id != self.bond.body.bond_id {
            return Err("claim loss evidence must reference the same bond".to_string());
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
            return Err("claim loss evidence must match the bound coverage subject".to_string());
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimPackage = SignedExportEnvelope<LiabilityClaimPackageArtifact>;

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
    pub fn validate(&self) -> Result<(), String> {
        verify_signed_artifact(&self.claim, "claim response claim")?;
        self.claim.body.validate()?;
        if self.provider_response_ref.trim().is_empty() {
            return Err("claim responses require a non-empty provider_response_ref".to_string());
        }
        match self.disposition {
            LiabilityClaimResponseDisposition::Acknowledged => {
                if self.covered_amount.is_some() {
                    return Err(
                        "acknowledged claim responses cannot include covered_amount".to_string()
                    );
                }
                if self.denial_reason.is_some() {
                    return Err(
                        "acknowledged claim responses cannot include denial_reason".to_string()
                    );
                }
            }
            LiabilityClaimResponseDisposition::Accepted => {
                let covered_amount = self
                    .covered_amount
                    .as_ref()
                    .ok_or_else(|| "accepted claim responses require covered_amount".to_string())?;
                validate_positive_money(covered_amount, "covered_amount")?;
                if covered_amount.currency != self.claim.body.claim_amount.currency {
                    return Err(
                        "covered_amount currency must match claim_amount currency".to_string()
                    );
                }
                if covered_amount.units > self.claim.body.claim_amount.units {
                    return Err("covered_amount cannot exceed claim_amount".to_string());
                }
                if self.denial_reason.is_some() {
                    return Err("accepted claim responses cannot include denial_reason".to_string());
                }
            }
            LiabilityClaimResponseDisposition::Denied => {
                if self.covered_amount.is_some() {
                    return Err("denied claim responses cannot include covered_amount".to_string());
                }
                if self
                    .denial_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    return Err("denied claim responses require denial_reason".to_string());
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimResponse = SignedExportEnvelope<LiabilityClaimResponseArtifact>;

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
    pub fn validate(&self) -> Result<(), String> {
        verify_signed_artifact(&self.provider_response, "claim dispute provider_response")?;
        self.provider_response.body.validate()?;
        if self.opened_by.trim().is_empty() {
            return Err("claim disputes require a non-empty opened_by".to_string());
        }
        if self.reason.trim().is_empty() {
            return Err("claim disputes require a non-empty reason".to_string());
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
            return Err(
                "claim disputes require a denied or partially accepted provider response"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimDispute = SignedExportEnvelope<LiabilityClaimDisputeArtifact>;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimAdjudicationArtifact {
    pub fn validate(&self) -> Result<(), String> {
        verify_signed_artifact(&self.dispute, "claim adjudication dispute")?;
        self.dispute.body.validate()?;
        if self.adjudicator.trim().is_empty() {
            return Err("claim adjudications require a non-empty adjudicator".to_string());
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
                    "claim_upheld adjudications require awarded_amount".to_string()
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(
                        "awarded_amount currency must match claim_amount currency".to_string()
                    );
                }
                if awarded_amount.units > claim_amount.units {
                    return Err("awarded_amount cannot exceed claim_amount".to_string());
                }
            }
            LiabilityClaimAdjudicationOutcome::ProviderUpheld => {
                if self.awarded_amount.is_some() {
                    return Err(
                        "provider_upheld adjudications cannot include awarded_amount".to_string(),
                    );
                }
            }
            LiabilityClaimAdjudicationOutcome::PartialSettlement => {
                let awarded_amount = self.awarded_amount.as_ref().ok_or_else(|| {
                    "partial_settlement adjudications require awarded_amount".to_string()
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(
                        "awarded_amount currency must match claim_amount currency".to_string()
                    );
                }
                if awarded_amount.units >= claim_amount.units {
                    return Err(
                        "partial_settlement awarded_amount must be less than claim_amount"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimAdjudication =
    SignedExportEnvelope<LiabilityClaimAdjudicationArtifact>;
