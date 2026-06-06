use serde::{Deserialize, Serialize};

use crate::authority::{
    ensure_open_market_issue_authority_signers, verify_signed_activation, verify_signed_case,
    verify_signed_charter, verify_signed_fee_schedule, verify_signed_listing,
};
use crate::canonical_json_bytes;
use crate::capability::MonetaryAmount;
use crate::crypto::{sha256_hex, PublicKey};
use crate::evidence::OpenMarketEvidenceReference;
use crate::fee_schedule::{OpenMarketBondClass, SignedOpenMarketFeeSchedule};
use crate::governance::generic::{SignedGenericGovernanceCase, SignedGenericGovernanceCharter};
use crate::listing::{SignedGenericListing, SignedGenericTrustActivation};
use crate::receipt::SignedExportEnvelope;
use crate::validation::{validate_monetary_amount, validate_non_empty};

pub const OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA: &str = "chio.registry.market-penalty.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketAbuseClass {
    SpamPublication,
    FraudulentListing,
    ReplayPublication,
    UnverifiableListingBehavior,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketPenaltyAction {
    HoldBond,
    SlashBond,
    ReverseSlash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketPenaltyState {
    Proposed,
    Enforced,
    Reversed,
    Denied,
    Superseded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketPenaltyEffectiveState {
    Clear,
    BondHeld,
    BondSlashed,
    Reversed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyArtifact {
    pub schema: String,
    pub penalty_id: String,
    pub fee_schedule_id: String,
    pub charter_id: String,
    pub case_id: String,
    pub governing_operator_id: String,
    pub namespace: String,
    pub listing_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_operator_id: Option<String>,
    pub abuse_class: OpenMarketAbuseClass,
    pub bond_class: OpenMarketBondClass,
    pub action: OpenMarketPenaltyAction,
    pub state: OpenMarketPenaltyState,
    pub penalty_amount: MonetaryAmount,
    pub opened_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub evidence_refs: Vec<OpenMarketEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_penalty_id: Option<String>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketPenaltyArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported open-market penalty schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.penalty_id, "penalty_id")?;
        validate_non_empty(&self.fee_schedule_id, "fee_schedule_id")?;
        validate_non_empty(&self.charter_id, "charter_id")?;
        validate_non_empty(&self.case_id, "case_id")?;
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.listing_id, "listing_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        validate_monetary_amount(&self.penalty_amount, "penalty_amount")?;
        if self.updated_at < self.opened_at {
            return Err("updated_at must be greater than or equal to opened_at".to_string());
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.opened_at {
                return Err("expires_at must be greater than opened_at".to_string());
            }
        }
        if self.evidence_refs.is_empty() {
            return Err("evidence_refs must not be empty".to_string());
        }
        for (index, evidence_ref) in self.evidence_refs.iter().enumerate() {
            evidence_ref.validate(&format!("evidence_refs[{index}]"))?;
        }
        if matches!(self.action, OpenMarketPenaltyAction::ReverseSlash) {
            if self.supersedes_penalty_id.as_deref().is_none() {
                return Err("reverse_slash penalty requires supersedes_penalty_id".to_string());
            }
            if !matches!(self.state, OpenMarketPenaltyState::Reversed) {
                return Err("reverse_slash penalty must use reversed state".to_string());
            }
        }
        Ok(())
    }
}

pub type SignedOpenMarketPenalty = SignedExportEnvelope<OpenMarketPenaltyArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyIssueRequest {
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub charter: SignedGenericGovernanceCharter,
    pub case: SignedGenericGovernanceCase,
    pub listing: SignedGenericListing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    pub abuse_class: OpenMarketAbuseClass,
    pub bond_class: OpenMarketBondClass,
    pub action: OpenMarketPenaltyAction,
    pub state: OpenMarketPenaltyState,
    pub penalty_amount: MonetaryAmount,
    pub evidence_refs: Vec<OpenMarketEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_penalty_id: Option<String>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketPenaltyIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        verify_signed_listing(&self.listing, "penalty listing")?;
        verify_signed_fee_schedule(&self.fee_schedule)?;
        verify_signed_charter(&self.charter)?;
        verify_signed_case(&self.case)?;
        if let Some(activation) = self.activation.as_ref() {
            verify_signed_activation(activation)?;
        }
        validate_non_empty(&self.issued_by, "issued_by")?;
        validate_monetary_amount(&self.penalty_amount, "penalty_amount")?;
        if self.evidence_refs.is_empty() {
            return Err("evidence_refs must not be empty".to_string());
        }
        for (index, evidence_ref) in self.evidence_refs.iter().enumerate() {
            evidence_ref.validate(&format!("evidence_refs[{index}]"))?;
        }
        Ok(())
    }
}

pub fn build_open_market_penalty_artifact(
    local_operator_id: &str,
    request: &OpenMarketPenaltyIssueRequest,
    issued_at: u64,
    trusted_local_operator_signer: &PublicKey,
) -> Result<OpenMarketPenaltyArtifact, String> {
    build_open_market_penalty_artifact_with_trusted_signers(
        local_operator_id,
        request,
        issued_at,
        std::slice::from_ref(trusted_local_operator_signer),
    )
}

pub fn build_open_market_penalty_artifact_with_trusted_signers(
    local_operator_id: &str,
    request: &OpenMarketPenaltyIssueRequest,
    issued_at: u64,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyArtifact, String> {
    request.validate()?;
    ensure_open_market_issue_authority_signers(request, trusted_local_operator_signers)?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    if request.fee_schedule.body.governing_operator_id != local_operator_id
        || request.charter.body.governing_operator_id != local_operator_id
        || request.case.body.governing_operator_id != local_operator_id
    {
        return Err(
            "open-market penalty must be issued by the fee schedule and governance authority operator"
                .to_string(),
        );
    }
    if request
        .activation
        .as_ref()
        .is_some_and(|activation| activation.body.local_operator_id != local_operator_id)
    {
        return Err(
            "open-market penalties must use a trust activation issued by the governing operator"
                .to_string(),
        );
    }
    let opened_at = request.opened_at.unwrap_or(issued_at);
    let updated_at = request.updated_at.unwrap_or(opened_at);
    let penalty_id = format!(
        "market-penalty-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                &request.fee_schedule.body.fee_schedule_id,
                &request.case.body.case_id,
                &request.listing.body.listing_id,
                request.bond_class,
                request.action,
                request.state,
                opened_at,
                &request.supersedes_penalty_id,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = OpenMarketPenaltyArtifact {
        schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_string(),
        penalty_id,
        fee_schedule_id: request.fee_schedule.body.fee_schedule_id.clone(),
        charter_id: request.charter.body.charter_id.clone(),
        case_id: request.case.body.case_id.clone(),
        governing_operator_id: local_operator_id.to_string(),
        namespace: request.listing.body.namespace.clone(),
        listing_id: request.listing.body.listing_id.clone(),
        activation_id: request
            .activation
            .as_ref()
            .map(|activation| activation.body.activation_id.clone()),
        subject_operator_id: request.subject_operator_id.clone(),
        abuse_class: request.abuse_class,
        bond_class: request.bond_class,
        action: request.action,
        state: request.state,
        penalty_amount: request.penalty_amount.clone(),
        opened_at,
        updated_at,
        expires_at: request.expires_at,
        evidence_refs: request.evidence_refs.clone(),
        supersedes_penalty_id: request.supersedes_penalty_id.clone(),
        issued_by: request.issued_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}
