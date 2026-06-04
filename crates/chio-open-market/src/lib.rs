//! Open-market economics and penalty contracts for the Chio protocol.
//!
//! This crate models open bidding for tool access along with the bonds and
//! penalties that back it. It defines the bidding flow (`bid`, `accept`, and
//! the bid/ask/accepted-bid artifacts), bond classes and collateral
//! references, abuse classes, and penalty state machines. It builds on the
//! listing and governance surfaces in `chio-listing` and `chio-governance`.
//!
//! # Modules
//!
//! - [`bidding`] -- bid/ask/accept flow and the signed bidding artifacts.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, capability, crypto, receipt};
pub use chio_governance as governance;
pub use chio_listing as listing;

pub mod bidding;
pub use bidding::{
    accept, bid, AcceptedBid, AskResponse, BidMintContext, BidRequest, BiddingError,
    RequestedScope, SignedAcceptedBid, SignedAskResponse, SignedBidRequest, ACCEPTED_BID_SCHEMA,
    ASK_RESPONSE_SCHEMA, BID_REQUEST_SCHEMA,
};

use serde::{Deserialize, Serialize};

use crate::capability::MonetaryAmount;
use crate::crypto::{sha256_hex, PublicKey};
use crate::governance::{
    GenericGovernanceCaseKind, GenericGovernanceCaseState, SignedGenericGovernanceCase,
    SignedGenericGovernanceCharter,
};
use crate::listing::{
    ensure_generic_listing_signed_by_namespace_owner, normalize_namespace, GenericListingActorKind,
    GenericRegistryPublisher, GenericTrustAdmissionClass, SignedGenericListing,
    SignedGenericTrustActivation,
};
use crate::receipt::SignedExportEnvelope;

pub const OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA: &str = "chio.registry.market-fee-schedule.v1";
pub const OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA: &str = "chio.registry.market-penalty.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketBondClass {
    Publication,
    Listing,
    Dispute,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketCollateralReferenceKind {
    CreditBond,
    ExternalReference,
}

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketEvidenceKind {
    GovernanceCase,
    TrustActivation,
    Listing,
    PortableNegativeEvent,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketFindingCode {
    ListingUnverifiable,
    FeeScheduleUnverifiable,
    FeeScheduleExpired,
    FeeScheduleScopeMismatch,
    ActivationUnverifiable,
    ActivationMissing,
    ActivationMismatch,
    GovernanceCaseAuthorityInvalid,
    GovernanceCaseExpired,
    GovernanceCaseKindInvalid,
    PenaltyUnverifiable,
    PenaltyExpired,
    BondRequirementMissing,
    BondRequirementNotSlashable,
    PenaltyCurrencyMismatch,
    PenaltyAmountExceedsBond,
    PriorPenaltyMissing,
    PriorPenaltyInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketEconomicsScope {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_listing_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

impl OpenMarketEconomicsScope {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.namespace, "scope.namespace")?;
        for (index, operator_id) in self.allowed_listing_operator_ids.iter().enumerate() {
            validate_non_empty(
                operator_id,
                &format!("scope.allowed_listing_operator_ids[{index}]"),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketBondRequirement {
    pub bond_class: OpenMarketBondClass,
    pub required_amount: MonetaryAmount,
    pub collateral_reference_kind: OpenMarketCollateralReferenceKind,
    pub slashable: bool,
}

impl OpenMarketBondRequirement {
    pub fn validate(&self, field: &str) -> Result<(), String> {
        validate_monetary_amount(&self.required_amount, &format!("{field}.required_amount"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketFeeScheduleArtifact {
    pub schema: String,
    pub fee_schedule_id: String,
    pub namespace: String,
    pub governing_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governing_operator_name: Option<String>,
    pub scope: OpenMarketEconomicsScope,
    pub publication_fee: MonetaryAmount,
    pub dispute_fee: MonetaryAmount,
    pub market_participation_fee: MonetaryAmount,
    pub bond_requirements: Vec<OpenMarketBondRequirement>,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketFeeScheduleArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported open-market fee schedule schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.fee_schedule_id, "fee_schedule_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        self.scope.validate()?;
        if normalize_namespace(&self.namespace) != normalize_namespace(&self.scope.namespace) {
            return Err("fee schedule namespace must match scope namespace".to_string());
        }
        validate_monetary_amount(&self.publication_fee, "publication_fee")?;
        validate_monetary_amount(&self.dispute_fee, "dispute_fee")?;
        validate_monetary_amount(&self.market_participation_fee, "market_participation_fee")?;
        if self.bond_requirements.is_empty() {
            return Err("bond_requirements must not be empty".to_string());
        }
        for (index, requirement) in self.bond_requirements.iter().enumerate() {
            requirement.validate(&format!("bond_requirements[{index}]"))?;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.issued_at {
                return Err("expires_at must be greater than issued_at".to_string());
            }
        }
        Ok(())
    }
}

pub type SignedOpenMarketFeeSchedule = SignedExportEnvelope<OpenMarketFeeScheduleArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketFeeScheduleIssueRequest {
    pub scope: OpenMarketEconomicsScope,
    pub publication_fee: MonetaryAmount,
    pub dispute_fee: MonetaryAmount,
    pub market_participation_fee: MonetaryAmount,
    pub bond_requirements: Vec<OpenMarketBondRequirement>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketFeeScheduleIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.scope.validate()?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        validate_monetary_amount(&self.publication_fee, "publication_fee")?;
        validate_monetary_amount(&self.dispute_fee, "dispute_fee")?;
        validate_monetary_amount(&self.market_participation_fee, "market_participation_fee")?;
        if self.bond_requirements.is_empty() {
            return Err("bond_requirements must not be empty".to_string());
        }
        for (index, requirement) in self.bond_requirements.iter().enumerate() {
            requirement.validate(&format!("bond_requirements[{index}]"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketEvidenceReference {
    pub kind: OpenMarketEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl OpenMarketEvidenceReference {
    pub fn validate(&self, field: &str) -> Result<(), String> {
        validate_non_empty(&self.reference_id, &format!("{field}.reference_id"))?;
        if let Some(uri) = self.uri.as_deref() {
            validate_non_empty(uri, &format!("{field}.uri"))?;
        }
        if let Some(sha256) = self.sha256.as_deref() {
            let sha256_field = format!("{field}.sha256");
            if !is_sha256_hex(sha256) {
                return Err(format!(
                    "{sha256_field} must be a 64-character SHA-256 hex digest"
                ));
            }
        }
        Ok(())
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyEvaluationRequest {
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub listing: SignedGenericListing,
    pub current_publisher: GenericRegistryPublisher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    pub charter: SignedGenericGovernanceCharter,
    pub case: SignedGenericGovernanceCase,
    pub penalty: SignedOpenMarketPenalty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_penalty: Option<SignedOpenMarketPenalty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

impl OpenMarketPenaltyEvaluationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        self.current_publisher.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketFinding {
    pub code: OpenMarketFindingCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyEvaluation {
    pub listing_id: String,
    pub namespace: String,
    pub fee_schedule_id: String,
    pub charter_id: String,
    pub case_id: String,
    pub penalty_id: String,
    pub governing_operator_id: String,
    pub action: OpenMarketPenaltyAction,
    pub state: OpenMarketPenaltyState,
    pub effective_state: OpenMarketPenaltyEffectiveState,
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_participation_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_requirement: Option<OpenMarketBondRequirement>,
    pub blocks_admission: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<OpenMarketFinding>,
}

pub fn build_open_market_fee_schedule_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &OpenMarketFeeScheduleIssueRequest,
    issued_at: u64,
) -> Result<OpenMarketFeeScheduleArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    let issued_at = request.issued_at.unwrap_or(issued_at);
    let fee_schedule_id = format!(
        "market-fee-schedule-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                normalize_namespace(&request.scope.namespace),
                &request.publication_fee,
                &request.dispute_fee,
                &request.market_participation_fee,
                &request.bond_requirements,
                issued_at,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = OpenMarketFeeScheduleArtifact {
        schema: OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA.to_string(),
        fee_schedule_id,
        namespace: request.scope.namespace.clone(),
        governing_operator_id: local_operator_id.to_string(),
        governing_operator_name: local_operator_name,
        scope: request.scope.clone(),
        publication_fee: request.publication_fee.clone(),
        dispute_fee: request.dispute_fee.clone(),
        market_participation_fee: request.market_participation_fee.clone(),
        bond_requirements: request.bond_requirements.clone(),
        issued_at,
        expires_at: request.expires_at,
        issued_by: request.issued_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
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

pub fn evaluate_open_market_penalty(
    request: &OpenMarketPenaltyEvaluationRequest,
    now: u64,
    trusted_local_operator_signer: &PublicKey,
) -> Result<OpenMarketPenaltyEvaluation, String> {
    evaluate_open_market_penalty_with_trusted_signers(
        request,
        now,
        std::slice::from_ref(trusted_local_operator_signer),
    )
}

pub fn evaluate_open_market_penalty_with_trusted_signers(
    request: &OpenMarketPenaltyEvaluationRequest,
    now: u64,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyEvaluation, String> {
    request.validate()?;
    let evaluated_at = request.evaluated_at.unwrap_or(now);

    if let Err(error) = verify_signed_listing(&request.listing, "penalty listing") {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::ListingUnverifiable,
            &error,
            None,
        ));
    }
    if let Err(error) = verify_signed_fee_schedule(&request.fee_schedule) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleUnverifiable,
            &error,
            None,
        ));
    }
    if let Some(activation) = request.activation.as_ref() {
        if let Err(error) = verify_signed_activation(activation) {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationUnverifiable,
                &error,
                Some(&request.fee_schedule.body),
            ));
        }
    }
    if let Err(error) = verify_signed_charter(&request.charter) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Err(error) = verify_signed_case(&request.case) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Err(error) = verify_signed_penalty(&request.penalty) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyUnverifiable,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        if let Err(error) = verify_signed_penalty(prior_penalty) {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::PriorPenaltyInvalid,
                &error,
                Some(&request.fee_schedule.body),
            ));
        }
    }
    if let Err(error) =
        ensure_open_market_evaluation_authority_signers(request, trusted_local_operator_signers)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }

    let listing = &request.listing.body;
    let fee_schedule = &request.fee_schedule.body;
    let charter = &request.charter.body;
    let governance_case = &request.case.body;
    let penalty = &request.penalty.body;
    let namespace = normalize_namespace(&listing.namespace);

    if let Some(activation) = request.activation.as_ref() {
        if activation.body.local_operator_id != fee_schedule.governing_operator_id {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "open-market penalties require a trust activation issued by the governing operator",
                Some(fee_schedule),
            ));
        }
    }

    if normalize_namespace(&fee_schedule.namespace) != namespace
        || normalize_namespace(&fee_schedule.scope.namespace) != namespace
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "fee schedule namespace does not match the current listing namespace",
            Some(fee_schedule),
        ));
    }
    if normalize_namespace(&charter.authority_scope.namespace) != namespace
        || normalize_namespace(&governance_case.namespace) != namespace
        || normalize_namespace(&penalty.namespace) != namespace
        || governance_case.listing_id != listing.listing_id
        || penalty.listing_id != listing.listing_id
        || penalty.case_id != governance_case.case_id
        || penalty.charter_id != charter.charter_id
        || penalty.fee_schedule_id != fee_schedule.fee_schedule_id
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            "governance or penalty authority does not match the current listing, namespace, or fee schedule",
            Some(fee_schedule),
        ));
    }
    if fee_schedule.governing_operator_id != charter.governing_operator_id
        || fee_schedule.governing_operator_id != governance_case.governing_operator_id
        || fee_schedule.governing_operator_id != penalty.governing_operator_id
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            "fee schedule, governance, and penalty operators must match",
            Some(fee_schedule),
        ));
    }

    if fee_schedule
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleExpired,
            "open-market fee schedule has expired",
            Some(fee_schedule),
        ));
    }
    if charter
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
        || governance_case
            .expires_at
            .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseExpired,
            "governance authority has expired",
            Some(fee_schedule),
        ));
    }
    if penalty
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyExpired,
            "open-market penalty has expired",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_listing_operator_ids.is_empty()
        && !fee_schedule
            .scope
            .allowed_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "current listing publisher falls outside the fee schedule scope",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_actor_kinds.is_empty()
        && !fee_schedule
            .scope
            .allowed_actor_kinds
            .contains(&listing.subject.actor_kind)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "listing actor kind falls outside the fee schedule scope",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_admission_classes.is_empty() {
        let Some(activation) = request.activation.as_ref() else {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMissing,
                "fee schedule requires an explicit trust activation class",
                Some(fee_schedule),
            ));
        };
        if governance_case.activation_id.as_deref() != Some(activation.body.activation_id.as_str())
            || penalty.activation_id.as_deref() != Some(activation.body.activation_id.as_str())
        {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "governance case or penalty activation does not match the current trust activation",
                Some(fee_schedule),
            ));
        }
        if !fee_schedule
            .scope
            .allowed_admission_classes
            .contains(&activation.body.admission_class)
        {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "trust activation admission class falls outside the fee schedule scope",
                Some(fee_schedule),
            ));
        }
    }

    let bond_requirement = fee_schedule
        .bond_requirements
        .iter()
        .find(|requirement| requirement.bond_class == penalty.bond_class)
        .cloned();
    let Some(bond_requirement) = bond_requirement else {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::BondRequirementMissing,
            "fee schedule does not define the required bond class for this penalty",
            Some(fee_schedule),
        ));
    };

    match penalty.action {
        OpenMarketPenaltyAction::HoldBond | OpenMarketPenaltyAction::SlashBond => {
            if !matches!(
                (governance_case.kind, governance_case.state),
                (
                    GenericGovernanceCaseKind::Sanction,
                    GenericGovernanceCaseState::Enforced
                )
            ) {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::GovernanceCaseKindInvalid,
                    "bond hold or slash requires an enforced sanction case",
                    Some(fee_schedule),
                ));
            }
            if matches!(penalty.action, OpenMarketPenaltyAction::SlashBond)
                && !bond_requirement.slashable
            {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::BondRequirementNotSlashable,
                    "selected bond requirement is not slashable",
                    Some(fee_schedule),
                ));
            }
        }
        OpenMarketPenaltyAction::ReverseSlash => {
            if !matches!(governance_case.kind, GenericGovernanceCaseKind::Appeal) {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::GovernanceCaseKindInvalid,
                    "reverse slash requires an appeal governance case",
                    Some(fee_schedule),
                ));
            }
            let Some(prior_penalty) = request.prior_penalty.as_ref() else {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyMissing,
                    "reverse slash requires prior_penalty",
                    Some(fee_schedule),
                ));
            };
            let Some(supersedes_penalty_id) = penalty.supersedes_penalty_id.as_deref() else {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyInvalid,
                    "reverse slash must reference the prior penalty id",
                    Some(fee_schedule),
                ));
            };
            if prior_penalty.body.penalty_id != supersedes_penalty_id
                || prior_penalty.body.listing_id != listing.listing_id
                || prior_penalty.body.fee_schedule_id != fee_schedule.fee_schedule_id
                || prior_penalty.body.bond_class != penalty.bond_class
                || !matches!(
                    prior_penalty.body.action,
                    OpenMarketPenaltyAction::HoldBond | OpenMarketPenaltyAction::SlashBond
                )
                || !matches!(prior_penalty.body.state, OpenMarketPenaltyState::Enforced)
            {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyInvalid,
                    "prior penalty does not match the reverse-slash target",
                    Some(fee_schedule),
                ));
            }
        }
    }

    if bond_requirement.required_amount.currency != penalty.penalty_amount.currency {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyCurrencyMismatch,
            "penalty currency must match the configured bond currency",
            Some(fee_schedule),
        ));
    }
    if penalty.penalty_amount.units > bond_requirement.required_amount.units {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyAmountExceedsBond,
            "penalty amount exceeds the configured bond requirement",
            Some(fee_schedule),
        ));
    }

    let (effective_state, blocks_admission) =
        open_market_effective_state(penalty.action, penalty.state);

    Ok(OpenMarketPenaltyEvaluation {
        listing_id: listing.listing_id.clone(),
        namespace,
        fee_schedule_id: fee_schedule.fee_schedule_id.clone(),
        charter_id: charter.charter_id.clone(),
        case_id: governance_case.case_id.clone(),
        penalty_id: penalty.penalty_id.clone(),
        governing_operator_id: penalty.governing_operator_id.clone(),
        action: penalty.action,
        state: penalty.state,
        effective_state,
        evaluated_at,
        publication_fee: Some(fee_schedule.publication_fee.clone()),
        dispute_fee: Some(fee_schedule.dispute_fee.clone()),
        market_participation_fee: Some(fee_schedule.market_participation_fee.clone()),
        bond_requirement: Some(bond_requirement),
        blocks_admission,
        findings: Vec::new(),
    })
}

fn open_market_effective_state(
    action: OpenMarketPenaltyAction,
    state: OpenMarketPenaltyState,
) -> (OpenMarketPenaltyEffectiveState, bool) {
    match state {
        OpenMarketPenaltyState::Proposed
        | OpenMarketPenaltyState::Denied
        | OpenMarketPenaltyState::Superseded => (OpenMarketPenaltyEffectiveState::Clear, false),
        OpenMarketPenaltyState::Reversed => (OpenMarketPenaltyEffectiveState::Reversed, false),
        OpenMarketPenaltyState::Enforced => match action {
            OpenMarketPenaltyAction::HoldBond => (OpenMarketPenaltyEffectiveState::BondHeld, true),
            OpenMarketPenaltyAction::SlashBond => {
                (OpenMarketPenaltyEffectiveState::BondSlashed, true)
            }
            OpenMarketPenaltyAction::ReverseSlash => {
                (OpenMarketPenaltyEffectiveState::Reversed, false)
            }
        },
    }
}

fn open_market_failure(
    request: &OpenMarketPenaltyEvaluationRequest,
    evaluated_at: u64,
    code: OpenMarketFindingCode,
    message: &str,
    fee_schedule: Option<&OpenMarketFeeScheduleArtifact>,
) -> OpenMarketPenaltyEvaluation {
    OpenMarketPenaltyEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        fee_schedule_id: request.penalty.body.fee_schedule_id.clone(),
        charter_id: request.penalty.body.charter_id.clone(),
        case_id: request.penalty.body.case_id.clone(),
        penalty_id: request.penalty.body.penalty_id.clone(),
        governing_operator_id: request.penalty.body.governing_operator_id.clone(),
        action: request.penalty.body.action,
        state: request.penalty.body.state,
        effective_state: OpenMarketPenaltyEffectiveState::Clear,
        evaluated_at,
        publication_fee: fee_schedule.map(|schedule| schedule.publication_fee.clone()),
        dispute_fee: fee_schedule.map(|schedule| schedule.dispute_fee.clone()),
        market_participation_fee: fee_schedule
            .map(|schedule| schedule.market_participation_fee.clone()),
        bond_requirement: None,
        blocks_admission: false,
        findings: vec![OpenMarketFinding {
            code,
            message: message.to_string(),
        }],
    }
}

fn verify_signed_listing(listing: &SignedGenericListing, label: &str) -> Result<(), String> {
    ensure_generic_listing_signed_by_namespace_owner(listing, label)
}

fn verify_signed_activation(activation: &SignedGenericTrustActivation) -> Result<(), String> {
    activation.body.validate()?;
    if !activation
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("trust activation signature is invalid".to_string());
    }
    Ok(())
}

fn verify_signed_charter(charter: &SignedGenericGovernanceCharter) -> Result<(), String> {
    charter.body.validate()?;
    if !charter
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("governance charter signature is invalid".to_string());
    }
    Ok(())
}

fn verify_signed_case(case: &SignedGenericGovernanceCase) -> Result<(), String> {
    case.body.validate()?;
    if !case.verify_signature().map_err(|error| error.to_string())? {
        return Err("governance case signature is invalid".to_string());
    }
    Ok(())
}

fn verify_signed_fee_schedule(schedule: &SignedOpenMarketFeeSchedule) -> Result<(), String> {
    schedule.body.validate()?;
    if !schedule
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("fee schedule signature is invalid".to_string());
    }
    Ok(())
}

fn verify_signed_penalty(penalty: &SignedOpenMarketPenalty) -> Result<(), String> {
    penalty.body.validate()?;
    if !penalty
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("penalty signature is invalid".to_string());
    }
    Ok(())
}

fn ensure_open_market_issue_authority_signers(
    request: &OpenMarketPenaltyIssueRequest,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    ensure_matching_signer_key(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key(
        "governance charter",
        &request.charter.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key("governance case", &request.case.signer_key, trusted_signers)?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_matching_signer_key("trust activation", &activation.signer_key, trusted_signers)?;
    }
    Ok(())
}

fn ensure_open_market_evaluation_authority_signers(
    request: &OpenMarketPenaltyEvaluationRequest,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    ensure_matching_signer_key(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key(
        "governance charter",
        &request.charter.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key("governance case", &request.case.signer_key, trusted_signers)?;
    ensure_matching_signer_key("penalty", &request.penalty.signer_key, trusted_signers)?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_matching_signer_key("trust activation", &activation.signer_key, trusted_signers)?;
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        ensure_matching_signer_key("prior penalty", &prior_penalty.signer_key, trusted_signers)?;
    }
    Ok(())
}

fn ensure_matching_signer_key(
    label: &str,
    signer_key: &PublicKey,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    if !trusted_signers
        .iter()
        .any(|trusted_signer| trusted_signer == signer_key)
    {
        return Err(format!(
            "{label} signer does not match a trusted open-market governing authority signer"
        ));
    }
    Ok(())
}

fn validate_monetary_amount(value: &MonetaryAmount, field: &str) -> Result<(), String> {
    if value.units == 0 {
        return Err(format!("{field}.units must be greater than zero"));
    }
    validate_non_empty(&value.currency, &format!("{field}.currency"))
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::governance::{
        build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
        GenericGovernanceAuthorityScope, GenericGovernanceCaseIssueRequest,
        GenericGovernanceCharterIssueRequest, GenericGovernanceEvidenceKind,
        GenericGovernanceEvidenceReference,
    };
    use crate::listing::{
        build_generic_trust_activation_artifact, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceArtifact, GenericNamespaceLifecycleState, GenericNamespaceOwnership,
        GenericRegistryPublisher, GenericRegistryPublisherRole, GenericTrustActivationDisposition,
        GenericTrustActivationEligibility, GenericTrustActivationIssueRequest,
        GenericTrustActivationReviewContext, GENERIC_LISTING_ARTIFACT_SCHEMA,
        GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
    };

    use chio_test_support::prelude::*;

    fn sample_listing(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericListing {
        let namespace = GenericNamespaceArtifact {
            schema: GENERIC_NAMESPACE_ARTIFACT_SCHEMA.to_string(),
            namespace_id: "namespace-registry-chio-example".to_string(),
            lifecycle_state: GenericNamespaceLifecycleState::Active,
            ownership: GenericNamespaceOwnership {
                namespace: "https://registry.chio.example".to_string(),
                owner_id: owner_id.to_string(),
                owner_name: Some("Registry Operator".to_string()),
                registry_url: "https://registry.chio.example".to_string(),
                signer_public_key: signing_keypair.public_key(),
                registered_at: 100,
                transferred_from_owner_id: None,
            },
            boundary: GenericListingBoundary::default(),
        };
        let listing = GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: "listing-demo".to_string(),
            namespace: namespace.ownership.namespace.clone(),
            published_at: 200,
            expires_at: Some(500),
            status: GenericListingStatus::Active,
            namespace_ownership: namespace.ownership.clone(),
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: "demo-server".to_string(),
                display_name: Some("Demo Server".to_string()),
                metadata_url: Some("https://registry.chio.example/servers/demo".to_string()),
                resolution_url: None,
                homepage_url: None,
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: "cert-check-demo".to_string(),
                source_artifact_sha256: "sha256-demo".to_string(),
            },
            boundary: GenericListingBoundary::default(),
        };
        SignedGenericListing::sign(listing, signing_keypair).test_expect("sign listing")
    }

    fn sample_publisher(owner_id: &str) -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: owner_id.to_string(),
            operator_name: Some("Registry Operator".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn sample_activation(
        owner_id: &str,
        signing_keypair: &Keypair,
        listing: &SignedGenericListing,
    ) -> SignedGenericTrustActivation {
        let artifact = build_generic_trust_activation_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &GenericTrustActivationIssueRequest {
                listing: listing.clone(),
                admission_class: GenericTrustAdmissionClass::BondBacked,
                disposition: GenericTrustActivationDisposition::Approved,
                eligibility: GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                    allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                    allowed_statuses: vec![GenericListingStatus::Active],
                    require_fresh_listing: true,
                    require_bond_backing: true,
                    required_listing_operator_ids: vec![owner_id.to_string()],
                    policy_reference: Some("policy/open-market/default".to_string()),
                },
                review_context: GenericTrustActivationReviewContext {
                    publisher: sample_publisher(owner_id),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 0,
                        max_age_secs: 300,
                        valid_until: 500,
                        generated_at: 200,
                    },
                },
                requested_by: "ops@chio.example".to_string(),
                reviewed_by: Some("reviewer@chio.example".to_string()),
                requested_at: Some(200),
                reviewed_at: Some(201),
                expires_at: Some(450),
                note: None,
            },
            200,
        )
        .test_expect("build activation");
        SignedGenericTrustActivation::sign(artifact, signing_keypair).test_expect("sign activation")
    }

    fn sample_charter(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericGovernanceCharter {
        let artifact = build_generic_governance_charter_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &GenericGovernanceCharterIssueRequest {
                authority_scope: GenericGovernanceAuthorityScope {
                    namespace: "https://registry.chio.example".to_string(),
                    allowed_listing_operator_ids: vec![owner_id.to_string()],
                    allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                    policy_reference: Some("policy/governance/default".to_string()),
                },
                allowed_case_kinds: vec![
                    GenericGovernanceCaseKind::Sanction,
                    GenericGovernanceCaseKind::Appeal,
                ],
                escalation_operator_ids: Vec::new(),
                issued_by: "governance@chio.example".to_string(),
                issued_at: Some(202),
                expires_at: Some(600),
                note: None,
            },
            202,
        )
        .test_expect("build charter");
        SignedGenericGovernanceCharter::sign(artifact, signing_keypair).test_expect("sign charter")
    }

    fn sample_sanction_case(
        owner_id: &str,
        signing_keypair: &Keypair,
        listing: &SignedGenericListing,
        activation: &SignedGenericTrustActivation,
        charter: &SignedGenericGovernanceCharter,
    ) -> SignedGenericGovernanceCase {
        let artifact = build_generic_governance_case_artifact(
            owner_id,
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                kind: GenericGovernanceCaseKind::Sanction,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some(owner_id.to_string()),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::TrustActivation,
                    reference_id: activation.body.activation_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: None,
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                opened_at: Some(203),
                updated_at: Some(203),
                expires_at: Some(500),
                note: None,
            },
            203,
        )
        .test_expect("build case");
        SignedGenericGovernanceCase::sign(artifact, signing_keypair).test_expect("sign case")
    }

    fn sample_fee_schedule(
        owner_id: &str,
        signing_keypair: &Keypair,
    ) -> SignedOpenMarketFeeSchedule {
        let artifact = build_open_market_fee_schedule_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &OpenMarketFeeScheduleIssueRequest {
                scope: OpenMarketEconomicsScope {
                    namespace: "https://registry.chio.example".to_string(),
                    allowed_listing_operator_ids: vec![owner_id.to_string()],
                    allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                    allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                    policy_reference: Some("policy/open-market/default".to_string()),
                },
                publication_fee: MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                },
                dispute_fee: MonetaryAmount {
                    units: 2500,
                    currency: "USD".to_string(),
                },
                market_participation_fee: MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                },
                bond_requirements: vec![OpenMarketBondRequirement {
                    bond_class: OpenMarketBondClass::Listing,
                    required_amount: MonetaryAmount {
                        units: 5000,
                        currency: "USD".to_string(),
                    },
                    collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                    slashable: true,
                }],
                issued_by: "market@chio.example".to_string(),
                issued_at: Some(202),
                expires_at: Some(600),
                note: None,
            },
            202,
        )
        .test_expect("build fee schedule");
        SignedOpenMarketFeeSchedule::sign(artifact, signing_keypair)
            .test_expect("sign fee schedule")
    }

    fn sample_penalty_issue_request(
        owner_id: &str,
        fee_schedule: SignedOpenMarketFeeSchedule,
        charter: SignedGenericGovernanceCharter,
        case: SignedGenericGovernanceCase,
        listing: SignedGenericListing,
        activation: Option<SignedGenericTrustActivation>,
    ) -> OpenMarketPenaltyIssueRequest {
        OpenMarketPenaltyIssueRequest {
            fee_schedule,
            charter,
            case,
            listing,
            activation,
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::SlashBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: "case-ref".to_string(),
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        }
    }

    #[test]
    fn open_market_evaluation_applies_fee_schedule_and_slash_penalty() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &OpenMarketPenaltyIssueRequest {
                fee_schedule: fee_schedule.clone(),
                charter: charter.clone(),
                case: governance_case.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::SlashBond,
                state: OpenMarketPenaltyState::Enforced,
                penalty_amount: MonetaryAmount {
                    units: 2500,
                    currency: "USD".to_string(),
                },
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::GovernanceCase,
                    reference_id: governance_case.body.case_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                subject_operator_id: Some(owner_id.to_string()),
                supersedes_penalty_id: None,
                issued_by: "market@chio.example".to_string(),
                opened_at: Some(204),
                updated_at: Some(204),
                expires_at: Some(500),
                note: None,
            },
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
            .test_expect("sign penalty");

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(activation),
                charter,
                case: governance_case,
                penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(
            evaluation.effective_state,
            OpenMarketPenaltyEffectiveState::BondSlashed
        );
        assert!(evaluation.blocks_admission);
        assert!(evaluation.findings.is_empty());
        assert_eq!(
            evaluation
                .publication_fee
                .as_ref()
                .test_expect("publication fee")
                .units,
            100
        );
        assert_eq!(
            evaluation
                .bond_requirement
                .as_ref()
                .test_expect("bond requirement")
                .bond_class,
            OpenMarketBondClass::Listing
        );
    }

    #[test]
    fn open_market_penalty_issue_accepts_rotated_trusted_authority_signers() {
        let previous_keypair = Keypair::from_seed(&[7_u8; 32]);
        let current_keypair = Keypair::from_seed(&[8_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &previous_keypair);
        let activation = sample_activation(owner_id, &current_keypair, &listing);
        let charter = sample_charter(owner_id, &current_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &current_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &previous_keypair);
        let request = sample_penalty_issue_request(
            owner_id,
            fee_schedule,
            charter,
            governance_case,
            listing,
            Some(activation),
        );

        let artifact = build_open_market_penalty_artifact_with_trusted_signers(
            owner_id,
            &request,
            204,
            &[previous_keypair.public_key(), current_keypair.public_key()],
        )
        .test_expect("rotated trusted signer set should issue penalty");

        assert_eq!(artifact.governing_operator_id, owner_id);
    }

    #[test]
    fn open_market_evaluation_rejects_expired_fee_schedule() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let mut fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        fee_schedule.body.expires_at = Some(204);
        let fee_schedule = SignedOpenMarketFeeSchedule::sign(fee_schedule.body, &signing_keypair)
            .test_expect("resign");
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &OpenMarketPenaltyIssueRequest {
                fee_schedule: fee_schedule.clone(),
                charter: charter.clone(),
                case: governance_case.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::HoldBond,
                state: OpenMarketPenaltyState::Enforced,
                penalty_amount: MonetaryAmount {
                    units: 1000,
                    currency: "USD".to_string(),
                },
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::GovernanceCase,
                    reference_id: governance_case.body.case_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                subject_operator_id: Some(owner_id.to_string()),
                supersedes_penalty_id: None,
                issued_by: "market@chio.example".to_string(),
                opened_at: Some(204),
                updated_at: Some(204),
                expires_at: Some(500),
                note: None,
            },
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
            .test_expect("sign penalty");

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(activation),
                charter,
                case: governance_case,
                penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(
            evaluation.findings[0].code,
            OpenMarketFindingCode::FeeScheduleExpired
        );
    }

    #[test]
    fn open_market_evaluation_rejects_missing_bond_requirement() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let artifact = build_open_market_fee_schedule_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &OpenMarketFeeScheduleIssueRequest {
                scope: OpenMarketEconomicsScope {
                    namespace: "https://registry.chio.example".to_string(),
                    allowed_listing_operator_ids: vec![owner_id.to_string()],
                    allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                    allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                    policy_reference: Some("policy/open-market/default".to_string()),
                },
                publication_fee: MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                },
                dispute_fee: MonetaryAmount {
                    units: 2500,
                    currency: "USD".to_string(),
                },
                market_participation_fee: MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                },
                bond_requirements: vec![OpenMarketBondRequirement {
                    bond_class: OpenMarketBondClass::Dispute,
                    required_amount: MonetaryAmount {
                        units: 5000,
                        currency: "USD".to_string(),
                    },
                    collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                    slashable: true,
                }],
                issued_by: "market@chio.example".to_string(),
                issued_at: Some(202),
                expires_at: Some(600),
                note: None,
            },
            202,
        )
        .test_expect("build fee schedule");
        let fee_schedule = SignedOpenMarketFeeSchedule::sign(artifact, &signing_keypair)
            .test_expect("sign fee schedule");
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &OpenMarketPenaltyIssueRequest {
                fee_schedule: fee_schedule.clone(),
                charter: charter.clone(),
                case: governance_case.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::HoldBond,
                state: OpenMarketPenaltyState::Enforced,
                penalty_amount: MonetaryAmount {
                    units: 1000,
                    currency: "USD".to_string(),
                },
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::GovernanceCase,
                    reference_id: governance_case.body.case_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                subject_operator_id: Some(owner_id.to_string()),
                supersedes_penalty_id: None,
                issued_by: "market@chio.example".to_string(),
                opened_at: Some(204),
                updated_at: Some(204),
                expires_at: Some(500),
                note: None,
            },
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
            .test_expect("sign penalty");

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(activation),
                charter,
                case: governance_case,
                penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(
            evaluation.findings[0].code,
            OpenMarketFindingCode::BondRequirementMissing
        );
    }

    #[test]
    fn open_market_penalty_issue_rejects_non_local_activation_authority() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let mut forged_activation_body = activation.body.clone();
        forged_activation_body.local_operator_id = "https://remote.chio.example".to_string();
        forged_activation_body.local_operator_name = Some("Remote Operator".to_string());
        let forged_activation =
            SignedGenericTrustActivation::sign(forged_activation_body, &signing_keypair)
                .test_expect("sign forged activation");
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);

        let error = build_open_market_penalty_artifact(
            owner_id,
            &OpenMarketPenaltyIssueRequest {
                fee_schedule,
                charter,
                case: governance_case.clone(),
                listing,
                activation: Some(forged_activation),
                abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::SlashBond,
                state: OpenMarketPenaltyState::Enforced,
                penalty_amount: MonetaryAmount {
                    units: 2500,
                    currency: "USD".to_string(),
                },
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::GovernanceCase,
                    reference_id: governance_case.body.case_id,
                    uri: None,
                    sha256: None,
                }],
                subject_operator_id: Some(owner_id.to_string()),
                supersedes_penalty_id: None,
                issued_by: "market@chio.example".to_string(),
                opened_at: Some(204),
                updated_at: Some(204),
                expires_at: Some(500),
                note: None,
            },
            204,
            &signing_keypair.public_key(),
        )
        .test_expect_err("non-local activation authority rejected");
        assert!(error.contains("issued by the governing operator"));
    }

    #[test]
    fn open_market_evaluation_rejects_non_local_activation_authority() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &OpenMarketPenaltyIssueRequest {
                fee_schedule: fee_schedule.clone(),
                charter: charter.clone(),
                case: governance_case.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
                bond_class: OpenMarketBondClass::Listing,
                action: OpenMarketPenaltyAction::SlashBond,
                state: OpenMarketPenaltyState::Enforced,
                penalty_amount: MonetaryAmount {
                    units: 2500,
                    currency: "USD".to_string(),
                },
                evidence_refs: vec![OpenMarketEvidenceReference {
                    kind: OpenMarketEvidenceKind::GovernanceCase,
                    reference_id: governance_case.body.case_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                subject_operator_id: Some(owner_id.to_string()),
                supersedes_penalty_id: None,
                issued_by: "market@chio.example".to_string(),
                opened_at: Some(204),
                updated_at: Some(204),
                expires_at: Some(500),
                note: None,
            },
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
            .test_expect("sign penalty");
        let mut forged_activation_body = activation.body.clone();
        forged_activation_body.local_operator_id = "https://remote.chio.example".to_string();
        forged_activation_body.local_operator_name = Some("Remote Operator".to_string());
        let forged_activation =
            SignedGenericTrustActivation::sign(forged_activation_body, &signing_keypair)
                .test_expect("sign forged activation");

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(forged_activation),
                charter,
                case: governance_case,
                penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(
            evaluation.findings[0].code,
            OpenMarketFindingCode::ActivationMismatch
        );
    }

    #[test]
    fn open_market_scope_rejects_blank_operator_ids() {
        let error = OpenMarketEconomicsScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["   ".to_string()],
            allowed_actor_kinds: Vec::new(),
            allowed_admission_classes: Vec::new(),
            policy_reference: None,
        }
        .validate()
        .test_expect_err("blank operator ids rejected");

        assert!(error.contains("scope.allowed_listing_operator_ids[0]"));
    }

    #[test]
    fn open_market_evidence_reference_rejects_invalid_sha256() {
        let error = OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::External,
            reference_id: "incident-1".to_string(),
            uri: None,
            sha256: Some("not-a-digest".to_string()),
        }
        .validate("evidence")
        .test_expect_err("invalid evidence sha256 rejected");

        assert!(error.contains("evidence.sha256"));
    }

    #[test]
    fn open_market_fee_schedule_validate_rejects_namespace_mismatch() {
        let error = OpenMarketFeeScheduleArtifact {
            schema: OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA.to_string(),
            fee_schedule_id: "fee-1".to_string(),
            namespace: "https://registry.chio.example".to_string(),
            governing_operator_id: "https://registry.chio.example".to_string(),
            governing_operator_name: Some("Registry Operator".to_string()),
            scope: OpenMarketEconomicsScope {
                namespace: "https://different.chio.example".to_string(),
                allowed_listing_operator_ids: vec!["https://registry.chio.example".to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: None,
            },
            publication_fee: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            dispute_fee: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            market_participation_fee: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            bond_requirements: vec![OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Listing,
                required_amount: MonetaryAmount {
                    units: 5000,
                    currency: "USD".to_string(),
                },
                collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                slashable: true,
            }],
            issued_at: 100,
            expires_at: Some(200),
            issued_by: "market@chio.example".to_string(),
            note: None,
        }
        .validate()
        .test_expect_err("namespace mismatch rejected");

        assert!(error.contains("namespace must match scope namespace"));
    }

    #[test]
    fn open_market_fee_schedule_issue_request_requires_bond_requirements() {
        let error = OpenMarketFeeScheduleIssueRequest {
            scope: OpenMarketEconomicsScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec!["https://registry.chio.example".to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: None,
            },
            publication_fee: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            dispute_fee: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            market_participation_fee: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            bond_requirements: Vec::new(),
            issued_by: "market@chio.example".to_string(),
            issued_at: Some(202),
            expires_at: Some(600),
            note: None,
        }
        .validate()
        .test_expect_err("bond requirements required");

        assert!(error.contains("bond_requirements must not be empty"));
    }

    #[test]
    fn open_market_penalty_validate_requires_reverse_slash_metadata() {
        let error = OpenMarketPenaltyArtifact {
            schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_string(),
            penalty_id: "penalty-1".to_string(),
            fee_schedule_id: "fee-1".to_string(),
            charter_id: "charter-1".to_string(),
            case_id: "case-1".to_string(),
            governing_operator_id: "https://registry.chio.example".to_string(),
            namespace: "https://registry.chio.example".to_string(),
            listing_id: "listing-demo".to_string(),
            activation_id: Some("activation-1".to_string()),
            subject_operator_id: Some("https://registry.chio.example".to_string()),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::ReverseSlash,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            opened_at: 100,
            updated_at: 100,
            expires_at: Some(200),
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: "case-1".to_string(),
                uri: None,
                sha256: None,
            }],
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            note: None,
        }
        .validate()
        .test_expect_err("reverse slash metadata required");

        assert!(error.contains("requires supersedes_penalty_id"));
    }

    #[test]
    fn open_market_penalty_issue_request_rejects_invalid_fee_schedule_signature() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        let mut tampered_fee_schedule = fee_schedule.clone();
        tampered_fee_schedule.body.publication_fee.units += 1;

        let error = sample_penalty_issue_request(
            owner_id,
            tampered_fee_schedule,
            charter,
            governance_case,
            listing,
            Some(activation),
        )
        .validate()
        .test_expect_err("tampered fee schedule rejected");

        assert!(error.contains("fee schedule signature is invalid"));
    }

    #[test]
    fn open_market_penalty_issue_request_rejects_mismatched_authority_signer() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let attacker_keypair = Keypair::from_seed(&[8_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let forged_charter =
            SignedGenericGovernanceCharter::sign(charter.body.clone(), &attacker_keypair)
                .test_expect("sign forged charter");
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);

        let request = sample_penalty_issue_request(
            owner_id,
            fee_schedule,
            forged_charter,
            governance_case,
            listing,
            Some(activation),
        );

        let error = build_open_market_penalty_artifact(
            owner_id,
            &request,
            204,
            &signing_keypair.public_key(),
        )
        .test_expect_err("mismatched governing signer rejected");

        assert!(error.contains("governing authority signer"));
    }

    #[test]
    fn build_open_market_fee_schedule_artifact_uses_request_issued_at() {
        let owner_id = "https://registry.chio.example";
        let mut request = OpenMarketFeeScheduleIssueRequest {
            scope: OpenMarketEconomicsScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec![owner_id.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            publication_fee: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            dispute_fee: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            market_participation_fee: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            bond_requirements: vec![OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Listing,
                required_amount: MonetaryAmount {
                    units: 5000,
                    currency: "USD".to_string(),
                },
                collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                slashable: true,
            }],
            issued_by: "market@chio.example".to_string(),
            issued_at: Some(777),
            expires_at: Some(900),
            note: None,
        };
        let artifact = build_open_market_fee_schedule_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &request,
            202,
        )
        .test_expect("build fee schedule");

        assert_eq!(artifact.issued_at, 777);
        assert_eq!(artifact.governing_operator_id, owner_id);
        assert!(artifact.fee_schedule_id.starts_with("market-fee-"));
        request.issued_at = Some(778);
        let changed = build_open_market_fee_schedule_artifact(
            owner_id,
            Some("Registry Operator".to_string()),
            &request,
            202,
        )
        .test_expect("build changed fee schedule");
        assert_ne!(artifact.fee_schedule_id, changed.fee_schedule_id);
    }

    #[test]
    fn open_market_evaluation_rejects_invalid_penalty_signature() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &sample_penalty_issue_request(
                owner_id,
                fee_schedule.clone(),
                charter.clone(),
                governance_case.clone(),
                listing.clone(),
                Some(activation.clone()),
            ),
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
            .test_expect("sign penalty");
        let mut tampered_penalty = penalty.clone();
        tampered_penalty.body.note = Some("tampered".to_string());

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(activation),
                charter,
                case: governance_case,
                penalty: tampered_penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(
            evaluation.findings[0].code,
            OpenMarketFindingCode::PenaltyUnverifiable
        );
    }

    #[test]
    fn open_market_evaluation_rejects_mismatched_authority_signer() {
        let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
        let attacker_keypair = Keypair::from_seed(&[8_u8; 32]);
        let owner_id = "https://registry.chio.example";
        let listing = sample_listing(owner_id, &signing_keypair);
        let activation = sample_activation(owner_id, &signing_keypair, &listing);
        let charter = sample_charter(owner_id, &signing_keypair);
        let governance_case =
            sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
        let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
        let penalty_artifact = build_open_market_penalty_artifact(
            owner_id,
            &sample_penalty_issue_request(
                owner_id,
                fee_schedule.clone(),
                charter.clone(),
                governance_case.clone(),
                listing.clone(),
                Some(activation.clone()),
            ),
            204,
            &signing_keypair.public_key(),
        )
        .test_expect("build penalty");
        let forged_penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &attacker_keypair)
            .test_expect("sign forged penalty");

        let evaluation = evaluate_open_market_penalty(
            &OpenMarketPenaltyEvaluationRequest {
                fee_schedule,
                listing,
                current_publisher: sample_publisher(owner_id),
                activation: Some(activation),
                charter,
                case: governance_case,
                penalty: forged_penalty,
                prior_penalty: None,
                evaluated_at: Some(205),
            },
            205,
            &signing_keypair.public_key(),
        )
        .test_expect("evaluate open market");

        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(
            evaluation.findings[0].code,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid
        );
        assert!(evaluation.findings[0]
            .message
            .contains("governing authority signer"));
    }
}
