//! Generic governance charters and case evaluation for the Chio protocol.
//!
//! This crate is used to author and evaluate governance charters and to
//! authorize governed actions against a signed lease. It defines the
//! capability-lease artifacts and action classes (scoped observation,
//! delegated action, narrow destructive), governance-receipt artifacts, and
//! verification helpers such as [`verify_capability_lease`],
//! [`verify_destructive_authorization`], and
//! [`verify_step_governance_boundary`]. It builds on the listing surface in
//! `chio-listing`.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto, receipt};
pub use chio_listing as listing;

use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;
use crate::listing::{
    normalize_namespace, GenericListingActorKind, GenericRegistryPublisher, SignedGenericListing,
    SignedGenericTrustActivation,
};
use crate::receipt::SignedExportEnvelope;

pub const GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA: &str = "chio.registry.governance-charter.v1";
pub const GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA: &str = "chio.registry.governance-case.v1";
pub const CAPABILITY_LEASE_SCHEMA_V1: &str = "chio.capability-lease.v1";
pub const GOVERNANCE_RECEIPT_SCHEMA_V1: &str = "chio.governance-receipt.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLeaseActionClass {
    ScopedObservation,
    DelegatedAction,
    NarrowDestructive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityLeaseArtifact {
    pub schema: String,
    pub lease_id: String,
    pub issuer: String,
    pub subject: String,
    pub scope_digest: String,
    pub action_class: CapabilityLeaseActionClass,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl CapabilityLeaseArtifact {
    pub fn validate(&self) -> Result<(), GovernanceAuthorizationError> {
        if self.schema != CAPABILITY_LEASE_SCHEMA_V1 {
            return Err(GovernanceAuthorizationError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        validate_non_empty(&self.lease_id, "lease_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.issuer, "issuer")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.subject, "subject")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_sha256_hex(&self.scope_digest, "scope_digest")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(GovernanceAuthorizationError::InvalidArtifact(
                "expires_at_unix_ms must be greater than issued_at_unix_ms".to_string(),
            ));
        }
        Ok(())
    }
}

pub type SignedCapabilityLease = SignedExportEnvelope<CapabilityLeaseArtifact>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceReceiptCaseKind {
    DestructiveAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceReceiptArtifact {
    pub schema: String,
    pub receipt_id: String,
    pub authorizing_kernel: String,
    pub case_kind: GovernanceReceiptCaseKind,
    pub authorized_lease_id: String,
    pub workflow_id: String,
    pub step_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl GovernanceReceiptArtifact {
    pub fn validate(&self) -> Result<(), GovernanceAuthorizationError> {
        if self.schema != GOVERNANCE_RECEIPT_SCHEMA_V1 {
            return Err(GovernanceAuthorizationError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        validate_non_empty(&self.receipt_id, "receipt_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.authorizing_kernel, "authorizing_kernel")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.authorized_lease_id, "authorized_lease_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.workflow_id, "workflow_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_sha256_hex(&self.step_sha256, "step_sha256")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(GovernanceAuthorizationError::InvalidArtifact(
                "expires_at_unix_ms must be greater than issued_at_unix_ms".to_string(),
            ));
        }
        Ok(())
    }
}

pub type SignedGovernanceReceipt = SignedExportEnvelope<GovernanceReceiptArtifact>;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GovernanceAuthorizationError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid authorization artifact: {0}")]
    InvalidArtifact(String),
    #[error("authorization signature is invalid")]
    InvalidSignature,
    #[error("capability lease is expired or unknown: {0}")]
    LeaseExpiredOrUnknown(String),
    #[error("capability lease is not yet valid: {0}")]
    LeaseNotYetValid(String),
    #[error("capability lease scope digest mismatch")]
    ScopeDigestMismatch,
    #[error("governance receipt is required for destructive steps")]
    GovernanceReceiptRequired,
    #[error("governance receipt is not yet valid: {0}")]
    GovernanceReceiptNotYetValid(String),
    #[error("governance receipt workflow mismatch")]
    WorkflowMismatch,
    #[error("governance receipt step hash mismatch")]
    StepHashMismatch,
    #[error("governance receipt lease mismatch")]
    LeaseMismatch,
    #[error("canonical signature operation failed: {0}")]
    Crypto(String),
}

pub fn verify_capability_lease(
    lease: &SignedCapabilityLease,
    now_unix_ms: u64,
    expected_scope_digest: Option<String>,
) -> Result<(), GovernanceAuthorizationError> {
    lease.body.validate()?;
    if !lease
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if lease.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseNotYetValid(
            lease.body.lease_id.clone(),
        ));
    }
    if lease.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            lease.body.lease_id.clone(),
        ));
    }
    if let Some(expected) = expected_scope_digest {
        validate_sha256_hex(&expected, "expected_scope_digest")?;
        if lease.body.scope_digest != expected {
            return Err(GovernanceAuthorizationError::ScopeDigestMismatch);
        }
    }
    Ok(())
}

pub fn verify_destructive_authorization(
    receipt: &SignedGovernanceReceipt,
    expected_lease_id: &str,
    expected_workflow_id: &str,
    expected_step_sha256: &str,
    now_unix_ms: u64,
) -> Result<(), GovernanceAuthorizationError> {
    receipt.body.validate()?;
    validate_sha256_hex(expected_step_sha256, "expected_step_sha256")?;
    if !receipt
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            receipt.body.receipt_id.clone(),
        ));
    }
    if receipt.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            receipt.body.receipt_id.clone(),
        ));
    }
    if receipt.body.authorized_lease_id != expected_lease_id {
        return Err(GovernanceAuthorizationError::LeaseMismatch);
    }
    if receipt.body.workflow_id != expected_workflow_id {
        return Err(GovernanceAuthorizationError::WorkflowMismatch);
    }
    if receipt.body.step_sha256 != expected_step_sha256 {
        return Err(GovernanceAuthorizationError::StepHashMismatch);
    }
    Ok(())
}

pub fn verify_step_governance_boundary(
    destructive: bool,
    receipt: Option<&SignedGovernanceReceipt>,
    now_unix_ms: u64,
) -> Result<(), GovernanceAuthorizationError> {
    if !destructive {
        return Ok(());
    }
    let Some(receipt) = receipt else {
        return Err(GovernanceAuthorizationError::GovernanceReceiptRequired);
    };
    receipt.body.validate()?;
    if receipt.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            receipt.body.receipt_id.clone(),
        ));
    }
    if !receipt
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            receipt.body.receipt_id.clone(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericGovernanceCaseKind {
    Dispute,
    Freeze,
    Sanction,
    Appeal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericGovernanceCaseState {
    Open,
    Escalated,
    Enforced,
    Resolved,
    Denied,
    Superseded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericGovernanceEffectiveState {
    Clear,
    Disputed,
    Frozen,
    Sanctioned,
    Appealed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericGovernanceEvidenceKind {
    Listing,
    TrustActivation,
    Certification,
    RegistrySearch,
    OperatorReport,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericGovernanceFindingCode {
    ListingUnverifiable,
    ActivationUnverifiable,
    CharterUnverifiable,
    CaseUnverifiable,
    PriorCaseUnverifiable,
    CharterExpired,
    CaseExpired,
    CharterScopeMismatch,
    CharterKindUnsupported,
    CaseMismatch,
    MissingActivation,
    ActivationMismatch,
    AppealTargetMissing,
    AppealTargetInvalid,
    SupersessionTargetMissing,
    SupersessionTargetInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceAuthorityScope {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_listing_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

impl GenericGovernanceAuthorityScope {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.namespace, "authority_scope.namespace")?;
        for (index, operator_id) in self.allowed_listing_operator_ids.iter().enumerate() {
            validate_non_empty(
                operator_id,
                &format!("authority_scope.allowed_listing_operator_ids[{index}]"),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceEvidenceReference {
    pub kind: GenericGovernanceEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl GenericGovernanceEvidenceReference {
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
pub struct GenericGovernanceCharterArtifact {
    pub schema: String,
    pub charter_id: String,
    pub governing_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governing_operator_name: Option<String>,
    pub authority_scope: GenericGovernanceAuthorityScope,
    pub allowed_case_kinds: Vec<GenericGovernanceCaseKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_operator_ids: Vec<String>,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericGovernanceCharterArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic governance charter schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.charter_id, "charter_id")?;
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        self.authority_scope.validate()?;
        if normalize_namespace(&self.authority_scope.namespace).is_empty() {
            return Err("authority_scope.namespace must not be empty".to_string());
        }
        if self.allowed_case_kinds.is_empty() {
            return Err("allowed_case_kinds must not be empty".to_string());
        }
        for (index, operator_id) in self.escalation_operator_ids.iter().enumerate() {
            validate_non_empty(operator_id, &format!("escalation_operator_ids[{index}]"))?;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.issued_at {
                return Err("expires_at must be greater than issued_at".to_string());
            }
        }
        Ok(())
    }
}

pub type SignedGenericGovernanceCharter = SignedExportEnvelope<GenericGovernanceCharterArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceCaseArtifact {
    pub schema: String,
    pub case_id: String,
    pub charter_id: String,
    pub governing_operator_id: String,
    pub kind: GenericGovernanceCaseKind,
    pub state: GenericGovernanceCaseState,
    pub namespace: String,
    pub listing_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_operator_id: Option<String>,
    pub opened_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalated_to_operator_ids: Vec<String>,
    pub evidence_refs: Vec<GenericGovernanceEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_of_case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_case_id: Option<String>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericGovernanceCaseArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic governance case schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.case_id, "case_id")?;
        validate_non_empty(&self.charter_id, "charter_id")?;
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.listing_id, "listing_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        if self.updated_at < self.opened_at {
            return Err("updated_at must be greater than or equal to opened_at".to_string());
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.opened_at {
                return Err("expires_at must be greater than opened_at".to_string());
            }
        }
        for (index, operator_id) in self.escalated_to_operator_ids.iter().enumerate() {
            validate_non_empty(operator_id, &format!("escalated_to_operator_ids[{index}]"))?;
        }
        if self.evidence_refs.is_empty() {
            return Err("evidence_refs must not be empty".to_string());
        }
        for (index, evidence_ref) in self.evidence_refs.iter().enumerate() {
            evidence_ref.validate(&format!("evidence_refs[{index}]"))?;
        }
        if matches!(self.kind, GenericGovernanceCaseKind::Appeal) {
            if self.appeal_of_case_id.as_deref().is_none() {
                return Err("appeal case requires appeal_of_case_id".to_string());
            }
        } else if self.appeal_of_case_id.is_some() {
            return Err("appeal_of_case_id is only valid for appeal cases".to_string());
        }
        if matches!(self.state, GenericGovernanceCaseState::Escalated)
            && self.escalated_to_operator_ids.is_empty()
        {
            return Err("escalated case requires escalated_to_operator_ids".to_string());
        }
        Ok(())
    }
}

pub type SignedGenericGovernanceCase = SignedExportEnvelope<GenericGovernanceCaseArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceCharterIssueRequest {
    pub authority_scope: GenericGovernanceAuthorityScope,
    pub allowed_case_kinds: Vec<GenericGovernanceCaseKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_operator_ids: Vec<String>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericGovernanceCharterIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.authority_scope.validate()?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        if self.allowed_case_kinds.is_empty() {
            return Err("allowed_case_kinds must not be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceCaseIssueRequest {
    pub charter: SignedGenericGovernanceCharter,
    pub listing: SignedGenericListing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    pub kind: GenericGovernanceCaseKind,
    pub state: GenericGovernanceCaseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalated_to_operator_ids: Vec<String>,
    pub evidence_refs: Vec<GenericGovernanceEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_of_case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_case_id: Option<String>,
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

impl GenericGovernanceCaseIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        if !self
            .listing
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Err("governance case listing signature is invalid".to_string());
        }
        if !self
            .charter
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Err("governance charter signature is invalid".to_string());
        }
        self.charter.body.validate()?;
        if let Some(activation) = self.activation.as_ref() {
            if !activation
                .verify_signature()
                .map_err(|error| error.to_string())?
            {
                return Err("trust activation signature is invalid".to_string());
            }
            activation
                .body
                .validate()
                .map_err(|error| error.to_string())?;
        }
        validate_non_empty(&self.issued_by, "issued_by")?;
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
pub struct GenericGovernanceCaseEvaluationRequest {
    pub listing: SignedGenericListing,
    pub current_publisher: GenericRegistryPublisher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    pub charter: SignedGenericGovernanceCharter,
    pub case: SignedGenericGovernanceCase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_case: Option<SignedGenericGovernanceCase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

impl GenericGovernanceCaseEvaluationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        self.current_publisher.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceFinding {
    pub code: GenericGovernanceFindingCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericGovernanceCaseEvaluation {
    pub listing_id: String,
    pub namespace: String,
    pub charter_id: String,
    pub case_id: String,
    pub governing_operator_id: String,
    pub kind: GenericGovernanceCaseKind,
    pub state: GenericGovernanceCaseState,
    pub effective_state: GenericGovernanceEffectiveState,
    pub evaluated_at: u64,
    pub blocks_admission: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GenericGovernanceFinding>,
}

pub fn build_generic_governance_charter_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &GenericGovernanceCharterIssueRequest,
    issued_at: u64,
) -> Result<GenericGovernanceCharterArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    let issued_at = request.issued_at.unwrap_or(issued_at);
    let charter_id = format!(
        "charter-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                normalize_namespace(&request.authority_scope.namespace),
                &request.allowed_case_kinds,
                issued_at,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = GenericGovernanceCharterArtifact {
        schema: GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA.to_string(),
        charter_id,
        governing_operator_id: local_operator_id.to_string(),
        governing_operator_name: local_operator_name,
        authority_scope: request.authority_scope.clone(),
        allowed_case_kinds: request.allowed_case_kinds.clone(),
        escalation_operator_ids: request.escalation_operator_ids.clone(),
        issued_at,
        expires_at: request.expires_at,
        issued_by: request.issued_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn build_generic_governance_case_artifact(
    local_operator_id: &str,
    request: &GenericGovernanceCaseIssueRequest,
    issued_at: u64,
) -> Result<GenericGovernanceCaseArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    if request.charter.body.governing_operator_id != local_operator_id {
        return Err("governance case must be issued by the charter governing operator".to_string());
    }
    if request
        .activation
        .as_ref()
        .is_some_and(|activation| activation.body.local_operator_id != local_operator_id)
    {
        return Err(
            "governance cases must use a trust activation issued by the governing operator"
                .to_string(),
        );
    }
    let opened_at = request.opened_at.unwrap_or(issued_at);
    let updated_at = request.updated_at.unwrap_or(opened_at);
    let case_id = format!(
        "case-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                &request.charter.body.charter_id,
                &request.listing.body.listing_id,
                request.kind,
                request.state,
                opened_at,
                &request.appeal_of_case_id,
                &request.supersedes_case_id,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = GenericGovernanceCaseArtifact {
        schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
        case_id,
        charter_id: request.charter.body.charter_id.clone(),
        governing_operator_id: local_operator_id.to_string(),
        kind: request.kind,
        state: request.state,
        namespace: request.listing.body.namespace.clone(),
        listing_id: request.listing.body.listing_id.clone(),
        activation_id: request
            .activation
            .as_ref()
            .map(|activation| activation.body.activation_id.clone()),
        subject_operator_id: request.subject_operator_id.clone(),
        opened_at,
        updated_at,
        expires_at: request.expires_at,
        escalated_to_operator_ids: request.escalated_to_operator_ids.clone(),
        evidence_refs: request.evidence_refs.clone(),
        appeal_of_case_id: request.appeal_of_case_id.clone(),
        supersedes_case_id: request.supersedes_case_id.clone(),
        issued_by: request.issued_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn evaluate_generic_governance_case(
    request: &GenericGovernanceCaseEvaluationRequest,
    now: u64,
) -> Result<GenericGovernanceCaseEvaluation, String> {
    request.validate()?;
    let evaluated_at = request.evaluated_at.unwrap_or(now);

    if !request
        .listing
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::ListingUnverifiable,
            "listing signature is invalid",
        ));
    }
    if !request
        .charter
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterUnverifiable,
            "governance charter signature is invalid",
        ));
    }
    if let Err(error) = request.charter.body.validate() {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterUnverifiable,
            &error,
        ));
    }
    if !request
        .case
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseUnverifiable,
            "governance case signature is invalid",
        ));
    }
    if let Err(error) = request.case.body.validate() {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseUnverifiable,
            &error,
        ));
    }
    if let Some(activation) = request.activation.as_ref() {
        if !activation
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationUnverifiable,
                "trust activation signature is invalid",
            ));
        }
        if let Err(error) = activation.body.validate() {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationUnverifiable,
                &error,
            ));
        }
    }
    if let Some(prior_case) = request.prior_case.as_ref() {
        if !prior_case
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::PriorCaseUnverifiable,
                "prior governance case signature is invalid",
            ));
        }
        if let Err(error) = prior_case.body.validate() {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::PriorCaseUnverifiable,
                &error,
            ));
        }
    }
    if let Some(activation) = request.activation.as_ref() {
        if activation.body.local_operator_id != request.charter.body.governing_operator_id {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationMismatch,
                "governance cases require a trust activation issued by the governing operator",
            ));
        }
    }

    let charter = &request.charter.body;
    let case = &request.case.body;
    let listing = &request.listing.body;
    let namespace = normalize_namespace(&listing.namespace);

    if charter.governing_operator_id != case.governing_operator_id
        || charter.charter_id != case.charter_id
        || normalize_namespace(&charter.authority_scope.namespace) != namespace
        || normalize_namespace(&case.namespace) != namespace
        || case.listing_id != listing.listing_id
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseMismatch,
            "governance charter or case does not match the current listing identity or namespace",
        ));
    }

    if charter
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterExpired,
            "governance charter has expired",
        ));
    }
    if case
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseExpired,
            "governance case has expired",
        ));
    }
    if !charter.allowed_case_kinds.contains(&case.kind) {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterKindUnsupported,
            "governance charter does not authorize this case kind",
        ));
    }
    if !charter
        .authority_scope
        .allowed_listing_operator_ids
        .is_empty()
        && !charter
            .authority_scope
            .allowed_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterScopeMismatch,
            "current listing publisher falls outside the charter authority scope",
        ));
    }
    if !charter.authority_scope.allowed_actor_kinds.is_empty()
        && !charter
            .authority_scope
            .allowed_actor_kinds
            .contains(&listing.subject.actor_kind)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterScopeMismatch,
            "listing actor kind falls outside the charter authority scope",
        ));
    }

    if matches!(
        case.kind,
        GenericGovernanceCaseKind::Freeze | GenericGovernanceCaseKind::Sanction
    ) {
        let Some(activation) = request.activation.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::MissingActivation,
                "freeze or sanction cases require an explicit local trust activation",
            ));
        };
        if case.activation_id.as_deref() != Some(activation.body.activation_id.as_str()) {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationMismatch,
                "governance case activation does not match the provided trust activation",
            ));
        }
    }

    if let Some(supersedes_case_id) = case.supersedes_case_id.as_deref() {
        let Some(prior_case) = request.prior_case.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::SupersessionTargetMissing,
                "superseding governance case requires prior_case",
            ));
        };
        if prior_case.body.case_id != supersedes_case_id
            || normalize_namespace(&prior_case.body.namespace) != namespace
            || prior_case.body.listing_id != listing.listing_id
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::SupersessionTargetInvalid,
                "supersession target does not match the referenced prior governance case",
            ));
        }
    }

    if matches!(case.kind, GenericGovernanceCaseKind::Appeal) {
        let Some(appeal_of_case_id) = case.appeal_of_case_id.as_deref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetMissing,
                "appeal case requires appeal_of_case_id",
            ));
        };
        let Some(prior_case) = request.prior_case.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetMissing,
                "appeal case requires prior_case",
            ));
        };
        if prior_case.body.case_id != appeal_of_case_id
            || normalize_namespace(&prior_case.body.namespace) != namespace
            || prior_case.body.listing_id != listing.listing_id
            || matches!(prior_case.body.kind, GenericGovernanceCaseKind::Appeal)
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetInvalid,
                "appeal target does not match a valid prior governance case",
            ));
        }
    }

    let (effective_state, blocks_admission) = effective_state_for_case(case);
    Ok(GenericGovernanceCaseEvaluation {
        listing_id: listing.listing_id.clone(),
        namespace,
        charter_id: charter.charter_id.clone(),
        case_id: case.case_id.clone(),
        governing_operator_id: case.governing_operator_id.clone(),
        kind: case.kind,
        state: case.state,
        effective_state,
        evaluated_at,
        blocks_admission,
        findings: Vec::new(),
    })
}

fn effective_state_for_case(
    case: &GenericGovernanceCaseArtifact,
) -> (GenericGovernanceEffectiveState, bool) {
    match case.state {
        GenericGovernanceCaseState::Resolved
        | GenericGovernanceCaseState::Denied
        | GenericGovernanceCaseState::Superseded => (GenericGovernanceEffectiveState::Clear, false),
        GenericGovernanceCaseState::Open | GenericGovernanceCaseState::Escalated => match case.kind
        {
            GenericGovernanceCaseKind::Dispute => {
                (GenericGovernanceEffectiveState::Disputed, false)
            }
            GenericGovernanceCaseKind::Appeal => (GenericGovernanceEffectiveState::Appealed, false),
            GenericGovernanceCaseKind::Freeze => (GenericGovernanceEffectiveState::Frozen, false),
            GenericGovernanceCaseKind::Sanction => {
                (GenericGovernanceEffectiveState::Sanctioned, false)
            }
        },
        GenericGovernanceCaseState::Enforced => match case.kind {
            GenericGovernanceCaseKind::Dispute => {
                (GenericGovernanceEffectiveState::Disputed, false)
            }
            GenericGovernanceCaseKind::Appeal => (GenericGovernanceEffectiveState::Appealed, false),
            GenericGovernanceCaseKind::Freeze => (GenericGovernanceEffectiveState::Frozen, true),
            GenericGovernanceCaseKind::Sanction => {
                (GenericGovernanceEffectiveState::Sanctioned, true)
            }
        },
    }
}

fn governance_failure(
    request: &GenericGovernanceCaseEvaluationRequest,
    evaluated_at: u64,
    code: GenericGovernanceFindingCode,
    message: &str,
) -> GenericGovernanceCaseEvaluation {
    GenericGovernanceCaseEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        charter_id: request.case.body.charter_id.clone(),
        case_id: request.case.body.case_id.clone(),
        governing_operator_id: request.case.body.governing_operator_id.clone(),
        kind: request.case.body.kind,
        state: request.case.body.state,
        effective_state: GenericGovernanceEffectiveState::Clear,
        evaluated_at,
        blocks_admission: false,
        findings: vec![GenericGovernanceFinding {
            code,
            message: message.to_string(),
        }],
    }
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), GovernanceAuthorizationError> {
    if !is_sha256_hex(value) {
        return Err(GovernanceAuthorizationError::InvalidArtifact(format!(
            "{field} must be a 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::listing::{
        build_generic_trust_activation_artifact, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceArtifact, GenericNamespaceLifecycleState, GenericNamespaceOwnership,
        GenericRegistryPublisherRole, GenericTrustActivationDisposition,
        GenericTrustActivationEligibility, GenericTrustActivationIssueRequest,
        GenericTrustActivationReviewContext, GenericTrustAdmissionClass,
        GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
    };

    use chio_test_support::prelude::*;

    fn sample_namespace(owner_id: &str, signing_keypair: &Keypair) -> GenericNamespaceArtifact {
        GenericNamespaceArtifact {
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
        }
    }

    fn sample_listing(owner_id: &str, signing_keypair: &Keypair) -> GenericListingArtifact {
        GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: "listing-artifact-1".to_string(),
            namespace: "https://registry.chio.example".to_string(),
            namespace_ownership: sample_namespace(owner_id, signing_keypair).ownership,
            published_at: 110,
            expires_at: Some(1_000),
            status: GenericListingStatus::Active,
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: "tool-server-a".to_string(),
                display_name: Some("Tool Server A".to_string()),
                metadata_url: Some("https://tool.chio.example/metadata".to_string()),
                resolution_url: Some("https://tool.chio.example/mcp".to_string()),
                homepage_url: Some("https://tool.chio.example".to_string()),
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: "artifact-1".to_string(),
                source_artifact_sha256: "deadbeef".to_string(),
            },
            boundary: GenericListingBoundary::default(),
        }
    }

    fn signed_sample_listing(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericListing {
        SignedGenericListing::sign(sample_listing(owner_id, signing_keypair), signing_keypair)
            .test_expect("sign sample listing")
    }

    fn sample_publisher(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
    ) -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role,
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.chio.example"),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn sample_activation(listing: &SignedGenericListing) -> SignedGenericTrustActivation {
        let authority_keypair = Keypair::generate();
        let activation = build_generic_trust_activation_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &GenericTrustActivationIssueRequest {
                listing: listing.clone(),
                admission_class: GenericTrustAdmissionClass::Reviewable,
                disposition: GenericTrustActivationDisposition::Approved,
                eligibility: GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                    allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                    allowed_statuses: vec![GenericListingStatus::Active],
                    require_fresh_listing: true,
                    require_bond_backing: false,
                    required_listing_operator_ids: vec!["origin-a".to_string()],
                    policy_reference: Some("policy/open-registry/default".to_string()),
                },
                review_context: GenericTrustActivationReviewContext {
                    publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                },
                requested_by: "ops@chio.example".to_string(),
                reviewed_by: Some("reviewer@chio.example".to_string()),
                requested_at: Some(120),
                reviewed_at: Some(121),
                expires_at: Some(500),
                note: Some("approved".to_string()),
            },
            121,
        )
        .test_expect("build activation");
        SignedGenericTrustActivation::sign(activation, &authority_keypair)
            .test_expect("sign activation")
    }

    #[test]
    fn sha256_hex_helper_accepts_exact_uppercase_compatible_digest() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn governance_evidence_reference_rejects_invalid_sha256() {
        let reference = GenericGovernanceEvidenceReference {
            kind: GenericGovernanceEvidenceKind::External,
            reference_id: "external-report-1".to_string(),
            uri: None,
            sha256: Some("not-a-digest".to_string()),
        };

        let error = reference
            .validate("evidence")
            .test_expect_err("invalid evidence sha256 rejected");
        assert!(error.contains("evidence.sha256"));
    }

    fn sample_charter_request() -> GenericGovernanceCharterIssueRequest {
        GenericGovernanceCharterIssueRequest {
            authority_scope: GenericGovernanceAuthorityScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec!["origin-a".to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                policy_reference: Some("policy/governance/default".to_string()),
            },
            allowed_case_kinds: vec![
                GenericGovernanceCaseKind::Dispute,
                GenericGovernanceCaseKind::Freeze,
                GenericGovernanceCaseKind::Sanction,
                GenericGovernanceCaseKind::Appeal,
            ],
            escalation_operator_ids: vec!["network-audit.chio.example".to_string()],
            issued_by: "governance@chio.example".to_string(),
            issued_at: Some(130),
            expires_at: Some(800),
            note: Some("default governance charter".to_string()),
        }
    }

    fn sample_charter(
        local_operator_id: &str,
        authority_keypair: &Keypair,
    ) -> SignedGenericGovernanceCharter {
        SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                local_operator_id,
                Some(format!("Operator {local_operator_id}")),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            authority_keypair,
        )
        .test_expect("sign charter")
    }

    fn sample_case_issue_request(
        charter: SignedGenericGovernanceCharter,
        listing: SignedGenericListing,
        activation: Option<SignedGenericTrustActivation>,
    ) -> GenericGovernanceCaseIssueRequest {
        let evidence_kind = if activation.is_some() {
            GenericGovernanceEvidenceKind::TrustActivation
        } else {
            GenericGovernanceEvidenceKind::Listing
        };
        let reference_id = activation.as_ref().map_or_else(
            || listing.body.listing_id.clone(),
            |activation| activation.body.activation_id.clone(),
        );
        GenericGovernanceCaseIssueRequest {
            charter,
            listing,
            activation,
            kind: GenericGovernanceCaseKind::Freeze,
            state: GenericGovernanceCaseState::Enforced,
            subject_operator_id: Some("origin-a".to_string()),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: evidence_kind,
                reference_id,
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: None,
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            opened_at: Some(140),
            updated_at: Some(140),
            expires_at: Some(500),
            note: Some("freeze".to_string()),
        }
    }

    #[test]
    fn generic_governance_freeze_requires_activation() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &GenericGovernanceCaseIssueRequest {
                    charter: charter.clone(),
                    listing: listing.clone(),
                    activation: None,
                    kind: GenericGovernanceCaseKind::Freeze,
                    state: GenericGovernanceCaseState::Enforced,
                    subject_operator_id: Some("origin-a".to_string()),
                    escalated_to_operator_ids: Vec::new(),
                    evidence_refs: vec![GenericGovernanceEvidenceReference {
                        kind: GenericGovernanceEvidenceKind::Listing,
                        reference_id: listing.body.listing_id.clone(),
                        uri: None,
                        sha256: None,
                    }],
                    appeal_of_case_id: None,
                    supersedes_case_id: None,
                    issued_by: "governance@chio.example".to_string(),
                    opened_at: Some(140),
                    updated_at: Some(140),
                    expires_at: Some(500),
                    note: Some("freeze".to_string()),
                },
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: None,
                charter,
                case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");
        assert!(!evaluation.blocks_admission);
        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::MissingActivation
        );
    }

    #[test]
    fn generic_governance_enforced_freeze_blocks_admission() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &GenericGovernanceCaseIssueRequest {
                    charter: charter.clone(),
                    listing: listing.clone(),
                    activation: Some(activation.clone()),
                    kind: GenericGovernanceCaseKind::Freeze,
                    state: GenericGovernanceCaseState::Enforced,
                    subject_operator_id: Some("origin-a".to_string()),
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
                    opened_at: Some(140),
                    updated_at: Some(140),
                    expires_at: Some(500),
                    note: Some("freeze".to_string()),
                },
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: Some(activation),
                charter,
                case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");
        assert!(evaluation.findings.is_empty());
        assert!(evaluation.blocks_admission);
        assert_eq!(
            evaluation.effective_state,
            GenericGovernanceEffectiveState::Frozen
        );
    }

    #[test]
    fn generic_governance_case_issue_rejects_non_local_activation_authority() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let mut forged_activation_body = activation.body.clone();
        forged_activation_body.local_operator_id = "remote-b".to_string();
        forged_activation_body.local_operator_name = Some("Remote B".to_string());
        let forged_activation =
            SignedGenericTrustActivation::sign(forged_activation_body, &Keypair::generate())
                .test_expect("sign forged activation");
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");

        let error = build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter,
                listing,
                activation: Some(forged_activation),
                kind: GenericGovernanceCaseKind::Freeze,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some("origin-a".to_string()),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::TrustActivation,
                    reference_id: activation.body.activation_id,
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: None,
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("freeze".to_string()),
            },
            140,
        )
        .test_expect_err("non-local activation authority rejected");
        assert!(error.contains("issued by the governing operator"));
    }

    #[test]
    fn generic_governance_evaluation_rejects_non_local_activation_authority() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &GenericGovernanceCaseIssueRequest {
                    charter: charter.clone(),
                    listing: listing.clone(),
                    activation: Some(activation.clone()),
                    kind: GenericGovernanceCaseKind::Freeze,
                    state: GenericGovernanceCaseState::Enforced,
                    subject_operator_id: Some("origin-a".to_string()),
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
                    opened_at: Some(140),
                    updated_at: Some(140),
                    expires_at: Some(500),
                    note: Some("freeze".to_string()),
                },
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");
        let mut forged_activation_body = activation.body.clone();
        forged_activation_body.local_operator_id = "remote-b".to_string();
        forged_activation_body.local_operator_name = Some("Remote B".to_string());
        let forged_activation =
            SignedGenericTrustActivation::sign(forged_activation_body, &Keypair::generate())
                .test_expect("sign forged activation");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: Some(forged_activation),
                charter,
                case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");
        assert!(!evaluation.blocks_admission);
        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::ActivationMismatch
        );
    }

    #[test]
    fn generic_governance_charter_scope_mismatch_fails_closed() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &GenericGovernanceCaseIssueRequest {
                    charter: charter.clone(),
                    listing: listing.clone(),
                    activation: Some(activation.clone()),
                    kind: GenericGovernanceCaseKind::Sanction,
                    state: GenericGovernanceCaseState::Enforced,
                    subject_operator_id: Some("origin-a".to_string()),
                    escalated_to_operator_ids: Vec::new(),
                    evidence_refs: vec![GenericGovernanceEvidenceReference {
                        kind: GenericGovernanceEvidenceKind::External,
                        reference_id: "incident-1".to_string(),
                        uri: None,
                        sha256: None,
                    }],
                    appeal_of_case_id: None,
                    supersedes_case_id: None,
                    issued_by: "governance@chio.example".to_string(),
                    opened_at: Some(140),
                    updated_at: Some(140),
                    expires_at: Some(500),
                    note: Some("sanction".to_string()),
                },
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "other-origin",
                ),
                activation: Some(activation),
                charter,
                case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");
        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::CharterScopeMismatch
        );
    }

    #[test]
    fn generic_governance_appeal_requires_prior_case() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = SignedGenericGovernanceCharter::sign(
            build_generic_governance_charter_artifact(
                "origin-a",
                Some("Origin A".to_string()),
                &sample_charter_request(),
                130,
            )
            .test_expect("build charter"),
            &authority_keypair,
        )
        .test_expect("sign charter");
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &GenericGovernanceCaseIssueRequest {
                    charter: charter.clone(),
                    listing: listing.clone(),
                    activation: Some(activation),
                    kind: GenericGovernanceCaseKind::Appeal,
                    state: GenericGovernanceCaseState::Open,
                    subject_operator_id: Some("origin-a".to_string()),
                    escalated_to_operator_ids: Vec::new(),
                    evidence_refs: vec![GenericGovernanceEvidenceReference {
                        kind: GenericGovernanceEvidenceKind::External,
                        reference_id: "appeal-1".to_string(),
                        uri: None,
                        sha256: None,
                    }],
                    appeal_of_case_id: Some("case-missing".to_string()),
                    supersedes_case_id: None,
                    issued_by: "governance@chio.example".to_string(),
                    opened_at: Some(140),
                    updated_at: Some(140),
                    expires_at: Some(500),
                    note: Some("appeal".to_string()),
                },
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: None,
                charter,
                case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");
        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::AppealTargetMissing
        );
    }

    #[test]
    fn generic_governance_authority_scope_rejects_blank_operator_ids() {
        let error = GenericGovernanceAuthorityScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["   ".to_string()],
            allowed_actor_kinds: Vec::new(),
            policy_reference: None,
        }
        .validate()
        .test_expect_err("blank operator ids rejected");

        assert!(error.contains("authority_scope.allowed_listing_operator_ids[0]"));
    }

    #[test]
    fn generic_governance_charter_validate_rejects_expired_artifact() {
        let error = GenericGovernanceCharterArtifact {
            schema: GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA.to_string(),
            charter_id: "charter-1".to_string(),
            governing_operator_id: "origin-a".to_string(),
            governing_operator_name: Some("Origin A".to_string()),
            authority_scope: GenericGovernanceAuthorityScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec!["origin-a".to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                policy_reference: None,
            },
            allowed_case_kinds: vec![GenericGovernanceCaseKind::Freeze],
            escalation_operator_ids: vec!["network-audit.chio.example".to_string()],
            issued_at: 200,
            expires_at: Some(199),
            issued_by: "governance@chio.example".to_string(),
            note: None,
        }
        .validate()
        .test_expect_err("expired charters rejected");

        assert!(error.contains("expires_at must be greater than issued_at"));
    }

    #[test]
    fn generic_governance_case_validate_requires_escalation_targets() {
        let error = GenericGovernanceCaseArtifact {
            schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
            case_id: "case-1".to_string(),
            charter_id: "charter-1".to_string(),
            governing_operator_id: "origin-a".to_string(),
            kind: GenericGovernanceCaseKind::Freeze,
            state: GenericGovernanceCaseState::Escalated,
            namespace: "https://registry.chio.example".to_string(),
            listing_id: "listing-1".to_string(),
            activation_id: Some("activation-1".to_string()),
            subject_operator_id: Some("origin-a".to_string()),
            opened_at: 100,
            updated_at: 100,
            expires_at: Some(200),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::External,
                reference_id: "incident-1".to_string(),
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: None,
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            note: None,
        }
        .validate()
        .test_expect_err("escalated cases require operator targets");

        assert!(error.contains("escalated case requires escalated_to_operator_ids"));
    }

    #[test]
    fn generic_governance_case_validate_rejects_appeal_id_on_non_appeal_case() {
        let error = GenericGovernanceCaseArtifact {
            schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
            case_id: "case-1".to_string(),
            charter_id: "charter-1".to_string(),
            governing_operator_id: "origin-a".to_string(),
            kind: GenericGovernanceCaseKind::Sanction,
            state: GenericGovernanceCaseState::Open,
            namespace: "https://registry.chio.example".to_string(),
            listing_id: "listing-1".to_string(),
            activation_id: None,
            subject_operator_id: Some("origin-a".to_string()),
            opened_at: 100,
            updated_at: 100,
            expires_at: Some(200),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::External,
                reference_id: "incident-1".to_string(),
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: Some("case-0".to_string()),
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            note: None,
        }
        .validate()
        .test_expect_err("appeal target only valid for appeal cases");

        assert!(error.contains("only valid for appeal cases"));
    }

    #[test]
    fn generic_governance_case_issue_request_rejects_invalid_listing_signature() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let charter = sample_charter("origin-a", &authority_keypair);
        let mut tampered_listing = listing.clone();
        tampered_listing.body.subject.actor_id = "tool-server-b".to_string();

        let error = sample_case_issue_request(charter, tampered_listing, None)
            .validate()
            .test_expect_err("tampered listing signature rejected");

        assert!(error.contains("listing signature is invalid"));
    }

    #[test]
    fn generic_governance_case_issue_request_rejects_invalid_activation_signature() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let charter = sample_charter("origin-a", &authority_keypair);
        let activation = sample_activation(&listing);
        let mut tampered_activation = activation.clone();
        tampered_activation.body.local_operator_id = "remote-b".to_string();

        let error = sample_case_issue_request(charter, listing, Some(tampered_activation))
            .validate()
            .test_expect_err("tampered activation signature rejected");

        assert!(error.contains("trust activation signature is invalid"));
    }

    #[test]
    fn build_generic_governance_charter_artifact_uses_request_issued_at() {
        let mut request = sample_charter_request();
        request.issued_at = Some(777);

        let charter = build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &request,
            130,
        )
        .test_expect("build charter");

        assert_eq!(charter.issued_at, 777);
        assert_eq!(charter.governing_operator_id, "origin-a");
        assert!(charter.charter_id.starts_with("charter-"));
    }

    #[test]
    fn generic_governance_evaluation_rejects_invalid_case_signature() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = sample_charter("origin-a", &authority_keypair);
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact(
                "origin-a",
                &sample_case_issue_request(
                    charter.clone(),
                    listing.clone(),
                    Some(activation.clone()),
                ),
                140,
            )
            .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");
        let mut tampered_case = case.clone();
        tampered_case.body.note = Some("tampered".to_string());

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: Some(activation),
                charter,
                case: tampered_case,
                prior_case: None,
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");

        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::CaseUnverifiable
        );
    }

    #[test]
    fn generic_governance_supersession_target_mismatch_fails_closed() {
        let listing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing("origin-a", &listing_keypair);
        let activation = sample_activation(&listing);
        let charter = sample_charter("origin-a", &authority_keypair);
        let mut case_request =
            sample_case_issue_request(charter.clone(), listing.clone(), Some(activation.clone()));
        case_request.kind = GenericGovernanceCaseKind::Sanction;
        case_request.supersedes_case_id = Some("prior-case-1".to_string());
        case_request.evidence_refs[0].kind = GenericGovernanceEvidenceKind::External;
        case_request.evidence_refs[0].reference_id = "incident-1".to_string();
        let case = SignedGenericGovernanceCase::sign(
            build_generic_governance_case_artifact("origin-a", &case_request, 140)
                .test_expect("build case"),
            &authority_keypair,
        )
        .test_expect("sign case");
        let prior_case = SignedGenericGovernanceCase::sign(
            GenericGovernanceCaseArtifact {
                schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
                case_id: "prior-case-1".to_string(),
                charter_id: charter.body.charter_id.clone(),
                governing_operator_id: "origin-a".to_string(),
                kind: GenericGovernanceCaseKind::Freeze,
                state: GenericGovernanceCaseState::Resolved,
                namespace: "https://registry.chio.example".to_string(),
                listing_id: "different-listing".to_string(),
                activation_id: Some(activation.body.activation_id.clone()),
                subject_operator_id: Some("origin-a".to_string()),
                opened_at: 120,
                updated_at: 121,
                expires_at: Some(500),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::External,
                    reference_id: "prior-incident".to_string(),
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: None,
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                note: None,
            },
            &authority_keypair,
        )
        .test_expect("sign prior case");

        let evaluation = evaluate_generic_governance_case(
            &GenericGovernanceCaseEvaluationRequest {
                listing,
                current_publisher: sample_publisher(
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                ),
                activation: Some(activation),
                charter,
                case,
                prior_case: Some(prior_case),
                evaluated_at: Some(150),
            },
            150,
        )
        .test_expect("evaluate governance");

        assert_eq!(
            evaluation.findings[0].code,
            GenericGovernanceFindingCode::SupersessionTargetInvalid
        );
    }

    #[test]
    fn capability_lease_validates_signature_lifetime_and_scope() {
        let issuer = Keypair::from_seed(&[11u8; 32]);
        let lease = CapabilityLeaseArtifact {
            schema: CAPABILITY_LEASE_SCHEMA_V1.to_string(),
            lease_id: "lease:buyer:refund:001".to_string(),
            issuer: "did:chio:buyer".to_string(),
            subject: "did:chio:vendor-payments".to_string(),
            scope_digest: "a".repeat(64),
            action_class: CapabilityLeaseActionClass::NarrowDestructive,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        };
        let signed = SignedCapabilityLease::sign(lease, &issuer).test_expect("sign lease");

        assert!(matches!(
            verify_capability_lease(&signed, 999, Some("a".repeat(64))),
            Err(GovernanceAuthorizationError::LeaseNotYetValid(_))
        ));
        assert!(verify_capability_lease(&signed, 1_500, Some("a".repeat(64))).is_ok());
        assert!(matches!(
            verify_capability_lease(&signed, 2_000, Some("a".repeat(64))),
            Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(_))
        ));
        assert!(matches!(
            verify_capability_lease(&signed, 1_500, Some("b".repeat(64))),
            Err(GovernanceAuthorizationError::ScopeDigestMismatch)
        ));
    }

    #[test]
    fn destructive_governance_receipt_binds_lease_workflow_and_step_hash() {
        let issuer = Keypair::from_seed(&[12u8; 32]);
        let receipt = GovernanceReceiptArtifact {
            schema: GOVERNANCE_RECEIPT_SCHEMA_V1.to_string(),
            receipt_id: "gov:buyer:refund:001".to_string(),
            authorizing_kernel: "did:chio:buyer".to_string(),
            case_kind: GovernanceReceiptCaseKind::DestructiveAuthorization,
            authorized_lease_id: "lease:buyer:refund:001".to_string(),
            workflow_id: "wf-chio-refund-001".to_string(),
            step_sha256: "c".repeat(64),
            issued_at_unix_ms: 1_100,
            expires_at_unix_ms: 1_900,
        };
        let signed =
            SignedGovernanceReceipt::sign(receipt, &issuer).test_expect("sign governance receipt");

        assert!(verify_destructive_authorization(
            &signed,
            "lease:buyer:refund:001",
            "wf-chio-refund-001",
            &"c".repeat(64),
            1_500,
        )
        .is_ok());
        assert!(matches!(
            verify_destructive_authorization(
                &signed,
                "lease:buyer:refund:001",
                "wf-chio-refund-001",
                &"c".repeat(64),
                1_099,
            ),
            Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
                _
            ))
        ));
        assert!(matches!(
            verify_step_governance_boundary(true, Some(&signed), 1_099),
            Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
                _
            ))
        ));
        assert!(matches!(
            verify_destructive_authorization(
                &signed,
                "lease:buyer:refund:001",
                "wf-other",
                &"c".repeat(64),
                1_500,
            ),
            Err(GovernanceAuthorizationError::WorkflowMismatch)
        ));
    }

    #[test]
    fn non_destructive_steps_do_not_require_governance_receipts() {
        assert!(verify_step_governance_boundary(false, None, 1_500).is_ok());
        assert!(matches!(
            verify_step_governance_boundary(true, None, 1_500),
            Err(GovernanceAuthorizationError::GovernanceReceiptRequired)
        ));
    }
}
