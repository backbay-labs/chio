use serde::{Deserialize, Serialize};

use crate::canonical_json_bytes;
use crate::crypto::sha256_hex;
use crate::listing::{
    normalize_namespace, GenericListingActorKind, GenericRegistryPublisher, SignedGenericListing,
    SignedGenericTrustActivation,
};
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{is_sha256_hex, validate_non_empty};

pub const GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA: &str = "chio.registry.governance-charter.v1";
pub const GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA: &str = "chio.registry.governance-case.v1";

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
