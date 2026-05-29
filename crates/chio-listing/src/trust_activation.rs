//! Generic trust activation: admission classes, eligibility policy, activation artifacts, and evaluation.

use serde::{Deserialize, Serialize};

use crate::crypto::{sha256_hex, PublicKey};
use crate::receipt::SignedExportEnvelope;
use crate::util::{
    ensure_generic_listing_signed_by_namespace_owner, generic_listing_body_sha256,
    normalize_namespace, validate_non_empty,
};
use crate::{
    canonical_json_bytes, GenericListingActorKind, GenericListingFreshnessState,
    GenericListingReplicaFreshness, GenericListingStatus, GenericRegistryPublisher,
    GenericRegistryPublisherRole, SignedGenericListing, GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustAdmissionClass {
    PublicUntrusted,
    Reviewable,
    BondBacked,
    RoleGated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustActivationDisposition {
    PendingReview,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustActivationFindingCode {
    MissingActivation,
    ListingUnverifiable,
    ActivationUnverifiable,
    ListingMismatch,
    ListingStale,
    ListingDivergent,
    ActivationExpired,
    ActivationPendingReview,
    ActivationDenied,
    AdmissionClassUntrusted,
    ActorKindIneligible,
    PublisherRoleIneligible,
    ListingStatusIneligible,
    ListingOperatorIneligible,
    BondBackingRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEligibility {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_publisher_roles: Vec<GenericRegistryPublisherRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_statuses: Vec<GenericListingStatus>,
    #[serde(default)]
    pub require_fresh_listing: bool,
    #[serde(default)]
    pub require_bond_backing: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_listing_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

impl GenericTrustActivationEligibility {
    pub fn validate(&self, admission_class: GenericTrustAdmissionClass) -> Result<(), String> {
        for (index, operator_id) in self.required_listing_operator_ids.iter().enumerate() {
            validate_non_empty(
                operator_id,
                &format!("eligibility.required_listing_operator_ids[{index}]"),
            )?;
        }
        if matches!(admission_class, GenericTrustAdmissionClass::RoleGated)
            && self.required_listing_operator_ids.is_empty()
        {
            return Err(
                "role_gated trust activation requires required_listing_operator_ids".to_string(),
            );
        }
        if matches!(admission_class, GenericTrustAdmissionClass::BondBacked)
            && !self.require_bond_backing
        {
            return Err("bond_backed trust activation must require bond backing".to_string());
        }
        if !matches!(admission_class, GenericTrustAdmissionClass::BondBacked)
            && self.require_bond_backing
        {
            return Err(
                "require_bond_backing is only valid for bond_backed trust activation".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationReviewContext {
    pub publisher: GenericRegistryPublisher,
    pub freshness: GenericListingReplicaFreshness,
}

impl GenericTrustActivationReviewContext {
    pub fn validate(&self) -> Result<(), String> {
        self.publisher.validate()?;
        self.freshness.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationArtifact {
    pub schema: String,
    pub activation_id: String,
    pub local_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_operator_name: Option<String>,
    pub listing_id: String,
    pub namespace: String,
    pub listing_sha256: String,
    pub listing_published_at: u64,
    pub admission_class: GenericTrustAdmissionClass,
    pub disposition: GenericTrustActivationDisposition,
    pub eligibility: GenericTrustActivationEligibility,
    pub review_context: GenericTrustActivationReviewContext,
    pub requested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericTrustActivationArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic trust activation schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.activation_id, "activation_id")?;
        validate_non_empty(&self.local_operator_id, "local_operator_id")?;
        validate_non_empty(&self.listing_id, "listing_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.listing_sha256, "listing_sha256")?;
        validate_non_empty(&self.requested_by, "requested_by")?;
        self.eligibility.validate(self.admission_class)?;
        self.review_context.validate()?;
        if let Some(reviewed_at) = self.reviewed_at {
            if reviewed_at < self.requested_at {
                return Err("reviewed_at must be greater than or equal to requested_at".to_string());
            }
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.requested_at {
                return Err("expires_at must be greater than requested_at".to_string());
            }
        }
        match self.disposition {
            GenericTrustActivationDisposition::PendingReview => {
                if self.reviewed_at.is_some() || self.reviewed_by.is_some() {
                    return Err(
                        "pending_review trust activation must not carry review completion fields"
                            .to_string(),
                    );
                }
            }
            GenericTrustActivationDisposition::Approved
            | GenericTrustActivationDisposition::Denied => {
                if self.reviewed_at.is_none() || self.reviewed_by.as_deref().is_none() {
                    return Err(
                        "approved or denied trust activation requires reviewed_at and reviewed_by"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedGenericTrustActivation = SignedExportEnvelope<GenericTrustActivationArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationIssueRequest {
    pub listing: SignedGenericListing,
    pub admission_class: GenericTrustAdmissionClass,
    pub disposition: GenericTrustActivationDisposition,
    pub eligibility: GenericTrustActivationEligibility,
    pub review_context: GenericTrustActivationReviewContext,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericTrustActivationIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        ensure_generic_listing_signed_by_namespace_owner(
            &self.listing,
            "trust activation listing",
        )?;
        self.review_context.validate()?;
        self.eligibility.validate(self.admission_class)?;
        validate_non_empty(&self.requested_by, "requested_by")?;
        if matches!(
            self.disposition,
            GenericTrustActivationDisposition::Approved
        ) && self.review_context.freshness.state != GenericListingFreshnessState::Fresh
        {
            return Err(
                "approved trust activation requires fresh listing review context".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEvaluationRequest {
    pub listing: SignedGenericListing,
    pub current_publisher: GenericRegistryPublisher,
    pub current_freshness: GenericListingReplicaFreshness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

impl GenericTrustActivationEvaluationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        self.current_publisher.validate()?;
        self.current_freshness.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationFinding {
    pub code: GenericTrustActivationFindingCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEvaluation {
    pub listing_id: String,
    pub namespace: String,
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_class: Option<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<GenericTrustActivationDisposition>,
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GenericTrustActivationFinding>,
}

pub fn build_generic_trust_activation_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &GenericTrustActivationIssueRequest,
    issued_at: u64,
) -> Result<GenericTrustActivationArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    let requested_at = request.requested_at.unwrap_or(issued_at);
    let reviewed_at = request.reviewed_at.or(match request.disposition {
        GenericTrustActivationDisposition::PendingReview => None,
        GenericTrustActivationDisposition::Approved | GenericTrustActivationDisposition::Denied => {
            Some(issued_at)
        }
    });
    let listing_sha256 = generic_listing_body_sha256(&request.listing)?;
    let activation_id = format!(
        "activation-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                &request.listing.body.listing_id,
                &listing_sha256,
                request.admission_class,
                request.disposition,
                requested_at,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = GenericTrustActivationArtifact {
        schema: GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA.to_string(),
        activation_id,
        local_operator_id: local_operator_id.to_string(),
        local_operator_name,
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        listing_sha256,
        listing_published_at: request.listing.body.published_at,
        admission_class: request.admission_class,
        disposition: request.disposition,
        eligibility: request.eligibility.clone(),
        review_context: request.review_context.clone(),
        requested_at,
        reviewed_at,
        expires_at: request.expires_at,
        requested_by: request.requested_by.clone(),
        reviewed_by: request.reviewed_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn evaluate_generic_trust_activation(
    request: &GenericTrustActivationEvaluationRequest,
    now: u64,
    trusted_local_operator_signer: &PublicKey,
) -> Result<GenericTrustActivationEvaluation, String> {
    request.validate()?;
    let mut evaluation = GenericTrustActivationEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        evaluated_at: request.evaluated_at.unwrap_or(now),
        local_operator_id: None,
        admission_class: None,
        disposition: None,
        admitted: false,
        findings: Vec::new(),
    };

    if let Err(error) = ensure_generic_listing_signed_by_namespace_owner(
        &request.listing,
        "trust activation listing",
    ) {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingUnverifiable,
            message: error,
        });
        return Ok(evaluation);
    }

    let Some(activation) = request.activation.as_ref() else {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::MissingActivation,
            message: "listing visibility requires an explicit local trust activation artifact"
                .to_string(),
        });
        return Ok(evaluation);
    };

    if !activation
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationUnverifiable,
            message: "trust activation signature is invalid".to_string(),
        });
        return Ok(evaluation);
    }
    if activation.signer_key != *trusted_local_operator_signer {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationUnverifiable,
            message: "trust activation signer is not trusted by this local operator".to_string(),
        });
        return Ok(evaluation);
    }

    if let Err(error) = activation.body.validate() {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationUnverifiable,
            message: error,
        });
        return Ok(evaluation);
    }

    evaluation.local_operator_id = Some(activation.body.local_operator_id.clone());
    evaluation.admission_class = Some(activation.body.admission_class);
    evaluation.disposition = Some(activation.body.disposition);

    let listing_sha256 = generic_listing_body_sha256(&request.listing)?;
    if activation.body.listing_id != request.listing.body.listing_id
        || normalize_namespace(&activation.body.namespace)
            != normalize_namespace(&request.listing.body.namespace)
        || activation.body.listing_sha256 != listing_sha256
        || activation.body.listing_published_at != request.listing.body.published_at
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingMismatch,
            message:
                "trust activation does not match the current listing identity, namespace, or body hash"
                    .to_string(),
        });
        return Ok(evaluation);
    }

    match request.current_freshness.state {
        GenericListingFreshnessState::Stale => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ListingStale,
                message:
                    "current listing report is stale and cannot be activated for runtime trust"
                        .to_string(),
            });
            return Ok(evaluation);
        }
        GenericListingFreshnessState::Divergent => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ListingDivergent,
                message:
                    "current listing report is divergent and cannot be activated for runtime trust"
                        .to_string(),
            });
            return Ok(evaluation);
        }
        GenericListingFreshnessState::Fresh => {}
    }

    if activation
        .body
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluation.evaluated_at)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationExpired,
            message: "trust activation has expired".to_string(),
        });
        return Ok(evaluation);
    }

    match activation.body.disposition {
        GenericTrustActivationDisposition::PendingReview => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ActivationPendingReview,
                message: "trust activation remains pending review".to_string(),
            });
            return Ok(evaluation);
        }
        GenericTrustActivationDisposition::Denied => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ActivationDenied,
                message: "trust activation was explicitly denied".to_string(),
            });
            return Ok(evaluation);
        }
        GenericTrustActivationDisposition::Approved => {}
    }

    if activation.body.eligibility.require_fresh_listing
        && request.current_freshness.state != GenericListingFreshnessState::Fresh
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingStale,
            message: "trust activation requires fresh listing evidence".to_string(),
        });
        return Ok(evaluation);
    }

    if !activation.body.eligibility.allowed_actor_kinds.is_empty()
        && !activation
            .body
            .eligibility
            .allowed_actor_kinds
            .contains(&request.listing.body.subject.actor_kind)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActorKindIneligible,
            message: "listing actor kind is not eligible under the activation policy".to_string(),
        });
        return Ok(evaluation);
    }

    if !activation
        .body
        .eligibility
        .allowed_publisher_roles
        .is_empty()
        && !activation
            .body
            .eligibility
            .allowed_publisher_roles
            .contains(&request.current_publisher.role)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::PublisherRoleIneligible,
            message: "listing publisher role is not eligible under the activation policy"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if !activation.body.eligibility.allowed_statuses.is_empty()
        && !activation
            .body
            .eligibility
            .allowed_statuses
            .contains(&request.listing.body.status)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingStatusIneligible,
            message: "listing lifecycle status is not eligible under the activation policy"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if !activation
        .body
        .eligibility
        .required_listing_operator_ids
        .is_empty()
        && !activation
            .body
            .eligibility
            .required_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingOperatorIneligible,
            message: "listing operator is not eligible under the activation policy".to_string(),
        });
        return Ok(evaluation);
    }

    if matches!(
        activation.body.admission_class,
        GenericTrustAdmissionClass::PublicUntrusted
    ) {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::AdmissionClassUntrusted,
            message: "public_untrusted admission class preserves visibility without runtime trust"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if activation.body.eligibility.require_bond_backing {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::BondBackingRequired,
            message:
                "bond_backed activation remains review-visible only until bond backing is proven"
                    .to_string(),
        });
        return Ok(evaluation);
    }

    evaluation.admitted = true;
    Ok(evaluation)
}
