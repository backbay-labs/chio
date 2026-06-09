use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_ASSURANCE_PACKAGE_SCHEMA: &str = "chio.mercury.assurance_package.v1";
pub const MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA: &str =
    "chio.mercury.downstream_review_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryAssuranceAudience {
    InternalReview,
    ExternalReview,
}

impl MercuryAssuranceAudience {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InternalReview => "internal_review",
            Self::ExternalReview => "external_review",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssurancePackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub audience: MercuryAssuranceAudience,
    pub disclosure_profile: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub verifier_equivalent: bool,
}

impl MercuryAssurancePackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_ASSURANCE_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_ASSURANCE_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("assurance_package.package_id", &self.package_id)?;
        ensure_non_empty("assurance_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "assurance_package.disclosure_profile",
            &self.disclosure_profile,
        )?;
        ensure_non_empty(
            "assurance_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "assurance_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "assurance_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "assurance_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDownstreamConsumerProfile {
    CaseManagementReview,
}

impl MercuryDownstreamConsumerProfile {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CaseManagementReview => "case_management_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDownstreamTransport {
    FileDrop,
}

impl MercuryDownstreamTransport {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileDrop => "file_drop",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDownstreamArtifactRole {
    InternalAssurancePackage,
    ExternalAssurancePackage,
    ReviewerPackage,
    QualificationReport,
    ExternalInquiryPackage,
    ExternalInquiryVerification,
    ConsumerManifest,
    DeliveryAcknowledgement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDownstreamArtifact {
    pub role: MercuryDownstreamArtifactRole,
    pub relative_path: String,
    pub disclosure_profile: String,
}

impl MercuryDownstreamArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "downstream_review_package.artifacts[].relative_path",
            &self.relative_path,
        )?;
        ensure_non_empty(
            "downstream_review_package.artifacts[].disclosure_profile",
            &self.disclosure_profile,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDownstreamReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub consumer_profile: MercuryDownstreamConsumerProfile,
    pub transport: MercuryDownstreamTransport,
    pub destination_label: String,
    pub destination_owner: String,
    pub support_owner: String,
    pub acknowledgement_required: bool,
    pub fail_closed: bool,
    pub artifacts: Vec<MercuryDownstreamArtifact>,
}

impl MercuryDownstreamReviewPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("downstream_review_package.package_id", &self.package_id)?;
        ensure_non_empty("downstream_review_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "downstream_review_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "downstream_review_package.destination_label",
            &self.destination_label,
        )?;
        ensure_non_empty(
            "downstream_review_package.destination_owner",
            &self.destination_owner,
        )?;
        ensure_non_empty(
            "downstream_review_package.support_owner",
            &self.support_owner,
        )?;
        if !self.acknowledgement_required {
            return Err(MercuryContractError::Validation(
                "downstream_review_package.acknowledgement_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "downstream_review_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "downstream_review_package.artifacts",
            ));
        }

        let mut roles = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !roles.insert(artifact.role) {
                return Err(MercuryContractError::Validation(format!(
                    "downstream_review_package.artifacts contains duplicate role {:?}",
                    artifact.role
                )));
            }
        }

        Ok(())
    }
}

fn ensure_non_empty(field: &'static str, value: &str) -> Result<(), MercuryContractError> {
    if value.trim().is_empty() {
        Err(MercuryContractError::EmptyField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn assurance_package_validates() {
        let package = MercuryAssurancePackage {
            schema: MERCURY_ASSURANCE_PACKAGE_SCHEMA.to_string(),
            package_id: "assurance-internal-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            audience: MercuryAssuranceAudience::InternalReview,
            disclosure_profile: "internal-review-default".to_string(),
            proof_package_file: "qualification/supervised-live/proof-package.json".to_string(),
            inquiry_package_file: "assurance/internal-review/inquiry-package.json".to_string(),
            reviewer_package_file: "qualification/reviewer-package.json".to_string(),
            qualification_report_file: "qualification/qualification-report.json".to_string(),
            verifier_equivalent: false,
        };
        package.validate().expect("assurance package");
    }

    #[test]
    fn downstream_review_package_rejects_duplicate_roles() {
        let package = MercuryDownstreamReviewPackage {
            schema: MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA.to_string(),
            package_id: "downstream-review-package".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview,
            transport: MercuryDownstreamTransport::FileDrop,
            destination_label: "case-management-review-drop".to_string(),
            destination_owner: "partner-review-ops".to_string(),
            support_owner: "mercury-review-ops".to_string(),
            acknowledgement_required: true,
            fail_closed: true,
            artifacts: vec![
                MercuryDownstreamArtifact {
                    role: MercuryDownstreamArtifactRole::ReviewerPackage,
                    relative_path: "qualification/reviewer-package.json".to_string(),
                    disclosure_profile: "internal-review-default".to_string(),
                },
                MercuryDownstreamArtifact {
                    role: MercuryDownstreamArtifactRole::ReviewerPackage,
                    relative_path: "consumer-drop/reviewer-package.json".to_string(),
                    disclosure_profile: "external-review-default".to_string(),
                },
            ],
        };
        let error = package.validate().expect_err("duplicate role");
        assert!(error.to_string().contains("duplicate role"), "{error}");
    }
}
