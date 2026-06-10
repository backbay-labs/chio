use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_RELEASE_READINESS_PROFILE_SCHEMA: &str =
    "chio.mercury.release_readiness_profile.v1";
pub const MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA: &str =
    "chio.mercury.release_readiness_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReleaseReadinessAudience {
    Reviewer,
    Partner,
    Operator,
}

impl MercuryReleaseReadinessAudience {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reviewer => "reviewer",
            Self::Partner => "partner",
            Self::Operator => "operator",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReleaseReadinessDeliverySurface {
    SignedPartnerReviewBundle,
}

impl MercuryReleaseReadinessDeliverySurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignedPartnerReviewBundle => "signed_partner_review_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReleaseReadinessProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub audiences: Vec<MercuryReleaseReadinessAudience>,
    pub delivery_surface: MercuryReleaseReadinessDeliverySurface,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryReleaseReadinessProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_RELEASE_READINESS_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_RELEASE_READINESS_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("release_readiness_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("release_readiness_profile.workflow_id", &self.workflow_id)?;
        ensure_unique_audiences("release_readiness_profile.audiences", &self.audiences)?;
        ensure_non_empty(
            "release_readiness_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("release_readiness_profile.intended_use", &self.intended_use)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "release_readiness_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReleaseReadinessArtifactKind {
    PartnerDeliveryManifest,
    DeliveryAcknowledgement,
    OperatorReleaseChecklist,
    EscalationManifest,
    SupportHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReleaseReadinessArtifact {
    pub artifact_kind: MercuryReleaseReadinessArtifactKind,
    pub relative_path: String,
}

impl MercuryReleaseReadinessArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "release_readiness_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReleaseReadinessPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub audiences: Vec<MercuryReleaseReadinessAudience>,
    pub delivery_surface: MercuryReleaseReadinessDeliverySurface,
    pub release_owner: String,
    pub partner_owner: String,
    pub support_owner: String,
    pub acknowledgement_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub trust_network_package_file: String,
    pub assurance_suite_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryReleaseReadinessArtifact>,
}

impl MercuryReleaseReadinessPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("release_readiness_package.package_id", &self.package_id)?;
        ensure_non_empty("release_readiness_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "release_readiness_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_unique_audiences("release_readiness_package.audiences", &self.audiences)?;
        ensure_non_empty(
            "release_readiness_package.release_owner",
            &self.release_owner,
        )?;
        ensure_non_empty(
            "release_readiness_package.partner_owner",
            &self.partner_owner,
        )?;
        ensure_non_empty(
            "release_readiness_package.support_owner",
            &self.support_owner,
        )?;
        ensure_non_empty("release_readiness_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "release_readiness_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "release_readiness_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "release_readiness_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "release_readiness_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "release_readiness_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "release_readiness_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.acknowledgement_required {
            return Err(MercuryContractError::Validation(
                "release_readiness_package.acknowledgement_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "release_readiness_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "release_readiness_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "release_readiness_package.artifacts contains duplicate artifact kind {:?}",
                    artifact.artifact_kind
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

fn ensure_unique_audiences(
    field: &'static str,
    audiences: &[MercuryReleaseReadinessAudience],
) -> Result<(), MercuryContractError> {
    if audiences.is_empty() {
        return Err(MercuryContractError::MissingField(field));
    }

    let mut seen = HashSet::new();
    for audience in audiences {
        if !seen.insert(*audience) {
            return Err(MercuryContractError::Validation(format!(
                "{field} contains duplicate value {:?}",
                audience
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn release_readiness_profile_validates() {
        let profile = MercuryReleaseReadinessProfile {
            schema: MERCURY_RELEASE_READINESS_PROFILE_SCHEMA.to_string(),
            profile_id: "release-readiness-workflow-release-control".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            audiences: vec![
                MercuryReleaseReadinessAudience::Reviewer,
                MercuryReleaseReadinessAudience::Partner,
                MercuryReleaseReadinessAudience::Operator,
            ],
            delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
            retained_artifact_policy:
                "retain-bounded-release-review-and-partner-delivery-artifacts".to_string(),
            intended_use: "Launch one bounded Mercury release-readiness lane over the validated trust-network bundle."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("release readiness profile");
    }

    #[test]
    fn release_readiness_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryReleaseReadinessPackage {
            schema: MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA.to_string(),
            package_id: "release-readiness-workflow-release-control".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            audiences: vec![
                MercuryReleaseReadinessAudience::Reviewer,
                MercuryReleaseReadinessAudience::Partner,
                MercuryReleaseReadinessAudience::Operator,
            ],
            delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
            release_owner: "mercury-release-manager".to_string(),
            partner_owner: "mercury-partner-delivery".to_string(),
            support_owner: "mercury-release-ops".to_string(),
            acknowledgement_required: true,
            fail_closed: true,
            profile_file: "release-readiness-profile.json".to_string(),
            trust_network_package_file: "partner-delivery/trust-network-package.json".to_string(),
            assurance_suite_package_file: "partner-delivery/assurance-suite-package.json"
                .to_string(),
            proof_package_file: "partner-delivery/proof-package.json".to_string(),
            inquiry_package_file: "partner-delivery/inquiry-package.json".to_string(),
            reviewer_package_file: "partner-delivery/reviewer-package.json".to_string(),
            qualification_report_file: "partner-delivery/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryReleaseReadinessArtifact {
                    artifact_kind: MercuryReleaseReadinessArtifactKind::PartnerDeliveryManifest,
                    relative_path: "partner-delivery-manifest.json".to_string(),
                },
                MercuryReleaseReadinessArtifact {
                    artifact_kind: MercuryReleaseReadinessArtifactKind::PartnerDeliveryManifest,
                    relative_path: "partner-delivery-manifest-copy.json".to_string(),
                },
            ],
        };
        let error = package.validate().expect_err("duplicate artifact kind");
        assert!(
            error.to_string().contains("duplicate artifact kind"),
            "{error}"
        );
    }
}
