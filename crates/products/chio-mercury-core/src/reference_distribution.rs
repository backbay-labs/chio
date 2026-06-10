use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA: &str =
    "chio.mercury.reference_distribution_profile.v1";
pub const MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA: &str =
    "chio.mercury.reference_distribution_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReferenceDistributionMotion {
    LandedAccountExpansion,
}

impl MercuryReferenceDistributionMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LandedAccountExpansion => "landed_account_expansion",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReferenceDistributionSurface {
    ApprovedReferenceBundle,
}

impl MercuryReferenceDistributionSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApprovedReferenceBundle => "approved_reference_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReferenceDistributionProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub expansion_motion: MercuryReferenceDistributionMotion,
    pub distribution_surface: MercuryReferenceDistributionSurface,
    pub claim_discipline: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryReferenceDistributionProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "reference_distribution_profile.profile_id",
            &self.profile_id,
        )?;
        ensure_non_empty(
            "reference_distribution_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "reference_distribution_profile.claim_discipline",
            &self.claim_discipline,
        )?;
        ensure_non_empty(
            "reference_distribution_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "reference_distribution_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "reference_distribution_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryReferenceDistributionArtifactKind {
    AccountMotionFreeze,
    ReferenceDistributionManifest,
    ClaimDisciplineRules,
    BuyerReferenceApproval,
    SalesHandoffBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReferenceDistributionArtifact {
    pub artifact_kind: MercuryReferenceDistributionArtifactKind,
    pub relative_path: String,
}

impl MercuryReferenceDistributionArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "reference_distribution_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReferenceDistributionPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub expansion_motion: MercuryReferenceDistributionMotion,
    pub distribution_surface: MercuryReferenceDistributionSurface,
    pub reference_owner: String,
    pub buyer_approval_owner: String,
    pub sales_owner: String,
    pub approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub controlled_adoption_package_file: String,
    pub renewal_evidence_manifest_file: String,
    pub renewal_acknowledgement_file: String,
    pub reference_readiness_brief_file: String,
    pub release_readiness_package_file: String,
    pub trust_network_package_file: String,
    pub assurance_suite_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub inquiry_verification_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryReferenceDistributionArtifact>,
}

impl MercuryReferenceDistributionPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "reference_distribution_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "reference_distribution_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "reference_distribution_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "reference_distribution_package.reference_owner",
            &self.reference_owner,
        )?;
        ensure_non_empty(
            "reference_distribution_package.buyer_approval_owner",
            &self.buyer_approval_owner,
        )?;
        ensure_non_empty(
            "reference_distribution_package.sales_owner",
            &self.sales_owner,
        )?;
        ensure_non_empty(
            "reference_distribution_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.renewal_evidence_manifest_file",
            &self.renewal_evidence_manifest_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.renewal_acknowledgement_file",
            &self.renewal_acknowledgement_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.reference_readiness_brief_file",
            &self.reference_readiness_brief_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "reference_distribution_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.approval_required {
            return Err(MercuryContractError::Validation(
                "reference_distribution_package.approval_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "reference_distribution_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "reference_distribution_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "reference_distribution_package.artifacts contains duplicate artifact kind {:?}",
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reference_distribution_profile_validates() {
        let profile = MercuryReferenceDistributionProfile {
            schema: MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
            profile_id: "reference-distribution-landed-account-expansion".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
            distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
            claim_discipline: "approved-reference-evidence-only".to_string(),
            retained_artifact_policy:
                "retain-bounded-reference-distribution-and-expansion-artifacts".to_string(),
            intended_use: "Qualify one bounded Mercury reference-distribution lane over the validated controlled-adoption package."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("reference distribution profile");
    }

    #[test]
    fn reference_distribution_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryReferenceDistributionPackage {
            schema: MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
            package_id: "reference-distribution-landed-account-expansion".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes.".to_string(),
            expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
            distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
            reference_owner: "mercury-reference-program".to_string(),
            buyer_approval_owner: "mercury-buyer-reference-approval".to_string(),
            sales_owner: "mercury-landed-account-sales".to_string(),
            approval_required: true,
            fail_closed: true,
            profile_file: "reference-distribution-profile.json".to_string(),
            controlled_adoption_package_file: "reference-evidence/controlled-adoption-package.json"
                .to_string(),
            renewal_evidence_manifest_file: "reference-evidence/renewal-evidence-manifest.json"
                .to_string(),
            renewal_acknowledgement_file: "reference-evidence/renewal-acknowledgement.json"
                .to_string(),
            reference_readiness_brief_file: "reference-evidence/reference-readiness-brief.json"
                .to_string(),
            release_readiness_package_file: "reference-evidence/release-readiness-package.json"
                .to_string(),
            trust_network_package_file: "reference-evidence/trust-network-package.json"
                .to_string(),
            assurance_suite_package_file: "reference-evidence/assurance-suite-package.json"
                .to_string(),
            proof_package_file: "reference-evidence/proof-package.json".to_string(),
            inquiry_package_file: "reference-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file: "reference-evidence/inquiry-verification.json"
                .to_string(),
            reviewer_package_file: "reference-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "reference-evidence/qualification-report.json"
                .to_string(),
            artifacts: vec![
                MercuryReferenceDistributionArtifact {
                    artifact_kind:
                        MercuryReferenceDistributionArtifactKind::AccountMotionFreeze,
                    relative_path: "account-motion-freeze.json".to_string(),
                },
                MercuryReferenceDistributionArtifact {
                    artifact_kind:
                        MercuryReferenceDistributionArtifactKind::AccountMotionFreeze,
                    relative_path: "buyer-reference-approval.json".to_string(),
                },
            ],
        };

        let error = package
            .validate()
            .expect_err("duplicate artifact kinds must fail");
        assert!(
            error.to_string().contains("duplicate artifact kind"),
            "unexpected error: {error}"
        );
    }
}
