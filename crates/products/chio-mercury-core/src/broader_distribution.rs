use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA: &str =
    "chio.mercury.broader_distribution_profile.v1";
pub const MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA: &str =
    "chio.mercury.broader_distribution_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryBroaderDistributionMotion {
    SelectiveAccountQualification,
}

impl MercuryBroaderDistributionMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectiveAccountQualification => "selective_account_qualification",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryBroaderDistributionSurface {
    GovernedDistributionBundle,
}

impl MercuryBroaderDistributionSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovernedDistributionBundle => "governed_distribution_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryBroaderDistributionProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub distribution_motion: MercuryBroaderDistributionMotion,
    pub distribution_surface: MercuryBroaderDistributionSurface,
    pub claim_governance: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryBroaderDistributionProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("broader_distribution_profile.profile_id", &self.profile_id)?;
        ensure_non_empty(
            "broader_distribution_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "broader_distribution_profile.claim_governance",
            &self.claim_governance,
        )?;
        ensure_non_empty(
            "broader_distribution_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "broader_distribution_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "broader_distribution_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryBroaderDistributionArtifactKind {
    TargetAccountFreeze,
    BroaderDistributionManifest,
    ClaimGovernanceRules,
    SelectiveAccountApproval,
    DistributionHandoffBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryBroaderDistributionArtifact {
    pub artifact_kind: MercuryBroaderDistributionArtifactKind,
    pub relative_path: String,
}

impl MercuryBroaderDistributionArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "broader_distribution_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryBroaderDistributionPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub distribution_motion: MercuryBroaderDistributionMotion,
    pub distribution_surface: MercuryBroaderDistributionSurface,
    pub qualification_owner: String,
    pub approval_owner: String,
    pub distribution_owner: String,
    pub approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub reference_distribution_package_file: String,
    pub account_motion_freeze_file: String,
    pub reference_distribution_manifest_file: String,
    pub reference_claim_discipline_file: String,
    pub reference_buyer_approval_file: String,
    pub reference_sales_handoff_file: String,
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
    pub artifacts: Vec<MercuryBroaderDistributionArtifact>,
}

impl MercuryBroaderDistributionPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("broader_distribution_package.package_id", &self.package_id)?;
        ensure_non_empty(
            "broader_distribution_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "broader_distribution_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "broader_distribution_package.qualification_owner",
            &self.qualification_owner,
        )?;
        ensure_non_empty(
            "broader_distribution_package.approval_owner",
            &self.approval_owner,
        )?;
        ensure_non_empty(
            "broader_distribution_package.distribution_owner",
            &self.distribution_owner,
        )?;
        ensure_non_empty(
            "broader_distribution_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.account_motion_freeze_file",
            &self.account_motion_freeze_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_distribution_manifest_file",
            &self.reference_distribution_manifest_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_claim_discipline_file",
            &self.reference_claim_discipline_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_buyer_approval_file",
            &self.reference_buyer_approval_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_sales_handoff_file",
            &self.reference_sales_handoff_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.renewal_evidence_manifest_file",
            &self.renewal_evidence_manifest_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.renewal_acknowledgement_file",
            &self.renewal_acknowledgement_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reference_readiness_brief_file",
            &self.reference_readiness_brief_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "broader_distribution_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.approval_required {
            return Err(MercuryContractError::Validation(
                "broader_distribution_package.approval_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "broader_distribution_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "broader_distribution_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "broader_distribution_package.artifacts contains duplicate artifact kind {:?}",
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
    fn broader_distribution_profile_validates() {
        let profile = MercuryBroaderDistributionProfile {
            schema: MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
            profile_id: "broader-distribution-selective-account-qualification".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
            distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
            claim_governance: "governed-broader-distribution-evidence-only".to_string(),
            retained_artifact_policy:
                "retain-bounded-broader-distribution-and-qualification-artifacts".to_string(),
            intended_use: "Qualify one bounded Mercury broader-distribution lane over the validated reference-distribution package."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("broader distribution profile");
    }

    #[test]
    fn broader_distribution_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryBroaderDistributionPackage {
            schema: MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
            package_id: "broader-distribution-selective-account-qualification".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes.".to_string(),
            distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
            distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
            qualification_owner: "mercury-account-qualification".to_string(),
            approval_owner: "mercury-broader-distribution-approval".to_string(),
            distribution_owner: "mercury-broader-distribution".to_string(),
            approval_required: true,
            fail_closed: true,
            profile_file: "broader-distribution-profile.json".to_string(),
            reference_distribution_package_file: "qualification-evidence/reference-distribution-package.json".to_string(),
            account_motion_freeze_file: "qualification-evidence/account-motion-freeze.json".to_string(),
            reference_distribution_manifest_file:
                "qualification-evidence/reference-distribution-manifest.json".to_string(),
            reference_claim_discipline_file:
                "qualification-evidence/reference-claim-discipline-rules.json".to_string(),
            reference_buyer_approval_file:
                "qualification-evidence/reference-buyer-approval.json".to_string(),
            reference_sales_handoff_file:
                "qualification-evidence/reference-sales-handoff-brief.json".to_string(),
            controlled_adoption_package_file:
                "qualification-evidence/controlled-adoption-package.json".to_string(),
            renewal_evidence_manifest_file:
                "qualification-evidence/renewal-evidence-manifest.json".to_string(),
            renewal_acknowledgement_file:
                "qualification-evidence/renewal-acknowledgement.json".to_string(),
            reference_readiness_brief_file:
                "qualification-evidence/reference-readiness-brief.json".to_string(),
            release_readiness_package_file:
                "qualification-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file:
                "qualification-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file:
                "qualification-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "qualification-evidence/proof-package.json".to_string(),
            inquiry_package_file: "qualification-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "qualification-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "qualification-evidence/reviewer-package.json".to_string(),
            qualification_report_file:
                "qualification-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryBroaderDistributionArtifact {
                    artifact_kind: MercuryBroaderDistributionArtifactKind::TargetAccountFreeze,
                    relative_path: "target-account-freeze.json".to_string(),
                },
                MercuryBroaderDistributionArtifact {
                    artifact_kind: MercuryBroaderDistributionArtifactKind::TargetAccountFreeze,
                    relative_path: "selective-account-approval.json".to_string(),
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
