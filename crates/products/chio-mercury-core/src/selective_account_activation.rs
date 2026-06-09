use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA: &str =
    "chio.mercury.selective_account_activation_profile.v1";
pub const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA: &str =
    "chio.mercury.selective_account_activation_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySelectiveAccountActivationMotion {
    SelectiveAccountActivation,
}

impl MercurySelectiveAccountActivationMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectiveAccountActivation => "selective_account_activation",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySelectiveAccountActivationSurface {
    ControlledDeliveryBundle,
}

impl MercurySelectiveAccountActivationSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlledDeliveryBundle => "controlled_delivery_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySelectiveAccountActivationProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub activation_motion: MercurySelectiveAccountActivationMotion,
    pub delivery_surface: MercurySelectiveAccountActivationSurface,
    pub claim_containment: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercurySelectiveAccountActivationProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "selective_account_activation_profile.profile_id",
            &self.profile_id,
        )?;
        ensure_non_empty(
            "selective_account_activation_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "selective_account_activation_profile.claim_containment",
            &self.claim_containment,
        )?;
        ensure_non_empty(
            "selective_account_activation_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "selective_account_activation_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "selective_account_activation_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercurySelectiveAccountActivationArtifactKind {
    ActivationScopeFreeze,
    ActivationManifest,
    ClaimContainmentRules,
    ActivationApprovalRefresh,
    CustomerHandoffBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySelectiveAccountActivationArtifact {
    pub artifact_kind: MercurySelectiveAccountActivationArtifactKind,
    pub relative_path: String,
}

impl MercurySelectiveAccountActivationArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "selective_account_activation_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySelectiveAccountActivationPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub activation_motion: MercurySelectiveAccountActivationMotion,
    pub delivery_surface: MercurySelectiveAccountActivationSurface,
    pub activation_owner: String,
    pub approval_owner: String,
    pub delivery_owner: String,
    pub approval_refresh_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub broader_distribution_package_file: String,
    pub target_account_freeze_file: String,
    pub broader_distribution_manifest_file: String,
    pub claim_governance_rules_file: String,
    pub selective_account_approval_file: String,
    pub distribution_handoff_brief_file: String,
    pub reference_distribution_package_file: String,
    pub controlled_adoption_package_file: String,
    pub release_readiness_package_file: String,
    pub trust_network_package_file: String,
    pub assurance_suite_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub inquiry_verification_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercurySelectiveAccountActivationArtifact>,
}

impl MercurySelectiveAccountActivationPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "selective_account_activation_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.activation_owner",
            &self.activation_owner,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.approval_owner",
            &self.approval_owner,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.delivery_owner",
            &self.delivery_owner,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.target_account_freeze_file",
            &self.target_account_freeze_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.broader_distribution_manifest_file",
            &self.broader_distribution_manifest_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.claim_governance_rules_file",
            &self.claim_governance_rules_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.selective_account_approval_file",
            &self.selective_account_approval_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.distribution_handoff_brief_file",
            &self.distribution_handoff_brief_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "selective_account_activation_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.approval_refresh_required {
            return Err(MercuryContractError::Validation(
                "selective_account_activation_package.approval_refresh_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "selective_account_activation_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "selective_account_activation_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "selective_account_activation_package.artifacts contains duplicate artifact kind {:?}",
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
    fn selective_account_activation_profile_validates() {
        let profile = MercurySelectiveAccountActivationProfile {
            schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA.to_string(),
            profile_id: "selective-account-activation-controlled-delivery".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
            delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
            claim_containment: "controlled-delivery-evidence-only".to_string(),
            retained_artifact_policy:
                "retain-bounded-selective-account-activation-artifacts".to_string(),
            intended_use: "Activate one bounded Mercury selective-account lane over the validated broader-distribution package."
                .to_string(),
            fail_closed: true,
        };
        profile
            .validate()
            .expect("selective account activation profile");
    }

    #[test]
    fn selective_account_activation_package_rejects_duplicate_artifact_kinds() {
        let package = MercurySelectiveAccountActivationPackage {
            schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA.to_string(),
            package_id: "selective-account-activation-controlled-delivery".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes.".to_string(),
            activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
            delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
            activation_owner: "mercury-selective-account-activation".to_string(),
            approval_owner: "mercury-activation-approval".to_string(),
            delivery_owner: "mercury-controlled-delivery".to_string(),
            approval_refresh_required: true,
            fail_closed: true,
            profile_file: "selective-account-activation-profile.json".to_string(),
            broader_distribution_package_file:
                "activation-evidence/broader-distribution-package.json".to_string(),
            target_account_freeze_file: "activation-evidence/target-account-freeze.json"
                .to_string(),
            broader_distribution_manifest_file:
                "activation-evidence/broader-distribution-manifest.json".to_string(),
            claim_governance_rules_file:
                "activation-evidence/claim-governance-rules.json".to_string(),
            selective_account_approval_file:
                "activation-evidence/selective-account-approval.json".to_string(),
            distribution_handoff_brief_file:
                "activation-evidence/distribution-handoff-brief.json".to_string(),
            reference_distribution_package_file:
                "activation-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "activation-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "activation-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file: "activation-evidence/trust-network-package.json"
                .to_string(),
            assurance_suite_package_file:
                "activation-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "activation-evidence/proof-package.json".to_string(),
            inquiry_package_file: "activation-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file: "activation-evidence/inquiry-verification.json"
                .to_string(),
            reviewer_package_file: "activation-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "activation-evidence/qualification-report.json"
                .to_string(),
            artifacts: vec![
                MercurySelectiveAccountActivationArtifact {
                    artifact_kind:
                        MercurySelectiveAccountActivationArtifactKind::ActivationScopeFreeze,
                    relative_path: "activation-scope-freeze.json".to_string(),
                },
                MercurySelectiveAccountActivationArtifact {
                    artifact_kind:
                        MercurySelectiveAccountActivationArtifactKind::ActivationScopeFreeze,
                    relative_path: "activation-approval-refresh.json".to_string(),
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
