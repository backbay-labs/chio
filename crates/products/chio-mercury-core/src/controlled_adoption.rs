use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA: &str =
    "chio.mercury.controlled_adoption_profile.v1";
pub const MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA: &str =
    "chio.mercury.controlled_adoption_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryControlledAdoptionCohort {
    DesignPartnerRenewal,
}

impl MercuryControlledAdoptionCohort {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesignPartnerRenewal => "design_partner_renewal",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryControlledAdoptionSurface {
    RenewalReferenceBundle,
}

impl MercuryControlledAdoptionSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RenewalReferenceBundle => "renewal_reference_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryControlledAdoptionProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub cohort: MercuryControlledAdoptionCohort,
    pub adoption_surface: MercuryControlledAdoptionSurface,
    pub success_window: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryControlledAdoptionProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("controlled_adoption_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("controlled_adoption_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "controlled_adoption_profile.success_window",
            &self.success_window,
        )?;
        ensure_non_empty(
            "controlled_adoption_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "controlled_adoption_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "controlled_adoption_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryControlledAdoptionArtifactKind {
    CustomerSuccessChecklist,
    RenewalEvidenceManifest,
    RenewalAcknowledgement,
    ReferenceReadinessBrief,
    SupportEscalationManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryControlledAdoptionArtifact {
    pub artifact_kind: MercuryControlledAdoptionArtifactKind,
    pub relative_path: String,
}

impl MercuryControlledAdoptionArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "controlled_adoption_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryControlledAdoptionPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub cohort: MercuryControlledAdoptionCohort,
    pub adoption_surface: MercuryControlledAdoptionSurface,
    pub customer_success_owner: String,
    pub reference_owner: String,
    pub support_owner: String,
    pub acknowledgement_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub release_readiness_package_file: String,
    pub trust_network_package_file: String,
    pub assurance_suite_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryControlledAdoptionArtifact>,
}

impl MercuryControlledAdoptionPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("controlled_adoption_package.package_id", &self.package_id)?;
        ensure_non_empty("controlled_adoption_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "controlled_adoption_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.customer_success_owner",
            &self.customer_success_owner,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.reference_owner",
            &self.reference_owner,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.support_owner",
            &self.support_owner,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "controlled_adoption_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.acknowledgement_required {
            return Err(MercuryContractError::Validation(
                "controlled_adoption_package.acknowledgement_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "controlled_adoption_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "controlled_adoption_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "controlled_adoption_package.artifacts contains duplicate artifact kind {:?}",
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
    fn controlled_adoption_profile_validates() {
        let profile = MercuryControlledAdoptionProfile {
            schema: MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA.to_string(),
            profile_id: "controlled-adoption-design-partner-renewal".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
            adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
            success_window: "first-90-days-post-launch".to_string(),
            retained_artifact_policy:
                "retain-bounded-adoption-renewal-and-reference-artifacts".to_string(),
            intended_use: "Qualify one bounded Mercury controlled-adoption lane over the validated release-readiness package."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("controlled adoption profile");
    }

    #[test]
    fn controlled_adoption_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryControlledAdoptionPackage {
            schema: MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA.to_string(),
            package_id: "controlled-adoption-design-partner-renewal".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
            adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
            customer_success_owner: "mercury-customer-success".to_string(),
            reference_owner: "mercury-reference-program".to_string(),
            support_owner: "mercury-adoption-ops".to_string(),
            acknowledgement_required: true,
            fail_closed: true,
            profile_file: "controlled-adoption-profile.json".to_string(),
            release_readiness_package_file: "adoption-evidence/release-readiness-package.json"
                .to_string(),
            trust_network_package_file: "adoption-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file: "adoption-evidence/assurance-suite-package.json"
                .to_string(),
            proof_package_file: "adoption-evidence/proof-package.json".to_string(),
            inquiry_package_file: "adoption-evidence/inquiry-package.json".to_string(),
            reviewer_package_file: "adoption-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "adoption-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryControlledAdoptionArtifact {
                    artifact_kind: MercuryControlledAdoptionArtifactKind::CustomerSuccessChecklist,
                    relative_path: "customer-success-checklist.json".to_string(),
                },
                MercuryControlledAdoptionArtifact {
                    artifact_kind: MercuryControlledAdoptionArtifactKind::CustomerSuccessChecklist,
                    relative_path: "customer-success-checklist-copy.json".to_string(),
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
