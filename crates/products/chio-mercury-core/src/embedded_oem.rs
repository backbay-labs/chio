use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    assurance_suite::MercuryAssuranceReviewerPopulation, receipt_metadata::MercuryContractError,
};

pub const MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA: &str = "chio.mercury.embedded_oem_profile.v1";
pub const MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA: &str = "chio.mercury.embedded_oem_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryEmbeddedPartnerSurface {
    ReviewerWorkbenchEmbed,
}

impl MercuryEmbeddedPartnerSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReviewerWorkbenchEmbed => "reviewer_workbench_embed",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryEmbeddedSdkSurface {
    SignedArtifactBundle,
}

impl MercuryEmbeddedSdkSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignedArtifactBundle => "signed_artifact_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryEmbeddedOemProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub partner_surface: MercuryEmbeddedPartnerSurface,
    pub sdk_surface: MercuryEmbeddedSdkSurface,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryEmbeddedOemProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("embedded_oem_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("embedded_oem_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "embedded_oem_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("embedded_oem_profile.intended_use", &self.intended_use)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "embedded_oem_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryEmbeddedArtifactKind {
    DisclosureProfile,
    ReviewPackage,
    InvestigationPackage,
    ReviewerPackage,
    QualificationReport,
    DeliveryAcknowledgement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryEmbeddedOemArtifact {
    pub artifact_kind: MercuryEmbeddedArtifactKind,
    pub relative_path: String,
}

impl MercuryEmbeddedOemArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "embedded_oem_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryEmbeddedOemPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub partner_surface: MercuryEmbeddedPartnerSurface,
    pub sdk_surface: MercuryEmbeddedSdkSurface,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub partner_owner: String,
    pub support_owner: String,
    pub acknowledgement_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub sdk_manifest_file: String,
    pub assurance_suite_package_file: String,
    pub governance_decision_package_file: String,
    pub artifacts: Vec<MercuryEmbeddedOemArtifact>,
}

impl MercuryEmbeddedOemPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("embedded_oem_package.package_id", &self.package_id)?;
        ensure_non_empty("embedded_oem_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "embedded_oem_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty("embedded_oem_package.partner_owner", &self.partner_owner)?;
        ensure_non_empty("embedded_oem_package.support_owner", &self.support_owner)?;
        ensure_non_empty("embedded_oem_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "embedded_oem_package.sdk_manifest_file",
            &self.sdk_manifest_file,
        )?;
        ensure_non_empty(
            "embedded_oem_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "embedded_oem_package.governance_decision_package_file",
            &self.governance_decision_package_file,
        )?;
        if !self.acknowledgement_required {
            return Err(MercuryContractError::Validation(
                "embedded_oem_package.acknowledgement_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "embedded_oem_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "embedded_oem_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "embedded_oem_package.artifacts contains duplicate artifact kind {:?}",
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
    fn embedded_oem_profile_validates() {
        let profile = MercuryEmbeddedOemProfile {
            schema: MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA.to_string(),
            profile_id: "embedded-oem-reviewer-workbench".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
            sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            retained_artifact_policy: "retain-bounded-redacted-review-artifacts".to_string(),
            intended_use: "Embed a bounded Mercury review bundle inside one partner workbench."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("embedded oem profile");
    }

    #[test]
    fn embedded_oem_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryEmbeddedOemPackage {
            schema: MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA.to_string(),
            package_id: "embedded-oem-reviewer-workbench".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
            sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            partner_owner: "partner-review-platform-owner".to_string(),
            support_owner: "mercury-embedded-ops".to_string(),
            acknowledgement_required: true,
            fail_closed: true,
            profile_file: "embedded-oem-profile.json".to_string(),
            sdk_manifest_file: "partner-sdk-manifest.json".to_string(),
            assurance_suite_package_file: "partner-sdk-bundle/assurance-suite-package.json"
                .to_string(),
            governance_decision_package_file: "partner-sdk-bundle/governance-decision-package.json"
                .to_string(),
            artifacts: vec![
                MercuryEmbeddedOemArtifact {
                    artifact_kind: MercuryEmbeddedArtifactKind::ReviewPackage,
                    relative_path: "partner-sdk-bundle/review-package.json".to_string(),
                },
                MercuryEmbeddedOemArtifact {
                    artifact_kind: MercuryEmbeddedArtifactKind::ReviewPackage,
                    relative_path: "partner-sdk-bundle/review-package-copy.json".to_string(),
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
