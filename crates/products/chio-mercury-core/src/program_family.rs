use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA: &str = "chio.mercury.program_family_profile.v1";
pub const MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA: &str = "chio.mercury.program_family_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryProgramFamilyMotion {
    ProgramFamily,
}

impl MercuryProgramFamilyMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProgramFamily => "program_family",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryProgramFamilySurface {
    SharedReviewPackage,
}

impl MercuryProgramFamilySurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedReviewPackage => "shared_review_package",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProgramFamilyProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub program_motion: MercuryProgramFamilyMotion,
    pub review_surface: MercuryProgramFamilySurface,
    pub approval_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryProgramFamilyProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("program_family_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("program_family_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty("program_family_profile.approval_gate", &self.approval_gate)?;
        ensure_non_empty(
            "program_family_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("program_family_profile.intended_use", &self.intended_use)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "program_family_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryProgramFamilyArtifactKind {
    ProgramFamilyBoundaryFreeze,
    ProgramFamilyManifest,
    SharedReviewSummary,
    SharedReviewApproval,
    PortfolioClaimDiscipline,
    FamilyHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProgramFamilyArtifact {
    pub artifact_kind: MercuryProgramFamilyArtifactKind,
    pub relative_path: String,
}

impl MercuryProgramFamilyArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "program_family_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProgramFamilyPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub program_motion: MercuryProgramFamilyMotion,
    pub review_surface: MercuryProgramFamilySurface,
    pub program_family_owner: String,
    pub shared_review_owner: String,
    pub portfolio_claim_discipline_owner: String,
    pub shared_review_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub third_program_package_file: String,
    pub third_program_boundary_freeze_file: String,
    pub third_program_manifest_file: String,
    pub multi_program_reuse_summary_file: String,
    pub approval_refresh_file: String,
    pub multi_program_guardrails_file: String,
    pub third_program_handoff_file: String,
    pub second_portfolio_program_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryProgramFamilyArtifact>,
}

impl MercuryProgramFamilyPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("program_family_package.package_id", &self.package_id)?;
        ensure_non_empty("program_family_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "program_family_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "program_family_package.program_family_owner",
            &self.program_family_owner,
        )?;
        ensure_non_empty(
            "program_family_package.shared_review_owner",
            &self.shared_review_owner,
        )?;
        ensure_non_empty(
            "program_family_package.portfolio_claim_discipline_owner",
            &self.portfolio_claim_discipline_owner,
        )?;
        ensure_non_empty("program_family_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "program_family_package.third_program_package_file",
            &self.third_program_package_file,
        )?;
        ensure_non_empty(
            "program_family_package.third_program_boundary_freeze_file",
            &self.third_program_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "program_family_package.third_program_manifest_file",
            &self.third_program_manifest_file,
        )?;
        ensure_non_empty(
            "program_family_package.multi_program_reuse_summary_file",
            &self.multi_program_reuse_summary_file,
        )?;
        ensure_non_empty(
            "program_family_package.approval_refresh_file",
            &self.approval_refresh_file,
        )?;
        ensure_non_empty(
            "program_family_package.multi_program_guardrails_file",
            &self.multi_program_guardrails_file,
        )?;
        ensure_non_empty(
            "program_family_package.third_program_handoff_file",
            &self.third_program_handoff_file,
        )?;
        ensure_non_empty(
            "program_family_package.second_portfolio_program_package_file",
            &self.second_portfolio_program_package_file,
        )?;
        ensure_non_empty(
            "program_family_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "program_family_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "program_family_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "program_family_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.shared_review_approval_required {
            return Err(MercuryContractError::Validation(
                "program_family_package.shared_review_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "program_family_package.fail_closed must remain true".to_string(),
            ));
        }
        ensure_unique_artifacts("program_family_package.artifacts", &self.artifacts)?;
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

fn ensure_unique_artifacts(
    field: &'static str,
    artifacts: &[MercuryProgramFamilyArtifact],
) -> Result<(), MercuryContractError> {
    if artifacts.is_empty() {
        return Err(MercuryContractError::MissingField(field));
    }
    let mut kinds = HashSet::new();
    for artifact in artifacts {
        artifact.validate()?;
        if !kinds.insert(artifact.artifact_kind) {
            return Err(MercuryContractError::Validation(format!(
                "{field} contains duplicate artifact kind {:?}",
                artifact.artifact_kind
            )));
        }
    }
    Ok(())
}
