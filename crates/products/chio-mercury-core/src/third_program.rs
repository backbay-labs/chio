use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA: &str = "chio.mercury.third_program_profile.v1";
pub const MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA: &str = "chio.mercury.third_program_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryThirdProgramMotion {
    ThirdProgram,
}

impl MercuryThirdProgramMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThirdProgram => "third_program",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryThirdProgramSurface {
    MultiProgramReuseBundle,
}

impl MercuryThirdProgramSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultiProgramReuseBundle => "multi_program_reuse_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryThirdProgramProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub program_motion: MercuryThirdProgramMotion,
    pub review_surface: MercuryThirdProgramSurface,
    pub approval_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryThirdProgramProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("third_program_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("third_program_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty("third_program_profile.approval_gate", &self.approval_gate)?;
        ensure_non_empty(
            "third_program_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("third_program_profile.intended_use", &self.intended_use)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "third_program_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryThirdProgramArtifactKind {
    ThirdProgramBoundaryFreeze,
    ThirdProgramManifest,
    MultiProgramReuseSummary,
    ApprovalRefresh,
    MultiProgramGuardrails,
    ThirdProgramHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryThirdProgramArtifact {
    pub artifact_kind: MercuryThirdProgramArtifactKind,
    pub relative_path: String,
}

impl MercuryThirdProgramArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "third_program_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryThirdProgramPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub program_motion: MercuryThirdProgramMotion,
    pub review_surface: MercuryThirdProgramSurface,
    pub program_owner: String,
    pub multi_program_review_owner: String,
    pub multi_program_guardrails_owner: String,
    pub approval_refresh_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub second_portfolio_program_package_file: String,
    pub second_portfolio_program_boundary_freeze_file: String,
    pub second_portfolio_program_manifest_file: String,
    pub portfolio_reuse_summary_file: String,
    pub portfolio_reuse_approval_file: String,
    pub revenue_boundary_guardrails_file: String,
    pub second_program_handoff_file: String,
    pub portfolio_program_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryThirdProgramArtifact>,
}

impl MercuryThirdProgramPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("third_program_package.package_id", &self.package_id)?;
        ensure_non_empty("third_program_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "third_program_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty("third_program_package.program_owner", &self.program_owner)?;
        ensure_non_empty(
            "third_program_package.multi_program_review_owner",
            &self.multi_program_review_owner,
        )?;
        ensure_non_empty(
            "third_program_package.multi_program_guardrails_owner",
            &self.multi_program_guardrails_owner,
        )?;
        ensure_non_empty("third_program_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "third_program_package.second_portfolio_program_package_file",
            &self.second_portfolio_program_package_file,
        )?;
        ensure_non_empty(
            "third_program_package.second_portfolio_program_boundary_freeze_file",
            &self.second_portfolio_program_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "third_program_package.second_portfolio_program_manifest_file",
            &self.second_portfolio_program_manifest_file,
        )?;
        ensure_non_empty(
            "third_program_package.portfolio_reuse_summary_file",
            &self.portfolio_reuse_summary_file,
        )?;
        ensure_non_empty(
            "third_program_package.portfolio_reuse_approval_file",
            &self.portfolio_reuse_approval_file,
        )?;
        ensure_non_empty(
            "third_program_package.revenue_boundary_guardrails_file",
            &self.revenue_boundary_guardrails_file,
        )?;
        ensure_non_empty(
            "third_program_package.second_program_handoff_file",
            &self.second_program_handoff_file,
        )?;
        ensure_non_empty(
            "third_program_package.portfolio_program_package_file",
            &self.portfolio_program_package_file,
        )?;
        ensure_non_empty(
            "third_program_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "third_program_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "third_program_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "third_program_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.approval_refresh_required {
            return Err(MercuryContractError::Validation(
                "third_program_package.approval_refresh_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "third_program_package.fail_closed must remain true".to_string(),
            ));
        }
        ensure_unique_artifacts("third_program_package.artifacts", &self.artifacts)?;
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
    artifacts: &[MercuryThirdProgramArtifact],
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
