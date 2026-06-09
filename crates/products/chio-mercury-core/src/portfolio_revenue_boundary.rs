use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA: &str =
    "chio.mercury.portfolio_revenue_boundary_profile.v1";
pub const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA: &str =
    "chio.mercury.portfolio_revenue_boundary_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioRevenueBoundaryMotion {
    PortfolioRevenueBoundary,
}

impl MercuryPortfolioRevenueBoundaryMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortfolioRevenueBoundary => "portfolio_revenue_boundary",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioRevenueBoundarySurface {
    CommercialReviewBundle,
}

impl MercuryPortfolioRevenueBoundarySurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommercialReviewBundle => "commercial_review_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioRevenueBoundaryProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub program_motion: MercuryPortfolioRevenueBoundaryMotion,
    pub review_surface: MercuryPortfolioRevenueBoundarySurface,
    pub approval_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryPortfolioRevenueBoundaryProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "portfolio_revenue_boundary_profile.profile_id",
            &self.profile_id,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_profile.approval_gate",
            &self.approval_gate,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "portfolio_revenue_boundary_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioRevenueBoundaryArtifactKind {
    RevenueBoundaryFreeze,
    RevenueBoundaryManifest,
    CommercialReviewSummary,
    CommercialApproval,
    ChannelBoundaryRules,
    CommercialHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioRevenueBoundaryArtifact {
    pub artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind,
    pub relative_path: String,
}

impl MercuryPortfolioRevenueBoundaryArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "portfolio_revenue_boundary_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioRevenueBoundaryPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub program_motion: MercuryPortfolioRevenueBoundaryMotion,
    pub review_surface: MercuryPortfolioRevenueBoundarySurface,
    pub revenue_boundary_owner: String,
    pub commercial_review_owner: String,
    pub channel_boundary_owner: String,
    pub commercial_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub program_family_package_file: String,
    pub program_family_boundary_freeze_file: String,
    pub program_family_manifest_file: String,
    pub shared_review_summary_file: String,
    pub shared_review_approval_file: String,
    pub portfolio_claim_discipline_file: String,
    pub family_handoff_file: String,
    pub third_program_package_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub artifacts: Vec<MercuryPortfolioRevenueBoundaryArtifact>,
}

impl MercuryPortfolioRevenueBoundaryPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "portfolio_revenue_boundary_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.revenue_boundary_owner",
            &self.revenue_boundary_owner,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.commercial_review_owner",
            &self.commercial_review_owner,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.channel_boundary_owner",
            &self.channel_boundary_owner,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.program_family_package_file",
            &self.program_family_package_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.program_family_boundary_freeze_file",
            &self.program_family_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.program_family_manifest_file",
            &self.program_family_manifest_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.shared_review_summary_file",
            &self.shared_review_summary_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.shared_review_approval_file",
            &self.shared_review_approval_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.portfolio_claim_discipline_file",
            &self.portfolio_claim_discipline_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.family_handoff_file",
            &self.family_handoff_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.third_program_package_file",
            &self.third_program_package_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "portfolio_revenue_boundary_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.commercial_approval_required {
            return Err(MercuryContractError::Validation(
                "portfolio_revenue_boundary_package.commercial_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "portfolio_revenue_boundary_package.fail_closed must remain true".to_string(),
            ));
        }
        ensure_unique_artifacts(
            "portfolio_revenue_boundary_package.artifacts",
            &self.artifacts,
        )?;
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
    artifacts: &[MercuryPortfolioRevenueBoundaryArtifact],
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
