use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA: &str =
    "chio.mercury.portfolio_program_profile.v1";
pub const MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA: &str =
    "chio.mercury.portfolio_program_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioProgramMotion {
    PortfolioProgram,
}

impl MercuryPortfolioProgramMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortfolioProgram => "portfolio_program",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioProgramSurface {
    ProgramReviewBundle,
}

impl MercuryPortfolioProgramSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProgramReviewBundle => "program_review_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioProgramProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub program_motion: MercuryPortfolioProgramMotion,
    pub review_surface: MercuryPortfolioProgramSurface,
    pub approval_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryPortfolioProgramProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("portfolio_program_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("portfolio_program_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "portfolio_program_profile.approval_gate",
            &self.approval_gate,
        )?;
        ensure_non_empty(
            "portfolio_program_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("portfolio_program_profile.intended_use", &self.intended_use)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "portfolio_program_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPortfolioProgramArtifactKind {
    PortfolioProgramBoundaryFreeze,
    PortfolioProgramManifest,
    ProgramReviewSummary,
    PortfolioApproval,
    RevenueOperationsGuardrails,
    ProgramHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioProgramArtifact {
    pub artifact_kind: MercuryPortfolioProgramArtifactKind,
    pub relative_path: String,
}

impl MercuryPortfolioProgramArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "portfolio_program_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPortfolioProgramPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub program_motion: MercuryPortfolioProgramMotion,
    pub review_surface: MercuryPortfolioProgramSurface,
    pub program_owner: String,
    pub program_review_owner: String,
    pub revenue_operations_guardrails_owner: String,
    pub portfolio_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub second_account_expansion_package_file: String,
    pub second_account_expansion_boundary_freeze_file: String,
    pub second_account_expansion_manifest_file: String,
    pub second_account_portfolio_review_summary_file: String,
    pub second_account_expansion_approval_file: String,
    pub second_account_reuse_governance_file: String,
    pub second_account_handoff_file: String,
    pub renewal_qualification_package_file: String,
    pub renewal_boundary_freeze_file: String,
    pub renewal_qualification_manifest_file: String,
    pub outcome_review_summary_file: String,
    pub renewal_approval_file: String,
    pub reference_reuse_discipline_file: String,
    pub expansion_boundary_handoff_file: String,
    pub delivery_continuity_package_file: String,
    pub account_boundary_freeze_file: String,
    pub delivery_continuity_manifest_file: String,
    pub outcome_evidence_summary_file: String,
    pub renewal_gate_file: String,
    pub delivery_escalation_brief_file: String,
    pub customer_evidence_handoff_file: String,
    pub selective_account_activation_package_file: String,
    pub broader_distribution_package_file: String,
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
    pub artifacts: Vec<MercuryPortfolioProgramArtifact>,
}

impl MercuryPortfolioProgramPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("portfolio_program_package.package_id", &self.package_id)?;
        ensure_non_empty("portfolio_program_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "portfolio_program_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "portfolio_program_package.program_owner",
            &self.program_owner,
        )?;
        ensure_non_empty(
            "portfolio_program_package.program_review_owner",
            &self.program_review_owner,
        )?;
        ensure_non_empty(
            "portfolio_program_package.revenue_operations_guardrails_owner",
            &self.revenue_operations_guardrails_owner,
        )?;
        ensure_non_empty("portfolio_program_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "portfolio_program_package.second_account_expansion_package_file",
            &self.second_account_expansion_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_expansion_boundary_freeze_file",
            &self.second_account_expansion_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_expansion_manifest_file",
            &self.second_account_expansion_manifest_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_portfolio_review_summary_file",
            &self.second_account_portfolio_review_summary_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_expansion_approval_file",
            &self.second_account_expansion_approval_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_reuse_governance_file",
            &self.second_account_reuse_governance_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.second_account_handoff_file",
            &self.second_account_handoff_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.renewal_qualification_package_file",
            &self.renewal_qualification_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.renewal_boundary_freeze_file",
            &self.renewal_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.renewal_qualification_manifest_file",
            &self.renewal_qualification_manifest_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.outcome_review_summary_file",
            &self.outcome_review_summary_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.renewal_approval_file",
            &self.renewal_approval_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.reference_reuse_discipline_file",
            &self.reference_reuse_discipline_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.expansion_boundary_handoff_file",
            &self.expansion_boundary_handoff_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.delivery_continuity_package_file",
            &self.delivery_continuity_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.account_boundary_freeze_file",
            &self.account_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.delivery_continuity_manifest_file",
            &self.delivery_continuity_manifest_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.outcome_evidence_summary_file",
            &self.outcome_evidence_summary_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.renewal_gate_file",
            &self.renewal_gate_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.delivery_escalation_brief_file",
            &self.delivery_escalation_brief_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.customer_evidence_handoff_file",
            &self.customer_evidence_handoff_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.selective_account_activation_package_file",
            &self.selective_account_activation_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "portfolio_program_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.portfolio_approval_required {
            return Err(MercuryContractError::Validation(
                "portfolio_program_package.portfolio_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "portfolio_program_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "portfolio_program_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "portfolio_program_package.artifacts contains duplicate artifact kind {:?}",
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
    fn portfolio_program_profile_validates() {
        let profile = MercuryPortfolioProgramProfile {
            schema: MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA.to_string(),
            profile_id: "portfolio-program-program-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            program_motion: MercuryPortfolioProgramMotion::PortfolioProgram,
            review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle,
            approval_gate: "evidence_backed_portfolio_program_only".to_string(),
            retained_artifact_policy: "retain-bounded-portfolio-program-artifacts".to_string(),
            intended_use:
                "Qualify one bounded Mercury portfolio program through one program-review lane."
                    .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("portfolio program profile");
    }

    #[test]
    fn portfolio_program_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryPortfolioProgramPackage {
            schema: MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA.to_string(),
            package_id: "portfolio-program-program-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary:
                "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes."
                    .to_string(),
            program_motion: MercuryPortfolioProgramMotion::PortfolioProgram,
            review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle,
            program_owner: "mercury-portfolio-program".to_string(),
            program_review_owner: "mercury-program-review".to_string(),
            revenue_operations_guardrails_owner: "mercury-revenue-ops-guardrails".to_string(),
            portfolio_approval_required: true,
            fail_closed: true,
            profile_file: "portfolio-program-profile.json".to_string(),
            second_account_expansion_package_file:
                "portfolio-evidence/second-account-expansion-package.json".to_string(),
            second_account_expansion_boundary_freeze_file:
                "portfolio-evidence/second-account-portfolio-boundary-freeze.json".to_string(),
            second_account_expansion_manifest_file:
                "portfolio-evidence/second-account-expansion-manifest.json".to_string(),
            second_account_portfolio_review_summary_file:
                "portfolio-evidence/second-account-portfolio-review-summary.json".to_string(),
            second_account_expansion_approval_file:
                "portfolio-evidence/second-account-expansion-approval.json".to_string(),
            second_account_reuse_governance_file:
                "portfolio-evidence/second-account-reuse-governance.json".to_string(),
            second_account_handoff_file:
                "portfolio-evidence/second-account-handoff.json".to_string(),
            renewal_qualification_package_file:
                "portfolio-evidence/renewal-qualification-package.json".to_string(),
            renewal_boundary_freeze_file:
                "portfolio-evidence/renewal-boundary-freeze.json".to_string(),
            renewal_qualification_manifest_file:
                "portfolio-evidence/renewal-qualification-manifest.json".to_string(),
            outcome_review_summary_file:
                "portfolio-evidence/outcome-review-summary.json".to_string(),
            renewal_approval_file: "portfolio-evidence/renewal-approval.json".to_string(),
            reference_reuse_discipline_file:
                "portfolio-evidence/reference-reuse-discipline.json".to_string(),
            expansion_boundary_handoff_file:
                "portfolio-evidence/expansion-boundary-handoff.json".to_string(),
            delivery_continuity_package_file:
                "portfolio-evidence/delivery-continuity-package.json".to_string(),
            account_boundary_freeze_file:
                "portfolio-evidence/account-boundary-freeze.json".to_string(),
            delivery_continuity_manifest_file:
                "portfolio-evidence/delivery-continuity-manifest.json".to_string(),
            outcome_evidence_summary_file:
                "portfolio-evidence/outcome-evidence-summary.json".to_string(),
            renewal_gate_file: "portfolio-evidence/renewal-gate.json".to_string(),
            delivery_escalation_brief_file:
                "portfolio-evidence/delivery-escalation-brief.json".to_string(),
            customer_evidence_handoff_file:
                "portfolio-evidence/customer-evidence-handoff.json".to_string(),
            selective_account_activation_package_file:
                "portfolio-evidence/selective-account-activation-package.json".to_string(),
            broader_distribution_package_file:
                "portfolio-evidence/broader-distribution-package.json".to_string(),
            reference_distribution_package_file:
                "portfolio-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "portfolio-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "portfolio-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file: "portfolio-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file:
                "portfolio-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "portfolio-evidence/proof-package.json".to_string(),
            inquiry_package_file: "portfolio-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "portfolio-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "portfolio-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "portfolio-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryPortfolioProgramArtifact {
                    artifact_kind:
                        MercuryPortfolioProgramArtifactKind::PortfolioProgramBoundaryFreeze,
                    relative_path: "portfolio-program-boundary-freeze.json".to_string(),
                },
                MercuryPortfolioProgramArtifact {
                    artifact_kind:
                        MercuryPortfolioProgramArtifactKind::PortfolioProgramBoundaryFreeze,
                    relative_path: "portfolio-approval.json".to_string(),
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
