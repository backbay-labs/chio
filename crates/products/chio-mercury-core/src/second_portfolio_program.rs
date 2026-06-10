use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA: &str =
    "chio.mercury.second_portfolio_program_profile.v1";
pub const MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA: &str =
    "chio.mercury.second_portfolio_program_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondPortfolioProgramMotion {
    SecondPortfolioProgram,
}

impl MercurySecondPortfolioProgramMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecondPortfolioProgram => "second_portfolio_program",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondPortfolioProgramSurface {
    PortfolioReuseBundle,
}

impl MercurySecondPortfolioProgramSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortfolioReuseBundle => "portfolio_reuse_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondPortfolioProgramProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub program_motion: MercurySecondPortfolioProgramMotion,
    pub review_surface: MercurySecondPortfolioProgramSurface,
    pub approval_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercurySecondPortfolioProgramProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "second_portfolio_program_profile.profile_id",
            &self.profile_id,
        )?;
        ensure_non_empty(
            "second_portfolio_program_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "second_portfolio_program_profile.approval_gate",
            &self.approval_gate,
        )?;
        ensure_non_empty(
            "second_portfolio_program_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "second_portfolio_program_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "second_portfolio_program_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondPortfolioProgramArtifactKind {
    SecondPortfolioProgramBoundaryFreeze,
    SecondPortfolioProgramManifest,
    PortfolioReuseSummary,
    PortfolioReuseApproval,
    RevenueBoundaryGuardrails,
    SecondProgramHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondPortfolioProgramArtifact {
    pub artifact_kind: MercurySecondPortfolioProgramArtifactKind,
    pub relative_path: String,
}

impl MercurySecondPortfolioProgramArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "second_portfolio_program_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondPortfolioProgramPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub program_motion: MercurySecondPortfolioProgramMotion,
    pub review_surface: MercurySecondPortfolioProgramSurface,
    pub program_owner: String,
    pub portfolio_reuse_review_owner: String,
    pub revenue_boundary_guardrails_owner: String,
    pub portfolio_reuse_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub portfolio_program_package_file: String,
    pub portfolio_program_boundary_freeze_file: String,
    pub portfolio_program_manifest_file: String,
    pub program_review_summary_file: String,
    pub portfolio_approval_file: String,
    pub revenue_operations_guardrails_file: String,
    pub program_handoff_file: String,
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
    pub artifacts: Vec<MercurySecondPortfolioProgramArtifact>,
}

impl MercurySecondPortfolioProgramPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "second_portfolio_program_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.program_owner",
            &self.program_owner,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.portfolio_reuse_review_owner",
            &self.portfolio_reuse_review_owner,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.revenue_boundary_guardrails_owner",
            &self.revenue_boundary_guardrails_owner,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.portfolio_program_package_file",
            &self.portfolio_program_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.portfolio_program_boundary_freeze_file",
            &self.portfolio_program_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.portfolio_program_manifest_file",
            &self.portfolio_program_manifest_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.program_review_summary_file",
            &self.program_review_summary_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.portfolio_approval_file",
            &self.portfolio_approval_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.revenue_operations_guardrails_file",
            &self.revenue_operations_guardrails_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.program_handoff_file",
            &self.program_handoff_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_expansion_package_file",
            &self.second_account_expansion_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_expansion_boundary_freeze_file",
            &self.second_account_expansion_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_expansion_manifest_file",
            &self.second_account_expansion_manifest_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_portfolio_review_summary_file",
            &self.second_account_portfolio_review_summary_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_expansion_approval_file",
            &self.second_account_expansion_approval_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_reuse_governance_file",
            &self.second_account_reuse_governance_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.second_account_handoff_file",
            &self.second_account_handoff_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.renewal_qualification_package_file",
            &self.renewal_qualification_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.renewal_boundary_freeze_file",
            &self.renewal_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.renewal_qualification_manifest_file",
            &self.renewal_qualification_manifest_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.outcome_review_summary_file",
            &self.outcome_review_summary_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.renewal_approval_file",
            &self.renewal_approval_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.reference_reuse_discipline_file",
            &self.reference_reuse_discipline_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.expansion_boundary_handoff_file",
            &self.expansion_boundary_handoff_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.delivery_continuity_package_file",
            &self.delivery_continuity_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.account_boundary_freeze_file",
            &self.account_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.delivery_continuity_manifest_file",
            &self.delivery_continuity_manifest_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.outcome_evidence_summary_file",
            &self.outcome_evidence_summary_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.renewal_gate_file",
            &self.renewal_gate_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.delivery_escalation_brief_file",
            &self.delivery_escalation_brief_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.customer_evidence_handoff_file",
            &self.customer_evidence_handoff_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.selective_account_activation_package_file",
            &self.selective_account_activation_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "second_portfolio_program_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.portfolio_reuse_approval_required {
            return Err(MercuryContractError::Validation(
                "second_portfolio_program_package.portfolio_reuse_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "second_portfolio_program_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "second_portfolio_program_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "second_portfolio_program_package.artifacts contains duplicate artifact kind {:?}",
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
    fn second_portfolio_program_profile_validates() {
        let profile = MercurySecondPortfolioProgramProfile {
            schema: MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA.to_string(),
            profile_id: "second-portfolio-program-portfolio-reuse".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram,
            review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle,
            approval_gate: "evidence_backed_second_portfolio_program_only".to_string(),
            retained_artifact_policy:
                "retain-bounded-second-portfolio-program-and-portfolio-reuse-artifacts"
                    .to_string(),
            intended_use:
                "Qualify one bounded Mercury second portfolio program through one portfolio-reuse lane."
                    .to_string(),
            fail_closed: true,
        };
        profile
            .validate()
            .expect("second portfolio program profile");
    }

    #[test]
    fn second_portfolio_program_package_rejects_duplicate_artifact_kinds() {
        let package = MercurySecondPortfolioProgramPackage {
            schema: MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA.to_string(),
            package_id: "second-portfolio-program-portfolio-reuse".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary:
                "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes."
                    .to_string(),
            program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram,
            review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle,
            program_owner: "mercury-second-portfolio-program".to_string(),
            portfolio_reuse_review_owner: "mercury-portfolio-reuse-review".to_string(),
            revenue_boundary_guardrails_owner: "mercury-revenue-boundary-guardrails".to_string(),
            portfolio_reuse_approval_required: true,
            fail_closed: true,
            profile_file: "second-portfolio-program-profile.json".to_string(),
            portfolio_program_package_file:
                "portfolio-reuse-evidence/portfolio-program-package.json".to_string(),
            portfolio_program_boundary_freeze_file:
                "portfolio-reuse-evidence/portfolio-program-boundary-freeze.json".to_string(),
            portfolio_program_manifest_file:
                "portfolio-reuse-evidence/portfolio-program-manifest.json".to_string(),
            program_review_summary_file:
                "portfolio-reuse-evidence/program-review-summary.json".to_string(),
            portfolio_approval_file:
                "portfolio-reuse-evidence/portfolio-approval.json".to_string(),
            revenue_operations_guardrails_file:
                "portfolio-reuse-evidence/revenue-operations-guardrails.json".to_string(),
            program_handoff_file: "portfolio-reuse-evidence/program-handoff.json".to_string(),
            second_account_expansion_package_file:
                "portfolio-reuse-evidence/second-account-expansion-package.json".to_string(),
            second_account_expansion_boundary_freeze_file:
                "portfolio-reuse-evidence/second-account-portfolio-boundary-freeze.json"
                    .to_string(),
            second_account_expansion_manifest_file:
                "portfolio-reuse-evidence/second-account-expansion-manifest.json".to_string(),
            second_account_portfolio_review_summary_file:
                "portfolio-reuse-evidence/second-account-portfolio-review-summary.json"
                    .to_string(),
            second_account_expansion_approval_file:
                "portfolio-reuse-evidence/second-account-expansion-approval.json".to_string(),
            second_account_reuse_governance_file:
                "portfolio-reuse-evidence/second-account-reuse-governance.json".to_string(),
            second_account_handoff_file:
                "portfolio-reuse-evidence/second-account-handoff.json".to_string(),
            renewal_qualification_package_file:
                "portfolio-reuse-evidence/renewal-qualification-package.json".to_string(),
            renewal_boundary_freeze_file:
                "portfolio-reuse-evidence/renewal-boundary-freeze.json".to_string(),
            renewal_qualification_manifest_file:
                "portfolio-reuse-evidence/renewal-qualification-manifest.json".to_string(),
            outcome_review_summary_file:
                "portfolio-reuse-evidence/outcome-review-summary.json".to_string(),
            renewal_approval_file: "portfolio-reuse-evidence/renewal-approval.json".to_string(),
            reference_reuse_discipline_file:
                "portfolio-reuse-evidence/reference-reuse-discipline.json".to_string(),
            expansion_boundary_handoff_file:
                "portfolio-reuse-evidence/expansion-boundary-handoff.json".to_string(),
            delivery_continuity_package_file:
                "portfolio-reuse-evidence/delivery-continuity-package.json".to_string(),
            account_boundary_freeze_file:
                "portfolio-reuse-evidence/account-boundary-freeze.json".to_string(),
            delivery_continuity_manifest_file:
                "portfolio-reuse-evidence/delivery-continuity-manifest.json".to_string(),
            outcome_evidence_summary_file:
                "portfolio-reuse-evidence/outcome-evidence-summary.json".to_string(),
            renewal_gate_file: "portfolio-reuse-evidence/renewal-gate.json".to_string(),
            delivery_escalation_brief_file:
                "portfolio-reuse-evidence/delivery-escalation-brief.json".to_string(),
            customer_evidence_handoff_file:
                "portfolio-reuse-evidence/customer-evidence-handoff.json".to_string(),
            selective_account_activation_package_file:
                "portfolio-reuse-evidence/selective-account-activation-package.json"
                    .to_string(),
            broader_distribution_package_file:
                "portfolio-reuse-evidence/broader-distribution-package.json".to_string(),
            reference_distribution_package_file:
                "portfolio-reuse-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "portfolio-reuse-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "portfolio-reuse-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file:
                "portfolio-reuse-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file:
                "portfolio-reuse-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "portfolio-reuse-evidence/proof-package.json".to_string(),
            inquiry_package_file: "portfolio-reuse-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "portfolio-reuse-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "portfolio-reuse-evidence/reviewer-package.json".to_string(),
            qualification_report_file:
                "portfolio-reuse-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercurySecondPortfolioProgramArtifact {
                    artifact_kind:
                        MercurySecondPortfolioProgramArtifactKind::SecondPortfolioProgramBoundaryFreeze,
                    relative_path: "second-portfolio-program-boundary-freeze.json".to_string(),
                },
                MercurySecondPortfolioProgramArtifact {
                    artifact_kind:
                        MercurySecondPortfolioProgramArtifactKind::SecondPortfolioProgramBoundaryFreeze,
                    relative_path: "portfolio-reuse-approval.json".to_string(),
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
