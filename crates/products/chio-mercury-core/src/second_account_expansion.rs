use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA: &str =
    "chio.mercury.second_account_expansion_profile.v1";
pub const MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA: &str =
    "chio.mercury.second_account_expansion_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondAccountExpansionMotion {
    SecondAccountExpansion,
}

impl MercurySecondAccountExpansionMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecondAccountExpansion => "second_account_expansion",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondAccountExpansionSurface {
    PortfolioReviewBundle,
}

impl MercurySecondAccountExpansionSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortfolioReviewBundle => "portfolio_review_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondAccountExpansionProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub expansion_motion: MercurySecondAccountExpansionMotion,
    pub review_surface: MercurySecondAccountExpansionSurface,
    pub expansion_decision_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercurySecondAccountExpansionProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "second_account_expansion_profile.profile_id",
            &self.profile_id,
        )?;
        ensure_non_empty(
            "second_account_expansion_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "second_account_expansion_profile.expansion_decision_gate",
            &self.expansion_decision_gate,
        )?;
        ensure_non_empty(
            "second_account_expansion_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "second_account_expansion_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "second_account_expansion_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercurySecondAccountExpansionArtifactKind {
    PortfolioBoundaryFreeze,
    SecondAccountExpansionManifest,
    PortfolioReviewSummary,
    ExpansionApproval,
    ReuseGovernance,
    SecondAccountHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondAccountExpansionArtifact {
    pub artifact_kind: MercurySecondAccountExpansionArtifactKind,
    pub relative_path: String,
}

impl MercurySecondAccountExpansionArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "second_account_expansion_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySecondAccountExpansionPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub expansion_motion: MercurySecondAccountExpansionMotion,
    pub review_surface: MercurySecondAccountExpansionSurface,
    pub expansion_owner: String,
    pub portfolio_review_owner: String,
    pub reuse_governance_owner: String,
    pub expansion_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
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
    pub artifacts: Vec<MercurySecondAccountExpansionArtifact>,
}

impl MercurySecondAccountExpansionPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "second_account_expansion_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.expansion_owner",
            &self.expansion_owner,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.portfolio_review_owner",
            &self.portfolio_review_owner,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.reuse_governance_owner",
            &self.reuse_governance_owner,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.renewal_qualification_package_file",
            &self.renewal_qualification_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.renewal_boundary_freeze_file",
            &self.renewal_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.renewal_qualification_manifest_file",
            &self.renewal_qualification_manifest_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.outcome_review_summary_file",
            &self.outcome_review_summary_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.renewal_approval_file",
            &self.renewal_approval_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.reference_reuse_discipline_file",
            &self.reference_reuse_discipline_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.expansion_boundary_handoff_file",
            &self.expansion_boundary_handoff_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.delivery_continuity_package_file",
            &self.delivery_continuity_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.account_boundary_freeze_file",
            &self.account_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.delivery_continuity_manifest_file",
            &self.delivery_continuity_manifest_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.outcome_evidence_summary_file",
            &self.outcome_evidence_summary_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.renewal_gate_file",
            &self.renewal_gate_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.delivery_escalation_brief_file",
            &self.delivery_escalation_brief_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.customer_evidence_handoff_file",
            &self.customer_evidence_handoff_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.selective_account_activation_package_file",
            &self.selective_account_activation_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "second_account_expansion_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.expansion_approval_required {
            return Err(MercuryContractError::Validation(
                "second_account_expansion_package.expansion_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "second_account_expansion_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "second_account_expansion_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "second_account_expansion_package.artifacts contains duplicate artifact kind {:?}",
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
    fn second_account_expansion_profile_validates() {
        let profile = MercurySecondAccountExpansionProfile {
            schema: MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA.to_string(),
            profile_id: "second-account-expansion-portfolio-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion,
            review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle,
            expansion_decision_gate: "evidence_backed_second_account_expansion_only".to_string(),
            retained_artifact_policy: "retain-bounded-second-account-expansion-artifacts"
                .to_string(),
            intended_use:
                "Qualify one second Mercury account through one bounded portfolio-review lane."
                    .to_string(),
            fail_closed: true,
        };
        profile
            .validate()
            .expect("second account expansion profile");
    }

    #[test]
    fn second_account_expansion_package_rejects_duplicate_artifact_kinds() {
        let package = MercurySecondAccountExpansionPackage {
            schema: MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA.to_string(),
            package_id: "second-account-expansion-portfolio-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary:
                "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes."
                    .to_string(),
            expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion,
            review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle,
            expansion_owner: "mercury-second-account-expansion".to_string(),
            portfolio_review_owner: "mercury-portfolio-review".to_string(),
            reuse_governance_owner: "mercury-reuse-governance".to_string(),
            expansion_approval_required: true,
            fail_closed: true,
            profile_file: "second-account-expansion-profile.json".to_string(),
            renewal_qualification_package_file:
                "expansion-evidence/renewal-qualification-package.json".to_string(),
            renewal_boundary_freeze_file:
                "expansion-evidence/renewal-boundary-freeze.json".to_string(),
            renewal_qualification_manifest_file:
                "expansion-evidence/renewal-qualification-manifest.json".to_string(),
            outcome_review_summary_file:
                "expansion-evidence/outcome-review-summary.json".to_string(),
            renewal_approval_file: "expansion-evidence/renewal-approval.json".to_string(),
            reference_reuse_discipline_file:
                "expansion-evidence/reference-reuse-discipline.json".to_string(),
            expansion_boundary_handoff_file:
                "expansion-evidence/expansion-boundary-handoff.json".to_string(),
            delivery_continuity_package_file:
                "expansion-evidence/delivery-continuity-package.json".to_string(),
            account_boundary_freeze_file:
                "expansion-evidence/account-boundary-freeze.json".to_string(),
            delivery_continuity_manifest_file:
                "expansion-evidence/delivery-continuity-manifest.json".to_string(),
            outcome_evidence_summary_file:
                "expansion-evidence/outcome-evidence-summary.json".to_string(),
            renewal_gate_file: "expansion-evidence/renewal-gate.json".to_string(),
            delivery_escalation_brief_file:
                "expansion-evidence/delivery-escalation-brief.json".to_string(),
            customer_evidence_handoff_file:
                "expansion-evidence/customer-evidence-handoff.json".to_string(),
            selective_account_activation_package_file:
                "expansion-evidence/selective-account-activation-package.json".to_string(),
            broader_distribution_package_file:
                "expansion-evidence/broader-distribution-package.json".to_string(),
            reference_distribution_package_file:
                "expansion-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "expansion-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "expansion-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file:
                "expansion-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file:
                "expansion-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "expansion-evidence/proof-package.json".to_string(),
            inquiry_package_file: "expansion-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "expansion-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "expansion-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "expansion-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercurySecondAccountExpansionArtifact {
                    artifact_kind:
                        MercurySecondAccountExpansionArtifactKind::PortfolioBoundaryFreeze,
                    relative_path: "portfolio-boundary-freeze.json".to_string(),
                },
                MercurySecondAccountExpansionArtifact {
                    artifact_kind:
                        MercurySecondAccountExpansionArtifactKind::PortfolioBoundaryFreeze,
                    relative_path: "expansion-approval.json".to_string(),
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
