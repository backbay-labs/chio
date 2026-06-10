use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA: &str =
    "chio.mercury.renewal_qualification_profile.v1";
pub const MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA: &str =
    "chio.mercury.renewal_qualification_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryRenewalQualificationMotion {
    RenewalQualification,
}

impl MercuryRenewalQualificationMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RenewalQualification => "renewal_qualification",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryRenewalQualificationSurface {
    OutcomeReviewBundle,
}

impl MercuryRenewalQualificationSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutcomeReviewBundle => "outcome_review_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryRenewalQualificationProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub renewal_motion: MercuryRenewalQualificationMotion,
    pub review_surface: MercuryRenewalQualificationSurface,
    pub renewal_decision_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryRenewalQualificationProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("renewal_qualification_profile.profile_id", &self.profile_id)?;
        ensure_non_empty(
            "renewal_qualification_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "renewal_qualification_profile.renewal_decision_gate",
            &self.renewal_decision_gate,
        )?;
        ensure_non_empty(
            "renewal_qualification_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "renewal_qualification_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "renewal_qualification_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryRenewalQualificationArtifactKind {
    RenewalBoundaryFreeze,
    RenewalQualificationManifest,
    OutcomeReviewSummary,
    RenewalApproval,
    ReferenceReuseDiscipline,
    ExpansionBoundaryHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryRenewalQualificationArtifact {
    pub artifact_kind: MercuryRenewalQualificationArtifactKind,
    pub relative_path: String,
}

impl MercuryRenewalQualificationArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "renewal_qualification_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryRenewalQualificationPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub renewal_motion: MercuryRenewalQualificationMotion,
    pub review_surface: MercuryRenewalQualificationSurface,
    pub qualification_owner: String,
    pub review_owner: String,
    pub expansion_owner: String,
    pub renewal_approval_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
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
    pub artifacts: Vec<MercuryRenewalQualificationArtifact>,
}

impl MercuryRenewalQualificationPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("renewal_qualification_package.package_id", &self.package_id)?;
        ensure_non_empty(
            "renewal_qualification_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.qualification_owner",
            &self.qualification_owner,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.review_owner",
            &self.review_owner,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.expansion_owner",
            &self.expansion_owner,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.delivery_continuity_package_file",
            &self.delivery_continuity_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.account_boundary_freeze_file",
            &self.account_boundary_freeze_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.delivery_continuity_manifest_file",
            &self.delivery_continuity_manifest_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.outcome_evidence_summary_file",
            &self.outcome_evidence_summary_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.renewal_gate_file",
            &self.renewal_gate_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.delivery_escalation_brief_file",
            &self.delivery_escalation_brief_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.customer_evidence_handoff_file",
            &self.customer_evidence_handoff_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.selective_account_activation_package_file",
            &self.selective_account_activation_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "renewal_qualification_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.renewal_approval_required {
            return Err(MercuryContractError::Validation(
                "renewal_qualification_package.renewal_approval_required must remain true"
                    .to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "renewal_qualification_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "renewal_qualification_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "renewal_qualification_package.artifacts contains duplicate artifact kind {:?}",
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
    fn renewal_qualification_profile_validates() {
        let profile = MercuryRenewalQualificationProfile {
            schema: MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA.to_string(),
            profile_id: "renewal-qualification-outcome-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification,
            review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle,
            renewal_decision_gate: "evidence_backed_renewal_review_only".to_string(),
            retained_artifact_policy: "retain-bounded-renewal-qualification-artifacts".to_string(),
            intended_use: "Renew one Mercury account through one bounded outcome-review lane."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("renewal qualification profile");
    }

    #[test]
    fn renewal_qualification_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryRenewalQualificationPackage {
            schema: MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA.to_string(),
            package_id: "renewal-qualification-outcome-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary:
                "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes."
                    .to_string(),
            renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification,
            review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle,
            qualification_owner: "mercury-renewal-qualification".to_string(),
            review_owner: "mercury-outcome-review".to_string(),
            expansion_owner: "mercury-expansion-boundary".to_string(),
            renewal_approval_required: true,
            fail_closed: true,
            profile_file: "renewal-qualification-profile.json".to_string(),
            delivery_continuity_package_file:
                "renewal-evidence/delivery-continuity-package.json".to_string(),
            account_boundary_freeze_file:
                "renewal-evidence/account-boundary-freeze.json".to_string(),
            delivery_continuity_manifest_file:
                "renewal-evidence/delivery-continuity-manifest.json".to_string(),
            outcome_evidence_summary_file:
                "renewal-evidence/outcome-evidence-summary.json".to_string(),
            renewal_gate_file: "renewal-evidence/renewal-gate.json".to_string(),
            delivery_escalation_brief_file:
                "renewal-evidence/delivery-escalation-brief.json".to_string(),
            customer_evidence_handoff_file:
                "renewal-evidence/customer-evidence-handoff.json".to_string(),
            selective_account_activation_package_file:
                "renewal-evidence/selective-account-activation-package.json".to_string(),
            broader_distribution_package_file:
                "renewal-evidence/broader-distribution-package.json".to_string(),
            reference_distribution_package_file:
                "renewal-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "renewal-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "renewal-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file: "renewal-evidence/trust-network-package.json"
                .to_string(),
            assurance_suite_package_file:
                "renewal-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "renewal-evidence/proof-package.json".to_string(),
            inquiry_package_file: "renewal-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "renewal-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "renewal-evidence/reviewer-package.json".to_string(),
            qualification_report_file: "renewal-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryRenewalQualificationArtifact {
                    artifact_kind: MercuryRenewalQualificationArtifactKind::RenewalBoundaryFreeze,
                    relative_path: "renewal-boundary-freeze.json".to_string(),
                },
                MercuryRenewalQualificationArtifact {
                    artifact_kind: MercuryRenewalQualificationArtifactKind::RenewalBoundaryFreeze,
                    relative_path: "renewal-approval.json".to_string(),
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
