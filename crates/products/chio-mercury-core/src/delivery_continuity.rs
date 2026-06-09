use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA: &str =
    "chio.mercury.delivery_continuity_profile.v1";
pub const MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA: &str =
    "chio.mercury.delivery_continuity_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDeliveryContinuityMotion {
    ControlledDeliveryContinuity,
}

impl MercuryDeliveryContinuityMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlledDeliveryContinuity => "controlled_delivery_continuity",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDeliveryContinuitySurface {
    OutcomeEvidenceBundle,
}

impl MercuryDeliveryContinuitySurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutcomeEvidenceBundle => "outcome_evidence_bundle",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDeliveryContinuityProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub continuity_motion: MercuryDeliveryContinuityMotion,
    pub continuity_surface: MercuryDeliveryContinuitySurface,
    pub renewal_gate: String,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryDeliveryContinuityProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("delivery_continuity_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("delivery_continuity_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "delivery_continuity_profile.renewal_gate",
            &self.renewal_gate,
        )?;
        ensure_non_empty(
            "delivery_continuity_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "delivery_continuity_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "delivery_continuity_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDeliveryContinuityArtifactKind {
    AccountBoundaryFreeze,
    DeliveryContinuityManifest,
    OutcomeEvidenceSummary,
    RenewalGateRecord,
    DeliveryEscalationBrief,
    CustomerEvidenceHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDeliveryContinuityArtifact {
    pub artifact_kind: MercuryDeliveryContinuityArtifactKind,
    pub relative_path: String,
}

impl MercuryDeliveryContinuityArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "delivery_continuity_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDeliveryContinuityPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub continuity_motion: MercuryDeliveryContinuityMotion,
    pub continuity_surface: MercuryDeliveryContinuitySurface,
    pub continuity_owner: String,
    pub renewal_owner: String,
    pub evidence_owner: String,
    pub renewal_gate_required: bool,
    pub fail_closed: bool,
    pub profile_file: String,
    pub selective_account_activation_package_file: String,
    pub activation_scope_freeze_file: String,
    pub selective_account_activation_manifest_file: String,
    pub claim_containment_rules_file: String,
    pub activation_approval_refresh_file: String,
    pub customer_handoff_brief_file: String,
    pub broader_distribution_package_file: String,
    pub broader_distribution_manifest_file: String,
    pub target_account_freeze_file: String,
    pub claim_governance_rules_file: String,
    pub selective_account_approval_file: String,
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
    pub artifacts: Vec<MercuryDeliveryContinuityArtifact>,
}

impl MercuryDeliveryContinuityPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("delivery_continuity_package.package_id", &self.package_id)?;
        ensure_non_empty("delivery_continuity_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "delivery_continuity_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.continuity_owner",
            &self.continuity_owner,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.renewal_owner",
            &self.renewal_owner,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.evidence_owner",
            &self.evidence_owner,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.profile_file",
            &self.profile_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.selective_account_activation_package_file",
            &self.selective_account_activation_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.activation_scope_freeze_file",
            &self.activation_scope_freeze_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.selective_account_activation_manifest_file",
            &self.selective_account_activation_manifest_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.claim_containment_rules_file",
            &self.claim_containment_rules_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.activation_approval_refresh_file",
            &self.activation_approval_refresh_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.customer_handoff_brief_file",
            &self.customer_handoff_brief_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.broader_distribution_package_file",
            &self.broader_distribution_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.broader_distribution_manifest_file",
            &self.broader_distribution_manifest_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.target_account_freeze_file",
            &self.target_account_freeze_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.claim_governance_rules_file",
            &self.claim_governance_rules_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.selective_account_approval_file",
            &self.selective_account_approval_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.reference_distribution_package_file",
            &self.reference_distribution_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.controlled_adoption_package_file",
            &self.controlled_adoption_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.release_readiness_package_file",
            &self.release_readiness_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.trust_network_package_file",
            &self.trust_network_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.assurance_suite_package_file",
            &self.assurance_suite_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "delivery_continuity_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        if !self.renewal_gate_required {
            return Err(MercuryContractError::Validation(
                "delivery_continuity_package.renewal_gate_required must remain true".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "delivery_continuity_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "delivery_continuity_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "delivery_continuity_package.artifacts contains duplicate artifact kind {:?}",
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
    fn delivery_continuity_profile_validates() {
        let profile = MercuryDeliveryContinuityProfile {
            schema: MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA.to_string(),
            profile_id: "delivery-continuity-outcome-evidence".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
            continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
            renewal_gate: "evidence_backed_renewal_only".to_string(),
            retained_artifact_policy:
                "retain-bounded-delivery-continuity-artifacts".to_string(),
            intended_use:
                "Maintain one activated Mercury account inside one bounded evidence-backed continuity lane."
                    .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("delivery continuity profile");
    }

    #[test]
    fn delivery_continuity_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryDeliveryContinuityPackage {
            schema: MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA.to_string(),
            package_id: "delivery-continuity-outcome-evidence".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary:
                "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes."
                    .to_string(),
            continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
            continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
            continuity_owner: "mercury-delivery-continuity".to_string(),
            renewal_owner: "mercury-renewal-gate".to_string(),
            evidence_owner: "mercury-customer-evidence".to_string(),
            renewal_gate_required: true,
            fail_closed: true,
            profile_file: "delivery-continuity-profile.json".to_string(),
            selective_account_activation_package_file:
                "continuity-evidence/selective-account-activation-package.json".to_string(),
            activation_scope_freeze_file:
                "continuity-evidence/activation-scope-freeze.json".to_string(),
            selective_account_activation_manifest_file:
                "continuity-evidence/selective-account-activation-manifest.json".to_string(),
            claim_containment_rules_file:
                "continuity-evidence/claim-containment-rules.json".to_string(),
            activation_approval_refresh_file:
                "continuity-evidence/activation-approval-refresh.json".to_string(),
            customer_handoff_brief_file:
                "continuity-evidence/customer-handoff-brief.json".to_string(),
            broader_distribution_package_file:
                "continuity-evidence/broader-distribution-package.json".to_string(),
            broader_distribution_manifest_file:
                "continuity-evidence/broader-distribution-manifest.json".to_string(),
            target_account_freeze_file:
                "continuity-evidence/target-account-freeze.json".to_string(),
            claim_governance_rules_file:
                "continuity-evidence/claim-governance-rules.json".to_string(),
            selective_account_approval_file:
                "continuity-evidence/selective-account-approval.json".to_string(),
            reference_distribution_package_file:
                "continuity-evidence/reference-distribution-package.json".to_string(),
            controlled_adoption_package_file:
                "continuity-evidence/controlled-adoption-package.json".to_string(),
            release_readiness_package_file:
                "continuity-evidence/release-readiness-package.json".to_string(),
            trust_network_package_file:
                "continuity-evidence/trust-network-package.json".to_string(),
            assurance_suite_package_file:
                "continuity-evidence/assurance-suite-package.json".to_string(),
            proof_package_file: "continuity-evidence/proof-package.json".to_string(),
            inquiry_package_file: "continuity-evidence/inquiry-package.json".to_string(),
            inquiry_verification_file:
                "continuity-evidence/inquiry-verification.json".to_string(),
            reviewer_package_file: "continuity-evidence/reviewer-package.json".to_string(),
            qualification_report_file:
                "continuity-evidence/qualification-report.json".to_string(),
            artifacts: vec![
                MercuryDeliveryContinuityArtifact {
                    artifact_kind: MercuryDeliveryContinuityArtifactKind::AccountBoundaryFreeze,
                    relative_path: "account-boundary-freeze.json".to_string(),
                },
                MercuryDeliveryContinuityArtifact {
                    artifact_kind: MercuryDeliveryContinuityArtifactKind::AccountBoundaryFreeze,
                    relative_path: "renewal-gate.json".to_string(),
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
