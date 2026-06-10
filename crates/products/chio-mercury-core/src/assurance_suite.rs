use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA: &str =
    "chio.mercury.assurance_disclosure_profile.v1";
pub const MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA: &str =
    "chio.mercury.assurance_review_package.v1";
pub const MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA: &str =
    "chio.mercury.assurance_investigation_package.v1";
pub const MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA: &str = "chio.mercury.assurance_suite_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryAssuranceReviewerPopulation {
    InternalReview,
    AuditorReview,
    CounterpartyReview,
}

impl MercuryAssuranceReviewerPopulation {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InternalReview => "internal_review",
            Self::AuditorReview => "auditor_review",
            Self::CounterpartyReview => "counterparty_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryAssuranceArtifactKind {
    DisclosureProfile,
    ReviewPackage,
    InvestigationPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssuranceDisclosureProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub redaction_profile: String,
    pub verifier_equivalent: bool,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryAssuranceDisclosureProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("assurance_disclosure_profile.profile_id", &self.profile_id)?;
        ensure_non_empty(
            "assurance_disclosure_profile.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "assurance_disclosure_profile.redaction_profile",
            &self.redaction_profile,
        )?;
        ensure_non_empty(
            "assurance_disclosure_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty(
            "assurance_disclosure_profile.intended_use",
            &self.intended_use,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "assurance_disclosure_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssuranceReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub disclosure_profile_file: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub inquiry_verification_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub governance_decision_package_file: String,
    pub verifier_equivalent: bool,
}

impl MercuryAssuranceReviewPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("assurance_review_package.package_id", &self.package_id)?;
        ensure_non_empty("assurance_review_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "assurance_review_package.disclosure_profile_file",
            &self.disclosure_profile_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.inquiry_verification_file",
            &self.inquiry_verification_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        ensure_non_empty(
            "assurance_review_package.governance_decision_package_file",
            &self.governance_decision_package_file,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssuranceInvestigationPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub assurance_review_package_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    pub investigation_focus: Vec<String>,
    pub event_ids: Vec<String>,
    pub source_record_ids: Vec<String>,
    pub idempotency_keys: Vec<String>,
    pub fail_closed: bool,
}

impl MercuryAssuranceInvestigationPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "assurance_investigation_package.package_id",
            &self.package_id,
        )?;
        ensure_non_empty(
            "assurance_investigation_package.workflow_id",
            &self.workflow_id,
        )?;
        ensure_non_empty(
            "assurance_investigation_package.assurance_review_package_file",
            &self.assurance_review_package_file,
        )?;
        ensure_non_empty_vec(
            "assurance_investigation_package.investigation_focus",
            &self.investigation_focus,
        )?;
        ensure_non_empty_vec("assurance_investigation_package.event_ids", &self.event_ids)?;
        ensure_non_empty_vec(
            "assurance_investigation_package.source_record_ids",
            &self.source_record_ids,
        )?;
        ensure_non_empty_vec(
            "assurance_investigation_package.idempotency_keys",
            &self.idempotency_keys,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "assurance_investigation_package.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssuranceSuiteArtifact {
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub artifact_kind: MercuryAssuranceArtifactKind,
    pub relative_path: String,
}

impl MercuryAssuranceSuiteArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "assurance_suite_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryAssuranceSuitePackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub reviewer_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub governance_decision_package_file: String,
    pub reviewer_populations: Vec<MercuryAssuranceReviewerPopulation>,
    pub artifacts: Vec<MercuryAssuranceSuiteArtifact>,
}

impl MercuryAssuranceSuitePackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("assurance_suite_package.package_id", &self.package_id)?;
        ensure_non_empty("assurance_suite_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "assurance_suite_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "assurance_suite_package.reviewer_owner",
            &self.reviewer_owner,
        )?;
        ensure_non_empty("assurance_suite_package.support_owner", &self.support_owner)?;
        ensure_non_empty(
            "assurance_suite_package.governance_decision_package_file",
            &self.governance_decision_package_file,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "assurance_suite_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.reviewer_populations.is_empty() {
            return Err(MercuryContractError::MissingField(
                "assurance_suite_package.reviewer_populations",
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "assurance_suite_package.artifacts",
            ));
        }

        let expected_populations: HashSet<_> = self.reviewer_populations.iter().copied().collect();
        if expected_populations.len() != self.reviewer_populations.len() {
            return Err(MercuryContractError::Validation(
                "assurance_suite_package.reviewer_populations contains duplicate value".to_string(),
            ));
        }

        let mut artifact_pairs = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            let pair = (artifact.reviewer_population, artifact.artifact_kind);
            if !artifact_pairs.insert(pair) {
                return Err(MercuryContractError::Validation(format!(
                    "assurance_suite_package.artifacts contains duplicate population/kind pair {:?}/{:?}",
                    artifact.reviewer_population, artifact.artifact_kind
                )));
            }
        }

        for reviewer_population in &expected_populations {
            for artifact_kind in [
                MercuryAssuranceArtifactKind::DisclosureProfile,
                MercuryAssuranceArtifactKind::ReviewPackage,
                MercuryAssuranceArtifactKind::InvestigationPackage,
            ] {
                if !artifact_pairs.contains(&(*reviewer_population, artifact_kind)) {
                    return Err(MercuryContractError::Validation(format!(
                        "assurance_suite_package.artifacts is missing {:?} for reviewer population {:?}",
                        artifact_kind, reviewer_population
                    )));
                }
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

fn ensure_non_empty_vec(
    field: &'static str,
    values: &[String],
) -> Result<(), MercuryContractError> {
    if values.is_empty() {
        return Err(MercuryContractError::MissingField(field));
    }
    for value in values {
        ensure_non_empty(field, value)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_profile_validates() {
        let profile = MercuryAssuranceDisclosureProfile {
            schema: MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA.to_string(),
            profile_id: "assurance-internal-review-default".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
            redaction_profile: "internal-review-default".to_string(),
            verifier_equivalent: true,
            retained_artifact_policy: "retain-all-qualified-review-artifacts".to_string(),
            intended_use: "Internal review over the same qualified workflow evidence.".to_string(),
            fail_closed: true,
        };
        profile.validate().expect("disclosure profile");
    }

    #[test]
    fn investigation_package_requires_continuity_fields() {
        let package = MercuryAssuranceInvestigationPackage {
            schema: MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA.to_string(),
            package_id: "investigation-counterparty-review".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            assurance_review_package_file:
                "reviewer-populations/counterparty-review/review-package.json".to_string(),
            account_id: Some("account-1".to_string()),
            desk_id: Some("desk-1".to_string()),
            strategy_id: Some("strategy-1".to_string()),
            investigation_focus: vec!["rollback readiness".to_string()],
            event_ids: vec!["event-1".to_string()],
            source_record_ids: Vec::new(),
            idempotency_keys: vec!["idem-1".to_string()],
            fail_closed: true,
        };

        let error = package
            .validate()
            .expect_err("missing source record ids should fail");
        assert!(error.to_string().contains("source_record_ids"), "{error}");
    }

    #[test]
    fn assurance_suite_package_requires_complete_population_artifacts() {
        let package = MercuryAssuranceSuitePackage {
            schema: MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA.to_string(),
            package_id: "assurance-suite-release-control".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            reviewer_owner: "mercury-assurance-review".to_string(),
            support_owner: "mercury-assurance-ops".to_string(),
            fail_closed: true,
            governance_decision_package_file:
                "governance-workbench/governance-decision-package.json".to_string(),
            reviewer_populations: vec![
                MercuryAssuranceReviewerPopulation::InternalReview,
                MercuryAssuranceReviewerPopulation::AuditorReview,
            ],
            artifacts: vec![
                MercuryAssuranceSuiteArtifact {
                    reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
                    artifact_kind: MercuryAssuranceArtifactKind::DisclosureProfile,
                    relative_path: "reviewer-populations/internal-review/disclosure-profile.json"
                        .to_string(),
                },
                MercuryAssuranceSuiteArtifact {
                    reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
                    artifact_kind: MercuryAssuranceArtifactKind::ReviewPackage,
                    relative_path: "reviewer-populations/internal-review/review-package.json"
                        .to_string(),
                },
                MercuryAssuranceSuiteArtifact {
                    reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
                    artifact_kind: MercuryAssuranceArtifactKind::InvestigationPackage,
                    relative_path:
                        "reviewer-populations/internal-review/investigation-package.json"
                            .to_string(),
                },
            ],
        };

        let error = package
            .validate()
            .expect_err("missing auditor artifact family should fail");
        assert!(error.to_string().contains("missing"), "{error}");
    }
}
