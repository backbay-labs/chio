use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::receipt_metadata::MercuryContractError;

pub const MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA: &str =
    "chio.mercury.governance_decision_package.v1";
pub const MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA: &str =
    "chio.mercury.governance_review_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryGovernanceWorkflowPath {
    ChangeReviewReleaseControl,
}

impl MercuryGovernanceWorkflowPath {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChangeReviewReleaseControl => "change_review_release_control",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryGovernanceChangeClass {
    Model,
    Prompt,
    Policy,
    Parameter,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryGovernanceReviewAudience {
    WorkflowOwner,
    ControlTeam,
}

impl MercuryGovernanceReviewAudience {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowOwner => "workflow_owner",
            Self::ControlTeam => "control_team",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryGovernanceGateState {
    Approved,
    Ready,
    Routed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryGovernanceControlState {
    pub approval_gate: MercuryGovernanceGateState,
    pub release_gate: MercuryGovernanceGateState,
    pub rollback_gate: MercuryGovernanceGateState,
    pub exception_gate: MercuryGovernanceGateState,
    pub escalation_owner: String,
}

impl MercuryGovernanceControlState {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "governance_control_state.escalation_owner",
            &self.escalation_owner,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryGovernanceReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub audience: MercuryGovernanceReviewAudience,
    pub disclosure_profile: String,
    pub proof_package_file: String,
    pub inquiry_package_file: String,
    pub reviewer_package_file: String,
    pub qualification_report_file: String,
    pub decision_package_file: String,
    pub verifier_equivalent: bool,
}

impl MercuryGovernanceReviewPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("governance_review_package.package_id", &self.package_id)?;
        ensure_non_empty("governance_review_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "governance_review_package.disclosure_profile",
            &self.disclosure_profile,
        )?;
        ensure_non_empty(
            "governance_review_package.proof_package_file",
            &self.proof_package_file,
        )?;
        ensure_non_empty(
            "governance_review_package.inquiry_package_file",
            &self.inquiry_package_file,
        )?;
        ensure_non_empty(
            "governance_review_package.reviewer_package_file",
            &self.reviewer_package_file,
        )?;
        ensure_non_empty(
            "governance_review_package.qualification_report_file",
            &self.qualification_report_file,
        )?;
        ensure_non_empty(
            "governance_review_package.decision_package_file",
            &self.decision_package_file,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryGovernanceDecisionPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub workflow_path: MercuryGovernanceWorkflowPath,
    pub change_classes: Vec<MercuryGovernanceChangeClass>,
    pub workflow_owner: String,
    pub control_team_owner: String,
    pub fail_closed: bool,
    pub control_state: MercuryGovernanceControlState,
    pub workflow_owner_review_package_file: String,
    pub control_team_review_package_file: String,
}

impl MercuryGovernanceDecisionPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("governance_decision_package.package_id", &self.package_id)?;
        ensure_non_empty("governance_decision_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "governance_decision_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty(
            "governance_decision_package.workflow_owner",
            &self.workflow_owner,
        )?;
        ensure_non_empty(
            "governance_decision_package.control_team_owner",
            &self.control_team_owner,
        )?;
        ensure_non_empty(
            "governance_decision_package.workflow_owner_review_package_file",
            &self.workflow_owner_review_package_file,
        )?;
        ensure_non_empty(
            "governance_decision_package.control_team_review_package_file",
            &self.control_team_review_package_file,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "governance_decision_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.change_classes.is_empty() {
            return Err(MercuryContractError::MissingField(
                "governance_decision_package.change_classes",
            ));
        }

        let mut change_classes = HashSet::new();
        for change_class in &self.change_classes {
            if !change_classes.insert(*change_class) {
                return Err(MercuryContractError::Validation(format!(
                    "governance_decision_package.change_classes contains duplicate value {:?}",
                    change_class
                )));
            }
        }
        self.control_state.validate()?;
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
    fn governance_decision_package_validates() {
        let package = MercuryGovernanceDecisionPackage {
            schema: MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA.to_string(),
            package_id: "governance-change-review-release-control".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl,
            change_classes: vec![
                MercuryGovernanceChangeClass::Model,
                MercuryGovernanceChangeClass::Prompt,
                MercuryGovernanceChangeClass::Policy,
                MercuryGovernanceChangeClass::Parameter,
                MercuryGovernanceChangeClass::Release,
            ],
            workflow_owner: "workflow-owner".to_string(),
            control_team_owner: "control-review-team".to_string(),
            fail_closed: true,
            control_state: MercuryGovernanceControlState {
                approval_gate: MercuryGovernanceGateState::Approved,
                release_gate: MercuryGovernanceGateState::Approved,
                rollback_gate: MercuryGovernanceGateState::Ready,
                exception_gate: MercuryGovernanceGateState::Routed,
                escalation_owner: "control-review-team".to_string(),
            },
            workflow_owner_review_package_file:
                "governance-reviews/workflow-owner/review-package.json".to_string(),
            control_team_review_package_file: "governance-reviews/control-team/review-package.json"
                .to_string(),
        };
        package.validate().expect("governance decision package");
    }

    #[test]
    fn governance_decision_package_rejects_duplicate_change_classes() {
        let package = MercuryGovernanceDecisionPackage {
            schema: MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA.to_string(),
            package_id: "governance-change-review-release-control".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl,
            change_classes: vec![
                MercuryGovernanceChangeClass::Model,
                MercuryGovernanceChangeClass::Model,
            ],
            workflow_owner: "workflow-owner".to_string(),
            control_team_owner: "control-review-team".to_string(),
            fail_closed: true,
            control_state: MercuryGovernanceControlState {
                approval_gate: MercuryGovernanceGateState::Approved,
                release_gate: MercuryGovernanceGateState::Approved,
                rollback_gate: MercuryGovernanceGateState::Ready,
                exception_gate: MercuryGovernanceGateState::Routed,
                escalation_owner: "control-review-team".to_string(),
            },
            workflow_owner_review_package_file:
                "governance-reviews/workflow-owner/review-package.json".to_string(),
            control_team_review_package_file: "governance-reviews/control-team/review-package.json"
                .to_string(),
        };
        let error = package.validate().expect_err("duplicate change classes");
        assert!(error.to_string().contains("duplicate value"), "{error}");
    }
}
