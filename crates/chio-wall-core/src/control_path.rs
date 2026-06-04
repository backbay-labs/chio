use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const CHIO_WALL_CONTROL_PROFILE_SCHEMA: &str = "chio.wall.control_profile.v1";
pub const CHIO_WALL_POLICY_SNAPSHOT_SCHEMA: &str = "chio.wall.policy_snapshot.v1";
pub const CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA: &str = "chio.wall.authorization_context.v1";
pub const CHIO_WALL_GUARD_OUTCOME_SCHEMA: &str = "chio.wall.guard_outcome.v1";
pub const CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA: &str = "chio.wall.denied_access_record.v1";
pub const CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA: &str = "chio.wall.buyer_review_package.v1";
pub const CHIO_WALL_CONTROL_PACKAGE_SCHEMA: &str = "chio.wall.control_package.v1";
const REQUIRED_CONTROL_PACKAGE_ARTIFACTS: [ChioWallArtifactKind; 7] = [
    ChioWallArtifactKind::ControlProfile,
    ChioWallArtifactKind::PolicySnapshot,
    ChioWallArtifactKind::AuthorizationContext,
    ChioWallArtifactKind::GuardOutcome,
    ChioWallArtifactKind::DeniedAccessRecord,
    ChioWallArtifactKind::BuyerReviewPackage,
    ChioWallArtifactKind::ChioEvidenceExport,
];

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChioWallContractError {
    #[error("invalid Chio-Wall schema `{actual}` (expected `{expected}`)")]
    InvalidSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("field `{0}` must not be empty")]
    EmptyField(&'static str),
    #[error("field `{0}` must not have surrounding whitespace")]
    PaddedField(&'static str),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("json error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for ChioWallContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChioWallBuyerMotion {
    ControlRoomBarrierReview,
}

impl ChioWallBuyerMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlRoomBarrierReview => "control_room_barrier_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChioWallControlSurface {
    ToolAccessDomainBoundary,
}

impl ChioWallControlSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolAccessDomainBoundary => "tool_access_domain_boundary",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChioWallInformationDomain {
    Research,
    Execution,
}

impl ChioWallInformationDomain {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::Execution => "execution",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallControlProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub buyer_motion: ChioWallBuyerMotion,
    pub control_surface: ChioWallControlSurface,
    pub source_domain: ChioWallInformationDomain,
    pub protected_domain: ChioWallInformationDomain,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl ChioWallControlProfile {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_CONTROL_PROFILE_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_CONTROL_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("control_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("control_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "control_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("control_profile.intended_use", &self.intended_use)?;
        if self.source_domain == self.protected_domain {
            return Err(ChioWallContractError::Validation(
                "control_profile.source_domain and protected_domain must differ".to_string(),
            ));
        }
        ensure_fail_closed("control_profile.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallPolicySnapshot {
    pub schema: String,
    pub policy_id: String,
    pub source_domain: ChioWallInformationDomain,
    pub allowed_tools: Vec<String>,
    pub fail_closed: bool,
    pub note: String,
}

impl ChioWallPolicySnapshot {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_POLICY_SNAPSHOT_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_POLICY_SNAPSHOT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("policy_snapshot.policy_id", &self.policy_id)?;
        ensure_non_empty("policy_snapshot.note", &self.note)?;
        ensure_non_empty_list("policy_snapshot.allowed_tools", &self.allowed_tools)?;
        ensure_unique_strings(
            "policy_snapshot.allowed_tools contains duplicate tool name",
            &self.allowed_tools,
        )?;
        ensure_fail_closed("policy_snapshot.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallAuthorizationContext {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub actor_label: String,
    pub buyer_motion: ChioWallBuyerMotion,
    pub control_surface: ChioWallControlSurface,
    pub source_domain: ChioWallInformationDomain,
    pub requested_domain: ChioWallInformationDomain,
    pub tool_name: String,
    pub policy_reference: String,
}

impl ChioWallAuthorizationContext {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("authorization_context.request_id", &self.request_id)?;
        ensure_non_empty("authorization_context.workflow_id", &self.workflow_id)?;
        ensure_non_empty("authorization_context.actor_label", &self.actor_label)?;
        ensure_non_empty("authorization_context.tool_name", &self.tool_name)?;
        ensure_non_empty(
            "authorization_context.policy_reference",
            &self.policy_reference,
        )?;
        if self.source_domain == self.requested_domain {
            return Err(ChioWallContractError::Validation(
                "authorization_context.requested_domain must differ from source_domain".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChioWallGuardDecision {
    Allow,
    Deny,
}

impl ChioWallGuardDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallGuardOutcome {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub decision: ChioWallGuardDecision,
    pub guard_name: String,
    pub pipeline_name: String,
    pub matched_policy: String,
    pub evaluated_tool: String,
    pub allowed_tools: Vec<String>,
    pub reason: String,
    pub fail_closed: bool,
}

impl ChioWallGuardOutcome {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_GUARD_OUTCOME_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_GUARD_OUTCOME_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("guard_outcome.request_id", &self.request_id)?;
        ensure_non_empty("guard_outcome.workflow_id", &self.workflow_id)?;
        ensure_non_empty("guard_outcome.guard_name", &self.guard_name)?;
        ensure_non_empty("guard_outcome.pipeline_name", &self.pipeline_name)?;
        ensure_non_empty("guard_outcome.matched_policy", &self.matched_policy)?;
        ensure_non_empty("guard_outcome.evaluated_tool", &self.evaluated_tool)?;
        ensure_non_empty("guard_outcome.reason", &self.reason)?;
        ensure_non_empty_list("guard_outcome.allowed_tools", &self.allowed_tools)?;
        ensure_unique_strings(
            "guard_outcome.allowed_tools contains duplicate tool name",
            &self.allowed_tools,
        )?;
        if self.decision == ChioWallGuardDecision::Deny
            && self
                .allowed_tools
                .iter()
                .any(|tool| tool == &self.evaluated_tool)
        {
            return Err(ChioWallContractError::Validation(
                "guard_outcome cannot deny a tool that is present in allowed_tools".to_string(),
            ));
        }
        ensure_fail_closed("guard_outcome.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallDeniedAccessRecord {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub source_domain: ChioWallInformationDomain,
    pub requested_domain: ChioWallInformationDomain,
    pub tool_name: String,
    pub escalation_owner: String,
    pub support_owner: String,
    pub note: String,
}

impl ChioWallDeniedAccessRecord {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("denied_access_record.request_id", &self.request_id)?;
        ensure_non_empty("denied_access_record.workflow_id", &self.workflow_id)?;
        ensure_non_empty("denied_access_record.tool_name", &self.tool_name)?;
        ensure_non_empty(
            "denied_access_record.escalation_owner",
            &self.escalation_owner,
        )?;
        ensure_non_empty("denied_access_record.support_owner", &self.support_owner)?;
        ensure_non_empty("denied_access_record.note", &self.note)?;
        if self.source_domain == self.requested_domain {
            return Err(ChioWallContractError::Validation(
                "denied_access_record.requested_domain must differ from source_domain".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChioWallArtifactKind {
    ControlProfile,
    PolicySnapshot,
    AuthorizationContext,
    GuardOutcome,
    DeniedAccessRecord,
    BuyerReviewPackage,
    ChioEvidenceExport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallArtifact {
    pub artifact_kind: ChioWallArtifactKind,
    pub relative_path: String,
}

impl ChioWallArtifact {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        ensure_non_empty(
            "control_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallBuyerReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub buyer_motion: ChioWallBuyerMotion,
    pub control_surface: ChioWallControlSurface,
    pub control_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub control_package_file: String,
    pub authorization_context_file: String,
    pub policy_snapshot_file: String,
    pub guard_outcome_file: String,
    pub denied_access_record_file: String,
    pub chio_evidence_dir: String,
    pub note: String,
}

impl ChioWallBuyerReviewPackage {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("buyer_review_package.package_id", &self.package_id)?;
        ensure_non_empty("buyer_review_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty("buyer_review_package.control_owner", &self.control_owner)?;
        ensure_non_empty("buyer_review_package.support_owner", &self.support_owner)?;
        ensure_non_empty(
            "buyer_review_package.control_package_file",
            &self.control_package_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.authorization_context_file",
            &self.authorization_context_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.policy_snapshot_file",
            &self.policy_snapshot_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.guard_outcome_file",
            &self.guard_outcome_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.denied_access_record_file",
            &self.denied_access_record_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.chio_evidence_dir",
            &self.chio_evidence_dir,
        )?;
        ensure_non_empty("buyer_review_package.note", &self.note)?;
        ensure_fail_closed("buyer_review_package.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioWallControlPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_system_boundary: String,
    pub buyer_motion: ChioWallBuyerMotion,
    pub control_surface: ChioWallControlSurface,
    pub control_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub profile_file: String,
    pub buyer_review_package_file: String,
    pub chio_evidence_dir: String,
    pub artifacts: Vec<ChioWallArtifact>,
}

impl ChioWallControlPackage {
    pub fn validate(&self) -> Result<(), ChioWallContractError> {
        if self.schema != CHIO_WALL_CONTROL_PACKAGE_SCHEMA {
            return Err(ChioWallContractError::InvalidSchema {
                expected: CHIO_WALL_CONTROL_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("control_package.package_id", &self.package_id)?;
        ensure_non_empty("control_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "control_package.same_system_boundary",
            &self.same_system_boundary,
        )?;
        ensure_non_empty("control_package.control_owner", &self.control_owner)?;
        ensure_non_empty("control_package.support_owner", &self.support_owner)?;
        ensure_non_empty("control_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "control_package.buyer_review_package_file",
            &self.buyer_review_package_file,
        )?;
        ensure_non_empty("control_package.chio_evidence_dir", &self.chio_evidence_dir)?;
        ensure_fail_closed("control_package.fail_closed", self.fail_closed)?;
        if self.artifacts.is_empty() {
            return Err(ChioWallContractError::MissingField(
                "control_package.artifacts",
            ));
        }
        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(ChioWallContractError::Validation(format!(
                    "control_package.artifacts contains duplicate artifact kind {:?}",
                    artifact.artifact_kind
                )));
            }
        }
        for required in REQUIRED_CONTROL_PACKAGE_ARTIFACTS {
            if !artifact_kinds.contains(&required) {
                return Err(ChioWallContractError::Validation(format!(
                    "control_package.artifacts missing artifact kind {required:?}",
                )));
            }
        }
        Ok(())
    }
}

fn ensure_non_empty(field: &'static str, value: &str) -> Result<(), ChioWallContractError> {
    if value.trim().is_empty() {
        return Err(ChioWallContractError::EmptyField(field));
    }
    if value.trim() != value {
        return Err(ChioWallContractError::PaddedField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ChioWallContractError::Validation(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn ensure_non_empty_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ChioWallContractError> {
    if values.is_empty() {
        return Err(ChioWallContractError::MissingField(field));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ChioWallContractError::Validation(format!(
            "{field} must not contain empty values"
        )));
    }
    if values.iter().any(|value| value.trim() != value) {
        return Err(ChioWallContractError::Validation(format!(
            "{field} must not contain padded values"
        )));
    }
    if values
        .iter()
        .any(|value| value.chars().any(char::is_control))
    {
        return Err(ChioWallContractError::Validation(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn ensure_unique_strings(
    message: &'static str,
    values: &[String],
) -> Result<(), ChioWallContractError> {
    let unique_count = values.iter().collect::<HashSet<_>>().len();
    if unique_count != values.len() {
        return Err(ChioWallContractError::Validation(message.to_string()));
    }
    Ok(())
}

fn ensure_fail_closed(field: &'static str, value: bool) -> Result<(), ChioWallContractError> {
    if !value {
        Err(ChioWallContractError::Validation(format!(
            "{field} must remain true"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_valid(result: Result<(), ChioWallContractError>, context: &str) {
        if let Err(error) = result {
            panic!("{context}: {error}");
        }
    }

    fn validation_error(
        result: Result<(), ChioWallContractError>,
        context: &str,
    ) -> ChioWallContractError {
        match result {
            Ok(()) => panic!("{context}"),
            Err(error) => error,
        }
    }

    fn sample_profile() -> ChioWallControlProfile {
        ChioWallControlProfile {
            schema: CHIO_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
            profile_id: "chio-wall-profile".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
            source_domain: ChioWallInformationDomain::Research,
            protected_domain: ChioWallInformationDomain::Execution,
            retained_artifact_policy: "retain_authorization_context_and_deny_records".to_string(),
            intended_use: "Barrier review for denied cross-domain tool access.".to_string(),
            fail_closed: true,
        }
    }

    fn sample_policy_snapshot() -> ChioWallPolicySnapshot {
        ChioWallPolicySnapshot {
            schema: CHIO_WALL_POLICY_SNAPSHOT_SCHEMA.to_string(),
            policy_id: "chio.wall.policy".to_string(),
            source_domain: ChioWallInformationDomain::Research,
            allowed_tools: vec!["research_news.read".to_string()],
            fail_closed: true,
            note: "bounded allowlist".to_string(),
        }
    }

    fn sample_authorization_context() -> ChioWallAuthorizationContext {
        ChioWallAuthorizationContext {
            schema: CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA.to_string(),
            request_id: "req-1".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            actor_label: "research-agent-alpha".to_string(),
            buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
            source_domain: ChioWallInformationDomain::Research,
            requested_domain: ChioWallInformationDomain::Execution,
            tool_name: "execution_oms.submit_order".to_string(),
            policy_reference: "chio.wall.policy".to_string(),
        }
    }

    fn sample_denied_outcome() -> ChioWallGuardOutcome {
        ChioWallGuardOutcome {
            schema: CHIO_WALL_GUARD_OUTCOME_SCHEMA.to_string(),
            request_id: "req-1".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            decision: ChioWallGuardDecision::Deny,
            guard_name: "mcp-tool".to_string(),
            pipeline_name: "guard-pipeline".to_string(),
            matched_policy: "chio.wall.policy".to_string(),
            evaluated_tool: "execution_oms.submit_order".to_string(),
            allowed_tools: vec!["research_news.read".to_string()],
            reason: "tool denied".to_string(),
            fail_closed: true,
        }
    }

    fn sample_denied_access_record() -> ChioWallDeniedAccessRecord {
        ChioWallDeniedAccessRecord {
            schema: CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA.to_string(),
            request_id: "req-1".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            source_domain: ChioWallInformationDomain::Research,
            requested_domain: ChioWallInformationDomain::Execution,
            tool_name: "execution_oms.submit_order".to_string(),
            escalation_owner: "barrier-control-room".to_string(),
            support_owner: "chio-wall-ops".to_string(),
            note: "denied cross-domain tool access".to_string(),
        }
    }

    fn sample_buyer_review_package() -> ChioWallBuyerReviewPackage {
        ChioWallBuyerReviewPackage {
            schema: CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA.to_string(),
            package_id: "chio-wall-review".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
            control_owner: "barrier-control-room".to_string(),
            support_owner: "chio-wall-ops".to_string(),
            fail_closed: true,
            control_package_file: "control-package.json".to_string(),
            authorization_context_file: "authorization-context.json".to_string(),
            policy_snapshot_file: "policy-snapshot.json".to_string(),
            guard_outcome_file: "guard-outcome.json".to_string(),
            denied_access_record_file: "denied-access-record.json".to_string(),
            chio_evidence_dir: "chio-evidence".to_string(),
            note: "bounded buyer review".to_string(),
        }
    }

    fn sample_control_package() -> ChioWallControlPackage {
        ChioWallControlPackage {
            schema: CHIO_WALL_CONTROL_PACKAGE_SCHEMA.to_string(),
            package_id: "chio-wall-package".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            same_system_boundary:
                "Information-domain tool access evidence for one bounded barrier-control workflow."
                    .to_string(),
            buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
            control_owner: "barrier-control-room".to_string(),
            support_owner: "chio-wall-ops".to_string(),
            fail_closed: true,
            profile_file: "control-profile.json".to_string(),
            buyer_review_package_file: "buyer-review-package.json".to_string(),
            chio_evidence_dir: "chio-evidence".to_string(),
            artifacts: vec![
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::ControlProfile,
                    relative_path: "control-profile.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::PolicySnapshot,
                    relative_path: "policy-snapshot.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::AuthorizationContext,
                    relative_path: "authorization-context.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::GuardOutcome,
                    relative_path: "guard-outcome.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::DeniedAccessRecord,
                    relative_path: "denied-access-record.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::BuyerReviewPackage,
                    relative_path: "buyer-review-package.json".to_string(),
                },
                ChioWallArtifact {
                    artifact_kind: ChioWallArtifactKind::ChioEvidenceExport,
                    relative_path: "chio-evidence".to_string(),
                },
            ],
        }
    }

    #[test]
    fn control_profile_validates() {
        assert_valid(sample_profile().validate(), "profile validates");
    }

    #[test]
    fn control_profile_rejects_padded_profile_id() {
        let mut profile = sample_profile();
        profile.profile_id = " chio-wall-profile ".to_string();
        let error = validation_error(profile.validate(), "padded profile id rejected");
        assert!(matches!(
            error,
            ChioWallContractError::PaddedField("control_profile.profile_id")
        ));
    }

    #[test]
    fn control_profile_rejects_control_character_profile_id() {
        let mut profile = sample_profile();
        profile.profile_id = "chio-wall\nprofile".to_string();
        let error = validation_error(profile.validate(), "control profile id rejected");
        assert!(error.to_string().contains("control characters"));
    }

    #[test]
    fn control_profile_rejects_same_domain_boundary() {
        let mut profile = sample_profile();
        profile.protected_domain = ChioWallInformationDomain::Research;
        let error = validation_error(profile.validate(), "same source/protected domain rejected");
        assert!(error.to_string().contains("must differ"));
    }

    #[test]
    fn policy_snapshot_rejects_duplicate_allowed_tools() {
        let mut snapshot = sample_policy_snapshot();
        snapshot.allowed_tools = vec![
            "research_news.read".to_string(),
            "research_news.read".to_string(),
        ];
        let error = validation_error(snapshot.validate(), "duplicate tool rejected");
        assert!(error.to_string().contains("duplicate tool name"));
    }

    #[test]
    fn policy_snapshot_rejects_empty_allowed_tool_entries() {
        let mut snapshot = sample_policy_snapshot();
        snapshot.allowed_tools = vec!["research_news.read".to_string(), "   ".to_string()];
        let error = validation_error(snapshot.validate(), "empty allowlist entry rejected");
        assert!(error.to_string().contains("must not contain empty values"));
    }

    #[test]
    fn policy_snapshot_rejects_padded_allowed_tool_entries() {
        let mut snapshot = sample_policy_snapshot();
        snapshot.allowed_tools = vec![
            "research_news.read".to_string(),
            " execution_oms.submit_order ".to_string(),
        ];
        let error = validation_error(snapshot.validate(), "padded allowlist entry rejected");
        assert!(error.to_string().contains("padded values"));
    }

    #[test]
    fn authorization_context_rejects_same_domain_request() {
        let mut context = sample_authorization_context();
        context.requested_domain = ChioWallInformationDomain::Research;
        let error = validation_error(context.validate(), "same-domain request rejected");
        assert!(error.to_string().contains("must differ"));
    }

    #[test]
    fn guard_outcome_rejects_denied_tool_in_allowlist() {
        let mut outcome = sample_denied_outcome();
        outcome
            .allowed_tools
            .push("execution_oms.submit_order".to_string());
        let error = validation_error(outcome.validate(), "invalid denial rejected");
        assert!(error.to_string().contains("cannot deny"));
    }

    #[test]
    fn guard_outcome_allows_tool_not_present_in_allowlist() {
        let mut outcome = sample_denied_outcome();
        outcome.decision = ChioWallGuardDecision::Allow;
        outcome.reason = "operator explicitly allowed bounded workflow".to_string();
        assert_valid(
            outcome.validate(),
            "allow outcome remains structurally valid",
        );
    }

    #[test]
    fn denied_access_record_rejects_same_domain_request() {
        let mut record = sample_denied_access_record();
        record.requested_domain = ChioWallInformationDomain::Research;
        let error = validation_error(record.validate(), "same-domain denied access rejected");
        assert!(error.to_string().contains("must differ"));
    }

    #[test]
    fn buyer_review_package_requires_fail_closed_and_non_empty_files() {
        let mut review = sample_buyer_review_package();
        review.control_package_file = " ".to_string();
        let error = validation_error(review.validate(), "empty file path should fail validation");
        assert!(error.to_string().contains("control_package_file"));

        let mut review = sample_buyer_review_package();
        review.fail_closed = false;
        let error = validation_error(
            review.validate(),
            "fail_closed=false should fail validation",
        );
        assert!(error.to_string().contains("must remain true"));
    }

    #[test]
    fn control_package_rejects_duplicate_artifacts() {
        let mut package = sample_control_package();
        package.artifacts.push(ChioWallArtifact {
            artifact_kind: ChioWallArtifactKind::ControlProfile,
            relative_path: "control-profile-copy.json".to_string(),
        });
        let error = validation_error(package.validate(), "duplicate artifact rejected");
        assert!(error.to_string().contains("duplicate artifact kind"));
    }

    #[test]
    fn control_package_requires_non_empty_artifact_paths() {
        let mut package = sample_control_package();
        package.artifacts[0].relative_path = " ".to_string();
        let error = validation_error(
            package.validate(),
            "empty artifact path should fail validation",
        );
        assert!(error.to_string().contains("relative_path"));
    }

    #[test]
    fn control_package_requires_complete_artifact_set() {
        let mut package = sample_control_package();
        package
            .artifacts
            .retain(|artifact| artifact.artifact_kind != ChioWallArtifactKind::ChioEvidenceExport);

        let error = validation_error(
            package.validate(),
            "incomplete control package artifacts should fail validation",
        );

        assert!(error.to_string().contains("missing artifact kind"));
    }
}
