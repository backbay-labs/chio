use serde::{Deserialize, Serialize};

use crate::bundle::MercuryBundleManifest;
use crate::pilot::{MercuryPilotScenario, MercuryPilotStep};
use crate::receipt_metadata::{MercuryContractError, MercuryDecisionType, MercuryDisclosurePolicy};

pub const MERCURY_SUPERVISED_LIVE_CAPTURE_SCHEMA: &str = "chio.mercury.supervised_live_capture.v1";

pub type MercurySupervisedLiveStep = MercuryPilotStep;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercurySupervisedLiveGateState {
    Approved,
    Blocked,
    #[default]
    NotRequired,
}

impl MercurySupervisedLiveGateState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Blocked => "blocked",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveGate {
    pub state: MercurySupervisedLiveGateState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approver_subjects: Vec<String>,
}

impl MercurySupervisedLiveGate {
    pub fn validate(&self, field: &'static str) -> Result<(), MercuryContractError> {
        if self.state == MercurySupervisedLiveGateState::Approved {
            let approval_ticket_id = self.approval_ticket_id.as_deref().ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "{field} must include approval_ticket_id when state is approved"
                ))
            })?;
            if approval_ticket_id.trim().is_empty() {
                return Err(MercuryContractError::Validation(format!(
                    "{field}.approval_ticket_id must not be empty when state is approved"
                )));
            }
            if self.approver_subjects.is_empty() {
                return Err(MercuryContractError::Validation(format!(
                    "{field} must include approver_subjects when state is approved"
                )));
            }
        }
        Ok(())
    }

    pub fn ensure_approved(&self, field: &'static str) -> Result<(), MercuryContractError> {
        self.validate(field)?;
        if self.state != MercurySupervisedLiveGateState::Approved {
            return Err(MercuryContractError::Validation(format!(
                "{field} must be approved for supervised-live export readiness"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercurySupervisedLiveHealthStatus {
    #[default]
    Healthy,
    Degraded,
    Failed,
}

impl MercurySupervisedLiveHealthStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn is_healthy(self) -> bool {
        self == Self::Healthy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveEvidenceHealth {
    pub intake: MercurySupervisedLiveHealthStatus,
    pub retention: MercurySupervisedLiveHealthStatus,
    pub signing: MercurySupervisedLiveHealthStatus,
    pub publication: MercurySupervisedLiveHealthStatus,
    pub monitoring: MercurySupervisedLiveHealthStatus,
}

impl MercurySupervisedLiveEvidenceHealth {
    #[must_use]
    pub fn healthy() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn all_healthy(&self) -> bool {
        self.intake.is_healthy()
            && self.retention.is_healthy()
            && self.signing.is_healthy()
            && self.publication.is_healthy()
            && self.monitoring.is_healthy()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercurySupervisedLiveCoverageState {
    #[default]
    Covered,
    Interrupted,
    Degraded,
    RecoveryReview,
}

impl MercurySupervisedLiveCoverageState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Interrupted => "interrupted",
            Self::Degraded => "degraded",
            Self::RecoveryReview => "recovery_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercurySupervisedLiveInterruptKind {
    ManualPause,
    IntakeGap,
    KeyIssue,
    MonitoringIssue,
    ReviewerUnavailable,
    RecoveryReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveInterruption {
    pub kind: MercurySupervisedLiveInterruptKind,
    pub incident_id: String,
    pub summary: String,
}

impl MercurySupervisedLiveInterruption {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.incident_id.trim().is_empty() {
            return Err(MercuryContractError::Validation(
                "supervised_live_capture.control_state.interruptions[].incident_id must not be empty"
                    .to_string(),
            ));
        }
        if self.summary.trim().is_empty() {
            return Err(MercuryContractError::Validation(
                "supervised_live_capture.control_state.interruptions[].summary must not be empty"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveControlState {
    pub release_gate: MercurySupervisedLiveGate,
    pub rollback_gate: MercurySupervisedLiveGate,
    pub coverage_state: MercurySupervisedLiveCoverageState,
    pub evidence_health: MercurySupervisedLiveEvidenceHealth,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interruptions: Vec<MercurySupervisedLiveInterruption>,
}

impl MercurySupervisedLiveControlState {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        self.release_gate
            .validate("supervised_live_capture.control_state.release_gate")?;
        self.rollback_gate
            .validate("supervised_live_capture.control_state.rollback_gate")?;
        for interruption in &self.interruptions {
            interruption.validate()?;
        }
        if self.coverage_state == MercurySupervisedLiveCoverageState::Covered {
            if !self.evidence_health.all_healthy() {
                return Err(MercuryContractError::Validation(
                    "supervised_live_capture.control_state.coverage_state cannot be covered when evidence_health is degraded"
                        .to_string(),
                ));
            }
            if !self.interruptions.is_empty() {
                return Err(MercuryContractError::Validation(
                    "supervised_live_capture.control_state.coverage_state cannot be covered when interruptions are present"
                        .to_string(),
                ));
            }
        } else if self.interruptions.is_empty() {
            return Err(MercuryContractError::Validation(
                "supervised_live_capture.control_state must include interruptions when coverage_state is not covered"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn ensure_export_ready(&self) -> Result<(), MercuryContractError> {
        self.validate()?;
        self.release_gate
            .ensure_approved("supervised_live_capture.control_state.release_gate")?;
        self.rollback_gate
            .ensure_approved("supervised_live_capture.control_state.rollback_gate")?;
        if self.coverage_state != MercurySupervisedLiveCoverageState::Covered {
            return Err(MercuryContractError::Validation(format!(
                "supervised-live export must fail closed when coverage_state is {}",
                self.coverage_state.as_str()
            )));
        }
        if !self.evidence_health.all_healthy() {
            return Err(MercuryContractError::Validation(
                "supervised-live export must fail closed when evidence_health is not fully healthy"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercurySupervisedLiveMode {
    #[default]
    Mirrored,
    Live,
}

impl MercurySupervisedLiveMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mirrored => "mirrored",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveInquiryConfig {
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<String>,
    #[serde(default)]
    pub verifier_equivalent: bool,
}

impl MercurySupervisedLiveInquiryConfig {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("supervised_live_capture.inquiry.audience", &self.audience)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercurySupervisedLiveCapture {
    pub schema: String,
    pub capture_id: String,
    pub workflow_id: String,
    pub mode: MercurySupervisedLiveMode,
    pub description: String,
    pub control_state: MercurySupervisedLiveControlState,
    pub steps: Vec<MercurySupervisedLiveStep>,
    pub bundle_manifests: Vec<MercuryBundleManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inquiry: Option<MercurySupervisedLiveInquiryConfig>,
}

impl MercurySupervisedLiveCapture {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_SUPERVISED_LIVE_CAPTURE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_SUPERVISED_LIVE_CAPTURE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("supervised_live_capture.capture_id", &self.capture_id)?;
        ensure_non_empty("supervised_live_capture.workflow_id", &self.workflow_id)?;
        ensure_non_empty("supervised_live_capture.description", &self.description)?;
        self.control_state.validate()?;
        if self.steps.is_empty() {
            return Err(MercuryContractError::MissingField(
                "supervised_live_capture.steps",
            ));
        }
        if self.bundle_manifests.is_empty() {
            return Err(MercuryContractError::MissingField(
                "supervised_live_capture.bundle_manifests",
            ));
        }
        if let Some(inquiry) = &self.inquiry {
            inquiry.validate()?;
        }

        for step in &self.steps {
            step.validate()?;
            if step.metadata.business_ids.workflow_id != self.workflow_id {
                return Err(MercuryContractError::Validation(format!(
                    "supervised-live step {} has workflow_id {} but capture workflow_id is {}",
                    step.step_id, step.metadata.business_ids.workflow_id, self.workflow_id
                )));
            }
            let source_record_id = step
                .metadata
                .provenance
                .source_record_id
                .as_deref()
                .ok_or({
                    MercuryContractError::MissingField(
                        "supervised_live_capture.steps[].metadata.provenance.source_record_id",
                    )
                })?;
            ensure_non_empty(
                "supervised_live_capture.steps[].metadata.provenance.source_record_id",
                source_record_id,
            )?;
            let idempotency_key = step.metadata.chronology.idempotency_key.as_deref().ok_or({
                MercuryContractError::MissingField(
                    "supervised_live_capture.steps[].metadata.chronology.idempotency_key",
                )
            })?;
            ensure_non_empty(
                "supervised_live_capture.steps[].metadata.chronology.idempotency_key",
                idempotency_key,
            )?;
        }

        let has_release_step = self.steps.iter().any(|step| {
            step.metadata.decision_context.decision_type == MercuryDecisionType::Release
        });
        if has_release_step {
            self.control_state
                .release_gate
                .ensure_approved("supervised_live_capture.control_state.release_gate")?;
        }
        let has_rollback_step = self.steps.iter().any(|step| {
            step.metadata.decision_context.decision_type == MercuryDecisionType::Rollback
        });
        if has_rollback_step {
            self.control_state
                .rollback_gate
                .ensure_approved("supervised_live_capture.control_state.rollback_gate")?;
        }

        for manifest in &self.bundle_manifests {
            manifest.validate()?;
            if manifest.business_ids.workflow_id != self.workflow_id {
                return Err(MercuryContractError::Validation(format!(
                    "bundle manifest {} has workflow_id {} but capture workflow_id is {}",
                    manifest.bundle_id, manifest.business_ids.workflow_id, self.workflow_id
                )));
            }
        }

        Ok(())
    }

    pub fn ensure_export_ready(&self) -> Result<(), MercuryContractError> {
        self.validate()?;
        self.control_state.ensure_export_ready()
    }

    #[must_use]
    pub fn sample(mode: MercurySupervisedLiveMode) -> Self {
        let scenario = MercuryPilotScenario::gold_release_control();
        let mode_name = mode.as_str();
        let mut steps = scenario.primary_path;
        for step in &mut steps {
            step.metadata.provenance.source_system = match mode {
                MercurySupervisedLiveMode::Mirrored => {
                    "production-mirror-release-review".to_string()
                }
                MercurySupervisedLiveMode::Live => "supervised-live-release-review".to_string(),
            };
            step.metadata.provenance.hosting_mode = Some(format!("{mode_name}-production"));
        }

        let mut bundle_manifest = scenario.primary_bundle_manifest;
        bundle_manifest.bundle_id = format!("bundle-{mode_name}-release-2026-04-02");
        for artifact in &mut bundle_manifest.artifacts {
            artifact.retention_class = Some("supervised-live-180d".to_string());
        }

        Self {
            schema: MERCURY_SUPERVISED_LIVE_CAPTURE_SCHEMA.to_string(),
            capture_id: format!("capture-{mode_name}-release-control-2026-04-02"),
            workflow_id: scenario.workflow_id,
            mode,
            description: format!(
                "Supervised-live {} capture for the gold MERCURY release-control workflow.",
                mode_name
            ),
            control_state: MercurySupervisedLiveControlState {
                release_gate: MercurySupervisedLiveGate {
                    state: MercurySupervisedLiveGateState::Approved,
                    approval_ticket_id: Some("chg-1042".to_string()),
                    approver_subjects: vec!["approver-risk-1".to_string()],
                },
                rollback_gate: MercurySupervisedLiveGate {
                    state: MercurySupervisedLiveGateState::Approved,
                    approval_ticket_id: Some("chg-rollback-1".to_string()),
                    approver_subjects: vec!["approver-risk-1".to_string()],
                },
                coverage_state: MercurySupervisedLiveCoverageState::Covered,
                evidence_health: MercurySupervisedLiveEvidenceHealth::healthy(),
                interruptions: Vec::new(),
            },
            steps,
            bundle_manifests: vec![bundle_manifest],
            inquiry: Some(MercurySupervisedLiveInquiryConfig {
                audience: "design-partner".to_string(),
                redaction_profile: Some("design-partner-default".to_string()),
                verifier_equivalent: false,
            }),
        }
    }

    pub fn disclosure_policy(&self) -> Option<MercuryDisclosurePolicy> {
        self.steps
            .last()
            .map(|step| step.metadata.disclosure.clone())
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
    fn sample_supervised_live_capture_validates() {
        MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Mirrored)
            .validate()
            .expect("sample capture");
    }

    #[test]
    fn supervised_live_capture_requires_source_record_id() {
        let mut capture = MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live);
        capture.steps[0].metadata.provenance.source_record_id = None;
        let error = capture.validate().expect_err("missing source record id");
        assert!(error.to_string().contains("source_record_id"), "{error}");
    }

    #[test]
    fn supervised_live_capture_requires_idempotency_key() {
        let mut capture = MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live);
        capture.steps[0].metadata.chronology.idempotency_key = None;
        let error = capture.validate().expect_err("missing idempotency key");
        assert!(error.to_string().contains("idempotency_key"), "{error}");
    }

    #[test]
    fn supervised_live_capture_requires_interruptions_when_coverage_not_covered() {
        let mut capture = MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live);
        capture.control_state.coverage_state = MercurySupervisedLiveCoverageState::Degraded;
        let error = capture
            .validate()
            .expect_err("coverage degraded without interruption");
        assert!(error.to_string().contains("interruptions"), "{error}");
    }

    #[test]
    fn supervised_live_capture_export_readiness_fails_closed_on_degraded_health() {
        let mut capture = MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live);
        capture.control_state.coverage_state = MercurySupervisedLiveCoverageState::Degraded;
        capture.control_state.evidence_health.monitoring =
            MercurySupervisedLiveHealthStatus::Degraded;
        capture
            .control_state
            .interruptions
            .push(MercurySupervisedLiveInterruption {
                kind: MercurySupervisedLiveInterruptKind::MonitoringIssue,
                incident_id: "incident-monitoring-1".to_string(),
                summary: "Monitoring coverage degraded; supervised-live export paused.".to_string(),
            });
        let error = capture
            .ensure_export_ready()
            .expect_err("degraded health must fail closed");
        assert!(error.to_string().contains("fail closed"), "{error}");
    }
}
