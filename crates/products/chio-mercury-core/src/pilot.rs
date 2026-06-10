use serde::{Deserialize, Serialize};

use crate::bundle::{
    MercuryArtifactReference, MercuryBundleManifest, MERCURY_BUNDLE_MANIFEST_SCHEMA,
};
use crate::fixtures::{sample_mercury_bundle_manifest, sample_mercury_receipt_metadata};
use crate::receipt_metadata::{
    MercuryApprovalStatus, MercuryChronologyStage, MercuryContractError, MercuryDecisionType,
    MercuryReceiptMetadata,
};

pub const MERCURY_PILOT_SCENARIO_SCHEMA: &str = "chio.mercury.pilot_scenario.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPilotStep {
    pub step_id: String,
    pub receipt_id: String,
    pub timestamp: u64,
    pub tool_name: String,
    pub metadata: MercuryReceiptMetadata,
}

impl MercuryPilotStep {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("pilot_step.step_id", &self.step_id)?;
        ensure_non_empty("pilot_step.receipt_id", &self.receipt_id)?;
        ensure_non_empty("pilot_step.tool_name", &self.tool_name)?;
        self.metadata.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPilotScenario {
    pub schema: String,
    pub scenario_id: String,
    pub workflow_id: String,
    pub description: String,
    pub primary_path: Vec<MercuryPilotStep>,
    pub rollback_variant: Vec<MercuryPilotStep>,
    pub primary_bundle_manifest: MercuryBundleManifest,
    pub rollback_bundle_manifest: MercuryBundleManifest,
}

struct MercuryPilotStepSpec<'a> {
    step_id: &'a str,
    receipt_id: &'a str,
    timestamp: u64,
    tool_name: &'a str,
    decision_type: MercuryDecisionType,
    stage: MercuryChronologyStage,
    event_id: &'a str,
    parents: &'a [&'a str],
}

impl MercuryPilotScenario {
    #[must_use]
    pub fn gold_release_control() -> Self {
        let primary_steps = vec![
            build_step(
                MercuryPilotStepSpec {
                    step_id: "proposal",
                    receipt_id: "rcpt-mercury-proposal-1",
                    timestamp: 1_775_137_600,
                    tool_name: "proposal_review",
                    decision_type: MercuryDecisionType::Propose,
                    stage: MercuryChronologyStage::Proposal,
                    event_id: "evt-proposal-1",
                    parents: &[],
                },
                |metadata| {
                    metadata.approval_state.state = MercuryApprovalStatus::Pending;
                    metadata.approval_state.approver_subjects.clear();
                    metadata.approval_state.approval_ticket_id = Some("chg-1042".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.chronology.idempotency_key =
                        Some("idempotency-proposal-1".to_string());
                    metadata.provenance.source_record_id = Some("source-proposal-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "approval",
                    receipt_id: "rcpt-mercury-approval-1",
                    timestamp: 1_775_137_610,
                    tool_name: "approval_review",
                    decision_type: MercuryDecisionType::Approve,
                    stage: MercuryChronologyStage::Approval,
                    event_id: "evt-approval-1",
                    parents: &["evt-proposal-1"],
                },
                |metadata| {
                    metadata.approval_state.state = MercuryApprovalStatus::Approved;
                    metadata.approval_state.approver_subjects = vec!["approver-risk-1".to_string()];
                    metadata.approval_state.approval_ticket_id = Some("chg-1042".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.chronology.idempotency_key =
                        Some("idempotency-approval-1".to_string());
                    metadata.provenance.source_record_id = Some("source-approval-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "release",
                    receipt_id: "rcpt-mercury-release-1",
                    timestamp: 1_775_137_620,
                    tool_name: "release_control",
                    decision_type: MercuryDecisionType::Release,
                    stage: MercuryChronologyStage::Release,
                    event_id: "evt-release-1",
                    parents: &["evt-approval-1"],
                },
                |metadata| {
                    metadata.approval_state.state = MercuryApprovalStatus::Approved;
                    metadata.approval_state.approver_subjects = vec!["approver-risk-1".to_string()];
                    metadata.approval_state.approval_ticket_id = Some("chg-1042".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.chronology.idempotency_key = Some("idempotency-release-1".to_string());
                    metadata.provenance.source_record_id = Some("source-release-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "inquiry",
                    receipt_id: "rcpt-mercury-inquiry-1",
                    timestamp: 1_775_137_630,
                    tool_name: "inquiry_review",
                    decision_type: MercuryDecisionType::Inquiry,
                    stage: MercuryChronologyStage::Inquiry,
                    event_id: "evt-inquiry-1",
                    parents: &["evt-release-1"],
                },
                |metadata| {
                    metadata.approval_state.state = MercuryApprovalStatus::InquiryOpen;
                    metadata.approval_state.approver_subjects =
                        vec!["review-compliance-1".to_string()];
                    metadata.approval_state.approval_ticket_id = Some("inq-2201".to_string());
                    metadata.business_ids.inquiry_id = Some("inquiry-2026-04-02".to_string());
                    metadata.disclosure.policy = "review-safe-export".to_string();
                    metadata.disclosure.redaction_profile =
                        Some("design-partner-default".to_string());
                    metadata.disclosure.audience = Some("design-partner".to_string());
                    metadata.disclosure.verifier_equivalent = false;
                    metadata.disclosure.reviewed_export_approved = true;
                    metadata.chronology.idempotency_key = Some("idempotency-inquiry-1".to_string());
                    metadata.provenance.source_record_id = Some("source-inquiry-1".to_string());
                },
            ),
        ];

        let rollback_steps = vec![
            build_step(
                MercuryPilotStepSpec {
                    step_id: "proposal",
                    receipt_id: "rcpt-mercury-rollback-proposal-1",
                    timestamp: 1_775_137_700,
                    tool_name: "proposal_review",
                    decision_type: MercuryDecisionType::Propose,
                    stage: MercuryChronologyStage::Proposal,
                    event_id: "evt-rollback-proposal-1",
                    parents: &[],
                },
                |metadata| {
                    metadata.business_ids.release_id = Some("release-2026-04-02".to_string());
                    metadata.business_ids.rollback_id = Some("rollback-2026-04-02".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.approval_state.state = MercuryApprovalStatus::Pending;
                    metadata.approval_state.approver_subjects.clear();
                    metadata.approval_state.approval_ticket_id = Some("chg-rollback-1".to_string());
                    metadata.chronology.idempotency_key =
                        Some("idempotency-rollback-proposal-1".to_string());
                    metadata.provenance.source_record_id =
                        Some("source-rollback-proposal-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "approval",
                    receipt_id: "rcpt-mercury-rollback-approval-1",
                    timestamp: 1_775_137_710,
                    tool_name: "approval_review",
                    decision_type: MercuryDecisionType::Approve,
                    stage: MercuryChronologyStage::Approval,
                    event_id: "evt-rollback-approval-1",
                    parents: &["evt-rollback-proposal-1"],
                },
                |metadata| {
                    metadata.business_ids.release_id = Some("release-2026-04-02".to_string());
                    metadata.business_ids.rollback_id = Some("rollback-2026-04-02".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.approval_state.state = MercuryApprovalStatus::Approved;
                    metadata.approval_state.approver_subjects = vec!["approver-risk-1".to_string()];
                    metadata.approval_state.approval_ticket_id = Some("chg-rollback-1".to_string());
                    metadata.chronology.idempotency_key =
                        Some("idempotency-rollback-approval-1".to_string());
                    metadata.provenance.source_record_id =
                        Some("source-rollback-approval-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "release",
                    receipt_id: "rcpt-mercury-rollback-release-1",
                    timestamp: 1_775_137_720,
                    tool_name: "release_control",
                    decision_type: MercuryDecisionType::Release,
                    stage: MercuryChronologyStage::Release,
                    event_id: "evt-rollback-release-1",
                    parents: &["evt-rollback-approval-1"],
                },
                |metadata| {
                    metadata.business_ids.release_id = Some("release-2026-04-02".to_string());
                    metadata.business_ids.rollback_id = Some("rollback-2026-04-02".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.approval_state.state = MercuryApprovalStatus::Approved;
                    metadata.approval_state.approver_subjects = vec!["approver-risk-1".to_string()];
                    metadata.approval_state.approval_ticket_id = Some("chg-rollback-1".to_string());
                    metadata.chronology.idempotency_key =
                        Some("idempotency-rollback-release-1".to_string());
                    metadata.provenance.source_record_id =
                        Some("source-rollback-release-1".to_string());
                },
            ),
            build_step(
                MercuryPilotStepSpec {
                    step_id: "rollback",
                    receipt_id: "rcpt-mercury-rollback-1",
                    timestamp: 1_775_137_730,
                    tool_name: "rollback_control",
                    decision_type: MercuryDecisionType::Rollback,
                    stage: MercuryChronologyStage::Rollback,
                    event_id: "evt-rollback-1",
                    parents: &["evt-rollback-release-1"],
                },
                |metadata| {
                    metadata.business_ids.release_id = Some("release-2026-04-02".to_string());
                    metadata.business_ids.rollback_id = Some("rollback-2026-04-02".to_string());
                    metadata.business_ids.inquiry_id = None;
                    metadata.approval_state.state = MercuryApprovalStatus::RolledBack;
                    metadata.approval_state.approver_subjects = vec![
                        "approver-risk-1".to_string(),
                        "operator-release-1".to_string(),
                    ];
                    metadata.approval_state.approval_ticket_id = Some("chg-rollback-1".to_string());
                    metadata.disclosure.policy = "internal-review-only".to_string();
                    metadata.disclosure.redaction_profile = Some("internal-default".to_string());
                    metadata.disclosure.audience = Some("compliance".to_string());
                    metadata.disclosure.verifier_equivalent = true;
                    metadata.disclosure.reviewed_export_approved = true;
                    metadata.chronology.idempotency_key =
                        Some("idempotency-rollback-1".to_string());
                    metadata.provenance.source_record_id = Some("source-rollback-1".to_string());
                },
            ),
        ];

        let primary_business_ids = match primary_steps.last() {
            Some(step) => step.metadata.business_ids.clone(),
            None => unreachable!("primary pilot path is non-empty"),
        };
        let primary_bundle_manifest = build_manifest(
            "bundle-pilot-primary-2026-04-02",
            1_775_137_630,
            primary_business_ids,
            vec![
                MercuryArtifactReference {
                    artifact_id: "pilot-workflow-diff".to_string(),
                    artifact_type: "workflow_diff".to_string(),
                    sha256: "artifact-sha256-pilot-workflow-diff".to_string(),
                    media_type: "application/json".to_string(),
                    retention_class: Some("pilot-90d".to_string()),
                    legal_hold: false,
                    redaction_policy: Some("mask-counterparty".to_string()),
                },
                MercuryArtifactReference {
                    artifact_id: "design-partner-readout".to_string(),
                    artifact_type: "pilot_readout".to_string(),
                    sha256: "artifact-sha256-design-partner-readout".to_string(),
                    media_type: "application/json".to_string(),
                    retention_class: Some("pilot-90d".to_string()),
                    legal_hold: false,
                    redaction_policy: Some("review-safe".to_string()),
                },
            ],
        );

        let rollback_business_ids = match rollback_steps.last() {
            Some(step) => step.metadata.business_ids.clone(),
            None => unreachable!("rollback pilot path is non-empty"),
        };
        let rollback_bundle_manifest = build_manifest(
            "bundle-pilot-rollback-2026-04-02",
            1_775_137_730,
            rollback_business_ids,
            vec![
                MercuryArtifactReference {
                    artifact_id: "rollback-decision-note".to_string(),
                    artifact_type: "rollback_note".to_string(),
                    sha256: "artifact-sha256-rollback-note".to_string(),
                    media_type: "application/json".to_string(),
                    retention_class: Some("pilot-90d".to_string()),
                    legal_hold: false,
                    redaction_policy: Some("internal-only".to_string()),
                },
                MercuryArtifactReference {
                    artifact_id: "rollback-diff".to_string(),
                    artifact_type: "rollback_diff".to_string(),
                    sha256: "artifact-sha256-rollback-diff".to_string(),
                    media_type: "application/json".to_string(),
                    retention_class: Some("pilot-90d".to_string()),
                    legal_hold: false,
                    redaction_policy: Some("none".to_string()),
                },
            ],
        );

        Self {
            schema: MERCURY_PILOT_SCENARIO_SCHEMA.to_string(),
            scenario_id: "gold-release-control-pilot".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            description: "Primary propose -> approve -> release -> inquiry path plus rollback variant for the first MERCURY design-partner corpus.".to_string(),
            primary_path: primary_steps,
            rollback_variant: rollback_steps,
            primary_bundle_manifest,
            rollback_bundle_manifest,
        }
    }

    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PILOT_SCENARIO_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PILOT_SCENARIO_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("pilot_scenario.scenario_id", &self.scenario_id)?;
        ensure_non_empty("pilot_scenario.workflow_id", &self.workflow_id)?;
        ensure_non_empty("pilot_scenario.description", &self.description)?;
        validate_path(&self.primary_path, &self.workflow_id)?;
        validate_path(&self.rollback_variant, &self.workflow_id)?;
        self.primary_bundle_manifest.validate()?;
        self.rollback_bundle_manifest.validate()?;
        if self.primary_bundle_manifest.business_ids.workflow_id != self.workflow_id {
            return Err(MercuryContractError::Validation(
                "primary bundle manifest workflow_id does not match pilot scenario".to_string(),
            ));
        }
        if self.rollback_bundle_manifest.business_ids.workflow_id != self.workflow_id {
            return Err(MercuryContractError::Validation(
                "rollback bundle manifest workflow_id does not match pilot scenario".to_string(),
            ));
        }
        Ok(())
    }
}

fn build_step(
    spec: MercuryPilotStepSpec<'_>,
    mutate: impl FnOnce(&mut MercuryReceiptMetadata),
) -> MercuryPilotStep {
    let MercuryPilotStepSpec {
        step_id,
        receipt_id,
        timestamp,
        tool_name,
        decision_type,
        stage,
        event_id,
        parents,
    } = spec;
    let mut metadata = sample_mercury_receipt_metadata();
    metadata.decision_context.decision_type = decision_type;
    metadata.chronology.stage = stage;
    metadata.chronology.event_id = event_id.to_string();
    metadata.chronology.ingested_at = timestamp;
    metadata.chronology.source_timestamp = Some(timestamp.saturating_sub(5));
    metadata.chronology.causal_parent_event_ids =
        parents.iter().map(|parent| (*parent).to_string()).collect();
    mutate(&mut metadata);

    MercuryPilotStep {
        step_id: step_id.to_string(),
        receipt_id: receipt_id.to_string(),
        timestamp,
        tool_name: tool_name.to_string(),
        metadata,
    }
}

fn build_manifest(
    bundle_id: &str,
    created_at: u64,
    business_ids: crate::receipt_metadata::MercuryWorkflowIdentifiers,
    artifacts: Vec<MercuryArtifactReference>,
) -> MercuryBundleManifest {
    let mut manifest = sample_mercury_bundle_manifest();
    manifest.schema = MERCURY_BUNDLE_MANIFEST_SCHEMA.to_string();
    manifest.bundle_id = bundle_id.to_string();
    manifest.created_at = created_at;
    manifest.business_ids = business_ids;
    manifest.artifacts = artifacts;
    manifest
}

fn validate_path(
    steps: &[MercuryPilotStep],
    workflow_id: &str,
) -> Result<(), MercuryContractError> {
    if steps.is_empty() {
        return Err(MercuryContractError::MissingField("pilot_scenario.steps"));
    }
    for step in steps {
        step.validate()?;
        if step.metadata.business_ids.workflow_id != workflow_id {
            return Err(MercuryContractError::Validation(format!(
                "pilot step {} does not match workflow_id {}",
                step.step_id, workflow_id
            )));
        }
    }
    Ok(())
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
    fn gold_release_control_scenario_validates() {
        let scenario = MercuryPilotScenario::gold_release_control();
        scenario.validate().expect("pilot scenario");
        assert_eq!(scenario.primary_path.len(), 4);
        assert_eq!(scenario.rollback_variant.len(), 4);
        assert_eq!(scenario.workflow_id, "workflow-release-control");
        assert_eq!(
            scenario.primary_path[3]
                .metadata
                .business_ids
                .inquiry_id
                .as_deref(),
            Some("inquiry-2026-04-02")
        );
        assert_eq!(
            scenario.rollback_variant[3]
                .metadata
                .business_ids
                .rollback_id
                .as_deref(),
            Some("rollback-2026-04-02")
        );
    }
}
