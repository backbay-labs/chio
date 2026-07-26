use chio_core::web3::anchors::{
    CHIO_ANCHOR_CONTROL_STATE_SCHEMA, CHIO_ANCHOR_CONTROL_TRACE_SCHEMA,
};
use serde::{Deserialize, Serialize};

use crate::{bundle::AnchorLaneKind, AnchorError};

pub const CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA: &str = "chio.anchor-runtime-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorIndexerStatus {
    Healthy,
    Lagging,
    Drifted,
    Replaying,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorLaneHealthStatus {
    Healthy,
    Lagging,
    Drifted,
    Recovering,
    Paused,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorEmergencyMode {
    Normal,
    PublishPaused,
    ProofImportOnly,
    RecoveryOnly,
    Halted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorOperationKind {
    PublishRoot,
    ConfirmPublication,
    ImportSecondaryProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorControlChangeRecord {
    pub schema: String,
    pub actor: String,
    pub source: String,
    pub changed_at: u64,
    pub before: AnchorEmergencyControls,
    pub after: AnchorEmergencyControls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorEmergencyControls {
    pub mode: AnchorEmergencyMode,
    pub changed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AnchorEmergencyControls {
    #[must_use]
    pub fn normal(changed_at: u64) -> Self {
        Self {
            mode: AnchorEmergencyMode::Normal,
            changed_at,
            reason: None,
        }
    }

    #[must_use]
    pub fn allows(&self, operation: AnchorOperationKind) -> bool {
        match self.mode {
            AnchorEmergencyMode::Normal => true,
            AnchorEmergencyMode::PublishPaused => operation != AnchorOperationKind::PublishRoot,
            AnchorEmergencyMode::ProofImportOnly => {
                operation == AnchorOperationKind::ImportSecondaryProof
            }
            AnchorEmergencyMode::RecoveryOnly => {
                operation == AnchorOperationKind::ConfirmPublication
            }
            AnchorEmergencyMode::Halted => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorControlState {
    pub schema: String,
    pub updated_at: u64,
    pub controls: AnchorEmergencyControls,
    pub history: Vec<AnchorControlChangeRecord>,
}

impl AnchorControlState {
    #[must_use]
    pub fn new(updated_at: u64, controls: AnchorEmergencyControls) -> Self {
        Self {
            schema: CHIO_ANCHOR_CONTROL_STATE_SCHEMA.to_string(),
            updated_at,
            controls,
            history: Vec::new(),
        }
    }

    pub fn apply_change(
        &mut self,
        mode: AnchorEmergencyMode,
        changed_at: u64,
        actor: impl Into<String>,
        reason: Option<String>,
        source: impl Into<String>,
    ) {
        let before = self.controls.clone();
        self.controls = AnchorEmergencyControls {
            mode,
            changed_at,
            reason,
        };
        self.updated_at = changed_at;
        self.history.push(AnchorControlChangeRecord {
            schema: CHIO_ANCHOR_CONTROL_TRACE_SCHEMA.to_string(),
            actor: actor.into(),
            source: source.into(),
            changed_at,
            before,
            after: self.controls.clone(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorIndexerCursor {
    pub service_id: String,
    pub lane: AnchorLaneKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    pub indexed_checkpoint_seq: u64,
    pub canonical_checkpoint_seq: u64,
    pub lag_checkpoints: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed_block_number: Option<u64>,
    pub status: AnchorIndexerStatus,
    pub checked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl AnchorIndexerCursor {
    #[must_use]
    pub fn from_sequences(input: AnchorIndexerCursorInput) -> Self {
        let lag_checkpoints = input
            .canonical_checkpoint_seq
            .saturating_sub(input.indexed_checkpoint_seq);
        let status = if input.failed {
            AnchorIndexerStatus::Failed
        } else if input.replaying {
            AnchorIndexerStatus::Replaying
        } else if lag_checkpoints == 0 {
            AnchorIndexerStatus::Healthy
        } else if lag_checkpoints <= 3 {
            AnchorIndexerStatus::Lagging
        } else {
            AnchorIndexerStatus::Drifted
        };
        Self {
            service_id: input.service_id,
            lane: input.lane,
            chain_id: input.chain_id,
            indexed_checkpoint_seq: input.indexed_checkpoint_seq,
            canonical_checkpoint_seq: input.canonical_checkpoint_seq,
            lag_checkpoints,
            indexed_block_number: input.indexed_block_number,
            status,
            checked_at: input.checked_at,
            note: input.note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorIndexerCursorInput {
    pub service_id: String,
    pub lane: AnchorLaneKind,
    pub chain_id: Option<String>,
    pub indexed_checkpoint_seq: u64,
    pub canonical_checkpoint_seq: u64,
    pub indexed_block_number: Option<u64>,
    pub replaying: bool,
    pub failed: bool,
    pub checked_at: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorLaneRuntimeStatus {
    pub lane: AnchorLaneKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    pub status: AnchorLaneHealthStatus,
    pub latest_checkpoint_seq: u64,
    pub indexed_checkpoint_seq: u64,
    pub reorg_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl AnchorLaneRuntimeStatus {
    #[must_use]
    pub fn from_indexer(
        indexer: &AnchorIndexerCursor,
        input: AnchorLaneRuntimeStatusInput,
    ) -> Self {
        let status = classify_anchor_lane(
            input.lane,
            indexer.status,
            input.controls,
            input.reorg_depth,
        );
        Self {
            lane: input.lane,
            chain_id: input.chain_id,
            status,
            latest_checkpoint_seq: input.latest_checkpoint_seq,
            indexed_checkpoint_seq: indexer.indexed_checkpoint_seq,
            reorg_depth: input.reorg_depth,
            last_published_at: input.last_published_at,
            next_action: input.next_action,
            note: input.note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorLaneRuntimeStatusInput {
    pub lane: AnchorLaneKind,
    pub chain_id: Option<String>,
    pub latest_checkpoint_seq: u64,
    pub controls: AnchorEmergencyControls,
    pub reorg_depth: u32,
    pub last_published_at: Option<u64>,
    pub next_action: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorIncidentAlert {
    pub code: String,
    pub severity: AnchorAlertSeverity,
    pub lane: AnchorLaneKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,
    pub observed_at: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorRuntimeReport {
    pub schema: String,
    pub generated_at: u64,
    pub controls: AnchorEmergencyControls,
    pub lanes: Vec<AnchorLaneRuntimeStatus>,
    pub indexers: Vec<AnchorIndexerCursor>,
    pub incidents: Vec<AnchorIncidentAlert>,
}

impl AnchorRuntimeReport {
    #[must_use]
    pub fn new(generated_at: u64, controls: AnchorEmergencyControls) -> Self {
        Self {
            schema: CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA.to_string(),
            generated_at,
            controls,
            lanes: Vec::new(),
            indexers: Vec::new(),
            incidents: Vec::new(),
        }
    }

    #[must_use]
    pub fn lane_incidents<'a>(
        &'a self,
        lane: AnchorLaneKind,
        chain_id: Option<&str>,
    ) -> Vec<&'a AnchorIncidentAlert> {
        self.incidents
            .iter()
            .filter(|incident| {
                incident.lane == lane
                    && match (chain_id, incident.chain_id.as_deref()) {
                        (Some(expected), Some(actual)) => expected == actual,
                        (Some(_), None) => true,
                        (None, _) => true,
                    }
            })
            .collect()
    }

    #[must_use]
    pub fn lane_has_active_conflict(&self, lane: AnchorLaneKind, chain_id: Option<&str>) -> bool {
        self.lane_incidents(lane, chain_id)
            .into_iter()
            .any(anchor_incident_is_conflict)
    }
}

#[must_use]
pub fn anchor_incident_is_conflict(incident: &AnchorIncidentAlert) -> bool {
    if incident.severity != AnchorAlertSeverity::Critical {
        return false;
    }
    let code = incident.code.to_ascii_lowercase();
    code.contains("equivocation")
        || code.contains("conflict")
        || code.contains("fork")
        || code.contains("divergence")
        || code.contains("reorg")
}

#[must_use]
pub fn classify_anchor_lane(
    lane: AnchorLaneKind,
    indexer_status: AnchorIndexerStatus,
    controls: AnchorEmergencyControls,
    reorg_depth: u32,
) -> AnchorLaneHealthStatus {
    if indexer_status == AnchorIndexerStatus::Failed {
        return AnchorLaneHealthStatus::Failed;
    }
    match controls.mode {
        AnchorEmergencyMode::Halted => return AnchorLaneHealthStatus::Paused,
        AnchorEmergencyMode::PublishPaused if lane == AnchorLaneKind::EvmPrimary => {
            return AnchorLaneHealthStatus::Paused;
        }
        AnchorEmergencyMode::ProofImportOnly if lane == AnchorLaneKind::EvmPrimary => {
            return AnchorLaneHealthStatus::Paused;
        }
        AnchorEmergencyMode::RecoveryOnly => {
            return AnchorLaneHealthStatus::Recovering;
        }
        AnchorEmergencyMode::Normal
        | AnchorEmergencyMode::PublishPaused
        | AnchorEmergencyMode::ProofImportOnly => {}
    }
    if reorg_depth > 0 || indexer_status == AnchorIndexerStatus::Replaying {
        AnchorLaneHealthStatus::Recovering
    } else {
        match indexer_status {
            AnchorIndexerStatus::Healthy => AnchorLaneHealthStatus::Healthy,
            AnchorIndexerStatus::Lagging => AnchorLaneHealthStatus::Lagging,
            AnchorIndexerStatus::Drifted => AnchorLaneHealthStatus::Drifted,
            AnchorIndexerStatus::Replaying => AnchorLaneHealthStatus::Recovering,
            AnchorIndexerStatus::Failed => AnchorLaneHealthStatus::Failed,
        }
    }
}

pub fn ensure_anchor_operation_allowed(
    controls: AnchorEmergencyControls,
    operation: AnchorOperationKind,
) -> Result<(), AnchorError> {
    if controls.allows(operation) {
        return Ok(());
    }
    let diagnostic = match operation {
        AnchorOperationKind::PublishRoot => {
            "anchor operation PublishRoot denied while emergency mode is active"
        }
        AnchorOperationKind::ConfirmPublication => {
            "anchor operation ConfirmPublication denied while emergency mode is active"
        }
        AnchorOperationKind::ImportSecondaryProof => {
            "anchor operation ImportSecondaryProof denied while emergency mode is active"
        }
    };
    Err(AnchorError::InvalidInput(String::from(diagnostic)))
}

#[cfg(test)]
mod tests {
    use super::{
        anchor_incident_is_conflict, classify_anchor_lane, ensure_anchor_operation_allowed,
        AnchorAlertSeverity, AnchorControlState, AnchorEmergencyControls, AnchorEmergencyMode,
        AnchorError, AnchorIncidentAlert, AnchorIndexerCursor, AnchorIndexerCursorInput,
        AnchorIndexerStatus, AnchorLaneHealthStatus, AnchorOperationKind, AnchorRuntimeReport,
        CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA,
    };
    use crate::bundle::AnchorLaneKind;

    use chio_test_support::prelude::*;

    #[test]
    fn indexer_cursor_classifies_drift() {
        let cursor = AnchorIndexerCursor::from_sequences(AnchorIndexerCursorInput {
            service_id: "root-registry-indexer".to_string(),
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            indexed_checkpoint_seq: 40,
            canonical_checkpoint_seq: 45,
            indexed_block_number: Some(23_456_789),
            replaying: false,
            failed: false,
            checked_at: 1_712_337_200,
            note: Some("five checkpoints behind canonical registry".to_string()),
        });
        assert_eq!(cursor.lag_checkpoints, 5);
        assert_eq!(cursor.status, AnchorIndexerStatus::Drifted);
    }

    #[test]
    fn publish_root_is_denied_when_publication_is_paused() {
        let controls = AnchorEmergencyControls {
            mode: AnchorEmergencyMode::PublishPaused,
            changed_at: 1_712_337_200,
            reason: Some("root registry divergence under investigation".to_string()),
        };
        let error = ensure_anchor_operation_allowed(controls, AnchorOperationKind::PublishRoot)
            .test_expect_err("publish should be denied");
        assert!(error
            .to_string()
            .contains("anchor operation PublishRoot denied"));
    }

    #[test]
    fn denied_operations_use_bounded_static_diagnostics() {
        let cases = [
            (
                AnchorOperationKind::PublishRoot,
                "anchor operation PublishRoot denied while emergency mode is active",
            ),
            (
                AnchorOperationKind::ConfirmPublication,
                "anchor operation ConfirmPublication denied while emergency mode is active",
            ),
            (
                AnchorOperationKind::ImportSecondaryProof,
                "anchor operation ImportSecondaryProof denied while emergency mode is active",
            ),
        ];

        for (operation, expected) in cases {
            let controls = AnchorEmergencyControls {
                mode: AnchorEmergencyMode::Halted,
                changed_at: 1_712_337_200,
                reason: None,
            };
            let error = ensure_anchor_operation_allowed(controls, operation)
                .test_expect_err("halted mode should deny every operation");
            let AnchorError::InvalidInput(diagnostic) = error else {
                panic!("denied anchor operation returned the wrong error variant");
            };
            assert_eq!(diagnostic, expected);
        }
    }

    #[test]
    fn recovery_mode_marks_lane_as_recovering() {
        let controls = AnchorEmergencyControls {
            mode: AnchorEmergencyMode::RecoveryOnly,
            changed_at: 1_712_337_200,
            reason: Some("canonical chain replay in progress".to_string()),
        };
        let status = classify_anchor_lane(
            AnchorLaneKind::EvmPrimary,
            AnchorIndexerStatus::Healthy,
            controls,
            0,
        );
        assert_eq!(status, AnchorLaneHealthStatus::Recovering);
    }

    #[test]
    fn runtime_report_example_round_trips() {
        let report: AnchorRuntimeReport = serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json"
        ))
        .test_expect("example report");
        assert_eq!(report.schema, CHIO_ANCHOR_RUNTIME_REPORT_SCHEMA);
        assert_eq!(report.controls.mode, AnchorEmergencyMode::RecoveryOnly);
        assert_eq!(report.lanes.len(), 3);
        assert!(report
            .incidents
            .iter()
            .any(|incident| incident.code == "root_registry_reorg"));
    }

    #[test]
    fn control_state_tracks_mode_history() {
        let mut state = AnchorControlState::new(
            1_764_825_600,
            AnchorEmergencyControls::normal(1_764_825_600),
        );
        state.apply_change(
            AnchorEmergencyMode::PublishPaused,
            1_764_825_620,
            "anchor-operator",
            Some("pause new publication".to_string()),
            "unit_test",
        );
        state.apply_change(
            AnchorEmergencyMode::RecoveryOnly,
            1_764_825_640,
            "anchor-operator",
            Some("replay canonical head".to_string()),
            "unit_test",
        );
        assert_eq!(state.controls.mode, AnchorEmergencyMode::RecoveryOnly);
        assert_eq!(state.history.len(), 2);
        assert_eq!(state.history[0].before.mode, AnchorEmergencyMode::Normal);
        assert_eq!(
            state.history[1].after.reason.as_deref(),
            Some("replay canonical head")
        );
    }

    #[test]
    fn runtime_report_detects_lane_conflict_incident() {
        let mut report =
            AnchorRuntimeReport::new(1_712_337_200, AnchorEmergencyControls::normal(1));
        report.incidents.push(AnchorIncidentAlert {
            code: "checkpoint_equivocation_detected".to_string(),
            severity: AnchorAlertSeverity::Critical,
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            checkpoint_seq: Some(42),
            observed_at: 1_712_337_199,
            message: "conflicting checkpoint publication observed".to_string(),
        });

        assert!(report.lane_has_active_conflict(AnchorLaneKind::EvmPrimary, Some("eip155:8453")));
        assert!(!report.lane_has_active_conflict(AnchorLaneKind::EvmPrimary, Some("eip155:42161")));
    }

    #[test]
    fn non_critical_incident_is_not_treated_as_conflict() {
        let incident = AnchorIncidentAlert {
            code: "checkpoint_reorg_detected".to_string(),
            severity: AnchorAlertSeverity::Warning,
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            checkpoint_seq: Some(42),
            observed_at: 1_712_337_199,
            message: "reorg observed".to_string(),
        };

        assert!(!anchor_incident_is_conflict(&incident));
    }
}
