use chio_core::web3::settlement::{
    CHIO_SETTLE_CONTROL_STATE_SCHEMA, CHIO_SETTLE_CONTROL_TRACE_SCHEMA,
};
use serde::{Deserialize, Serialize};

use crate::{
    settlement_completion_flow_receipt_id, SettlementError, SettlementFinalityStatus,
    SettlementRecoveryAction,
};

pub const CHIO_SETTLE_RUNTIME_REPORT_SCHEMA: &str = "chio.settle-runtime-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementIndexerStatus {
    Healthy,
    Lagging,
    Drifted,
    Replaying,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRuntimeStatus {
    Healthy,
    AwaitingFinality,
    Recovering,
    Paused,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEmergencyMode {
    Normal,
    DispatchPaused,
    RefundOnly,
    RecoveryOnly,
    Halted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementOperationKind {
    DispatchEscrow,
    ReleaseEscrow,
    RefundEscrow,
    LockBond,
    ReleaseBond,
    ImpairBond,
    ExpireBond,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementControlChangeRecord {
    pub schema: String,
    pub actor: String,
    pub source: String,
    pub changed_at: u64,
    pub before: SettlementEmergencyControls,
    pub after: SettlementEmergencyControls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementEmergencyControls {
    pub mode: SettlementEmergencyMode,
    pub changed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SettlementEmergencyControls {
    #[must_use]
    pub fn normal(changed_at: u64) -> Self {
        Self {
            mode: SettlementEmergencyMode::Normal,
            changed_at,
            reason: None,
        }
    }

    #[must_use]
    pub fn allows(&self, operation: SettlementOperationKind) -> bool {
        match self.mode {
            SettlementEmergencyMode::Normal => true,
            SettlementEmergencyMode::DispatchPaused => !matches!(
                operation,
                SettlementOperationKind::DispatchEscrow | SettlementOperationKind::LockBond
            ),
            SettlementEmergencyMode::RefundOnly => matches!(
                operation,
                SettlementOperationKind::RefundEscrow
                    | SettlementOperationKind::ImpairBond
                    | SettlementOperationKind::ExpireBond
            ),
            SettlementEmergencyMode::RecoveryOnly => !matches!(
                operation,
                SettlementOperationKind::DispatchEscrow | SettlementOperationKind::LockBond
            ),
            SettlementEmergencyMode::Halted => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementControlState {
    pub schema: String,
    pub updated_at: u64,
    pub controls: SettlementEmergencyControls,
    pub history: Vec<SettlementControlChangeRecord>,
}

impl SettlementControlState {
    #[must_use]
    pub fn new(updated_at: u64, controls: SettlementEmergencyControls) -> Self {
        Self {
            schema: CHIO_SETTLE_CONTROL_STATE_SCHEMA.to_string(),
            updated_at,
            controls,
            history: Vec::new(),
        }
    }

    pub fn apply_change(
        &mut self,
        mode: SettlementEmergencyMode,
        changed_at: u64,
        actor: impl Into<String>,
        reason: Option<String>,
        source: impl Into<String>,
    ) {
        let before = self.controls.clone();
        self.controls = SettlementEmergencyControls {
            mode,
            changed_at,
            reason,
        };
        self.updated_at = changed_at;
        self.history.push(SettlementControlChangeRecord {
            schema: CHIO_SETTLE_CONTROL_TRACE_SCHEMA.to_string(),
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
pub struct SettlementIndexerCursor {
    pub service_id: String,
    pub chain_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_indexed_block_number: Option<u64>,
    pub canonical_block_number: u64,
    pub lag_blocks: u64,
    pub status: SettlementIndexerStatus,
    pub checked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SettlementIndexerCursor {
    #[must_use]
    pub fn from_blocks(input: SettlementIndexerCursorInput) -> Self {
        let lag_blocks = input
            .canonical_block_number
            .saturating_sub(input.last_indexed_block_number.unwrap_or(0));
        let status = if input.failed {
            SettlementIndexerStatus::Failed
        } else if input.replaying {
            SettlementIndexerStatus::Replaying
        } else if lag_blocks == 0 {
            SettlementIndexerStatus::Healthy
        } else if lag_blocks <= 12 {
            SettlementIndexerStatus::Lagging
        } else {
            SettlementIndexerStatus::Drifted
        };
        Self {
            service_id: input.service_id,
            chain_id: input.chain_id,
            last_indexed_block_number: input.last_indexed_block_number,
            canonical_block_number: input.canonical_block_number,
            lag_blocks,
            status,
            checked_at: input.checked_at,
            note: input.note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementIndexerCursorInput {
    pub service_id: String,
    pub chain_id: String,
    pub last_indexed_block_number: Option<u64>,
    pub canonical_block_number: u64,
    pub replaying: bool,
    pub failed: bool,
    pub checked_at: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementRecoveryRecord {
    pub execution_receipt_id: String,
    pub chain_id: String,
    pub tx_hash: String,
    pub finality_status: SettlementFinalityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reorg_depth: Option<u32>,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementLaneRuntimeStatus {
    pub chain_id: String,
    pub network_name: String,
    pub status: SettlementRuntimeStatus,
    pub indexer_status: SettlementIndexerStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finality_status: Option<SettlementFinalityStatus>,
    pub queued_recoveries: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SettlementLaneRuntimeStatus {
    #[must_use]
    pub fn new(input: SettlementLaneRuntimeStatusInput) -> Self {
        let status =
            classify_settlement_lane(input.indexer_status, input.finality_status, input.controls);
        Self {
            chain_id: input.chain_id,
            network_name: input.network_name,
            status,
            indexer_status: input.indexer_status,
            finality_status: input.finality_status,
            queued_recoveries: input.queued_recoveries,
            last_observed_at: input.last_observed_at,
            note: input.note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementLaneRuntimeStatusInput {
    pub chain_id: String,
    pub network_name: String,
    pub indexer_status: SettlementIndexerStatus,
    pub finality_status: Option<SettlementFinalityStatus>,
    pub controls: SettlementEmergencyControls,
    pub queued_recoveries: usize,
    pub last_observed_at: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementIncidentAlert {
    pub code: String,
    pub severity: SettlementAlertSeverity,
    pub chain_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_receipt_id: Option<String>,
    pub observed_at: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementRuntimeReport {
    pub schema: String,
    pub generated_at: u64,
    pub controls: SettlementEmergencyControls,
    pub lanes: Vec<SettlementLaneRuntimeStatus>,
    pub indexers: Vec<SettlementIndexerCursor>,
    pub recoveries: Vec<SettlementRecoveryRecord>,
    pub incidents: Vec<SettlementIncidentAlert>,
}

impl SettlementRuntimeReport {
    #[must_use]
    pub fn new(generated_at: u64, controls: SettlementEmergencyControls) -> Self {
        Self {
            schema: CHIO_SETTLE_RUNTIME_REPORT_SCHEMA.to_string(),
            generated_at,
            controls,
            lanes: Vec::new(),
            indexers: Vec::new(),
            recoveries: Vec::new(),
            incidents: Vec::new(),
        }
    }
}

#[must_use]
pub fn classify_settlement_lane(
    indexer_status: SettlementIndexerStatus,
    finality_status: Option<SettlementFinalityStatus>,
    controls: SettlementEmergencyControls,
) -> SettlementRuntimeStatus {
    if indexer_status == SettlementIndexerStatus::Failed {
        return SettlementRuntimeStatus::Failed;
    }
    match controls.mode {
        SettlementEmergencyMode::Halted
        | SettlementEmergencyMode::DispatchPaused
        | SettlementEmergencyMode::RefundOnly => {
            return SettlementRuntimeStatus::Paused;
        }
        SettlementEmergencyMode::RecoveryOnly => return SettlementRuntimeStatus::Recovering,
        SettlementEmergencyMode::Normal => {}
    }
    if indexer_status == SettlementIndexerStatus::Replaying
        || finality_status == Some(SettlementFinalityStatus::Reorged)
    {
        SettlementRuntimeStatus::Recovering
    } else if matches!(
        finality_status,
        Some(SettlementFinalityStatus::AwaitingConfirmations)
            | Some(SettlementFinalityStatus::AwaitingDisputeWindow)
    ) || matches!(
        indexer_status,
        SettlementIndexerStatus::Lagging | SettlementIndexerStatus::Drifted
    ) {
        SettlementRuntimeStatus::AwaitingFinality
    } else {
        SettlementRuntimeStatus::Healthy
    }
}

pub fn ensure_settlement_operation_allowed(
    controls: SettlementEmergencyControls,
    operation: SettlementOperationKind,
) -> Result<(), SettlementError> {
    if controls.allows(operation) {
        return Ok(());
    }
    Err(SettlementError::InvalidInput(format!(
        "settlement operation {operation:?} denied while emergency mode {:?} is active",
        controls.mode
    )))
}

pub fn ensure_settlement_completion_flow_binding(
    row_id: &str,
    receipt_id: &str,
) -> Result<(), SettlementError> {
    let resolved_receipt_id = settlement_completion_flow_receipt_id(row_id)?;
    if resolved_receipt_id != receipt_id {
        return Err(SettlementError::InvalidBinding(format!(
            "completion-flow row `{row_id}` resolved receipt `{resolved_receipt_id}` but settlement receipt is `{receipt_id}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        classify_settlement_lane, ensure_settlement_completion_flow_binding,
        ensure_settlement_operation_allowed, SettlementControlState, SettlementEmergencyControls,
        SettlementEmergencyMode, SettlementIndexerCursor, SettlementIndexerCursorInput,
        SettlementIndexerStatus, SettlementOperationKind, SettlementRuntimeReport,
        SettlementRuntimeStatus, CHIO_SETTLE_RUNTIME_REPORT_SCHEMA,
    };
    use crate::{
        settlement_completion_flow_row_id, SettlementFinalityStatus,
        SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn indexer_cursor_classifies_lagging() {
        let cursor = SettlementIndexerCursor::from_blocks(SettlementIndexerCursorInput {
            service_id: "escrow-event-indexer".to_string(),
            chain_id: "eip155:8453".to_string(),
            last_indexed_block_number: Some(23_456_789),
            canonical_block_number: 23_456_797,
            replaying: false,
            failed: false,
            checked_at: 1_712_337_200,
            note: Some("eight blocks behind canonical head".to_string()),
        });
        assert_eq!(cursor.lag_blocks, 8);
        assert_eq!(cursor.status, SettlementIndexerStatus::Lagging);
    }

    #[test]
    fn refund_only_mode_denies_new_dispatch() {
        let controls = SettlementEmergencyControls {
            mode: SettlementEmergencyMode::RefundOnly,
            changed_at: 1_712_337_200,
            reason: Some("beneficiary release halted pending replay review".to_string()),
        };
        let error =
            ensure_settlement_operation_allowed(controls, SettlementOperationKind::DispatchEscrow)
                .test_expect_err("dispatch should be denied");
        assert!(error
            .to_string()
            .contains("settlement operation DispatchEscrow denied"));
    }

    #[test]
    fn reorged_lane_is_marked_recovering() {
        let controls = SettlementEmergencyControls::normal(1_712_337_200);
        let status = classify_settlement_lane(
            SettlementIndexerStatus::Healthy,
            Some(SettlementFinalityStatus::Reorged),
            controls,
        );
        assert_eq!(status, SettlementRuntimeStatus::Recovering);
    }

    #[test]
    fn runtime_report_example_round_trips() {
        let report: SettlementRuntimeReport = serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json"
        ))
        .test_expect("example report");
        assert_eq!(report.schema, CHIO_SETTLE_RUNTIME_REPORT_SCHEMA);
        assert_eq!(report.controls.mode, SettlementEmergencyMode::RefundOnly);
        assert_eq!(report.recoveries.len(), 1);
        assert!(report
            .incidents
            .iter()
            .any(|incident| incident.code == "settlement_reorg"));
    }

    #[test]
    fn control_state_tracks_mode_history() {
        let mut state = SettlementControlState::new(
            1_764_825_600,
            SettlementEmergencyControls::normal(1_764_825_600),
        );
        state.apply_change(
            SettlementEmergencyMode::DispatchPaused,
            1_764_825_620,
            "settlement-operator",
            Some("pause new dispatch".to_string()),
            "unit_test",
        );
        state.apply_change(
            SettlementEmergencyMode::RefundOnly,
            1_764_825_640,
            "settlement-operator",
            Some("refund-first recovery".to_string()),
            "unit_test",
        );
        assert_eq!(state.controls.mode, SettlementEmergencyMode::RefundOnly);
        assert_eq!(state.history.len(), 2);
        assert_eq!(
            state.history[1].after.reason.as_deref(),
            Some("refund-first recovery")
        );
    }

    #[test]
    fn completion_flow_binding_round_trips() {
        let row_id = settlement_completion_flow_row_id("rcpt-1").test_expect("row id");
        assert_eq!(
            row_id,
            format!("{SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX}{}", "rcpt-1")
        );
        ensure_settlement_completion_flow_binding(&row_id, "rcpt-1")
            .test_expect("matching binding");
    }

    #[test]
    fn completion_flow_binding_rejects_mismatch() {
        let error =
            ensure_settlement_completion_flow_binding("economic-completion-flow:rcpt-1", "rcpt-2")
                .test_expect_err("binding mismatch should fail");
        assert!(error.to_string().contains("resolved receipt"));
    }
}

/// Reference production settlement hook.
///
/// Validates an observation's shape and accepts it with a deterministic
/// transcript id, so a deployment can wire the observer slot and the
/// settlement driver end to end and watch `chio settle status` report over
/// tables production code writes. Rail-specific deployments replace this
/// with their own [`crate::SettlementHook`]; the seam is the contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpsSettlementHook;

impl OpsSettlementHook {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl crate::SettlementHook for OpsSettlementHook {
    fn observe(
        &self,
        observation: &crate::SettlementObservation,
    ) -> Result<crate::SettlementOutcome, crate::SettlementHookError> {
        if observation.receipt_id.trim().is_empty() {
            return Ok(crate::SettlementOutcome::permanent(
                "observation is missing a receipt id",
            ));
        }
        if observation.amount.units == 0 {
            // The kernel skips zero-priced receipts before the hook; a zero
            // amount reaching this point is outside the marketplace surface.
            return Ok(crate::SettlementOutcome::skipped("zero-priced observation"));
        }
        Ok(crate::SettlementOutcome::accepted(format!(
            "ops:{}",
            observation.receipt_id
        )))
    }
}

/// One terminal step of the settlement driver for a due attempt: the hook is
/// re-invoked and its outcome classified against the retry policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementDriveStep {
    /// The hook accepted the observation: persist the settled record and
    /// clear the bounded attempt envelope.
    Settle {
        /// Transcript id correlating the settled record with the hook run.
        transcript_id: String,
    },
    /// Recoverable failure: re-arm the attempt with the classified backoff.
    Retry {
        /// Attempt count after this failure.
        attempts: u32,
        /// Backoff before the attempt becomes visible again.
        backoff: std::time::Duration,
        /// Failure reason for the attempt row.
        reason: String,
    },
    /// Terminal failure: land a dead-letter row and clear the attempt.
    DeadLetter {
        /// Reason recorded on the dead-letter row.
        reason: String,
    },
    /// Nothing owed (skipped outcome): clear the attempt.
    Skip {
        /// Reason for operator visibility.
        reason: String,
    },
}

/// Settlement driver engine: re-invokes a hook for a due attempt and folds
/// the outcome through the retry policy into one terminal step. Pure over
/// its inputs; the host (CLI drive, embedder runtime) owns the stores and
/// applies the step.
pub struct SettlementRuntime<H> {
    hook: H,
    policy: crate::RetryPolicy,
}

impl<H: crate::SettlementHook> SettlementRuntime<H> {
    #[must_use]
    pub fn new(hook: H, policy: crate::RetryPolicy) -> Self {
        Self { hook, policy }
    }

    /// Drive one due attempt: re-invoke the hook and classify. A hook error
    /// is folded into a retryable outcome so the bounded envelope (not the
    /// error path) decides when it dead-letters.
    #[must_use]
    pub fn drive(
        &self,
        observation: &crate::SettlementObservation,
        prior_attempts: u32,
    ) -> SettlementDriveStep {
        let outcome = match self.hook.observe(observation) {
            Ok(outcome) => outcome,
            Err(error) => crate::SettlementOutcome::retryable(error.to_string()),
        };
        if let crate::SettlementOutcome::Accepted { transcript_id, .. } = &outcome {
            return SettlementDriveStep::Settle {
                transcript_id: transcript_id.clone(),
            };
        }
        match crate::classify_attempt(&self.policy, prior_attempts, &outcome) {
            crate::RetryDecision::Retry { attempt, backoff } => SettlementDriveStep::Retry {
                attempts: attempt,
                backoff,
                reason: match &outcome {
                    crate::SettlementOutcome::Retryable { reason, .. } => reason.clone(),
                    other => format!("{other:?}"),
                },
            },
            crate::RetryDecision::DeadLetter { reason } => {
                SettlementDriveStep::DeadLetter { reason }
            }
            crate::RetryDecision::Skip { reason } => SettlementDriveStep::Skip { reason },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod driver_tests {
    use super::*;
    use crate::{RetryPolicy, SettlementHook, SettlementObservation};
    use chio_core::capability::scope::MonetaryAmount;

    fn observation(receipt_id: &str, units: u64) -> SettlementObservation {
        SettlementObservation::new(
            receipt_id,
            100,
            "srv",
            "tool",
            "cap",
            MonetaryAmount {
                units,
                currency: "USD".to_string(),
            },
            "content-hash",
            "policy-hash",
        )
    }

    #[test]
    fn ops_hook_accepts_a_priced_observation() {
        let outcome = OpsSettlementHook::new()
            .observe(&observation("rcpt-ops", 250))
            .expect("observe");
        match outcome {
            crate::SettlementOutcome::Accepted { transcript_id, .. } => {
                assert_eq!(transcript_id, "ops:rcpt-ops");
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn runtime_folds_outcomes_into_terminal_steps() {
        struct FlakyHook;
        impl SettlementHook for FlakyHook {
            fn observe(
                &self,
                observation: &SettlementObservation,
            ) -> Result<crate::SettlementOutcome, crate::SettlementHookError> {
                Ok(crate::SettlementOutcome::retryable(format!(
                    "rail unavailable for {}",
                    observation.receipt_id
                )))
            }
        }

        let accepting = SettlementRuntime::new(OpsSettlementHook::new(), RetryPolicy::default());
        assert!(matches!(
            accepting.drive(&observation("rcpt-1", 100), 0),
            SettlementDriveStep::Settle { .. }
        ));

        let policy = RetryPolicy::default();
        let max_retries = policy.max_retries;
        let flaky = SettlementRuntime::new(FlakyHook, policy);
        assert!(matches!(
            flaky.drive(&observation("rcpt-2", 100), 0),
            SettlementDriveStep::Retry { attempts: 1, .. }
        ));
        // The bounded envelope, not the error path, decides the terminal
        // dead-letter.
        assert!(matches!(
            flaky.drive(&observation("rcpt-2", 100), max_retries),
            SettlementDriveStep::DeadLetter { .. }
        ));
    }
}
