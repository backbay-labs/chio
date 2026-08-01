//! Closed terminal outcome/evaluation projection evidence.

use super::*;
use crate::admission_operation::VerifiedAdmissionReceipt;
use crate::Keypair;
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use chio_core::economic_continuity::{EconomicContentV1, EconomicTerminalResultV1};
use chio_settle::channel::{
    verify_channel_terminal_outcome_commitment, ChannelTerminalOutcomeCommitmentBodyV1,
    SignedChannelTerminalOutcomeCommitmentV1, VerifiedAdmittedChannelReservationV1,
    CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolOutcomeTerminalEvidenceV1 {
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    operation_version: u64,
    dispatch_commit: AdmissionDispatchCommitBindingV1,
    outcome_recording_fence: StoreMutationFence,
    outcome_recorded_at_unix_ms: u64,
    projection_coordinator_lease_id: AdmissionIdentifier,
    projection_coordinator_lease_epoch: u64,
    projection_store_fence: StoreMutationFence,
    trusted_time_unix_ms: u64,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
    outcome_lifecycle_digest: AdmissionDigest,
    tool_server: AdmissionIdentifier,
    tool_name: AdmissionIdentifier,
    evaluation_id: AdmissionDigest,
    evaluation_lifecycle_digest: AdmissionDigest,
    raw_output_digest: AdmissionDigest,
    resolved_output_digest: AdmissionDigest,
    terminal_dependency_root_digest: AdmissionDigest,
    post_guard_decision_digest: AdmissionDigest,
    pricing_verdict_digest: AdmissionDigest,
    settlement_disposition: SettlementDispositionV1,
}

impl ToolOutcomeTerminalEvidenceV1 {
    #[cfg(feature = "admission-test-support")]
    pub fn from_records_for_test(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        Self::from_records(operation, context, outcome, evaluation)
    }

    pub(crate) fn from_records(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        validate_projection_context(operation, context)?;
        outcome.validate_against(operation)?;
        evaluation.validate_against(operation, outcome)?;
        let ResolvedToolOutcomeV1::Resolved {
            evaluation_id,
            resolved_output,
            terminal_dependency_root_digest,
            post_guard_decision_digest,
            pricing_verdict_digest,
            settlement_disposition,
            ..
        } = &outcome.disposition
        else {
            return Err(ToolOutcomeError::Invalid("terminal_projection.outcome"));
        };
        let PostReturnEvaluationStateV1::Resolved { resolution } = &evaluation.state else {
            return Err(ToolOutcomeError::Invalid("terminal_projection.evaluation"));
        };
        if outcome.operation_id != evaluation.operation_id
            || outcome.outcome_id != evaluation.tool_outcome_id
            || evaluation.tool_outcome_version.checked_add(1) != Some(outcome.version)
            || outcome.raw_output.digest() != &evaluation.raw_output_digest
            || evaluation_id != &evaluation.evaluation_id
            || resolved_output != &resolution.resolved_output
            || terminal_dependency_root_digest != &resolution.terminal_dependency_root_digest
            || post_guard_decision_digest != &resolution.post_guard_decision_digest
            || pricing_verdict_digest != &resolution.pricing_verdict_digest
            || settlement_disposition != &resolution.settlement_disposition
        {
            return Err(ToolOutcomeError::Binding("terminal_projection.records"));
        }
        let evidence = Self {
            operation_id: outcome.operation_id.clone(),
            request_id: outcome.request_id.clone(),
            operation_version: operation.version(),
            dispatch_commit: outcome.dispatch_commit.clone(),
            outcome_recording_fence: outcome.recording_fence.clone(),
            outcome_recorded_at_unix_ms: outcome.recorded_at_unix_ms,
            projection_coordinator_lease_id: context.coordinator_lease_id.clone(),
            projection_coordinator_lease_epoch: context.coordinator_lease_epoch,
            projection_store_fence: context.store_fence.clone(),
            trusted_time_unix_ms: context.trusted_time_unix_ms,
            outcome_id: outcome.outcome_id.clone(),
            outcome_version: outcome.version,
            outcome_lifecycle_digest: outcome.lifecycle_digest.clone(),
            tool_server: outcome.tool_server.clone(),
            tool_name: outcome.tool_name.clone(),
            evaluation_id: evaluation.evaluation_id.clone(),
            evaluation_lifecycle_digest: evaluation.lifecycle_digest.clone(),
            raw_output_digest: outcome.raw_output.digest().clone(),
            resolved_output_digest: resolved_output.digest().clone(),
            terminal_dependency_root_digest: terminal_dependency_root_digest.clone(),
            post_guard_decision_digest: post_guard_decision_digest.clone(),
            pricing_verdict_digest: pricing_verdict_digest.clone(),
            settlement_disposition: settlement_disposition.clone(),
        };
        evidence.validate_against(operation, context)?;
        Ok(evidence)
    }

    pub(crate) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), ToolOutcomeError> {
        validate_projection_context(operation, context)?;
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding(
                "terminal_projection.dispatch_commit",
            ))?;
        validate_retained_dispatch_commit(operation, commit)?;
        validate_successor_fence(
            &self.dispatch_commit.store_fence,
            &self.outcome_recording_fence,
        )?;
        validate_successor_fence(&self.outcome_recording_fence, &self.projection_store_fence)?;
        validate_successor_fence(&self.projection_store_fence, &context.store_fence)?;
        positive(
            "terminal_projection.outcome_recorded_at",
            self.outcome_recorded_at_unix_ms,
        )?;
        positive(
            "terminal_projection.trusted_time",
            self.trusted_time_unix_ms,
        )?;
        if self.operation_id != *operation.binding().operation_id()
            || self.request_id != operation.replay_key().request_id
            || self.request_id != context.request_id
            || self.operation_version != operation.version()
            || self.operation_version != context.expected_operation_version
            || self.dispatch_commit != *commit
            || self.dispatch_commit.committed_version == 0
            || self.projection_coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.trusted_time_unix_ms > context.trusted_time_unix_ms
            || (self.projection_store_fence == context.store_fence
                && self.projection_coordinator_lease_id != context.coordinator_lease_id)
            || self.outcome_version == 0
        {
            return Err(ToolOutcomeError::Binding(
                "terminal_projection.projection_context",
            ));
        }
        Ok(())
    }

    pub(crate) fn outcome_id(&self) -> &AdmissionDigest {
        &self.outcome_id
    }

    pub(crate) fn outcome_version(&self) -> u64 {
        self.outcome_version
    }

    pub(crate) fn tool_server(&self) -> &AdmissionIdentifier {
        &self.tool_server
    }

    pub(crate) fn tool_name(&self) -> &AdmissionIdentifier {
        &self.tool_name
    }

    pub(crate) fn resolved_output_digest(&self) -> &AdmissionDigest {
        &self.resolved_output_digest
    }

    pub(crate) const fn settlement_disposition(&self) -> &SettlementDispositionV1 {
        &self.settlement_disposition
    }
}

#[cfg(feature = "admission-test-support")]
pub fn sign_channel_terminal_outcome_commitment_for_test(
    operation: &AdmissionOperationV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    receipt: &VerifiedAdmissionReceipt,
    tool_outcome: &ToolOutcomeTerminalEvidenceV1,
    context: &AdmissionProjectionContext,
    kernel_keypair: &Keypair,
) -> Result<SignedChannelTerminalOutcomeCommitmentV1, ToolOutcomeError> {
    sign_channel_terminal_outcome_commitment(
        operation,
        reservation,
        receipt,
        tool_outcome,
        context,
        kernel_keypair,
    )
}

pub(crate) fn sign_channel_terminal_outcome_commitment(
    operation: &AdmissionOperationV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    receipt: &VerifiedAdmissionReceipt,
    tool_outcome: &ToolOutcomeTerminalEvidenceV1,
    context: &AdmissionProjectionContext,
    kernel_keypair: &Keypair,
) -> Result<SignedChannelTerminalOutcomeCommitmentV1, ToolOutcomeError> {
    let mismatch = || ToolOutcomeError::Binding("channel_terminal_outcome_commitment");
    tool_outcome.validate_against(operation, context)?;
    receipt
        .validate_against(
            operation,
            context,
            AdmissionOperationState::Completed,
            crate::admission_operation::AdmissionCompensationStatus::NotCompensated,
            Some((tool_outcome.outcome_id(), tool_outcome.outcome_version())),
        )
        .map_err(|_| mismatch())?;
    if reservation.artifact().body.operation_id != operation.binding().operation_id().as_str() {
        return Err(mismatch());
    }
    let result = EconomicContentV1::Inline {
        value: serde_json::to_value(tool_outcome)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
    };
    let terminal_result = EconomicTerminalResultV1 {
        result_id: tool_outcome.outcome_id.as_str().to_owned(),
        result_digest: result.digest().map_err(|_| mismatch())?,
        result,
    };
    let receipt_digest = sha256_hex(
        &canonical_json_bytes(receipt.receipt())
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
    );
    let body = ChannelTerminalOutcomeCommitmentBodyV1 {
        schema: CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA.to_owned(),
        operation_id: reservation.artifact().body.operation_id.clone(),
        reservation_id: reservation.artifact().body.reservation_id.clone(),
        reservation_digest: reservation.artifact().digest().map_err(|_| mismatch())?,
        receipt_id: receipt.receipt().id.clone(),
        receipt_digest,
        terminal_result,
        outcome_recorded_at_unix_ms: tool_outcome.outcome_recorded_at_unix_ms,
        terminalized_at_unix_ms: context.trusted_time_unix_ms,
    };
    let kernel_signature = kernel_keypair.sign(&body.signing_bytes().map_err(|_| mismatch())?);
    let signed = SignedChannelTerminalOutcomeCommitmentV1 {
        body,
        kernel_key: kernel_keypair.public_key(),
        kernel_signature,
    };
    verify_channel_terminal_outcome_commitment(
        &signed,
        &kernel_keypair.public_key(),
        reservation,
        receipt.receipt(),
    )
    .map_err(|_| mismatch())?;
    Ok(signed)
}

pub(crate) trait QualifiedDurableOutcomeAuthority: Send + Sync {
    fn verify_terminal_outcome(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<ToolOutcomeTerminalEvidenceV1, ToolOutcomeError>;

    fn verify_contractual_zero_charge(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedContractualZeroCharge, ToolOutcomeError>;
}
