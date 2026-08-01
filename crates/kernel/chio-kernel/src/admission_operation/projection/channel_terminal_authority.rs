use super::*;
use crate::tool_outcome::sign_channel_terminal_outcome_commitment;
use crate::Keypair;
use chio_settle::channel::{
    SignedChannelTerminalOutcomeCommitmentV1, VerifiedAdmittedChannelReservationV1,
};

#[derive(Debug, thiserror::Error)]
pub enum ChannelTerminalAuthorityError {
    #[error("channel terminal authority is unavailable: {0}")]
    Unavailable(String),
    #[error("channel terminal reservation was not found")]
    NotFound,
    #[error("channel terminal authority was fenced")]
    Fenced,
    #[error("channel terminal authority conflict: {0}")]
    Conflict(String),
    #[error("channel terminal authority outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("channel terminal authority returned mismatched evidence")]
    BindingMismatch,
}

pub struct ChannelTerminalAdvanceRequest<'a> {
    operation: &'a AdmissionOperationV1,
    context: &'a AdmissionProjectionContext,
    reservation: &'a VerifiedAdmittedChannelReservationV1,
    receipt: &'a VerifiedAdmissionReceipt,
    terminal_outcome: &'a SignedChannelTerminalOutcomeCommitmentV1,
}

impl<'a> ChannelTerminalAdvanceRequest<'a> {
    #[must_use]
    pub const fn operation(&self) -> &'a AdmissionOperationV1 {
        self.operation
    }

    #[must_use]
    pub const fn context(&self) -> &'a AdmissionProjectionContext {
        self.context
    }

    #[must_use]
    pub const fn reservation(&self) -> &'a VerifiedAdmittedChannelReservationV1 {
        self.reservation
    }

    #[must_use]
    pub const fn receipt(&self) -> &'a VerifiedAdmissionReceipt {
        self.receipt
    }

    #[must_use]
    pub const fn terminal_outcome(&self) -> &'a SignedChannelTerminalOutcomeCommitmentV1 {
        self.terminal_outcome
    }
}

#[derive(Debug, Clone)]
pub struct PreparedChannelTerminalProjectionV1 {
    reservation: VerifiedAdmittedChannelReservationV1,
    terminal_outcome: SignedChannelTerminalOutcomeCommitmentV1,
    advance: VerifiedChannelTerminalAdvanceV1,
    channel: VerifiedChannelTerminalProjectionV1,
    obligation: Option<ObligationProjection>,
}

impl PreparedChannelTerminalProjectionV1 {
    #[must_use]
    pub const fn reservation(&self) -> &VerifiedAdmittedChannelReservationV1 {
        &self.reservation
    }

    #[must_use]
    pub const fn terminal_outcome(&self) -> &SignedChannelTerminalOutcomeCommitmentV1 {
        &self.terminal_outcome
    }

    #[must_use]
    pub const fn advance(&self) -> &VerifiedChannelTerminalAdvanceV1 {
        &self.advance
    }

    #[must_use]
    pub const fn channel(&self) -> &VerifiedChannelTerminalProjectionV1 {
        &self.channel
    }

    #[must_use]
    pub const fn obligation(&self) -> Option<&ObligationProjection> {
        self.obligation.as_ref()
    }
}

pub struct ChannelTerminalCommitRequest<'a> {
    prepared: &'a PreparedChannelTerminalProjectionV1,
    recovery_lease: &'a AdmissionRecoveryLease,
    envelope: &'a SignedAdmissionTerminalProjectionV1,
    active_fence: &'a StoreMutationFence,
    trusted_now_unix_ms: u64,
}

impl<'a> ChannelTerminalCommitRequest<'a> {
    #[must_use]
    pub const fn prepared(&self) -> &'a PreparedChannelTerminalProjectionV1 {
        self.prepared
    }

    #[must_use]
    pub const fn recovery_lease(&self) -> &'a AdmissionRecoveryLease {
        self.recovery_lease
    }

    #[must_use]
    pub const fn envelope(&self) -> &'a SignedAdmissionTerminalProjectionV1 {
        self.envelope
    }

    #[must_use]
    pub const fn active_fence(&self) -> &'a StoreMutationFence {
        self.active_fence
    }

    #[must_use]
    pub const fn trusted_now_unix_ms(&self) -> u64 {
        self.trusted_now_unix_ms
    }
}

pub trait QualifiedChannelTerminalAuthority: Send + Sync {
    fn load_admitted_reservation(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedAdmittedChannelReservationV1, ChannelTerminalAuthorityError>;

    fn prepare_terminal_advance(
        &self,
        request: ChannelTerminalAdvanceRequest<'_>,
    ) -> Result<VerifiedChannelTerminalAdvanceV1, ChannelTerminalAuthorityError>;

    fn commit_anchored_terminal_projection(
        &self,
        request: ChannelTerminalCommitRequest<'_>,
    ) -> Result<AdmissionTerminal, ChannelTerminalAuthorityError>;
}

fn same_admitted_reservation(
    expected: &VerifiedAdmittedChannelReservationV1,
    actual: &VerifiedAdmittedChannelReservationV1,
) -> bool {
    let expected_snapshot = expected.snapshot();
    let actual_snapshot = actual.snapshot();
    expected.proposal() == actual.proposal()
        && expected_snapshot.lifecycle() == actual_snapshot.lifecycle()
        && expected_snapshot.escrow() == actual_snapshot.escrow()
        && expected_snapshot.settlement_authority_scope_id()
            == actual_snapshot.settlement_authority_scope_id()
        && expected_snapshot.checkpoint_sequence() == actual_snapshot.checkpoint_sequence()
        && expected_snapshot.checkpoint_digest() == actual_snapshot.checkpoint_digest()
        && expected_snapshot.channel_head_digest() == actual_snapshot.channel_head_digest()
        && expected_snapshot.escrow_head_digest() == actual_snapshot.escrow_head_digest()
        && expected_snapshot.channel_predecessor_digest()
            == actual_snapshot.channel_predecessor_digest()
        && expected_snapshot.escrow_predecessor_digest()
            == actual_snapshot.escrow_predecessor_digest()
        && expected_snapshot.observed_at_unix_ms() == actual_snapshot.observed_at_unix_ms()
        && expected.ready_effect() == actual.ready_effect()
        && expected.ready_effect_head_digest() == actual.ready_effect_head_digest()
}

pub(crate) fn prepare_channel_terminal_projection(
    authority: Option<&dyn QualifiedChannelTerminalAuthority>,
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    receipt: &VerifiedAdmissionReceipt,
    tool_outcome: &ToolOutcomeTerminalEvidenceV1,
    kernel_keypair: &Keypair,
) -> Result<PreparedChannelTerminalProjectionV1, ChannelTerminalAuthorityError> {
    if !operation.binding().participant_requirements().channel {
        return Err(ChannelTerminalAuthorityError::BindingMismatch);
    }
    let authority = authority.ok_or_else(|| {
        ChannelTerminalAuthorityError::Unavailable(
            "no qualified channel terminal authority is configured".to_owned(),
        )
    })?;
    let reservation = authority.load_admitted_reservation(operation, context)?;
    let terminal_outcome = sign_channel_terminal_outcome_commitment(
        operation,
        &reservation,
        receipt,
        tool_outcome,
        context,
        kernel_keypair,
    )
    .map_err(|_| ChannelTerminalAuthorityError::BindingMismatch)?;
    let advance = authority.prepare_terminal_advance(ChannelTerminalAdvanceRequest {
        operation,
        context,
        reservation: &reservation,
        receipt,
        terminal_outcome: &terminal_outcome,
    })?;
    let result = &terminal_outcome.body.terminal_result;
    if !same_admitted_reservation(&reservation, advance.reservation())
        || advance.effect_result_id() != result.result_id
        || advance.effect_result_digest() != result.result_digest
        || advance.effect_result() != &result.result
    {
        return Err(ChannelTerminalAuthorityError::BindingMismatch);
    }
    let (channel, obligation) = VerifiedChannelTerminalProjectionV1::from_verified(
        operation,
        context,
        receipt,
        tool_outcome,
        &advance,
    )
    .map_err(|_| ChannelTerminalAuthorityError::BindingMismatch)?;
    Ok(PreparedChannelTerminalProjectionV1 {
        reservation,
        terminal_outcome,
        advance,
        channel,
        obligation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_prepared_channel_terminal_projection(
    authority: &dyn QualifiedChannelTerminalAuthority,
    operation: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    projection: &AdmissionTerminalProjection,
    capabilities: &AdmissionProjectionCapabilities,
    prepared: &PreparedChannelTerminalProjectionV1,
    kernel_keypair: &Keypair,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionTerminal, ChannelTerminalAuthorityError> {
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        operation,
        projection,
        capabilities,
        kernel_keypair,
    )
    .map_err(|_| ChannelTerminalAuthorityError::BindingMismatch)?;
    let verified = envelope
        .verify()
        .map_err(|_| ChannelTerminalAuthorityError::BindingMismatch)?;
    if verified.channel_terminal() != Some(prepared.channel()) {
        return Err(ChannelTerminalAuthorityError::BindingMismatch);
    }
    let terminal = authority.commit_anchored_terminal_projection(ChannelTerminalCommitRequest {
        prepared,
        recovery_lease,
        envelope: &envelope,
        active_fence,
        trusted_now_unix_ms,
    })?;
    let expected = verified.terminal_operation();
    if terminal.operation_id != *expected.binding().operation_id()
        || terminal.state != expected.state()
        || Some(&terminal.replay) != expected.terminal_replay()
    {
        return Err(ChannelTerminalAuthorityError::BindingMismatch);
    }
    Ok(terminal)
}
