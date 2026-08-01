use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

struct InjectedChannelTerminalAuthority {
    reservation: VerifiedAdmittedChannelReservationV1,
    advance: VerifiedChannelTerminalAdvanceV1,
    signed_outcome: Mutex<Option<SignedChannelTerminalOutcomeCommitmentV1>>,
    commit_count: AtomicUsize,
}

impl InjectedChannelTerminalAuthority {
    fn new(fixture: &ChannelAdvanceFixture) -> Self {
        Self {
            reservation: fixture.reservation.clone(),
            advance: fixture.advance.clone(),
            signed_outcome: Mutex::new(None),
            commit_count: AtomicUsize::new(0),
        }
    }
}

impl QualifiedChannelTerminalAuthority for InjectedChannelTerminalAuthority {
    fn load_admitted_reservation(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedAdmittedChannelReservationV1, ChannelTerminalAuthorityError> {
        if operation.binding().operation_id() != &context.operation_id
            || self.reservation.artifact().body.operation_id
                != operation.binding().operation_id().as_str()
        {
            return Err(ChannelTerminalAuthorityError::BindingMismatch);
        }
        Ok(self.reservation.clone())
    }

    fn prepare_terminal_advance(
        &self,
        request: ChannelTerminalAdvanceRequest<'_>,
    ) -> Result<VerifiedChannelTerminalAdvanceV1, ChannelTerminalAuthorityError> {
        if request.operation().binding().operation_id().as_str()
            != request.reservation().artifact().body.operation_id
            || request.receipt().receipt().id != request.terminal_outcome().body.receipt_id
        {
            return Err(ChannelTerminalAuthorityError::BindingMismatch);
        }
        *self
            .signed_outcome
            .lock()
            .map_err(|_| ChannelTerminalAuthorityError::Unavailable("test lock".to_owned()))? =
            Some(request.terminal_outcome().clone());
        Ok(self.advance.clone())
    }

    fn commit_anchored_terminal_projection(
        &self,
        request: ChannelTerminalCommitRequest<'_>,
    ) -> Result<AdmissionTerminal, ChannelTerminalAuthorityError> {
        if request.active_fence() != request.recovery_lease().store_fence()
            || request.trusted_now_unix_ms() == 0
            || request.prepared().advance().batch_id()
                != request.prepared().channel().batch_id().as_str()
        {
            return Err(ChannelTerminalAuthorityError::BindingMismatch);
        }
        let verified = request
            .envelope()
            .verify()
            .map_err(|_| ChannelTerminalAuthorityError::BindingMismatch)?;
        let operation = verified.terminal_operation();
        let replay = operation
            .terminal_replay()
            .cloned()
            .ok_or(ChannelTerminalAuthorityError::BindingMismatch)?;
        self.commit_count.fetch_add(1, Ordering::SeqCst);
        Ok(AdmissionTerminal {
            operation_id: operation.binding().operation_id().clone(),
            state: operation.state(),
            replay,
        })
    }
}

fn projection_recovery_lease(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> TestResult<AdmissionRecoveryLease> {
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        id("claimant_id", "kernel:channel-test")?,
        context.coordinator_lease_id.clone(),
        context.coordinator_lease_epoch,
        operation.version(),
        context.trusted_time_unix_ms + 1_000,
        context.store_fence.clone(),
    )?;
    Ok(qualify_recovery_claim_for_test(
        operation,
        claim,
        context.trusted_time_unix_ms,
        &context.store_fence,
    )?)
}

#[test]
fn injected_authority_signs_and_commits_the_exact_channel_projection() -> TestResult<()> {
    let fixture = build_fixture(7, "injected-terminal-authority")?;
    let authority = InjectedChannelTerminalAuthority::new(&fixture.base);
    let kernel = Keypair::from_seed(&[36; 32]);
    let prepared = prepare_channel_terminal_projection(
        Some(&authority),
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &kernel,
    )?;
    assert_eq!(prepared.channel(), &fixture.channel);
    assert_eq!(prepared.obligation(), fixture.obligation.as_ref());
    let signed = authority
        .signed_outcome
        .lock()
        .map_err(|_| "signed outcome lock poisoned")?
        .clone()
        .ok_or("authority did not receive the signed terminal outcome")?;
    assert_eq!(signed.kernel_key, kernel.public_key());
    assert_eq!(
        signed.body.reservation_digest,
        fixture.base.reservation.artifact().digest()?
    );

    let projection = completed_projection(&fixture);
    let lease = projection_recovery_lease(&fixture.base.operation, &fixture.base.context)?;
    let terminal = commit_prepared_channel_terminal_projection(
        &authority,
        &fixture.base.operation,
        &lease,
        &projection,
        &capabilities(),
        &prepared,
        &kernel,
        &fixture.base.context.store_fence,
        fixture.base.context.trusted_time_unix_ms,
    )?;
    assert_eq!(terminal.state, AdmissionOperationState::Completed);
    assert_eq!(authority.commit_count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn channel_terminal_projection_fails_closed_without_an_injected_authority() -> TestResult<()> {
    let fixture = build_fixture(7, "absent-terminal-authority")?;
    let error = prepare_channel_terminal_projection(
        None,
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &Keypair::from_seed(&[36; 32]),
    )
    .expect_err("a channel-bound operation must require its terminal authority");
    assert!(matches!(
        error,
        ChannelTerminalAuthorityError::Unavailable(_)
    ));
    Ok(())
}

#[test]
fn channel_terminal_projection_rejects_an_authority_advance_substitution() -> TestResult<()> {
    let fixture = build_fixture(7, "terminal-authority-substitution")?;
    let alternate = build_fixture(7, "terminal-authority-alternate")?;
    let authority = InjectedChannelTerminalAuthority {
        reservation: fixture.base.reservation.clone(),
        advance: alternate.base.advance,
        signed_outcome: Mutex::new(None),
        commit_count: AtomicUsize::new(0),
    };
    let error = prepare_channel_terminal_projection(
        Some(&authority),
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &Keypair::from_seed(&[36; 32]),
    )
    .expect_err("an authority must not substitute another terminal advance");
    assert!(matches!(
        error,
        ChannelTerminalAuthorityError::BindingMismatch
    ));
    assert_eq!(authority.commit_count.load(Ordering::SeqCst), 0);
    Ok(())
}
