use chio_fiscal::{
    commit_fiscal_continuity_advance, FiscalAuthorityState, FiscalCharterRegistry,
    FiscalGenesisPolicy, FiscalProposalAdmissionState, FiscalStateAnchor, FiscalStateAnchorError,
    VerifiedFiscalActivation, VerifiedFiscalContinuityAdvance, VerifiedFiscalContinuityCheckpoint,
    VerifiedFiscalSchedule,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_store_sqlite::fiscal_store::{
    FiscalStagedTransitionRecord, FiscalStoreError, SqliteFiscalStore,
};

#[derive(Debug, thiserror::Error)]
pub enum FiscalStateCommitError {
    #[error("fiscal state could not be staged locally: {0}")]
    Store(#[from] FiscalStoreError),
    #[error("fiscal state could not advance at the independent anchor: {0}")]
    Anchor(#[from] FiscalStateAnchorError),
}

pub fn commit_fiscal_state_advance(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    next_authority: &FiscalAuthorityState,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateCommitError> {
    let staged = store.stage_advance(&advance, next_authority, fence)?;
    finish_fiscal_state_advance(
        store,
        anchor,
        staged,
        advance,
        next_authority,
        policy,
        charters,
        fence,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn commit_fiscal_activation(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    next_authority: &FiscalAuthorityState,
    activation: &VerifiedFiscalActivation,
    activated_admission: &FiscalProposalAdmissionState,
    candidate: &VerifiedFiscalSchedule,
    predecessor: Option<&VerifiedFiscalSchedule>,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateCommitError> {
    let staged = store.stage_activation_advance(
        &advance,
        next_authority,
        activation,
        activated_admission,
        candidate,
        predecessor,
        fence,
    )?;
    finish_fiscal_state_advance(
        store,
        anchor,
        staged,
        advance,
        next_authority,
        policy,
        charters,
        fence,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn commit_fiscal_charter_rotation(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    next_authority: &FiscalAuthorityState,
    activation: &VerifiedFiscalActivation,
    activated_admission: &FiscalProposalAdmissionState,
    successor_charter: &chio_fiscal::VerifiedFiscalCharter,
    successor_schedules: &[VerifiedFiscalSchedule],
    predecessor_charter: &chio_fiscal::VerifiedFiscalCharter,
    predecessor_schedules: &[VerifiedFiscalSchedule],
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateCommitError> {
    let staged = store.stage_charter_rotation_advance(
        &advance,
        next_authority,
        activation,
        activated_admission,
        successor_charter,
        successor_schedules,
        predecessor_charter,
        predecessor_schedules,
        fence,
    )?;
    finish_fiscal_state_advance(
        store,
        anchor,
        staged,
        advance,
        next_authority,
        policy,
        charters,
        fence,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_fiscal_state_advance(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    staged: FiscalStagedTransitionRecord,
    advance: VerifiedFiscalContinuityAdvance,
    next_authority: &FiscalAuthorityState,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateCommitError> {
    let committed = commit_fiscal_continuity_advance(anchor, advance, policy, charters)?;
    let checkpoint = committed.checkpoint().clone();
    store.mark_anchor_advanced(&staged.transition_id, &checkpoint, fence)?;
    store.finalize_advance(&staged.transition_id, &checkpoint, next_authority, fence)?;
    Ok(checkpoint)
}
