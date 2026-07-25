use chio_fiscal::{
    read_verified_fiscal_checkpoint, FiscalAuthorityState, FiscalCharterRegistry,
    FiscalGenesisPolicy, FiscalStateAnchor, FiscalStateAnchorError,
    VerifiedFiscalContinuityCheckpoint,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_store_sqlite::fiscal_store::{
    FiscalStageStatus, FiscalStagedTransitionRecord, FiscalStoreError, SqliteFiscalStore,
};

#[derive(Debug, thiserror::Error)]
pub enum FiscalStartupRecoveryError {
    #[error("fiscal startup recovery could not read the independent anchor")]
    Anchor(#[from] FiscalStateAnchorError),
    #[error("fiscal startup recovery could not verify local state: {0}")]
    Store(#[from] FiscalStoreError),
    #[error("fiscal startup state diverges from the independent anchor")]
    Divergence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiscalStartupRecoveryAction {
    Ready,
    DiscardedUnanchoredStage,
    FinalizedAnchoredStage,
}

#[derive(Debug, Clone)]
pub struct FiscalStartupRecovery {
    pub action: FiscalStartupRecoveryAction,
    pub checkpoint: VerifiedFiscalContinuityCheckpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedRecoveryDecision {
    Discard,
    Finalize,
}

pub fn reconcile_fiscal_startup(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<FiscalStartupRecovery, FiscalStartupRecoveryError> {
    let anchored = read_verified_fiscal_checkpoint(anchor, policy, charters)?;
    let authority = store.load_authority_state()?;
    let local = store.load_checkpoint(&authority.finalized_checkpoint_digest, policy, charters)?;
    if local.digest() != authority.finalized_checkpoint_digest {
        return Err(FiscalStartupRecoveryError::Divergence);
    }
    let Some(stage) = store.load_open_transition()? else {
        if anchored.digest() != local.digest() {
            return Err(FiscalStartupRecoveryError::Divergence);
        }
        return Ok(FiscalStartupRecovery {
            action: FiscalStartupRecoveryAction::Ready,
            checkpoint: anchored,
        });
    };
    reconcile_stage(
        store, stage, local, anchored, authority, policy, charters, fence,
    )
}

fn reconcile_stage(
    store: &SqliteFiscalStore,
    stage: FiscalStagedTransitionRecord,
    local: VerifiedFiscalContinuityCheckpoint,
    anchored: VerifiedFiscalContinuityCheckpoint,
    authority: FiscalAuthorityState,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<FiscalStartupRecovery, FiscalStartupRecoveryError> {
    match classify_staged_recovery(&stage, local.digest(), anchored.digest())? {
        StagedRecoveryDecision::Discard => {
            store.discard_unanchored_stage(&stage.transition_id, fence)?;
            return Ok(FiscalStartupRecovery {
                action: FiscalStartupRecoveryAction::DiscardedUnanchoredStage,
                checkpoint: anchored,
            });
        }
        StagedRecoveryDecision::Finalize => {}
    }
    let staged = store.load_checkpoint(&stage.next_checkpoint_digest, policy, charters)?;
    if staged.signed() != anchored.signed() {
        return Err(FiscalStartupRecoveryError::Divergence);
    }
    if stage.status == FiscalStageStatus::DbStaged {
        store.mark_anchor_advanced(&stage.transition_id, &anchored, fence)?;
    } else if stage.status != FiscalStageStatus::FiscalAnchorAdvanced {
        return Err(FiscalStartupRecoveryError::Divergence);
    }
    let recovered_authority =
        FiscalAuthorityState::from_checkpoint(policy, &anchored, authority.bootstrap_state)
            .map_err(|_| FiscalStartupRecoveryError::Divergence)?;
    store.finalize_advance(&stage.transition_id, &anchored, &recovered_authority, fence)?;
    Ok(FiscalStartupRecovery {
        action: FiscalStartupRecoveryAction::FinalizedAnchoredStage,
        checkpoint: anchored,
    })
}

fn classify_staged_recovery(
    stage: &FiscalStagedTransitionRecord,
    local_checkpoint_digest: &str,
    anchored_checkpoint_digest: &str,
) -> Result<StagedRecoveryDecision, FiscalStartupRecoveryError> {
    if stage.current_checkpoint_digest != local_checkpoint_digest {
        return Err(FiscalStartupRecoveryError::Divergence);
    }
    if anchored_checkpoint_digest == stage.current_checkpoint_digest {
        return if stage.status == FiscalStageStatus::DbStaged {
            Ok(StagedRecoveryDecision::Discard)
        } else {
            Err(FiscalStartupRecoveryError::Divergence)
        };
    }
    if anchored_checkpoint_digest == stage.next_checkpoint_digest
        && matches!(
            stage.status,
            FiscalStageStatus::DbStaged | FiscalStageStatus::FiscalAnchorAdvanced
        )
    {
        Ok(StagedRecoveryDecision::Finalize)
    } else {
        Err(FiscalStartupRecoveryError::Divergence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(status: FiscalStageStatus) -> FiscalStagedTransitionRecord {
        FiscalStagedTransitionRecord {
            transition_id: "transition".to_owned(),
            current_checkpoint_digest: "current".to_owned(),
            next_checkpoint_digest: "next".to_owned(),
            proof_json: Vec::new(),
            status,
            stage_version: 1,
        }
    }

    #[test]
    fn startup_recovery_classifies_exact_crash_points_and_rejects_divergence() {
        assert_eq!(
            classify_staged_recovery(&stage(FiscalStageStatus::DbStaged), "current", "current")
                .ok(),
            Some(StagedRecoveryDecision::Discard)
        );
        assert_eq!(
            classify_staged_recovery(&stage(FiscalStageStatus::DbStaged), "current", "next").ok(),
            Some(StagedRecoveryDecision::Finalize)
        );
        assert_eq!(
            classify_staged_recovery(
                &stage(FiscalStageStatus::FiscalAnchorAdvanced),
                "current",
                "next"
            )
            .ok(),
            Some(StagedRecoveryDecision::Finalize)
        );
        assert!(classify_staged_recovery(
            &stage(FiscalStageStatus::FiscalAnchorAdvanced),
            "current",
            "current"
        )
        .is_err());
        assert!(
            classify_staged_recovery(&stage(FiscalStageStatus::DbStaged), "current", "other")
                .is_err()
        );
    }
}
