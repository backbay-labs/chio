#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]
#![cfg(feature = "web3")]

use chio_anchor::{
    classify_anchor_lane, ensure_anchor_operation_allowed, prepare_ots_submission,
    prepare_solana_memo_publication, AnchorEmergencyControls, AnchorEmergencyMode,
    AnchorIndexerStatus, AnchorLaneHealthStatus, AnchorLaneKind, AnchorOperationKind,
};
use chio_core::crypto::Keypair;
use chio_kernel::checkpoint::{build_checkpoint, KernelCheckpoint};

fn test_ok<T, E>(result: Result<T, E>, context: &str) -> T
where
    E: std::fmt::Display,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn checkpoint(seq: u64) -> KernelCheckpoint {
    let keypair = Keypair::from_seed(&[seq as u8; 32]);
    test_ok(
        build_checkpoint(
            seq,
            seq.saturating_mul(10),
            seq.saturating_mul(10),
            &[format!("receipt-{seq}").into_bytes()],
            &keypair,
        ),
        "build checkpoint",
    )
}

#[test]
fn emergency_modes_allow_only_their_bounded_operation_sets() {
    let halted = AnchorEmergencyControls {
        mode: AnchorEmergencyMode::Halted,
        changed_at: 1,
        reason: Some("operator halt".to_string()),
    };
    assert!(ensure_anchor_operation_allowed(halted, AnchorOperationKind::PublishRoot).is_err());

    let import_only = AnchorEmergencyControls {
        mode: AnchorEmergencyMode::ProofImportOnly,
        changed_at: 2,
        reason: None,
    };
    assert!(ensure_anchor_operation_allowed(
        import_only.clone(),
        AnchorOperationKind::ImportSecondaryProof,
    )
    .is_ok());
    assert!(
        ensure_anchor_operation_allowed(import_only, AnchorOperationKind::PublishRoot).is_err()
    );
}

#[test]
fn lane_classification_prioritizes_failed_paused_and_recovery_states() {
    let normal = AnchorEmergencyControls::normal(10);
    assert_eq!(
        classify_anchor_lane(
            AnchorLaneKind::EvmPrimary,
            AnchorIndexerStatus::Failed,
            normal,
            0
        ),
        AnchorLaneHealthStatus::Failed
    );

    let halted = AnchorEmergencyControls {
        mode: AnchorEmergencyMode::Halted,
        changed_at: 11,
        reason: None,
    };
    assert_eq!(
        classify_anchor_lane(
            AnchorLaneKind::BitcoinOts,
            AnchorIndexerStatus::Healthy,
            halted,
            0
        ),
        AnchorLaneHealthStatus::Paused
    );

    assert_eq!(
        classify_anchor_lane(
            AnchorLaneKind::EvmPrimary,
            AnchorIndexerStatus::Replaying,
            AnchorEmergencyControls::normal(12),
            0,
        ),
        AnchorLaneHealthStatus::Recovering
    );
    assert_eq!(
        classify_anchor_lane(
            AnchorLaneKind::EvmPrimary,
            AnchorIndexerStatus::Healthy,
            AnchorEmergencyControls::normal(13),
            1,
        ),
        AnchorLaneHealthStatus::Recovering
    );
}

#[test]
fn ots_submission_requires_calendars_and_contiguous_checkpoints() {
    let calendar = vec!["https://calendar.example".to_string()];
    assert!(prepare_ots_submission(&[], &calendar).is_err());
    assert!(prepare_ots_submission(&[checkpoint(1)], &[]).is_err());
    assert!(prepare_ots_submission(&[checkpoint(1), checkpoint(3)], &calendar).is_err());

    let prepared = test_ok(
        prepare_ots_submission(&[checkpoint(1), checkpoint(2)], &calendar),
        "prepare ots submission",
    );
    assert_eq!(prepared.aggregated_checkpoint_start, 1);
    assert_eq!(prepared.aggregated_checkpoint_end, 2);
    assert_eq!(prepared.checkpoint_seqs, vec![1, 2]);
}

#[test]
fn solana_publication_requires_identity_fields_and_canonical_memo() {
    let checkpoint = checkpoint(7);
    assert!(prepare_solana_memo_publication(&checkpoint, "", "operator").is_err());
    assert!(prepare_solana_memo_publication(&checkpoint, "solana:devnet", " ").is_err());

    let prepared = test_ok(
        prepare_solana_memo_publication(&checkpoint, "solana:devnet", "operator"),
        "prepare solana memo",
    );
    assert_eq!(
        prepared.anchored_checkpoint_seq,
        checkpoint.body.checkpoint_seq
    );
    assert_eq!(prepared.anchored_merkle_root, checkpoint.body.merkle_root);
    assert!(prepared
        .memo_data
        .starts_with(&format!("Chio:{}:", checkpoint.body.checkpoint_seq)));
}
