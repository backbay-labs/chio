use super::super::*;
use super::support::*;
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum HeadOp {
    /// Append 1..=4 receipts through the trait path (group-commit actor).
    Append(u8),
    /// Manual checkpoint creation (writer-routed) with max_batch 1..=5.
    Checkpoint(u8),
}

fn head_op_strategy() -> impl Strategy<Value = HeadOp> {
    prop_oneof![
        (1u8..=4).prop_map(HeadOp::Append),
        (1u8..=5).prop_map(HeadOp::Checkpoint),
    ]
}

proptest! {
    // File-backed SQLite per case: keep the case count CI-friendly.
    #![proptest_config(ProptestConfig {
        cases: 24,
        .. ProptestConfig::default()
    })]

    /// For any interleaving of appends and checkpoint thresholds, the
    /// incremental head after replay equals the value seed_verified_head
    /// computes by full verification.
    #[test]
    fn prop_incremental_head_matches_full_audit(ops in proptest::collection::vec(head_op_strategy(), 1..16)) {
        let path = unique_db_path("chio-head-prop");
        let keypair = receipt_test_keypair();
        let store = SqliteReceiptStore::open(&path)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut appended: u64 = 0;
        for op in &ops {
            match op {
                HeadOp::Append(count) => {
                    for _ in 0..*count {
                        appended += 1;
                        let receipt = sample_receipt_with_keypair(
                            &format!("rcpt-prop-{appended}"),
                            appended,
                            &keypair,
                        );
                        store
                            .append_chio_receipt_returning_seq(&receipt)
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    }
                }
                HeadOp::Checkpoint(max_batch) => {
                    // Only meaningful once something is committed; flush so
                    // the writer-routed checkpoint sees the appends.
                    store
                        .flush_receipt_writes()
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    if appended > 0 {
                        store
                            .create_next_receipt_checkpoint(u64::from(*max_batch), &keypair)
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    }
                }
            }
        }
        store
            .flush_receipt_writes()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let snapshot = store.writer_head_snapshot();
        let connection = store
            .connection()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reference = seed_verified_head(&connection)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(snapshot.claim_log_count, reference.claim_log_count);
        prop_assert_eq!(snapshot.claim_log_max_seq, reference.claim_log_max_seq);
        prop_assert_eq!(snapshot.checkpoint_seq, reference.checkpoint_seq());
        prop_assert_eq!(
            snapshot.checkpointed_entry_seq,
            reference.checkpointed_entry_seq()
        );

        let _ = fs::remove_file(path);
    }
}
