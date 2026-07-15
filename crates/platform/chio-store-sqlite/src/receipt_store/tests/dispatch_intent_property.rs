use super::super::*;
use super::support::*;
use proptest::prelude::*;

use chio_kernel::receipt_store::{DispatchIntentKey, DispatchIntentRecord, SideEffectClass};

#[derive(Clone, Debug)]
enum IntentOp {
    /// Write an intent then commit its receipt via the consuming append.
    WriteThenConsume,
    /// Write an intent and leave it open (a crash between write and receipt).
    WriteThenLeaveOpen,
    /// A plain (non-journaled) append.
    PlainAppend,
}

fn intent_op_strategy() -> impl Strategy<Value = IntentOp> {
    prop_oneof![
        Just(IntentOp::WriteThenConsume),
        Just(IntentOp::WriteThenLeaveOpen),
        Just(IntentOp::PlainAppend),
    ]
}

fn intent_for_receipt(request_id: &str, receipt: &ChioReceipt, seq: u64) -> DispatchIntentRecord {
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: receipt.capability_id.clone(),
        tool_server: receipt.tool_server.clone(),
        tool_name: receipt.tool_name.clone(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: receipt.tenant_id.clone(),
        created_at_unix_ms: seq,
    }
}

proptest! {
    // File-backed SQLite per case: keep the case count CI-friendly.
    #![proptest_config(ProptestConfig {
        cases: 24,
        .. ProptestConfig::default()
    })]

    /// For any interleaving of consuming appends, abandoned intents, and
    /// plain appends: every consumed intent is gone, every receipt that
    /// consumed one is present, and exactly the abandoned intents remain
    /// open (receipt XOR open intent, per request).
    #[test]
    fn prop_receipt_xor_open_intent_holds(ops in proptest::collection::vec(intent_op_strategy(), 1..16)) {
        let path = unique_db_path("chio-intent-prop");
        let keypair = receipt_test_keypair();
        let store = SqliteReceiptStore::open(&path)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let mut seq: u64 = 0;
        let mut expected_open: u64 = 0;
        let mut consumed_receipt_ids: Vec<String> = Vec::new();
        for op in &ops {
            seq += 1;
            let id = format!("prop-{seq}");
            match op {
                IntentOp::WriteThenConsume => {
                    let receipt = sample_receipt_with_keypair(&id, seq, &keypair);
                    store
                        .record_dispatch_intent(&intent_for_receipt(&id, &receipt, seq))
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    let key = DispatchIntentKey {
                        request_id: id.clone(),
                        parameter_hash: receipt.action.parameter_hash.clone(),
                        tenant_id: receipt.tenant_id.clone(),
                    };
                    let entry_seq = store
                        .append_chio_receipt_consuming_intent(&receipt, &key)
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    prop_assert!(entry_seq.is_some(), "consuming append returns the entry seq");
                    consumed_receipt_ids.push(receipt.id.clone());
                }
                IntentOp::WriteThenLeaveOpen => {
                    let receipt = sample_receipt_with_keypair(&id, seq, &keypair);
                    store
                        .record_dispatch_intent(&intent_for_receipt(&id, &receipt, seq))
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    expected_open += 1;
                }
                IntentOp::PlainAppend => {
                    let receipt = sample_receipt_with_keypair(&id, seq, &keypair);
                    store
                        .append_chio_receipt_returning_seq(&receipt)
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                }
            }
        }
        store
            .flush_receipt_writes()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let open = store
            .open_dispatch_intent_count()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(open, expected_open, "only abandoned intents remain open");
        for receipt_id in &consumed_receipt_ids {
            let loaded = store
                .load_chio_receipt(receipt_id)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert!(loaded.is_some(), "consumed intent {} has its receipt", receipt_id);
        }

        let _ = std::fs::remove_file(&path);
    }
}
