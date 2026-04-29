#[allow(clippy::expect_used, clippy::unwrap_used)]
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, GovernedCallChainContext,
    GovernedCallChainProvenance, GovernedProvenanceEvidenceClass, MeteredBillingQuote,
    MeteredSettlementMode, MonetaryAmount, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, Decision,
    EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
    EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
    EconomicBudgetReceiptMetadata, EconomicMerchantReceiptMetadata,
    EconomicMeteringReceiptMetadata, EconomicPayeeReceiptMetadata, EconomicPayerReceiptMetadata,
    EconomicPricingBasisReceiptMetadata, EconomicRailReceiptMetadata,
    EconomicSettlementReceiptMetadata, FinancialReceiptMetadata, GovernedApprovalReceiptMetadata,
    GovernedTransactionReceiptMetadata, MeteredBillingReceiptMetadata, ReceiptAttributionMetadata,
    ReceiptLineageEndpoints, ReceiptLineageRelationKind, ReceiptLineageStatement,
    ReceiptLineageStatementBody, SettlementStatus, SignedExportEnvelope, ToolCallAction,
};
use chio_core::session::{
    OperationKind, OperationTerminalState, RequestId, SessionAnchorReference, SessionId,
};
use chio_kernel::checkpoint::build_checkpoint_publication;
use chio_kernel::{
    build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof, AnalyticsTimeBucket,
    BehavioralFeedQuery, EvidenceExportQuery, MeteredBillingEvidenceRecord,
    MeteredBillingReconciliationState, OperatorReportQuery, ReceiptAnalyticsQuery,
    SettlementReconciliationState,
};

use super::*;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn sample_receipt() -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-test-001".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({})),
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn valid_tool_action(parameters: serde_json::Value) -> ToolCallAction {
    ToolCallAction::from_parameters(parameters).unwrap()
}

fn sample_child_receipt() -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: "child-rcpt-test-001".to_string(),
            timestamp: 2,
            session_id: SessionId::new("sess-1"),
            parent_request_id: RequestId::new("parent-1"),
            request_id: RequestId::new("child-1"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-1".to_string(),
            policy_hash: "policy-1".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

#[test]
fn sqlite_receipt_store_persists_across_reopen() {
    let path = unique_db_path("chio-receipts");
    {
        let store = SqliteReceiptStore::open(&path).unwrap();
        store.append_chio_receipt(&sample_receipt()).unwrap();
        store.append_child_receipt(&sample_child_receipt()).unwrap();
        assert_eq!(store.tool_receipt_count().unwrap(), 1);
        assert_eq!(store.child_receipt_count().unwrap(), 1);
    }

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(reopened.tool_receipt_count().unwrap(), 1);
    assert_eq!(reopened.child_receipt_count().unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_lists_filtered_receipts() {
    let path = unique_db_path("chio-receipts-filtered");
    let store = SqliteReceiptStore::open(&path).unwrap();

    store.append_chio_receipt(&sample_receipt()).unwrap();
    store.append_child_receipt(&sample_child_receipt()).unwrap();

    let tool_receipts = store
        .list_tool_receipts(
            10,
            Some("cap-1"),
            Some("shell"),
            Some("bash"),
            Some("allow"),
        )
        .unwrap();
    assert_eq!(tool_receipts.len(), 1);
    assert_eq!(tool_receipts[0].capability_id, "cap-1");
    assert_eq!(tool_receipts[0].tool_name, "bash");

    let child_receipts = store
        .list_child_receipts(
            10,
            Some("sess-1"),
            Some("parent-1"),
            Some("child-1"),
            Some("create_message"),
            Some("completed"),
        )
        .unwrap();
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
    assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

    let _ = fs::remove_file(path);
}

fn sample_receipt_with_id(id: &str) -> ChioReceipt {
    sample_receipt_with_id_and_timestamp(id, 1)
}

fn sample_receipt_with_id_and_timestamp(id: &str, timestamp: u64) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({})),
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn legacy_receipt_with_mismatched_parameter_hash(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({ "cmd": "echo legacy" }),
                parameter_hash: "0".repeat(64),
            },
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn sample_child_receipt_with_id_and_timestamp(id: &str, timestamp: u64) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp,
            session_id: SessionId::new("sess-1"),
            parent_request_id: RequestId::new("parent-1"),
            request_id: RequestId::new(&format!("child-{id}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{id}"),
            policy_hash: "policy-1".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn canonical_receipt_bytes(
    store: &SqliteReceiptStore,
    start_seq: u64,
    end_seq: u64,
) -> Vec<Vec<u8>> {
    store
        .receipts_canonical_bytes_range(start_seq, end_seq)
        .unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect()
}

fn insert_checkpoint_row(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
) {
    insert_checkpoint_row_with_statement_json(
        store,
        checkpoint,
        batch_end_seq,
        &serde_json::to_string(&checkpoint.body).unwrap(),
    );
}

fn insert_checkpoint_row_with_statement_json(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
    statement_json: &str,
) {
    store
        .connection()
        .unwrap()
        .execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            rusqlite::params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                statement_json,
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )
        .unwrap();
}

fn load_claim_log_rows(store: &SqliteReceiptStore) -> Vec<(u64, String, String, u64, u64)> {
    let connection = store.connection().unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp
            FROM claim_receipt_log_entries
            ORDER BY entry_seq ASC
            "#,
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .unwrap();
    rows.map(|row| {
        let (entry_seq, receipt_id, receipt_kind, source_seq, timestamp) = row.unwrap();
        (
            entry_seq as u64,
            receipt_id,
            receipt_kind,
            source_seq as u64,
            timestamp as u64,
        )
    })
    .collect()
}

fn load_claim_log_identity(
    store: &SqliteReceiptStore,
    receipt_id: &str,
) -> (Option<String>, Option<String>) {
    let connection = store.connection().unwrap();
    connection
        .query_row(
            r#"
            SELECT subject_key, issuer_key
            FROM claim_receipt_log_entries
            WHERE receipt_id = ?1
            "#,
            rusqlite::params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .unwrap()
}

fn tamper_persisted_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;")
        .unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).unwrap();
    connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![tampered, receipt_id],
        )
        .unwrap();
}

fn tamper_claim_log_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;")
        .unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM claim_receipt_log_entries WHERE receipt_id = ?1 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).unwrap();
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![tampered, receipt_id],
        )
        .unwrap();
}

fn load_checkpoint_tree_head_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, u64, u64, Option<String>)> {
    let connection = store.connection().unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256
            FROM checkpoint_tree_heads
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .unwrap();
    rows.map(|row| {
        let (checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256) = row.unwrap();
        (
            checkpoint_seq as u64,
            batch_start_seq as u64,
            tree_size as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

fn load_checkpoint_predecessor_witness_rows(store: &SqliteReceiptStore) -> Vec<(u64, u64, String)> {
    let connection = store.connection().unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256
            FROM checkpoint_predecessor_witnesses
            ORDER BY witness_checkpoint_seq ASC
            "#,
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap();
    rows.map(|row| {
        let (predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256) =
            row.unwrap();
        (
            predecessor_checkpoint_seq as u64,
            witness_checkpoint_seq as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

fn load_checkpoint_publication_metadata_rows(
    store: &SqliteReceiptStore,
) -> Vec<(
    u64,
    String,
    String,
    u64,
    String,
    u64,
    u64,
    u64,
    Option<String>,
)> {
    let connection = store.connection().unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, publication_schema, merkle_root, published_at, kernel_key,
                   log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256
            FROM checkpoint_publication_metadata
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .unwrap();
    rows.map(|row| {
        let (
            checkpoint_seq,
            publication_schema,
            merkle_root,
            published_at,
            kernel_key,
            log_tree_size,
            entry_start_seq,
            entry_end_seq,
            previous_checkpoint_sha256,
        ) = row.unwrap();
        (
            checkpoint_seq as u64,
            publication_schema,
            merkle_root,
            published_at as u64,
            kernel_key,
            log_tree_size as u64,
            entry_start_seq as u64,
            entry_end_seq as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

fn load_checkpoint_publication_trust_anchor_binding_rows(
    store: &SqliteReceiptStore,
) -> Vec<(
    u64,
    chio_core::receipt::CheckpointPublicationTrustAnchorBinding,
)> {
    let connection = store.connection().unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, binding_json
            FROM checkpoint_publication_trust_anchor_bindings
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap();
    rows.map(|row| {
        let (checkpoint_seq, binding_json) = row.unwrap();
        (
            checkpoint_seq as u64,
            serde_json::from_str::<chio_core::receipt::CheckpointPublicationTrustAnchorBinding>(
                &binding_json,
            )
            .unwrap(),
        )
    })
    .collect()
}

fn seed_legacy_projectionless_store(
    path: &std::path::Path,
    tool_receipts: &[ChioReceipt],
    child_receipts: &[ChildRequestReceipt],
    checkpoints: &[chio_kernel::KernelCheckpoint],
) {
    let mut connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            r#"
            CREATE TABLE chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE chio_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            "#,
        )
        .unwrap();

    let tx = connection.transaction().unwrap();
    for receipt in tool_receipts {
        tx.execute(
            r#"
            INSERT INTO chio_tool_receipts (
                receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index,
                tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json
            ) VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            rusqlite::params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.capability_id,
                receipt.tool_server,
                receipt.tool_name,
                support::decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                serde_json::to_string(receipt).unwrap(),
            ],
        )
        .unwrap();
    }
    for receipt in child_receipts {
        tx.execute(
            r#"
            INSERT INTO chio_child_receipts (
                receipt_id, timestamp, session_id, parent_request_id, request_id,
                operation_kind, terminal_state, policy_hash, outcome_hash, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            rusqlite::params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                support::terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                serde_json::to_string(receipt).unwrap(),
            ],
        )
        .unwrap();
    }
    for checkpoint in checkpoints {
        tx.execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            rusqlite::params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                checkpoint.body.batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                serde_json::to_string(&checkpoint.body).unwrap(),
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn open_creates_kernel_checkpoints_table() {
    let path = unique_db_path("chio-receipts-cp-table");
    let store = SqliteReceiptStore::open(&path).unwrap();
    // Query the table to confirm it exists.
    let connection = store.connection().unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn open_creates_checkpoint_publication_metadata_table() {
    let path = unique_db_path("chio-receipts-cp-publication-table");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let connection = store.connection().unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM checkpoint_publication_metadata",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_returning_seq_returns_seq() {
    let path = unique_db_path("chio-receipts-seq");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = sample_receipt_with_id("rcpt-seq-001");
    let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
    assert!(seq > 0, "seq should be non-zero for a new insert");
    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_rejects_invalid_signature() {
    let path = unique_db_path("chio-receipts-invalid-signature");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let mut receipt = sample_receipt_with_id("rcpt-invalid-signature");
    receipt.tool_name = "sh".to_string();

    let error = store.append_chio_receipt(&receipt).unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("invalid signature")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_rejects_mismatched_parameter_hash() {
    let path = unique_db_path("chio-receipts-invalid-parameter-hash");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let keypair = Keypair::generate();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-invalid-parameter-hash".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({ "cmd": "echo changed" }),
                parameter_hash: "bad-parameter-hash".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap();

    let error = store.append_chio_receipt(&receipt).unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("mismatched action parameter hash")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn decode_verified_chio_receipt_preserves_legacy_mismatched_parameter_hash() {
    let receipt = legacy_receipt_with_mismatched_parameter_hash("rcpt-legacy-parameter-hash");
    let raw_json = serde_json::to_string(&receipt).unwrap();

    let decoded =
        decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(1)).unwrap();

    assert_eq!(decoded.id, receipt.id);
    assert!(!decoded.action.verify_hash().unwrap());
}

#[test]
fn list_tool_receipts_preserves_legacy_mismatched_parameter_hash_rows() {
    let path = unique_db_path("chio-receipts-legacy-parameter-hash");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = legacy_receipt_with_mismatched_parameter_hash("rcpt-legacy-row");
    {
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                INSERT INTO chio_tool_receipts (
                    receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index,
                    tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json
                ) VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                rusqlite::params![
                    receipt.id.as_str(),
                    receipt.timestamp as i64,
                    receipt.capability_id.as_str(),
                    receipt.tool_server.as_str(),
                    receipt.tool_name.as_str(),
                    support::decision_kind(&receipt.decision),
                    receipt.policy_hash.as_str(),
                    receipt.content_hash.as_str(),
                    serde_json::to_string(&receipt).unwrap(),
                ],
            )
            .unwrap();
    }

    let receipts = store
        .list_tool_receipts(10, None, None, None, None)
        .unwrap();

    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].id, "rcpt-legacy-row");
    assert!(!receipts[0].action.verify_hash().unwrap());

    let _ = fs::remove_file(path);
}

#[test]
fn append_child_receipt_rejects_invalid_signature() {
    let path = unique_db_path("chio-child-receipts-invalid-signature");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let mut receipt = sample_child_receipt_with_id_and_timestamp("child-invalid-signature", 2);
    receipt.outcome_hash = "outcome-mutated".to_string();

    let error = store.append_child_receipt(&receipt).unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("child-invalid-signature")
                && message.contains("has invalid signature")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn evidence_export_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-evidence-export-tamper");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = sample_receipt_with_id("tampered-export-receipt");
    store.append_chio_receipt(&receipt).unwrap();
    tamper_persisted_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store
        .build_evidence_export_bundle(&EvidenceExportQuery::default())
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("persisted tool receipt seq"));
    assert!(message.contains("tampered-export-receipt"));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn behavioral_feed_report_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-behavioral-feed-tamper");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = sample_receipt_with_id("tampered-report-receipt");
    store.append_chio_receipt(&receipt).unwrap();
    tamper_persisted_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store
        .query_behavioral_feed_receipts(&BehavioralFeedQuery::default())
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("persisted tool receipt seq"));
    assert!(message.contains("tampered-report-receipt"));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn claim_log_replay_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-claim-log-tamper");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = sample_receipt_with_id("tampered-claim-log-receipt");
    let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
    tamper_claim_log_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store.receipts_canonical_bytes_range(seq, seq).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("claim-log tool receipt seq"));
    assert!(message.contains("tampered-claim-log-receipt"));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_base_tables_reject_update_and_delete() {
    let path = unique_db_path("chio-receipts-base-immutable");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let tool = sample_receipt_with_id("base-immutable-tool");
    let child = sample_child_receipt_with_id_and_timestamp("base-immutable-child", 2);
    store.append_chio_receipt(&tool).unwrap();
    store.append_child_receipt(&child).unwrap();

    let connection = store.connection().unwrap();
    let error = connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = raw_json WHERE receipt_id = ?1",
            rusqlite::params![tool.id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("tool receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "DELETE FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![tool.id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("tool receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "UPDATE chio_child_receipts SET raw_json = raw_json WHERE receipt_id = ?1",
            rusqlite::params![child.id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("child receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "DELETE FROM chio_child_receipts WHERE receipt_id = ?1",
            rusqlite::params![child.id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("child receipts are immutable"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn claim_log_projection_uses_capability_lineage_when_receipt_lacks_attribution() {
    let path = unique_db_path("chio-claim-log-lineage-projection");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-claim-log-lineage".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&capability, None).unwrap();

    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-claim-log-lineage".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo projection" })),
            decision: Decision::Allow,
            content_hash: "content-claim-log-lineage".to_string(),
            policy_hash: "policy-claim-log-lineage".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 10,
                    currency: "USD".to_string(),
                    budget_remaining: 990,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status: SettlementStatus::Settled,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();

    store.append_chio_receipt(&receipt).unwrap();
    drop(store);

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    let (projected_subject_key, projected_issuer_key) =
        load_claim_log_identity(&reopened, &receipt.id);
    assert_eq!(projected_subject_key.as_deref(), Some(subject_hex.as_str()));
    assert_eq!(projected_issuer_key.as_deref(), Some(issuer_hex.as_str()));

    let _ = fs::remove_file(path);
}

#[test]
fn append_100_receipts_seqs_span_1_to_100() {
    let path = unique_db_path("chio-receipts-100");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let mut seqs = Vec::new();
    for i in 0..100usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
        let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
        seqs.push(seq);
    }
    assert_eq!(seqs[0], 1);
    assert_eq!(seqs[99], 100);
    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_returning_seq_supports_concurrent_writers() {
    let path = unique_db_path("chio-receipts-concurrent");
    let store = Arc::new(SqliteReceiptStore::open(&path).unwrap());
    let thread_count = 8usize;
    let receipts_per_thread = 24usize;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for worker in 0..thread_count {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut seqs = Vec::new();
            for receipt_index in 0..receipts_per_thread {
                let receipt =
                    sample_receipt_with_id(&format!("rcpt-concurrent-{worker}-{receipt_index}"));
                seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
            }
            seqs
        }));
    }

    let mut seqs = Vec::new();
    for handle in handles {
        seqs.extend(handle.join().unwrap());
    }

    assert_eq!(seqs.len(), thread_count * receipts_per_thread);
    assert!(seqs.iter().all(|seq| *seq > 0));

    let mut deduped = seqs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(deduped.len(), seqs.len());
    assert_eq!(store.tool_receipt_count().unwrap(), seqs.len() as u64);

    let _ = fs::remove_file(path);
}

#[test]
fn store_and_load_checkpoint_by_seq() {
    let path = unique_db_path("chio-receipts-cp-store");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    // Append 5 receipts.
    let mut seqs = Vec::new();
    for i in 0..5usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
        let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
        seqs.push(seq);
    }

    // Build checkpoint.
    let kp = Keypair::generate();
    let bytes: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("receipt-bytes-{i}").into_bytes())
        .collect();
    let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).unwrap();

    // Store and retrieve.
    ReceiptStore::store_checkpoint(&mut store, &cp).unwrap();
    let loaded = store.load_checkpoint_by_seq(1).unwrap();
    assert!(loaded.is_some(), "checkpoint should be loadable");
    let loaded = loaded.unwrap();
    assert_eq!(loaded.body.checkpoint_seq, 1);
    assert_eq!(loaded.body.tree_size, 5);
    assert_eq!(loaded.body.batch_start_seq, seqs[0]);
    assert_eq!(loaded.body.batch_end_seq, seqs[4]);
    assert_eq!(
        loaded.signature.to_hex(),
        cp.signature.to_hex(),
        "signature should round-trip"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn load_checkpoint_by_seq_returns_none_for_missing() {
    let path = unique_db_path("chio-receipts-cp-missing");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let result = store.load_checkpoint_by_seq(999).unwrap();
    assert!(result.is_none());
    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_enforces_predecessor_continuity() {
    let path = unique_db_path("chio-receipts-cp-continuity");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-predecessor-{i}"));
        seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
    }

    let checkpoint_kp = Keypair::generate();
    let first = build_checkpoint(
        1,
        seqs[0],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[0], seqs[1]),
        &checkpoint_kp,
    )
    .unwrap();
    ReceiptStore::store_checkpoint(&mut store, &first).unwrap();

    let second = build_checkpoint(
        2,
        seqs[3],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[3], seqs[3]),
        &checkpoint_kp,
    )
    .unwrap();
    let error = ReceiptStore::store_checkpoint(&mut store, &second).unwrap_err();
    assert!(
        error.to_string().contains("predecessor continuity"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn append_receipt_fails_closed_when_earlier_checkpoint_row_is_corrupted() {
    let path = unique_db_path("chio-receipts-cp-fail-closed");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let kp = Keypair::generate();

    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
    )
    .unwrap();
    let third = build_checkpoint_with_previous(
        3,
        5,
        6,
        &[b"five".to_vec(), b"six".to_vec()],
        &kp,
        Some(&second),
    )
    .unwrap();

    let mut corrupted_first_body = first.body.clone();
    corrupted_first_body.batch_end_seq += 1;
    let corrupted_first_json = serde_json::to_string(&corrupted_first_body).unwrap();
    insert_checkpoint_row_with_statement_json(
        &store,
        &first,
        first.body.batch_end_seq,
        &corrupted_first_json,
    );
    insert_checkpoint_row(&store, &second, second.body.batch_end_seq);
    insert_checkpoint_row(&store, &third, third.body.batch_end_seq);

    let error = ReceiptStore::append_chio_receipt_returning_seq(
        &mut store,
        &sample_receipt_with_id("rcpt-fail-closed"),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not match signed body"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_installs_immutable_checkpoint_triggers() {
    let path = unique_db_path("chio-receipts-cp-immutable");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let receipt = sample_receipt_with_id("rcpt-immutable-1");
    let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
    let checkpoint_kp = Keypair::generate();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .unwrap();
    ReceiptStore::store_checkpoint(&mut store, &checkpoint).unwrap();

    let error = store
        .connection()
        .unwrap()
        .execute(
            "UPDATE kernel_checkpoints SET issued_at = issued_at + 1 WHERE checkpoint_seq = 1",
            [],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("kernel checkpoints are immutable"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_rejects_conflicting_rewritten_checkpoint_rows() {
    let path = unique_db_path("chio-receipts-cp-rewrite-detect");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-rewrite-{i}"));
        seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
    }

    let checkpoint_kp = Keypair::generate();
    let first = build_checkpoint(
        1,
        seqs[0],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[0], seqs[1]),
        &checkpoint_kp,
    )
    .unwrap();
    insert_checkpoint_row(&store, &first, seqs[1] + 1);

    let second = build_checkpoint(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &checkpoint_kp,
    )
    .unwrap();
    let error = ReceiptStore::store_checkpoint(&mut store, &second).unwrap_err();
    assert!(
        error.to_string().contains("does not match signed body"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_wrong_predecessor_digest() {
    let path = unique_db_path("chio-receipts-cp-continuity");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let kp = Keypair::generate();

    let first_batch = vec![b"first-1".to_vec(), b"first-2".to_vec()];
    let first = build_checkpoint(1, 1, 2, &first_batch, &kp).unwrap();
    ReceiptStore::store_checkpoint(&mut store, &first).unwrap();

    let second_batch = vec![b"second-1".to_vec(), b"second-2".to_vec()];
    let mut second =
        build_checkpoint_with_previous(2, 3, 4, &second_batch, &kp, Some(&first)).unwrap();
    second.body.previous_checkpoint_sha256 = Some("not-the-real-digest".to_string());
    second.signature = kp.sign(&chio_core::canonical_json_bytes(&second.body).unwrap());
    let error = ReceiptStore::store_checkpoint(&mut store, &second).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match predecessor digest"));

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_conflicting_rewrite() {
    let path = unique_db_path("chio-receipts-cp-rewrite");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let kp = Keypair::generate();

    let checkpoint = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).unwrap();
    ReceiptStore::store_checkpoint(&mut store, &checkpoint).unwrap();

    let conflicting =
        build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"changed".to_vec()], &kp).unwrap();
    let error = ReceiptStore::store_checkpoint(&mut store, &conflicting).unwrap_err();
    assert!(error
        .to_string()
        .contains("already exists with different content"));

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_accepts_contiguous_predecessor() {
    let path = unique_db_path("chio-receipts-cp-predecessor");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let kp = Keypair::generate();

    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).unwrap();
    ReceiptStore::store_checkpoint(&mut store, &first).unwrap();

    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
    )
    .unwrap();
    ReceiptStore::store_checkpoint(&mut store, &second).unwrap();

    let loaded = store
        .load_checkpoint_by_seq(2)
        .unwrap()
        .expect("second checkpoint");
    assert_eq!(
        loaded.body.previous_checkpoint_sha256,
        second.body.previous_checkpoint_sha256
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipts_canonical_bytes_range_returns_correct_count() {
    let path = unique_db_path("chio-receipts-canon-range");
    let store = SqliteReceiptStore::open(&path).unwrap();

    for i in 0..10usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
        store.append_chio_receipt_returning_seq(&receipt).unwrap();
    }

    // Fetch seqs 3..=7 (5 receipts).
    let range = store.receipts_canonical_bytes_range(3, 7).unwrap();
    assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
    assert_eq!(range[0].0, 3);
    assert_eq!(range[4].0, 7);

    // Verify all bytes are non-empty canonical JSON.
    for (_, bytes) in &range {
        assert!(!bytes.is_empty());
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    }

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_log_includes_child_receipts_in_unified_surface() {
    let path = unique_db_path("chio-receipts-claim-log");
    let store = SqliteReceiptStore::open(&path).unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("claim-tool-1", 10))
        .unwrap();
    store
        .append_child_receipt(&sample_child_receipt_with_id_and_timestamp(
            "claim-child-1",
            11,
        ))
        .unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("claim-tool-2", 12))
        .unwrap();

    let rows = load_claim_log_rows(&store);
    assert_eq!(
        rows,
        vec![
            (
                1,
                "claim-tool-1".to_string(),
                "tool_receipt".to_string(),
                1,
                10
            ),
            (
                2,
                "claim-child-1".to_string(),
                "child_receipt".to_string(),
                1,
                11
            ),
            (
                3,
                "claim-tool-2".to_string(),
                "tool_receipt".to_string(),
                2,
                12
            ),
        ]
    );

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(load_claim_log_rows(&reopened), rows);

    let _ = fs::remove_file(path);
}

#[test]
fn append_receipt_sequences_follow_unified_claim_log() {
    let path = unique_db_path("chio-receipts-claim-log-seq");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let first_tool_seq = store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id_and_timestamp(
            "claim-seq-tool-1",
            10,
        ))
        .unwrap();
    let child_seq = ReceiptStore::append_child_receipt_returning_seq(
        &store,
        &sample_child_receipt_with_id_and_timestamp("claim-seq-child-1", 11),
    )
    .unwrap()
    .expect("sqlite store should return child claim-log seq");
    let second_tool_seq = store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id_and_timestamp(
            "claim-seq-tool-2",
            12,
        ))
        .unwrap();

    assert_eq!(first_tool_seq, 1);
    assert_eq!(child_seq, 2);
    assert_eq!(second_tool_seq, 3);

    let rows = load_claim_log_rows(&store);
    assert_eq!(
        rows.into_iter()
            .map(|(entry_seq, receipt_id, _, _, _)| (entry_seq, receipt_id))
            .collect::<Vec<_>>(),
        vec![
            (1, "claim-seq-tool-1".to_string()),
            (2, "claim-seq-child-1".to_string()),
            (3, "claim-seq-tool-2".to_string()),
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_log_includes_child_receipts_in_tree() {
    let path = unique_db_path("chio-receipts-claim-tree");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let tool_before = sample_receipt_with_id_and_timestamp("claim-tree-tool-1", 10);
    let child = sample_child_receipt_with_id_and_timestamp("claim-tree-child-1", 11);
    let tool_after = sample_receipt_with_id_and_timestamp("claim-tree-tool-2", 12);

    store.append_chio_receipt(&tool_before).unwrap();
    store.append_child_receipt(&child).unwrap();
    store.append_chio_receipt(&tool_after).unwrap();

    let claim_rows = load_claim_log_rows(&store);
    assert_eq!(
        claim_rows,
        vec![
            (
                1,
                "claim-tree-tool-1".to_string(),
                "tool_receipt".to_string(),
                1,
                10
            ),
            (
                2,
                "claim-tree-child-1".to_string(),
                "child_receipt".to_string(),
                1,
                11
            ),
            (
                3,
                "claim-tree-tool-2".to_string(),
                "tool_receipt".to_string(),
                2,
                12
            ),
        ]
    );

    let start_seq = claim_rows.first().expect("claim log row").0;
    let end_seq = claim_rows.last().expect("claim log row").0;
    let canonical_range = store
        .receipts_canonical_bytes_range(start_seq, end_seq)
        .unwrap();
    assert_eq!(
        canonical_range
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(canonical_range.len(), 3);
    let child_canonical = canonical_json_bytes(&child).unwrap();
    assert_eq!(canonical_range[1].1, child_canonical);
    let canonical = canonical_range
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();

    let checkpoint_kp = Keypair::generate();
    let checkpoint = build_checkpoint(1, start_seq, end_seq, &canonical, &checkpoint_kp).unwrap();
    assert_eq!(checkpoint.body.tree_size as u64, 3);
    store.store_checkpoint(&checkpoint).unwrap();
    let stored_checkpoint = store
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("stored checkpoint");
    assert_eq!(stored_checkpoint.body.batch_start_seq, 1);
    assert_eq!(stored_checkpoint.body.batch_end_seq, 3);
    assert_eq!(stored_checkpoint.body.tree_size, 3);

    let tree = MerkleTree::from_leaves(&canonical).unwrap();
    let proof = build_inclusion_proof(&tree, 1, start_seq, 2).unwrap();
    assert_eq!(proof.receipt_seq, 2);
    assert!(proof.verify(&child_canonical, &stored_checkpoint.body.merkle_root));

    let tree_heads = load_checkpoint_tree_head_rows(&store);
    assert_eq!(tree_heads, vec![(1, start_seq, 3, None)]);

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .receipts_canonical_bytes_range(start_seq, end_seq)
            .unwrap()
            .len(),
        3
    );
    assert_eq!(load_checkpoint_tree_head_rows(&reopened), tree_heads);

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_projects_tree_heads_and_predecessor_witnesses() {
    let path = unique_db_path("chio-receipts-tree-heads");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt =
            sample_receipt_with_id_and_timestamp(&format!("tree-head-{i}"), 100 + i as u64);
        seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
    }

    let checkpoint_kp = Keypair::generate();
    let first = build_checkpoint(
        1,
        seqs[0],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[0], seqs[1]),
        &checkpoint_kp,
    )
    .unwrap();
    store.store_checkpoint(&first).unwrap();

    let second = build_checkpoint_with_previous(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &checkpoint_kp,
        Some(&first),
    )
    .unwrap();
    store.store_checkpoint(&second).unwrap();

    let tree_heads = load_checkpoint_tree_head_rows(&store);
    assert_eq!(
        tree_heads,
        vec![
            (1, seqs[0], first.body.tree_size as u64, None),
            (
                2,
                seqs[2],
                second.body.tree_size as u64,
                second.body.previous_checkpoint_sha256.clone(),
            ),
        ]
    );

    let witnesses = load_checkpoint_predecessor_witness_rows(&store);
    assert_eq!(
        witnesses,
        vec![(
            1,
            2,
            second.body.previous_checkpoint_sha256.clone().unwrap(),
        )]
    );
    let first_publication = build_checkpoint_publication(&first).unwrap();
    let second_publication = build_checkpoint_publication(&second).unwrap();
    let publications = load_checkpoint_publication_metadata_rows(&store);
    assert_eq!(
        publications,
        vec![
            (
                first_publication.checkpoint_seq,
                first_publication.schema,
                first_publication.merkle_root.to_hex(),
                first_publication.published_at,
                first_publication.kernel_key.to_hex(),
                first_publication.log_tree_size,
                first_publication.entry_start_seq,
                first_publication.entry_end_seq,
                first_publication.previous_checkpoint_sha256,
            ),
            (
                second_publication.checkpoint_seq,
                second_publication.schema,
                second_publication.merkle_root.to_hex(),
                second_publication.published_at,
                second_publication.kernel_key.to_hex(),
                second_publication.log_tree_size,
                second_publication.entry_start_seq,
                second_publication.entry_end_seq,
                second_publication.previous_checkpoint_sha256,
            ),
        ]
    );

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(load_checkpoint_tree_head_rows(&reopened), tree_heads);
    assert_eq!(
        load_checkpoint_predecessor_witness_rows(&reopened),
        witnesses
    );
    assert_eq!(
        load_checkpoint_publication_metadata_rows(&reopened),
        publications
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_backfills_claim_log_and_checkpoint_transparency_projections() {
    let path = unique_db_path("chio-receipts-legacy-projections");
    let tool_receipt = sample_receipt_with_id_and_timestamp("legacy-tool-1", 20);
    let child_receipt = sample_child_receipt_with_id_and_timestamp("legacy-child-1", 21);
    let checkpoint_kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 1, &[b"legacy-one".to_vec()], &checkpoint_kp).unwrap();
    let second = build_checkpoint_with_previous(
        2,
        2,
        2,
        &[b"legacy-two".to_vec()],
        &checkpoint_kp,
        Some(&first),
    )
    .unwrap();

    seed_legacy_projectionless_store(
        &path,
        &[tool_receipt.clone()],
        &[child_receipt.clone()],
        &[first.clone(), second.clone()],
    );

    let store = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(
        load_claim_log_rows(&store),
        vec![
            (
                1,
                tool_receipt.id.clone(),
                "tool_receipt".to_string(),
                1,
                20
            ),
            (
                2,
                child_receipt.id.clone(),
                "child_receipt".to_string(),
                1,
                21
            ),
        ]
    );
    assert_eq!(
        load_checkpoint_tree_head_rows(&store),
        vec![
            (1, 1, first.body.tree_size as u64, None),
            (
                2,
                2,
                second.body.tree_size as u64,
                second.body.previous_checkpoint_sha256.clone(),
            ),
        ]
    );
    assert_eq!(
        load_checkpoint_predecessor_witness_rows(&store),
        vec![(
            1,
            2,
            second.body.previous_checkpoint_sha256.clone().unwrap(),
        )]
    );
    let first_publication = build_checkpoint_publication(&first).unwrap();
    let second_publication = build_checkpoint_publication(&second).unwrap();
    assert_eq!(
        load_checkpoint_publication_metadata_rows(&store),
        vec![
            (
                first_publication.checkpoint_seq,
                first_publication.schema,
                first_publication.merkle_root.to_hex(),
                first_publication.published_at,
                first_publication.kernel_key.to_hex(),
                first_publication.log_tree_size,
                first_publication.entry_start_seq,
                first_publication.entry_end_seq,
                first_publication.previous_checkpoint_sha256,
            ),
            (
                second_publication.checkpoint_seq,
                second_publication.schema,
                second_publication.merkle_root.to_hex(),
                second_publication.published_at,
                second_publication.kernel_key.to_hex(),
                second_publication.log_tree_size,
                second_publication.entry_start_seq,
                second_publication.entry_end_seq,
                second_publication.previous_checkpoint_sha256,
            ),
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn record_checkpoint_publication_trust_anchor_binding_is_idempotent_and_visible_in_export_summary()
{
    let path = unique_db_path("chio-receipts-publication-binding");
    let checkpoint_kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 1, &[b"alpha".to_vec()], &checkpoint_kp).unwrap();
    let second =
        build_checkpoint_with_previous(2, 2, 2, &[b"beta".to_vec()], &checkpoint_kp, Some(&first))
            .unwrap();

    let mut store = SqliteReceiptStore::open(&path).unwrap();
    store.store_checkpoint(&first).unwrap();
    store.store_checkpoint(&second).unwrap();

    let second_publication = build_checkpoint_publication(&second).unwrap();
    let binding = chio_core::receipt::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
            chio_core::receipt::CheckpointPublicationIdentityKind::LocalLog,
            second_publication.log_id.clone(),
        ),
        trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
            chio_core::receipt::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };

    store
        .record_checkpoint_publication_trust_anchor_binding(second.body.checkpoint_seq, &binding)
        .unwrap();
    store
        .record_checkpoint_publication_trust_anchor_binding(second.body.checkpoint_seq, &binding)
        .unwrap();

    assert_eq!(
        load_checkpoint_publication_trust_anchor_binding_rows(&store),
        vec![(second.body.checkpoint_seq, binding.clone())]
    );

    let summary = store
        .build_evidence_export_transparency_summary(&[first.clone(), second.clone()])
        .unwrap();
    assert!(summary.publications[0].trust_anchor_binding.is_none());
    assert_eq!(
        summary.publications[1].trust_anchor_binding.as_ref(),
        Some(&binding)
    );

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(
        load_checkpoint_publication_trust_anchor_binding_rows(&reopened),
        vec![(second.body.checkpoint_seq, binding.clone())]
    );
    let reopened_summary = reopened
        .build_evidence_export_transparency_summary(&[first.clone(), second.clone()])
        .unwrap();
    assert_eq!(
        reopened_summary.publications[1]
            .trust_anchor_binding
            .as_ref(),
        Some(&binding)
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_analytics_groups_by_agent_tool_and_time() {
    let path = unique_db_path("chio-receipts-analytics");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let keypair = Keypair::generate();

    let make_receipt = |id: &str,
                        subject_key: &str,
                        tool_server: &str,
                        tool_name: &str,
                        decision: Decision,
                        timestamp: u64,
                        cost_charged: u64,
                        attempted_cost: Option<u64>| {
        let financial = if cost_charged > 0 || attempted_cost.is_some() {
            Some(FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 1_000,
                budget_total: 2_000,
                delegation_depth: 0,
                root_budget_holder: "root-agent".to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            })
        } else {
            None
        };
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_key.to_string(),
                issuer_key: "issuer-key".to_string(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": financial,
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: format!("cap-{subject_key}"),
                tool_server: tool_server.to_string(),
                tool_name: tool_name.to_string(),
                action: valid_tool_action(serde_json::json!({})),
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-analytics".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    };

    store
        .append_chio_receipt(&make_receipt(
            "analytics-1",
            "agent-a",
            "shell",
            "bash",
            Decision::Allow,
            86_400,
            100,
            None,
        ))
        .unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "analytics-2",
            "agent-a",
            "shell",
            "bash",
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            86_450,
            0,
            Some(50),
        ))
        .unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "analytics-3",
            "agent-b",
            "files",
            "read",
            Decision::Incomplete {
                reason: "stream ended".to_string(),
            },
            172_800,
            0,
            None,
        ))
        .unwrap();

    let analytics = store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            group_limit: Some(10),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            ..ReceiptAnalyticsQuery::default()
        })
        .unwrap();

    assert_eq!(analytics.summary.total_receipts, 3);
    assert_eq!(analytics.summary.allow_count, 1);
    assert_eq!(analytics.summary.deny_count, 1);
    assert_eq!(analytics.summary.incomplete_count, 1);
    assert_eq!(analytics.summary.total_cost_charged, 100);
    assert_eq!(analytics.summary.total_attempted_cost, 50);
    assert_eq!(
        analytics.summary.reliability_score,
        Some(0.5),
        "allow / (allow + incomplete)"
    );
    assert_eq!(
        analytics.summary.compliance_rate,
        Some(2.0 / 3.0),
        "1 - deny / total"
    );
    assert_eq!(
        analytics.summary.budget_utilization_rate,
        Some(100.0 / 150.0)
    );

    assert_eq!(analytics.by_agent.len(), 2);
    assert_eq!(analytics.by_agent[0].subject_key, "agent-a");
    assert_eq!(analytics.by_agent[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_tool.len(), 2);
    assert_eq!(analytics.by_tool[0].tool_server, "shell");
    assert_eq!(analytics.by_tool[0].tool_name, "bash");
    assert_eq!(analytics.by_tool[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_time.len(), 2);
    assert_eq!(analytics.by_time[0].bucket_start, 86_400);
    assert_eq!(analytics.by_time[1].bucket_start, 172_800);

    let _ = fs::remove_file(path);
}

#[test]
fn cost_attribution_report_aggregates_matching_corpus_and_limits_detail_rows() {
    let path = unique_db_path("chio-receipts-cost-attribution");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_100,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();

    store.record_capability_snapshot(&root, None).unwrap();
    store
        .record_capability_snapshot(&child, Some("cap-root"))
        .unwrap();

    let make_financial_receipt = |id: &str,
                                  capability_id: &str,
                                  subject_key: Option<String>,
                                  root_budget_holder: &str,
                                  delegation_depth: u32,
                                  timestamp: u64,
                                  decision: Decision,
                                  cost_charged: u64,
                                  attempted_cost: Option<u64>| {
        let attribution = subject_key.map(|subject_key| ReceiptAttributionMetadata {
            subject_key,
            issuer_key: issuer_hex.clone(),
            delegation_depth,
            grant_index: Some(0),
        });
        let metadata = serde_json::json!({
            "attribution": attribution,
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 900,
                budget_total: 1_000,
                delegation_depth,
                root_budget_holder: root_budget_holder.to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: valid_tool_action(serde_json::json!({})),
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-cost".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: receipt_kp.public_key(),
            },
            &receipt_kp,
        )
        .unwrap()
    };

    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-1",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_200,
            Decision::Allow,
            125,
            None,
        ))
        .unwrap();
    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-2",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_201,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            0,
            Some(75),
        ))
        .unwrap();
    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-3",
            "cap-orphan",
            None,
            "orphan-root",
            2,
            1_202,
            Decision::Allow,
            50,
            None,
        ))
        .unwrap();

    let report = store
        .query_cost_attribution_report(&CostAttributionQuery {
            limit: Some(1),
            ..CostAttributionQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_receipts, 3);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.total_cost_charged, 175);
    assert_eq!(report.summary.total_attempted_cost, 75);
    assert_eq!(report.summary.max_delegation_depth, 2);
    assert_eq!(report.summary.distinct_root_subjects, 2);
    assert_eq!(report.summary.distinct_leaf_subjects, 1);
    assert_eq!(report.summary.lineage_gap_count, 1);
    assert!(report.summary.truncated);

    assert_eq!(report.by_root.len(), 2);
    assert_eq!(
        report.by_root[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(report.by_root[0].receipt_count, 2);
    assert_eq!(report.by_root[0].total_cost_charged, 125);
    assert_eq!(report.by_root[0].total_attempted_cost, 75);
    assert_eq!(report.by_root[0].distinct_leaf_subjects, 1);

    assert_eq!(report.by_leaf.len(), 1);
    assert_eq!(
        report.by_leaf[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(
        report.by_leaf[0].leaf_subject_key.as_str(),
        leaf_hex.as_str()
    );
    assert_eq!(report.by_leaf[0].receipt_count, 2);
    assert_eq!(report.by_leaf[0].total_cost_charged, 125);
    assert_eq!(report.by_leaf[0].total_attempted_cost, 75);

    assert_eq!(report.receipts.len(), 1);
    assert_eq!(report.receipts[0].capability_id, "cap-child");
    assert_eq!(
        report.receipts[0].root_subject_key.as_deref(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        report.receipts[0].leaf_subject_key.as_deref(),
        Some(leaf_hex.as_str())
    );
    assert!(report.receipts[0].lineage_complete);
    assert_eq!(report.receipts[0].chain.len(), 2);

    let _ = fs::remove_file(path);
}

#[test]
fn economic_receipt_projection_report_joins_signed_envelope_with_reconciliation_state() {
    let path = unique_db_path("chio-receipts-economic-projection");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-economic".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "model".to_string(),
                    tool_name: "infer".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&capability, None).unwrap();

    let quote = MeteredBillingQuote {
        quote_id: "quote-economic-1".to_string(),
        provider: "meterco".to_string(),
        billing_unit: "tokens".to_string(),
        quoted_units: 100,
        quoted_cost: MonetaryAmount {
            units: 400,
            currency: "USD".to_string(),
        },
        issued_at: 1_900,
        expires_at: Some(3_600),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-economic-1".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "model".to_string(),
            tool_name: "infer".to_string(),
            action: valid_tool_action(serde_json::json!({ "prompt": "hello" })),
            decision: Decision::Allow,
            content_hash: "content-economic-1".to_string(),
            policy_hash: "policy-economic-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex,
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 400,
                    currency: "USD".to_string(),
                    budget_remaining: 600,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: Some("payref-economic-1".to_string()),
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: Some(450),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-economic-1".to_string(),
                    intent_hash: "intent-hash-economic-1".to_string(),
                    purpose: "metered inference".to_string(),
                    server_id: "model".to_string(),
                    tool_name: "infer".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: Some(MeteredBillingReceiptMetadata {
                        settlement_mode: MeteredSettlementMode::HoldCapture,
                        quote: quote.clone(),
                        max_billed_units: Some(110),
                        usage_evidence: None,
                    }),
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-economic-1".to_string(),
                        approver_key: subject_hex.clone(),
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: None,
                    autonomy: None,
                    economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
                        version: EconomicAuthorizationReceiptMetadataVersion::V1,
                        economic_mode: EconomicAuthorizationMode::MeteredHoldCapture,
                        payer: EconomicPayerReceiptMetadata {
                            party_id: "agent-economic".to_string(),
                            funding_source_ref: "payref-economic-1".to_string(),
                            custody_provider: None,
                            obligor_ref: None,
                        },
                        merchant: EconomicMerchantReceiptMetadata {
                            merchant_id: "model".to_string(),
                            merchant_of_record: None,
                            order_ref: Some("req-economic-1".to_string()),
                        },
                        payee: EconomicPayeeReceiptMetadata {
                            beneficiary_id: "model".to_string(),
                            settlement_destination_ref: "payref-economic-1".to_string(),
                        },
                        rail: EconomicRailReceiptMetadata {
                            kind: "metered_billing".to_string(),
                            asset: "USD".to_string(),
                            network: None,
                            facilitator: Some("meterco".to_string()),
                            contract_or_account_ref: Some("payref-economic-1".to_string()),
                        },
                        amount_bounds: EconomicAmountBoundsReceiptMetadata {
                            approved_max: MonetaryAmount {
                                units: 500,
                                currency: "USD".to_string(),
                            },
                            hold_amount: Some(MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            }),
                            settlement_cap: MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            },
                        },
                        pricing_basis: Some(EconomicPricingBasisReceiptMetadata {
                            quote_hash: Some("quote-hash-economic-1".to_string()),
                            tariff_hash: None,
                            quote_expiry: quote.expires_at,
                        }),
                        metering: Some(EconomicMeteringReceiptMetadata {
                            provider: "meterco".to_string(),
                            meter_profile_hash: "meter-profile-economic-1".to_string(),
                            max_billable_units: Some(110),
                            billing_unit: Some("tokens".to_string()),
                        }),
                        liability_refs: None,
                        budget: EconomicBudgetReceiptMetadata {
                            grant_index: 0,
                            cost_charged: 400,
                            currency: "USD".to_string(),
                            budget_remaining: 600,
                            budget_total: 1_000,
                            delegation_depth: 0,
                            root_budget_holder: subject_hex.clone(),
                            attempted_cost: Some(450),
                        },
                        settlement: EconomicSettlementReceiptMetadata {
                            settlement_status: SettlementStatus::Pending,
                        },
                    }),
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();
    let receipt_id = receipt.id.clone();
    store.append_chio_receipt(&receipt).unwrap();
    store
        .upsert_settlement_reconciliation(
            &receipt_id,
            SettlementReconciliationState::Open,
            Some("capture pending"),
        )
        .unwrap();
    store
        .upsert_metered_billing_reconciliation(
            &receipt_id,
            &MeteredBillingEvidenceRecord {
                usage_evidence: chio_core::receipt::MeteredUsageEvidenceReceiptMetadata {
                    evidence_kind: "provider-export".to_string(),
                    evidence_id: "usage-economic-1".to_string(),
                    observed_units: 120,
                    evidence_sha256: Some("usage-sha-economic-1".to_string()),
                },
                billed_cost: MonetaryAmount {
                    units: 450,
                    currency: "USD".to_string(),
                },
                recorded_at: 2_010,
            },
            MeteredBillingReconciliationState::Open,
            Some("meter overrun"),
        )
        .unwrap();

    let report = store
        .query_economic_receipt_projection_report(&OperatorReportQuery {
            capability_id: Some("cap-economic".to_string()),
            economic_limit: Some(10),
            ..OperatorReportQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.metered_receipts, 1);
    assert_eq!(report.summary.pending_settlement_receipts, 1);
    assert_eq!(report.summary.failed_settlement_receipts, 0);
    assert_eq!(report.summary.settlement_actionable_receipts, 1);
    assert_eq!(report.summary.metering_actionable_receipts, 1);
    assert_eq!(report.summary.metering_evidence_missing_receipts, 0);
    assert_eq!(report.summary.metering_financial_mismatch_receipts, 1);
    assert!(!report.summary.truncated);

    assert_eq!(report.receipts.len(), 1);
    let row = &report.receipts[0];
    assert_eq!(row.receipt_id, receipt_id);
    assert_eq!(row.subject_key.as_deref(), Some(subject_hex.as_str()));
    assert_eq!(
        row.economic_authorization.economic_mode,
        EconomicAuthorizationMode::MeteredHoldCapture
    );
    assert_eq!(
        row.economic_authorization.rail.facilitator.as_deref(),
        Some("meterco")
    );
    assert_eq!(row.settlement.settlement_status, SettlementStatus::Pending);
    assert!(row.settlement.action_required);
    assert_eq!(row.settlement.note.as_deref(), Some("capture pending"));
    assert_eq!(
        row.metering
            .as_ref()
            .and_then(|metering| metering.evidence.as_ref())
            .map(|evidence| evidence.usage_evidence.observed_units),
        Some(120)
    );
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_quoted_units));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_max_billed_units));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_quoted_cost));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.financial_mismatch));
    assert_eq!(
        row.metering
            .as_ref()
            .and_then(|metering| metering.note.as_deref()),
        Some("meter overrun")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn economic_completion_flow_report_bundles_receipts_underwriting_and_credit_artifacts() {
    let path = unique_db_path("chio-receipts-economic-flow");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let receipt_kp = Keypair::generate();
    let subject_key = "subject-flow";
    let capability_id = format!("cap-{subject_key}");
    let quote = MeteredBillingQuote {
        quote_id: "quote-flow-1".to_string(),
        provider: "meterco".to_string(),
        billing_unit: "tokens".to_string(),
        quoted_units: 100,
        quoted_cost: MonetaryAmount {
            units: 400,
            currency: "USD".to_string(),
        },
        issued_at: 1_900,
        expires_at: Some(3_600),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-flow-1".to_string(),
            timestamp: 2_000,
            capability_id: capability_id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo flow" })),
            decision: Decision::Allow,
            content_hash: "content-flow-1".to_string(),
            policy_hash: "policy-flow-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: "issuer-flow".to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 400,
                    currency: "USD".to_string(),
                    budget_remaining: 600,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_key.to_string(),
                    payment_reference: Some("payref-flow-1".to_string()),
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: Some(450),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-flow-1".to_string(),
                    intent_hash: "intent-hash-flow-1".to_string(),
                    purpose: "metered flow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: Some(MeteredBillingReceiptMetadata {
                        settlement_mode: MeteredSettlementMode::HoldCapture,
                        quote: quote.clone(),
                        max_billed_units: Some(110),
                        usage_evidence: None,
                    }),
                    approval: None,
                    runtime_assurance: None,
                    call_chain: None,
                    autonomy: None,
                    economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
                        version: EconomicAuthorizationReceiptMetadataVersion::V1,
                        economic_mode: EconomicAuthorizationMode::MeteredHoldCapture,
                        payer: EconomicPayerReceiptMetadata {
                            party_id: subject_key.to_string(),
                            funding_source_ref: "payref-flow-1".to_string(),
                            custody_provider: None,
                            obligor_ref: None,
                        },
                        merchant: EconomicMerchantReceiptMetadata {
                            merchant_id: "shell".to_string(),
                            merchant_of_record: None,
                            order_ref: Some("req-flow-1".to_string()),
                        },
                        payee: EconomicPayeeReceiptMetadata {
                            beneficiary_id: "shell".to_string(),
                            settlement_destination_ref: "payref-flow-1".to_string(),
                        },
                        rail: EconomicRailReceiptMetadata {
                            kind: "metered_billing".to_string(),
                            asset: "USD".to_string(),
                            network: None,
                            facilitator: Some("meterco".to_string()),
                            contract_or_account_ref: Some("payref-flow-1".to_string()),
                        },
                        amount_bounds: EconomicAmountBoundsReceiptMetadata {
                            approved_max: MonetaryAmount {
                                units: 500,
                                currency: "USD".to_string(),
                            },
                            hold_amount: Some(MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            }),
                            settlement_cap: MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            },
                        },
                        pricing_basis: Some(EconomicPricingBasisReceiptMetadata {
                            quote_hash: Some("quote-hash-flow-1".to_string()),
                            tariff_hash: None,
                            quote_expiry: quote.expires_at,
                        }),
                        metering: Some(EconomicMeteringReceiptMetadata {
                            provider: "meterco".to_string(),
                            meter_profile_hash: "meter-profile-flow-1".to_string(),
                            max_billable_units: Some(110),
                            billing_unit: Some("tokens".to_string()),
                        }),
                        liability_refs: None,
                        budget: EconomicBudgetReceiptMetadata {
                            grant_index: 0,
                            cost_charged: 400,
                            currency: "USD".to_string(),
                            budget_remaining: 600,
                            budget_total: 1_000,
                            delegation_depth: 0,
                            root_budget_holder: subject_key.to_string(),
                            attempted_cost: Some(450),
                        },
                        settlement: EconomicSettlementReceiptMetadata {
                            settlement_status: SettlementStatus::Pending,
                        },
                    }),
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();
    let receipt_id = receipt.id.clone();
    store.append_chio_receipt(&receipt).unwrap();
    store
        .upsert_settlement_reconciliation(
            &receipt_id,
            SettlementReconciliationState::Open,
            Some("awaiting capture"),
        )
        .unwrap();
    store
        .upsert_metered_billing_reconciliation(
            &receipt_id,
            &MeteredBillingEvidenceRecord {
                usage_evidence: chio_core::receipt::MeteredUsageEvidenceReceiptMetadata {
                    evidence_kind: "provider-export".to_string(),
                    evidence_id: "usage-flow-1".to_string(),
                    observed_units: 120,
                    evidence_sha256: Some("usage-sha-flow-1".to_string()),
                },
                billed_cost: MonetaryAmount {
                    units: 450,
                    currency: "USD".to_string(),
                },
                recorded_at: 2_010,
            },
            MeteredBillingReconciliationState::Open,
            Some("meter overrun"),
        )
        .unwrap();

    store
        .record_underwriting_decision(&sample_underwriting_decision(subject_key))
        .unwrap();
    store
        .record_credit_facility(&sample_credit_facility(subject_key))
        .unwrap();
    store
        .record_credit_bond(&signed_credit_bond_fixture(
            subject_key,
            "cfd-1",
            "cbd-1",
            1_700_000_200,
            1_700_086_600,
            chio_kernel::CreditBondDisposition::Hold,
            chio_kernel::CreditBondLifecycleState::Active,
            None,
        ))
        .unwrap();

    let report = store
        .query_economic_completion_flow_report(&chio_kernel::ExposureLedgerQuery {
            agent_subject: Some(subject_key.to_string()),
            receipt_limit: Some(10),
            decision_limit: Some(10),
            ..chio_kernel::ExposureLedgerQuery::default()
        })
        .unwrap();

    assert_eq!(report.schema, chio_kernel::ECONOMIC_COMPLETION_FLOW_SCHEMA);
    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.matching_underwriting_decisions, 1);
    assert_eq!(report.summary.returned_underwriting_decisions, 1);
    assert_eq!(report.summary.matching_credit_facilities, 1);
    assert_eq!(report.summary.returned_credit_facilities, 1);
    assert_eq!(report.summary.matching_credit_bonds, 1);
    assert_eq!(report.summary.returned_credit_bonds, 1);
    assert_eq!(report.summary.pending_settlement_receipts, 1);
    assert_eq!(report.summary.failed_settlement_receipts, 0);
    assert_eq!(report.summary.metering_actionable_receipts, 1);
    assert_eq!(
        report.summary.latest_underwriting_decision_id.as_deref(),
        Some("uwd-1")
    );
    assert_eq!(
        report.summary.latest_underwriting_outcome,
        Some(chio_kernel::UnderwritingDecisionOutcome::Approve)
    );
    assert_eq!(
        report.summary.latest_credit_facility_id.as_deref(),
        Some("cfd-1")
    );
    assert_eq!(
        report.summary.latest_credit_facility_disposition,
        Some(chio_kernel::CreditFacilityDisposition::Grant)
    );
    assert_eq!(
        report.summary.latest_credit_bond_id.as_deref(),
        Some("cbd-1")
    );
    assert_eq!(
        report.summary.latest_credit_bond_disposition,
        Some(chio_kernel::CreditBondDisposition::Hold)
    );
    assert_eq!(report.economic_receipts.receipts.len(), 1);
    assert_eq!(report.underwriting_decisions.decisions.len(), 1);
    assert_eq!(report.credit_facilities.facilities.len(), 1);
    assert_eq!(report.credit_bonds.bonds.len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn compliance_report_counts_proof_and_lineage_coverage() {
    let path = unique_db_path("chio-receipts-compliance");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-compliance".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(4),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1000,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&token, None).unwrap();

    let make_receipt = |id: &str,
                        timestamp: u64,
                        decision: Decision,
                        settlement_status: SettlementStatus,
                        attempted_cost: Option<u64>| {
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_hex.clone(),
                issuer_key: issuer_hex.clone(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged: if attempted_cost.is_some() { 0 } else { 250 },
                currency: "USD".to_string(),
                budget_remaining: 750,
                budget_total: 1000,
                delegation_depth: 0,
                root_budget_holder: subject_hex.clone(),
                payment_reference: None,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: "cap-compliance".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: valid_tool_action(serde_json::json!({})),
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-compliance".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: checkpoint_kp.public_key(),
            },
            &checkpoint_kp,
        )
        .unwrap()
    };

    let seq = store
        .append_chio_receipt_returning_seq(&make_receipt(
            "compliance-1",
            2_000,
            Decision::Allow,
            SettlementStatus::Settled,
            None,
        ))
        .unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "compliance-2",
            2_001,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            SettlementStatus::Pending,
            Some(100),
        ))
        .unwrap();

    let bytes = store
        .receipts_canonical_bytes_range(seq, seq)
        .unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();
    let checkpoint = build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).unwrap();
    ReceiptStore::store_checkpoint(&mut store, &checkpoint).unwrap();

    let report = store
        .query_compliance_report(&OperatorReportQuery {
            agent_subject: Some(subject_hex.clone()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            ..OperatorReportQuery::default()
        })
        .unwrap();

    assert_eq!(report.matching_receipts, 2);
    assert_eq!(report.evidence_ready_receipts, 1);
    assert_eq!(report.uncheckpointed_receipts, 1);
    assert_eq!(report.lineage_covered_receipts, 2);
    assert_eq!(report.lineage_gap_receipts, 0);
    assert_eq!(report.pending_settlement_receipts, 1);
    assert_eq!(report.failed_settlement_receipts, 0);
    assert!(!report.direct_evidence_export_supported);
    assert_eq!(
        report.child_receipt_scope,
        crate::EvidenceChildReceiptScope::OmittedNoJoinPath
    );
    assert!(report
        .export_scope_note
        .as_deref()
        .is_some_and(|note| note.contains("tool filters narrow the operator report only")));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_store_authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound() {
    let path = unique_db_path("chio-receipts-auth-asserted-call-chain");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-auth-asserted".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&capability, None).unwrap();

    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-auth-asserted".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo delegated" })),
            decision: Decision::Allow,
            content_hash: "content-auth-asserted".to_string(),
            policy_hash: "policy-auth-asserted".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 250,
                    currency: "USD".to_string(),
                    budget_remaining: 750,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status: SettlementStatus::Settled,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-auth-asserted".to_string(),
                    intent_hash: "intent-hash-auth-asserted".to_string(),
                    purpose: "delegate external partner workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: None,
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-auth-asserted".to_string(),
                        approver_key: issuer_hex.clone(),
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: Some(GovernedCallChainProvenance::asserted(
                        GovernedCallChainContext {
                            chain_id: "chain-asserted".to_string(),
                            parent_request_id: "req-upstream-asserted".to_string(),
                            parent_receipt_id: Some("rcpt-upstream-asserted".to_string()),
                            origin_subject: "subject-root".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        },
                    )),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();
    store.append_chio_receipt(&receipt).unwrap();

    let report = store
        .query_authorization_context_report(&OperatorReportQuery {
            capability_id: Some(capability.id),
            authorization_limit: Some(10),
            ..OperatorReportQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.delegated_sender_bound_receipts, 0);
    assert_eq!(report.receipts.len(), 1);
    assert_eq!(
        report.receipts[0]
            .transaction_context
            .call_chain
            .as_ref()
            .expect("call-chain projection")
            .evidence_class,
        GovernedProvenanceEvidenceClass::Asserted
    );
    assert!(
        !report.receipts[0]
            .sender_constraint
            .delegated_call_chain_bound
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_lineage_verification_backfills_from_governed_call_chain_metadata() {
    let path = unique_db_path("chio-receipts-lineage-links");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let parent_receipt_kp = Keypair::generate();
    let child_receipt_kp = Keypair::generate();
    let statement_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-lineage-links".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&capability, None).unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-parent-lineage".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo parent" })),
            decision: Decision::Allow,
            content_hash: "content-parent-lineage".to_string(),
            policy_hash: "policy-lineage".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: parent_receipt_kp.public_key(),
        },
        &parent_receipt_kp,
    )
    .unwrap();
    store.append_chio_receipt(&parent_receipt).unwrap();

    let child_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-child-lineage".to_string(),
            timestamp: 2_100,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo child" })),
            decision: Decision::Allow,
            content_hash: "content-child-lineage".to_string(),
            policy_hash: "policy-lineage".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-lineage".to_string(),
                    intent_hash: "intent-hash-lineage".to_string(),
                    purpose: "continue delegated workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: None,
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-lineage".to_string(),
                        approver_key: issuer_hex.clone(),
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: Some(GovernedCallChainProvenance::verified(
                        GovernedCallChainContext {
                            chain_id: "chain-lineage".to_string(),
                            parent_request_id: "req-parent-lineage".to_string(),
                            parent_receipt_id: Some(parent_receipt.id.clone()),
                            origin_subject: "subject-root".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        },
                    )),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: child_receipt_kp.public_key(),
        },
        &child_receipt_kp,
    )
    .unwrap();
    store.append_chio_receipt(&child_receipt).unwrap();

    store
        .record_session_anchor_record(
            "sess-lineage",
            "anchor-child-lineage",
            "authctx-lineage",
            2_090,
            None,
            &serde_json::json!({
                "schema": "chio.session_anchor.v1",
                "id": "anchor-child-lineage"
            }),
        )
        .unwrap();
    store
        .record_request_lineage_record(
            "sess-lineage",
            "req-parent-lineage",
            None,
            Some("anchor-child-lineage"),
            2_091,
            Some("req-parent-lineage-fingerprint"),
            &serde_json::json!({
                "schema": "chio.request_lineage.v1",
                "requestId": "req-parent-lineage"
            }),
        )
        .unwrap();
    store
        .record_request_lineage_record(
            "sess-lineage",
            "req-child-lineage",
            Some("req-parent-lineage"),
            Some("anchor-child-lineage"),
            2_092,
            Some("req-child-lineage-fingerprint"),
            &serde_json::json!({
                "schema": "chio.request_lineage.v1",
                "requestId": "req-child-lineage",
                "parentRequestId": "req-parent-lineage"
            }),
        )
        .unwrap();

    let statement = ReceiptLineageStatement::sign(
        ReceiptLineageStatementBody::new(
            "stmt-lineage-001",
            ReceiptLineageEndpoints::new(
                parent_receipt.id.clone(),
                child_receipt.id.clone(),
                RequestId::new("req-parent-lineage"),
                RequestId::new("req-child-lineage"),
                SessionAnchorReference::new("anchor-parent-lineage", "anchor-parent-lineage-hash"),
                SessionAnchorReference::new("anchor-child-lineage", "anchor-child-lineage-hash"),
            ),
            ReceiptLineageRelationKind::Continued,
            2_101,
            statement_kp.public_key(),
        ),
        &statement_kp,
    )
    .unwrap();
    let statement_json = serde_json::to_value(&statement).unwrap();
    store
        .record_receipt_lineage_statement_record(
            &child_receipt.id,
            None,
            Some("sess-lineage"),
            None,
            None,
            None,
            Some("chain-lineage"),
            2_101,
            &statement_json,
        )
        .unwrap();

    let parent_links = store
        .list_receipt_lineage_statement_links(&parent_receipt.id)
        .unwrap();
    assert_eq!(parent_links.len(), 1);
    assert_eq!(
        parent_links[0].statement_id.as_deref(),
        Some("stmt-lineage-001")
    );
    assert_eq!(parent_links[0].child_receipt_id, child_receipt.id);
    assert_eq!(
        parent_links[0].parent_receipt_id.as_deref(),
        Some(parent_receipt.id.as_str())
    );
    assert_eq!(
        parent_links[0].child_request_id.as_deref(),
        Some("req-child-lineage")
    );
    assert_eq!(
        parent_links[0].parent_request_id.as_deref(),
        Some("req-parent-lineage")
    );
    assert_eq!(
        parent_links[0].session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(parent_links[0].chain_id.as_deref(), Some("chain-lineage"));

    let child_links = store
        .list_receipt_lineage_statement_links(&child_receipt.id)
        .unwrap();
    assert_eq!(child_links, parent_links);

    let verification = store
        .receipt_lineage_verification(&child_receipt.id)
        .unwrap()
        .expect("child receipt lineage verification");
    assert!(verification.session_anchor_verified);
    assert!(verification.parent_request_verified);
    assert!(verification.parent_receipt_verified);
    assert!(verification.replay_protected);

    let report = store
        .query_authorization_context_report(&OperatorReportQuery {
            capability_id: Some(capability.id),
            authorization_limit: Some(10),
            ..OperatorReportQuery::default()
        })
        .unwrap();
    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.session_anchor_receipts, 1);
    assert_eq!(report.summary.receipt_lineage_statement_receipts, 1);
    assert_eq!(report.receipts.len(), 1);
    let call_chain = report.receipts[0]
        .transaction_context
        .call_chain
        .as_ref()
        .expect("call-chain projection");
    assert_eq!(
        call_chain.session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(
        call_chain.receipt_lineage_statement_id.as_deref(),
        Some("stmt-lineage-001")
    );
    let diagnostics = report.receipts[0]
        .governed_transaction_diagnostics
        .as_ref()
        .expect("governed transaction diagnostics");
    assert_eq!(
        diagnostics.lineage_references.session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(
        diagnostics
            .lineage_references
            .receipt_lineage_statement_id
            .as_deref(),
        Some("stmt-lineage-001")
    );

    let review_pack = store
        .query_authorization_review_pack(&OperatorReportQuery {
            capability_id: Some("cap-lineage-links".to_string()),
            authorization_limit: Some(10),
            ..OperatorReportQuery::default()
        })
        .unwrap();
    assert_eq!(review_pack.summary.receipt_lineage_statement_receipts, 1);
    assert_eq!(
        review_pack.records[0]
            .governed_transaction
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.receipt_lineage_statement_id.as_deref()),
        Some("stmt-lineage-001")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_lineage_statement_links_parent_and_child_receipts() {
    let path = unique_db_path("chio-receipts-lineage-link");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let receipt_kp = Keypair::generate();

    let parent = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-lineage-parent".to_string(),
            timestamp: 1_000,
            capability_id: "cap-lineage".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo parent" })),
            decision: Decision::Allow,
            content_hash: "content-lineage-parent".to_string(),
            policy_hash: "policy-lineage-parent".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();
    store.append_chio_receipt(&parent).unwrap();

    let child = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-lineage-child".to_string(),
            timestamp: 1_001,
            capability_id: "cap-lineage".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo child" })),
            decision: Decision::Allow,
            content_hash: "content-lineage-child".to_string(),
            policy_hash: "policy-lineage-child".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-lineage-child".to_string(),
                    intent_hash: "intent-hash-lineage-child".to_string(),
                    purpose: "continue delegated workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    approval: None,
                    runtime_assurance: None,
                    call_chain: Some(
                        GovernedCallChainProvenance::verified(GovernedCallChainContext {
                            chain_id: "chain-lineage".to_string(),
                            parent_request_id: "req-lineage-parent".to_string(),
                            parent_receipt_id: Some(parent.id.clone()),
                            origin_subject: "subject-origin".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        })
                    ),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
        },
        &receipt_kp,
    )
    .unwrap();
    store.append_chio_receipt(&child).unwrap();

    let verification = store
        .receipt_lineage_verification(&child.id)
        .unwrap()
        .expect("lineage verification should exist");
    assert_eq!(verification.receipt_id, child.id);
    assert!(verification.parent_receipt_verified);
    assert!(verification.delegated_call_chain_bound());

    let _ = fs::remove_file(path);
}

fn sign_export<T>(body: T) -> SignedExportEnvelope<T>
where
    T: serde::Serialize + Clone,
{
    let keypair = Keypair::generate();
    SignedExportEnvelope::sign(body, &keypair).unwrap()
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn sample_liability_provider_report(
    provider_id: &str,
    bound_coverage_supported: bool,
) -> chio_kernel::LiabilityProviderReport {
    chio_kernel::LiabilityProviderReport {
        schema: chio_kernel::LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_id: provider_id.to_string(),
        display_name: format!("{provider_id} display"),
        provider_type: chio_kernel::LiabilityProviderType::AdmittedCarrier,
        provider_url: Some(format!("https://{provider_id}.example.com")),
        lifecycle_state: chio_kernel::LiabilityProviderLifecycleState::Active,
        support_boundary: chio_kernel::LiabilityProviderSupportBoundary {
            curated_registry_only: true,
            automatic_trust_admission: false,
            permissionless_federation_supported: false,
            bound_coverage_supported,
        },
        policies: vec![chio_kernel::LiabilityJurisdictionPolicy {
            jurisdiction: "us-ny".to_string(),
            coverage_classes: vec![chio_kernel::LiabilityCoverageClass::ToolExecution],
            supported_currencies: vec!["USD".to_string()],
            required_evidence: vec![
                chio_kernel::LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            ],
            max_coverage_amount: Some(usd(50_000)),
            claims_supported: true,
            quote_ttl_seconds: 3_600,
            notes: None,
        }],
        provenance: chio_kernel::LiabilityProviderProvenance {
            configured_by: "operator@example.com".to_string(),
            configured_at: 1_700_000_000,
            source_ref: "liability-runbook".to_string(),
            change_reason: Some("test fixture".to_string()),
        },
    }
}

fn signed_liability_provider(
    provider_record_id: &str,
    provider_id: &str,
    issued_at: u64,
    lifecycle_state: chio_kernel::LiabilityProviderLifecycleState,
    supersedes_provider_record_id: Option<&str>,
    bound_coverage_supported: bool,
) -> chio_kernel::SignedLiabilityProvider {
    sign_export(chio_kernel::LiabilityProviderArtifact {
        schema: chio_kernel::LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_record_id: provider_record_id.to_string(),
        issued_at,
        lifecycle_state,
        supersedes_provider_record_id: supersedes_provider_record_id.map(str::to_string),
        report: sample_liability_provider_report(provider_id, bound_coverage_supported),
    })
}

fn provider_policy_reference(
    provider: &chio_kernel::SignedLiabilityProvider,
    currency: &str,
) -> chio_kernel::LiabilityProviderPolicyReference {
    let report = &provider.body.report;
    let policy = &report.policies[0];
    chio_kernel::LiabilityProviderPolicyReference {
        provider_id: report.provider_id.clone(),
        provider_record_id: provider.body.provider_record_id.clone(),
        display_name: report.display_name.clone(),
        jurisdiction: policy.jurisdiction.clone(),
        coverage_class: policy.coverage_classes[0],
        currency: currency.to_string(),
        required_evidence: policy.required_evidence.clone(),
        max_coverage_amount: policy.max_coverage_amount.as_ref().map(|amount| {
            chio_core::capability::MonetaryAmount {
                units: amount.units,
                currency: currency.to_string(),
            }
        }),
        claims_supported: policy.claims_supported,
        quote_ttl_seconds: policy.quote_ttl_seconds,
        bound_coverage_supported: report.support_boundary.bound_coverage_supported,
    }
}

fn sample_credit_scorecard_summary() -> chio_kernel::CreditScorecardSummary {
    chio_kernel::CreditScorecardSummary {
        matching_receipts: 1,
        returned_receipts: 1,
        matching_decisions: 0,
        returned_decisions: 0,
        currencies: vec!["USD".to_string()],
        mixed_currency_book: false,
        confidence: chio_kernel::CreditScorecardConfidence::High,
        band: chio_kernel::CreditScorecardBand::Prime,
        overall_score: 0.95,
        anomaly_count: 0,
        probationary: false,
    }
}

fn sample_risk_package(subject_key: &str) -> chio_kernel::SignedCreditProviderRiskPackage {
    let keypair = Keypair::generate();
    let exposure = chio_kernel::SignedExposureLedgerReport::sign(
        chio_kernel::ExposureLedgerReport {
            schema: chio_kernel::EXPOSURE_LEDGER_SCHEMA.to_string(),
            generated_at: 1,
            filters: chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            support_boundary: chio_kernel::ExposureLedgerSupportBoundary::default(),
            summary: chio_kernel::ExposureLedgerSummary {
                matching_receipts: 1,
                returned_receipts: 1,
                matching_decisions: 0,
                returned_decisions: 0,
                active_decisions: 0,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                currencies: vec!["USD".to_string()],
                mixed_currency_book: false,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            positions: vec![chio_kernel::ExposureLedgerCurrencyPosition {
                currency: "USD".to_string(),
                governed_max_exposure_units: 4_000,
                reserved_units: 0,
                settled_units: 4_000,
                pending_units: 0,
                failed_units: 0,
                provisional_loss_units: 0,
                recovered_units: 0,
                quoted_premium_units: 0,
                active_quoted_premium_units: 0,
            }],
            receipts: Vec::new(),
            decisions: Vec::new(),
        },
        &keypair,
    )
    .unwrap();
    let scorecard = chio_kernel::SignedCreditScorecardReport::sign(
        chio_kernel::CreditScorecardReport {
            schema: chio_kernel::CREDIT_SCORECARD_SCHEMA.to_string(),
            generated_at: 2,
            filters: chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            support_boundary: chio_kernel::CreditScorecardSupportBoundary::default(),
            summary: sample_credit_scorecard_summary(),
            reputation: chio_kernel::CreditScorecardReputationContext {
                effective_score: 0.95,
                probationary: false,
                resolved_tier: None,
                imported_signal_count: 0,
                accepted_imported_signal_count: 0,
            },
            positions: exposure.body.positions.clone(),
            probation: chio_kernel::CreditScorecardProbationStatus {
                probationary: false,
                reasons: Vec::new(),
                receipt_count: 1,
                span_days: 1,
                target_receipt_count: 1,
                target_span_days: 1,
            },
            dimensions: Vec::new(),
            anomalies: Vec::new(),
        },
        &keypair,
    )
    .unwrap();

    chio_kernel::SignedCreditProviderRiskPackage::sign(
        chio_kernel::CreditProviderRiskPackage {
            schema: chio_kernel::CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
            generated_at: 3,
            subject_key: subject_key.to_string(),
            filters: chio_kernel::CreditProviderRiskPackageQuery {
                agent_subject: Some(subject_key.to_string()),
                ..chio_kernel::CreditProviderRiskPackageQuery::default()
            },
            support_boundary: chio_kernel::CreditProviderRiskPackageSupportBoundary::default(),
            exposure,
            scorecard,
            facility_report: chio_kernel::CreditFacilityReport {
                schema: chio_kernel::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                generated_at: 3,
                filters: chio_kernel::ExposureLedgerQuery {
                    agent_subject: Some(subject_key.to_string()),
                    ..chio_kernel::ExposureLedgerQuery::default()
                },
                scorecard: sample_credit_scorecard_summary(),
                disposition: chio_kernel::CreditFacilityDisposition::Grant,
                prerequisites: chio_kernel::CreditFacilityPrerequisites {
                    minimum_runtime_assurance_tier:
                        chio_core::capability::RuntimeAssuranceTier::Verified,
                    runtime_assurance_met: true,
                    certification_required: false,
                    certification_met: true,
                    manual_review_required: false,
                },
                support_boundary: chio_kernel::CreditFacilitySupportBoundary::default(),
                terms: Some(chio_kernel::CreditFacilityTerms {
                    credit_limit: usd(4_000),
                    utilization_ceiling_bps: 8_000,
                    reserve_ratio_bps: 1_500,
                    concentration_cap_bps: 3_000,
                    ttl_seconds: 86_400,
                    capital_source: chio_kernel::CreditFacilityCapitalSource::OperatorInternal,
                }),
                findings: Vec::new(),
            },
            compliance_score: None,
            latest_facility: Some(chio_kernel::CreditProviderFacilitySnapshot {
                facility_id: "cfd-1".to_string(),
                issued_at: 3,
                expires_at: 4,
                disposition: chio_kernel::CreditFacilityDisposition::Grant,
                lifecycle_state: chio_kernel::CreditFacilityLifecycleState::Active,
                credit_limit: Some(usd(4_000)),
                supersedes_facility_id: None,
                signer_key: keypair.public_key().to_hex(),
            }),
            runtime_assurance: Some(chio_kernel::CreditRuntimeAssuranceState {
                governed_receipts: 1,
                runtime_assurance_receipts: 1,
                highest_tier: Some(chio_core::capability::RuntimeAssuranceTier::Verified),
                latest_schema: Some("chio.runtime-attestation.azure-maa.jwt.v1".to_string()),
                latest_verifier_family: Some(chio_core::AttestationVerifierFamily::AzureMaa),
                latest_verifier: Some("verifier.chio".to_string()),
                latest_evidence_sha256: Some("sha256-runtime".to_string()),
                observed_verifier_families: vec![chio_core::AttestationVerifierFamily::AzureMaa],
                stale: false,
            }),
            certification: chio_kernel::CreditCertificationState {
                required: false,
                state: None,
                artifact_id: None,
                checked_at: None,
                published_at: None,
            },
            recent_loss_history: chio_kernel::CreditRecentLossHistory {
                summary: chio_kernel::CreditRecentLossSummary {
                    matching_loss_events: 0,
                    returned_loss_events: 0,
                    failed_settlement_events: 0,
                    provisional_loss_events: 0,
                    recovered_events: 0,
                },
                entries: Vec::new(),
            },
            evidence_refs: Vec::new(),
        },
        &keypair,
    )
    .unwrap()
}

fn signed_liability_quote_request(
    quote_request_id: &str,
    provider: &chio_kernel::SignedLiabilityProvider,
    subject_key: &str,
    currency: &str,
) -> chio_kernel::SignedLiabilityQuoteRequest {
    sign_export(chio_kernel::LiabilityQuoteRequestArtifact {
        schema: chio_kernel::LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: quote_request_id.to_string(),
        issued_at: 1_700_000_100,
        provider_policy: provider_policy_reference(provider, currency),
        requested_coverage_amount: chio_core::capability::MonetaryAmount {
            units: 10_000,
            currency: currency.to_string(),
        },
        requested_effective_from: 1_700_010_000,
        requested_effective_until: 1_700_020_000,
        risk_package: sample_risk_package(subject_key),
        notes: Some("initial market inquiry".to_string()),
    })
}

fn signed_liability_quote_response(
    quote_response_id: &str,
    quote_request: chio_kernel::SignedLiabilityQuoteRequest,
    supersedes_quote_response_id: Option<&str>,
) -> chio_kernel::SignedLiabilityQuoteResponse {
    sign_export(chio_kernel::LiabilityQuoteResponseArtifact {
        schema: chio_kernel::LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        quote_response_id: quote_response_id.to_string(),
        issued_at: quote_request.body.issued_at + 120,
        quote_request,
        provider_quote_ref: format!("{}-provider-quote", quote_response_id),
        disposition: chio_kernel::LiabilityQuoteDisposition::Quoted,
        supersedes_quote_response_id: supersedes_quote_response_id.map(str::to_string),
        quoted_terms: Some(chio_kernel::LiabilityQuoteTerms {
            quoted_coverage_amount: usd(10_000),
            quoted_premium_amount: usd(500),
            quoted_deductible_amount: Some(usd(1_000)),
            expires_at: 1_700_003_000,
        }),
        decline_reason: None,
    })
}

fn sample_credit_facility(subject_key: &str) -> chio_kernel::SignedCreditFacility {
    sign_export(chio_kernel::CreditFacilityArtifact {
        schema: chio_kernel::CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id: "cfd-1".to_string(),
        issued_at: 1_700_000_100,
        expires_at: 1_700_086_500,
        lifecycle_state: chio_kernel::CreditFacilityLifecycleState::Active,
        supersedes_facility_id: None,
        report: chio_kernel::CreditFacilityReport {
            schema: chio_kernel::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_090,
            filters: chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            scorecard: sample_credit_scorecard_summary(),
            disposition: chio_kernel::CreditFacilityDisposition::Grant,
            prerequisites: chio_kernel::CreditFacilityPrerequisites {
                minimum_runtime_assurance_tier:
                    chio_core::capability::RuntimeAssuranceTier::Verified,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                manual_review_required: false,
            },
            support_boundary: chio_kernel::CreditFacilitySupportBoundary::default(),
            terms: Some(chio_kernel::CreditFacilityTerms {
                credit_limit: usd(12_000),
                utilization_ceiling_bps: 8_000,
                reserve_ratio_bps: 1_500,
                concentration_cap_bps: 3_000,
                ttl_seconds: 86_400,
                capital_source: chio_kernel::CreditFacilityCapitalSource::OperatorInternal,
            }),
            findings: Vec::new(),
        },
    })
}

fn sample_underwriting_input(subject_key: &str) -> chio_kernel::UnderwritingPolicyInput {
    chio_kernel::UnderwritingPolicyInput {
        schema: chio_kernel::UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at: 1_700_000_120,
        filters: chio_kernel::UnderwritingPolicyInputQuery {
            agent_subject: Some(subject_key.to_string()),
            ..chio_kernel::UnderwritingPolicyInputQuery::default()
        },
        taxonomy: chio_kernel::UnderwritingRiskTaxonomy::default(),
        receipts: chio_kernel::UnderwritingReceiptEvidence {
            matching_receipts: 2,
            returned_receipts: 2,
            allow_count: 2,
            deny_count: 0,
            cancelled_count: 0,
            incomplete_count: 0,
            governed_receipts: 2,
            approval_receipts: 1,
            approved_receipts: 1,
            call_chain_receipts: 0,
            runtime_assurance_receipts: 1,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            actionable_settlement_receipts: 0,
            metered_receipts: 0,
            actionable_metered_receipts: 0,
            shared_evidence_reference_count: 0,
            shared_evidence_proof_required_count: 0,
            receipt_refs: Vec::new(),
        },
        reputation: Some(chio_kernel::UnderwritingReputationEvidence {
            subject_key: subject_key.to_string(),
            effective_score: 0.94,
            probationary: false,
            resolved_tier: Some("prime".to_string()),
            imported_signal_count: 0,
            accepted_imported_signal_count: 0,
        }),
        certification: Some(chio_kernel::UnderwritingCertificationEvidence {
            tool_server_id: "server-1".to_string(),
            state: chio_kernel::UnderwritingCertificationState::Active,
            artifact_id: Some("cert-1".to_string()),
            verdict: Some("pass".to_string()),
            checked_at: Some(1_700_000_110),
            published_at: Some(1_700_000_111),
        }),
        runtime_assurance: Some(chio_kernel::UnderwritingRuntimeAssuranceEvidence {
            governed_receipts: 2,
            runtime_assurance_receipts: 1,
            highest_tier: Some(chio_core::capability::RuntimeAssuranceTier::Verified),
            latest_schema: Some("chio.runtime-attestation.enterprise.v1".to_string()),
            latest_verifier_family: Some(chio_core::AttestationVerifierFamily::EnterpriseVerifier),
            latest_verifier: Some("verifier.chio".to_string()),
            latest_evidence_sha256: Some("sha256-attest".to_string()),
            observed_verifier_families: vec![
                chio_core::AttestationVerifierFamily::EnterpriseVerifier,
            ],
        }),
        compliance_score: None,
        signals: Vec::new(),
    }
}

fn sample_underwriting_decision(subject_key: &str) -> chio_kernel::SignedUnderwritingDecision {
    sign_export(chio_kernel::UnderwritingDecisionArtifact {
        schema: chio_kernel::UNDERWRITING_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: "uwd-1".to_string(),
        issued_at: 1_700_000_130,
        evaluation: chio_kernel::UnderwritingDecisionReport {
            schema: chio_kernel::UNDERWRITING_DECISION_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_129,
            policy: chio_kernel::UnderwritingDecisionPolicy::default(),
            outcome: chio_kernel::UnderwritingDecisionOutcome::Approve,
            risk_class: chio_kernel::UnderwritingRiskClass::Baseline,
            suggested_ceiling_factor: Some(1.0),
            findings: Vec::new(),
            input: sample_underwriting_input(subject_key),
        },
        lifecycle_state: chio_kernel::UnderwritingDecisionLifecycleState::Active,
        review_state: chio_kernel::UnderwritingReviewState::Approved,
        supersedes_decision_id: None,
        budget: chio_kernel::UnderwritingBudgetRecommendation {
            action: chio_kernel::UnderwritingBudgetAction::Preserve,
            ceiling_factor: Some(1.0),
            rationale: "approved under baseline risk profile".to_string(),
        },
        premium: chio_kernel::UnderwritingPremiumQuote {
            state: chio_kernel::UnderwritingPremiumState::Quoted,
            basis_points: Some(500),
            quoted_amount: Some(usd(500)),
            rationale: "5% premium quote".to_string(),
        },
    })
}

fn sample_capital_book(subject_key: &str) -> chio_kernel::SignedCapitalBookReport {
    sign_export(chio_kernel::CapitalBookReport {
        schema: chio_kernel::CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
        generated_at: 1_700_000_140,
        query: chio_kernel::CapitalBookQuery {
            agent_subject: Some(subject_key.to_string()),
            ..chio_kernel::CapitalBookQuery::default()
        },
        subject_key: subject_key.to_string(),
        support_boundary: chio_kernel::CapitalBookSupportBoundary::default(),
        summary: chio_kernel::CapitalBookSummary {
            matching_receipts: 2,
            returned_receipts: 2,
            matching_facilities: 1,
            returned_facilities: 1,
            matching_bonds: 1,
            returned_bonds: 1,
            matching_loss_events: 1,
            returned_loss_events: 1,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            funding_sources: 1,
            ledger_events: 0,
            truncated_receipts: false,
            truncated_facilities: false,
            truncated_bonds: false,
            truncated_loss_events: false,
        },
        sources: vec![chio_kernel::CapitalBookSource {
            source_id: "facility-source-1".to_string(),
            kind: chio_kernel::CapitalBookSourceKind::FacilityCommitment,
            owner_role: chio_kernel::CapitalBookRole::OperatorTreasury,
            counterparty_role: chio_kernel::CapitalBookRole::AgentCounterparty,
            counterparty_id: subject_key.to_string(),
            currency: "USD".to_string(),
            jurisdiction: Some("us-ny".to_string()),
            capital_source: Some(chio_kernel::CreditFacilityCapitalSource::OperatorInternal),
            facility_id: Some("cfd-1".to_string()),
            bond_id: None,
            committed_amount: Some(usd(12_000)),
            held_amount: None,
            drawn_amount: None,
            disbursed_amount: Some(usd(1_000)),
            released_amount: None,
            repaid_amount: None,
            impaired_amount: Some(usd(1_000)),
            description: "facility commitment".to_string(),
        }],
        events: Vec::new(),
    })
}

fn signed_liability_pricing_authority(
    authority_id: &str,
    quote_request: chio_kernel::SignedLiabilityQuoteRequest,
    subject_key: &str,
    auto_bind_enabled: bool,
) -> chio_kernel::SignedLiabilityPricingAuthority {
    sign_export(chio_kernel::LiabilityPricingAuthorityArtifact {
        schema: chio_kernel::LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA.to_string(),
        authority_id: authority_id.to_string(),
        issued_at: 1_700_000_150,
        provider_policy: quote_request.body.provider_policy.clone(),
        quote_request,
        facility: sample_credit_facility(subject_key),
        underwriting_decision: sample_underwriting_decision(subject_key),
        capital_book: sample_capital_book(subject_key),
        envelope: chio_kernel::LiabilityPricingAuthorityEnvelope {
            kind: chio_kernel::LiabilityPricingAuthorityEnvelopeKind::ProviderDelegate,
            delegate_id: "pricing-delegate-1".to_string(),
            regulated_role: None,
            authority_chain_ref: Some("auth-chain-1".to_string()),
        },
        max_coverage_amount: usd(10_000),
        max_premium_amount: usd(500),
        expires_at: 1_700_003_000,
        auto_bind_enabled,
        notes: Some("automated pricing authority".to_string()),
    })
}

fn signed_liability_placement(
    placement_id: &str,
    quote_response: chio_kernel::SignedLiabilityQuoteResponse,
) -> chio_kernel::SignedLiabilityPlacement {
    sign_export(chio_kernel::LiabilityPlacementArtifact {
        schema: chio_kernel::LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
        placement_id: placement_id.to_string(),
        issued_at: quote_response.body.issued_at + 60,
        selected_coverage_amount: usd(10_000),
        selected_premium_amount: usd(500),
        effective_from: quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        quote_response,
        placement_ref: Some(format!("placement-{placement_id}")),
        notes: Some("operator selected quoted terms".to_string()),
    })
}

fn signed_liability_bound_coverage(
    bound_coverage_id: &str,
    placement: chio_kernel::SignedLiabilityPlacement,
) -> chio_kernel::SignedLiabilityBoundCoverage {
    sign_export(chio_kernel::LiabilityBoundCoverageArtifact {
        schema: chio_kernel::LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
        bound_coverage_id: bound_coverage_id.to_string(),
        issued_at: placement.body.issued_at + 30,
        placement,
        policy_number: format!("POL-{bound_coverage_id}"),
        carrier_reference: Some(format!("carrier-{bound_coverage_id}")),
        bound_at: 1_700_000_500,
        effective_from: 1_700_010_000,
        effective_until: 1_700_020_000,
        coverage_amount: usd(10_000),
        premium_amount: usd(500),
    })
}

fn signed_manual_review_auto_bind(
    decision_id: &str,
    authority: chio_kernel::SignedLiabilityPricingAuthority,
    quote_response: chio_kernel::SignedLiabilityQuoteResponse,
) -> chio_kernel::SignedLiabilityAutoBindDecision {
    sign_export(chio_kernel::LiabilityAutoBindDecisionArtifact {
        schema: chio_kernel::LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: decision_id.to_string(),
        issued_at: 1_700_000_220,
        authority,
        quote_response,
        disposition: chio_kernel::LiabilityAutoBindDisposition::ManualReview,
        findings: vec![chio_kernel::LiabilityAutoBindFinding {
            code: chio_kernel::LiabilityAutoBindReasonCode::AutoBindDisabled,
            description: "manual review required by operator policy".to_string(),
        }],
        placement: None,
        bound_coverage: None,
    })
}

#[test]
fn liability_provider_registry_supersedes_and_resolves_latest_provider() {
    let path = unique_db_path("chio-liability-provider-registry");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let initial = signed_liability_provider(
        "lpr-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let superseding = signed_liability_provider(
        "lpr-2",
        "carrier-alpha",
        1_700_000_120,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        Some("lpr-1"),
        true,
    );

    store.record_liability_provider(&initial).unwrap();
    store.record_liability_provider(&superseding).unwrap();

    let list = store
        .query_liability_providers(&chio_kernel::LiabilityProviderListQuery {
            provider_id: Some("carrier-alpha".to_string()),
            jurisdiction: Some("US-NY".to_string()),
            coverage_class: Some(chio_kernel::LiabilityCoverageClass::ToolExecution),
            currency: Some("usd".to_string()),
            lifecycle_state: None,
            limit: Some(10),
        })
        .unwrap();
    assert_eq!(list.summary.matching_providers, 2);
    assert_eq!(list.summary.active_providers, 1);
    assert_eq!(list.summary.superseded_providers, 1);
    assert_eq!(list.providers[0].provider.body.provider_record_id, "lpr-2");
    assert_eq!(list.providers[1].provider.body.provider_record_id, "lpr-1");
    assert_eq!(
        list.providers[1]
            .superseded_by_provider_record_id
            .as_deref(),
        Some("lpr-2")
    );

    let resolved = store
        .resolve_liability_provider(&chio_kernel::LiabilityProviderResolutionQuery {
            provider_id: "carrier-alpha".to_string(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: chio_kernel::LiabilityCoverageClass::ToolExecution,
            currency: "USD".to_string(),
        })
        .unwrap();
    assert_eq!(resolved.provider.body.provider_record_id, "lpr-2");
    assert_eq!(resolved.matched_policy.jurisdiction, "us-ny");

    let _ = fs::remove_file(path);
}

#[test]
fn liability_market_workflow_tracks_quote_to_bound_coverage_with_manual_review() {
    let path = unique_db_path("chio-liability-market-workflow");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let provider = signed_liability_provider(
        "lpr-workflow-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let quote_request =
        signed_liability_quote_request("lqr-workflow-1", &provider, "subject-1", "USD");
    let quote_response =
        signed_liability_quote_response("lqp-workflow-1", quote_request.clone(), None);
    let authority = signed_liability_pricing_authority(
        "lpa-workflow-1",
        quote_request.clone(),
        "subject-1",
        true,
    );
    let manual_review =
        signed_manual_review_auto_bind("lab-workflow-1", authority.clone(), quote_response.clone());
    let placement = signed_liability_placement("lpl-workflow-1", quote_response.clone());
    let bound_coverage = signed_liability_bound_coverage("lbc-workflow-1", placement.clone());

    store.record_liability_provider(&provider).unwrap();
    store
        .record_liability_quote_request(&quote_request)
        .unwrap();
    store
        .record_liability_quote_response(&quote_response)
        .unwrap();
    store
        .record_liability_pricing_authority(&authority)
        .unwrap();
    store
        .record_liability_auto_bind_decision(&manual_review)
        .unwrap();
    store.record_liability_placement(&placement).unwrap();
    store
        .record_liability_bound_coverage(&bound_coverage)
        .unwrap();

    let report = store
        .query_liability_market_workflows(&chio_kernel::LiabilityMarketWorkflowQuery {
            quote_request_id: None,
            provider_id: Some("carrier-alpha".to_string()),
            agent_subject: Some("subject-1".to_string()),
            jurisdiction: Some("US-NY".to_string()),
            coverage_class: Some(chio_kernel::LiabilityCoverageClass::ToolExecution),
            currency: Some("usd".to_string()),
            limit: Some(10),
        })
        .unwrap();

    assert_eq!(report.summary.matching_requests, 1);
    assert_eq!(report.summary.quote_responses, 1);
    assert_eq!(report.summary.quoted_responses, 1);
    assert_eq!(report.summary.pricing_authorities, 1);
    assert_eq!(report.summary.auto_bind_decisions, 1);
    assert_eq!(report.summary.manual_review_decisions, 1);
    assert_eq!(report.summary.auto_bound_decisions, 0);
    assert_eq!(report.summary.placements, 1);
    assert_eq!(report.summary.bound_coverages, 1);

    let row = report.workflows.first().unwrap();
    assert_eq!(row.quote_request.body.quote_request_id, "lqr-workflow-1");
    assert_eq!(
        row.latest_quote_response
            .as_ref()
            .unwrap()
            .body
            .quote_response_id,
        "lqp-workflow-1"
    );
    assert_eq!(
        row.pricing_authority.as_ref().unwrap().body.authority_id,
        "lpa-workflow-1"
    );
    assert_eq!(
        row.latest_auto_bind_decision
            .as_ref()
            .unwrap()
            .body
            .disposition,
        chio_kernel::LiabilityAutoBindDisposition::ManualReview
    );
    assert_eq!(
        row.placement.as_ref().unwrap().body.placement_id,
        "lpl-workflow-1"
    );
    assert_eq!(
        row.bound_coverage.as_ref().unwrap().body.bound_coverage_id,
        "lbc-workflow-1"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn liability_market_rejects_unsupported_requests_and_stale_active_quotes() {
    let path = unique_db_path("chio-liability-market-conflicts");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    let provider = signed_liability_provider(
        "lpr-conflict-1",
        "carrier-alpha",
        1_700_000_000,
        chio_kernel::LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    store.record_liability_provider(&provider).unwrap();

    let unsupported_request =
        signed_liability_quote_request("lqr-conflict-eur", &provider, "subject-1", "EUR");
    assert!(matches!(
        store.record_liability_quote_request(&unsupported_request),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("does not support")
    ));

    let quote_request =
        signed_liability_quote_request("lqr-conflict-1", &provider, "subject-1", "USD");
    store
        .record_liability_quote_request(&quote_request)
        .unwrap();

    let initial_response =
        signed_liability_quote_response("lqp-conflict-1", quote_request.clone(), None);
    store
        .record_liability_quote_response(&initial_response)
        .unwrap();

    let duplicate_active =
        signed_liability_quote_response("lqp-conflict-2", quote_request.clone(), None);
    assert!(matches!(
        store.record_liability_quote_response(&duplicate_active),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("already has active response")
    ));

    let superseding_response = signed_liability_quote_response(
        "lqp-conflict-3",
        quote_request.clone(),
        Some("lqp-conflict-1"),
    );
    store
        .record_liability_quote_response(&superseding_response)
        .unwrap();

    let stale_placement =
        signed_liability_placement("lpl-conflict-stale", initial_response.clone());
    assert!(matches!(
        store.record_liability_placement(&stale_placement),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message.contains("is superseded")
    ));

    let _ = fs::remove_file(path);
}

fn signed_credit_facility_fixture(
    subject_key: &str,
    facility_id: &str,
    issued_at: u64,
    expires_at: u64,
    disposition: chio_kernel::CreditFacilityDisposition,
    lifecycle_state: chio_kernel::CreditFacilityLifecycleState,
    supersedes_facility_id: Option<&str>,
) -> chio_kernel::SignedCreditFacility {
    let manual_review_required =
        disposition == chio_kernel::CreditFacilityDisposition::ManualReview;
    let terms = if disposition == chio_kernel::CreditFacilityDisposition::Deny {
        None
    } else {
        Some(chio_kernel::CreditFacilityTerms {
            credit_limit: usd(12_000),
            utilization_ceiling_bps: 8_000,
            reserve_ratio_bps: 1_500,
            concentration_cap_bps: 3_000,
            ttl_seconds: 86_400,
            capital_source: chio_kernel::CreditFacilityCapitalSource::OperatorInternal,
        })
    };

    sign_export(chio_kernel::CreditFacilityArtifact {
        schema: chio_kernel::CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id: facility_id.to_string(),
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_facility_id: supersedes_facility_id.map(str::to_string),
        report: chio_kernel::CreditFacilityReport {
            schema: chio_kernel::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
            generated_at: issued_at.saturating_sub(10),
            filters: chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                capability_id: Some(format!("cap-{subject_key}")),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            scorecard: sample_credit_scorecard_summary(),
            disposition,
            prerequisites: chio_kernel::CreditFacilityPrerequisites {
                minimum_runtime_assurance_tier:
                    chio_core::capability::RuntimeAssuranceTier::Verified,
                runtime_assurance_met: disposition != chio_kernel::CreditFacilityDisposition::Deny,
                certification_required: false,
                certification_met: true,
                manual_review_required,
            },
            support_boundary: chio_kernel::CreditFacilitySupportBoundary::default(),
            terms,
            findings: Vec::new(),
        },
    })
}

fn signed_underwriting_decision_fixture(
    subject_key: &str,
    decision_id: &str,
    issued_at: u64,
    outcome: chio_kernel::UnderwritingDecisionOutcome,
    review_state: chio_kernel::UnderwritingReviewState,
    lifecycle_state: chio_kernel::UnderwritingDecisionLifecycleState,
    supersedes_decision_id: Option<&str>,
    quoted_amount: Option<MonetaryAmount>,
) -> chio_kernel::SignedUnderwritingDecision {
    let (budget_action, ceiling_factor) = match outcome {
        chio_kernel::UnderwritingDecisionOutcome::Approve
        | chio_kernel::UnderwritingDecisionOutcome::StepUp => {
            (chio_kernel::UnderwritingBudgetAction::Preserve, Some(1.0))
        }
        chio_kernel::UnderwritingDecisionOutcome::ReduceCeiling => {
            (chio_kernel::UnderwritingBudgetAction::Reduce, Some(0.8))
        }
        chio_kernel::UnderwritingDecisionOutcome::Deny => {
            (chio_kernel::UnderwritingBudgetAction::Deny, None)
        }
    };

    let premium_state = if quoted_amount.is_some() {
        chio_kernel::UnderwritingPremiumState::Quoted
    } else {
        chio_kernel::UnderwritingPremiumState::NotApplicable
    };
    let risk_class = if outcome == chio_kernel::UnderwritingDecisionOutcome::Deny {
        chio_kernel::UnderwritingRiskClass::Guarded
    } else {
        chio_kernel::UnderwritingRiskClass::Baseline
    };

    sign_export(chio_kernel::UnderwritingDecisionArtifact {
        schema: chio_kernel::UNDERWRITING_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: decision_id.to_string(),
        issued_at,
        evaluation: chio_kernel::UnderwritingDecisionReport {
            schema: chio_kernel::UNDERWRITING_DECISION_REPORT_SCHEMA.to_string(),
            generated_at: issued_at.saturating_sub(1),
            policy: chio_kernel::UnderwritingDecisionPolicy::default(),
            outcome,
            risk_class,
            suggested_ceiling_factor: ceiling_factor,
            findings: Vec::new(),
            input: sample_underwriting_input(subject_key),
        },
        lifecycle_state,
        review_state,
        supersedes_decision_id: supersedes_decision_id.map(str::to_string),
        budget: chio_kernel::UnderwritingBudgetRecommendation {
            action: budget_action,
            ceiling_factor,
            rationale: format!("fixture decision for {decision_id}"),
        },
        premium: chio_kernel::UnderwritingPremiumQuote {
            state: premium_state,
            basis_points: quoted_amount.as_ref().map(|_| 500),
            quoted_amount,
            rationale: format!("fixture premium for {decision_id}"),
        },
    })
}

fn signed_credit_bond_fixture(
    subject_key: &str,
    facility_id: &str,
    bond_id: &str,
    issued_at: u64,
    expires_at: u64,
    disposition: chio_kernel::CreditBondDisposition,
    lifecycle_state: chio_kernel::CreditBondLifecycleState,
    supersedes_bond_id: Option<&str>,
) -> chio_kernel::SignedCreditBond {
    sign_export(chio_kernel::CreditBondArtifact {
        schema: chio_kernel::CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
        bond_id: bond_id.to_string(),
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_bond_id: supersedes_bond_id.map(str::to_string),
        report: chio_kernel::CreditBondReport {
            schema: chio_kernel::CREDIT_BOND_REPORT_SCHEMA.to_string(),
            generated_at: issued_at.saturating_sub(10),
            filters: chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                capability_id: Some(format!("cap-{subject_key}")),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            exposure: chio_kernel::ExposureLedgerSummary {
                matching_receipts: 2,
                returned_receipts: 2,
                matching_decisions: 1,
                returned_decisions: 1,
                active_decisions: 1,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                currencies: vec!["USD".to_string()],
                mixed_currency_book: false,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            scorecard: sample_credit_scorecard_summary(),
            disposition,
            prerequisites: chio_kernel::CreditBondPrerequisites {
                active_facility_required: true,
                active_facility_met: true,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                currency_coherent: true,
            },
            support_boundary: chio_kernel::CreditBondSupportBoundary::default(),
            latest_facility_id: Some(facility_id.to_string()),
            terms: None,
            findings: Vec::new(),
        },
    })
}

fn signed_credit_loss_lifecycle_fixture(
    subject_key: &str,
    facility_id: &str,
    bond_id: &str,
    event_id: &str,
    issued_at: u64,
    event_kind: chio_kernel::CreditLossLifecycleEventKind,
    projected_bond_lifecycle_state: chio_kernel::CreditBondLifecycleState,
    event_amount: MonetaryAmount,
) -> chio_kernel::SignedCreditLossLifecycle {
    sign_export(chio_kernel::CreditLossLifecycleArtifact {
        schema: chio_kernel::CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: event_id.to_string(),
        issued_at,
        bond_id: bond_id.to_string(),
        event_kind,
        projected_bond_lifecycle_state,
        reserve_control_source_id: None,
        authority_chain: Vec::new(),
        execution_window: None,
        rail: None,
        observed_execution: None,
        reconciled_state: None,
        execution_state: None,
        appeal_state: None,
        appeal_window_ends_at: None,
        description: Some(format!("fixture loss event for {bond_id}")),
        report: chio_kernel::CreditLossLifecycleReport {
            schema: chio_kernel::CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
            generated_at: issued_at.saturating_sub(1),
            query: chio_kernel::CreditLossLifecycleQuery {
                bond_id: bond_id.to_string(),
                event_kind,
                amount: Some(event_amount.clone()),
            },
            summary: chio_kernel::CreditLossLifecycleSummary {
                bond_id: bond_id.to_string(),
                facility_id: Some(facility_id.to_string()),
                capability_id: Some(format!("cap-{subject_key}")),
                agent_subject: Some(subject_key.to_string()),
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                current_bond_lifecycle_state: chio_kernel::CreditBondLifecycleState::Active,
                projected_bond_lifecycle_state,
                current_delinquent_amount: Some(event_amount.clone()),
                current_recovered_amount: None,
                current_written_off_amount: None,
                current_released_reserve_amount: None,
                current_slashed_reserve_amount: None,
                outstanding_delinquent_amount: Some(event_amount.clone()),
                releaseable_reserve_amount: None,
                reserve_control_source_id: None,
                execution_state: None,
                appeal_state: None,
                appeal_window_ends_at: None,
                event_amount: Some(event_amount),
            },
            support_boundary: chio_kernel::CreditLossLifecycleSupportBoundary::default(),
            findings: Vec::new(),
        },
    })
}

fn signed_liability_claim_package_fixture(
    claim_id: &str,
    bound_coverage: chio_kernel::SignedLiabilityBoundCoverage,
    bond: chio_kernel::SignedCreditBond,
    loss_event: chio_kernel::SignedCreditLossLifecycle,
    receipt_ids: Vec<String>,
) -> chio_kernel::SignedLiabilityClaimPackage {
    let subject_key = bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .risk_package
        .body
        .subject_key
        .clone();

    sign_export(chio_kernel::LiabilityClaimPackageArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
        claim_id: claim_id.to_string(),
        issued_at: bound_coverage.body.issued_at + 30,
        bound_coverage,
        exposure: sample_risk_package(&subject_key).body.exposure.clone(),
        bond,
        loss_event,
        claimant: subject_key,
        claim_event_at: 1_700_015_000,
        claim_amount: usd(5_000),
        claim_ref: Some(format!("claim-ref-{claim_id}")),
        narrative: "Fixture claim package describing the covered incident".to_string(),
        receipt_ids,
        evidence_refs: Vec::new(),
    })
}

fn signed_liability_claim_response_fixture(
    claim_response_id: &str,
    claim: chio_kernel::SignedLiabilityClaimPackage,
    covered_amount: MonetaryAmount,
) -> chio_kernel::SignedLiabilityClaimResponse {
    sign_export(chio_kernel::LiabilityClaimResponseArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        claim_response_id: claim_response_id.to_string(),
        issued_at: claim.body.issued_at + 20,
        claim,
        provider_response_ref: format!("provider-response-{claim_response_id}"),
        disposition: chio_kernel::LiabilityClaimResponseDisposition::Accepted,
        covered_amount: Some(covered_amount),
        response_note: Some("provider accepts a partial settlement".to_string()),
        denial_reason: None,
        evidence_refs: Vec::new(),
    })
}

fn signed_liability_claim_dispute_fixture(
    dispute_id: &str,
    provider_response: chio_kernel::SignedLiabilityClaimResponse,
) -> chio_kernel::SignedLiabilityClaimDispute {
    sign_export(chio_kernel::LiabilityClaimDisputeArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
        dispute_id: dispute_id.to_string(),
        issued_at: provider_response.body.issued_at + 20,
        provider_response,
        opened_by: "claimant@example.com".to_string(),
        reason: "covered amount does not reflect the full claim".to_string(),
        note: Some("fixture dispute".to_string()),
        evidence_refs: Vec::new(),
    })
}

fn signed_liability_claim_adjudication_fixture(
    adjudication_id: &str,
    dispute: chio_kernel::SignedLiabilityClaimDispute,
    awarded_amount: MonetaryAmount,
) -> chio_kernel::SignedLiabilityClaimAdjudication {
    sign_export(chio_kernel::LiabilityClaimAdjudicationArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
        adjudication_id: adjudication_id.to_string(),
        issued_at: dispute.body.issued_at + 20,
        dispute,
        adjudicator: "panel@example.com".to_string(),
        outcome: chio_kernel::LiabilityClaimAdjudicationOutcome::PartialSettlement,
        awarded_amount: Some(awarded_amount),
        note: Some("fixture adjudication".to_string()),
        evidence_refs: Vec::new(),
    })
}

fn signed_capital_execution_instruction_fixture(
    instruction_id: &str,
    subject_key: &str,
    amount: MonetaryAmount,
) -> chio_kernel::SignedCapitalExecutionInstruction {
    sign_export(chio_kernel::CapitalExecutionInstructionArtifact {
        schema: chio_kernel::CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        instruction_id: instruction_id.to_string(),
        issued_at: 1_700_000_900,
        query: chio_kernel::CapitalBookQuery {
            agent_subject: Some(subject_key.to_string()),
            ..chio_kernel::CapitalBookQuery::default()
        },
        subject_key: subject_key.to_string(),
        source_id: "facility-source-claim".to_string(),
        source_kind: chio_kernel::CapitalBookSourceKind::FacilityCommitment,
        governed_receipt_id: Some("rc-claim-1".to_string()),
        completion_flow_row_id: Some("economic-completion-flow:rc-claim-1".to_string()),
        action: chio_kernel::CapitalExecutionInstructionAction::TransferFunds,
        owner_role: chio_kernel::CapitalExecutionRole::OperatorTreasury,
        counterparty_role: chio_kernel::CapitalExecutionRole::AgentCounterparty,
        counterparty_id: subject_key.to_string(),
        amount: Some(amount),
        authority_chain: vec![chio_kernel::CapitalExecutionAuthorityStep {
            role: chio_kernel::CapitalExecutionRole::OperatorTreasury,
            principal_id: "treasury-1".to_string(),
            approved_at: 1_700_000_900,
            expires_at: 1_700_020_500,
            note: Some("fixture authority".to_string()),
        }],
        execution_window: chio_kernel::CapitalExecutionWindow {
            not_before: 1_700_010_000,
            not_after: 1_700_020_500,
        },
        rail: chio_kernel::CapitalExecutionRail {
            kind: chio_kernel::CapitalExecutionRailKind::Sandbox,
            rail_id: "rail-claim".to_string(),
            custody_provider_id: "custody-claim".to_string(),
            source_account_ref: Some("acct-src".to_string()),
            destination_account_ref: Some("acct-dst".to_string()),
            jurisdiction: Some("us-ny".to_string()),
        },
        intended_state: chio_kernel::CapitalExecutionIntendedState::PendingExecution,
        reconciled_state: chio_kernel::CapitalExecutionReconciledState::NotObserved,
        related_instruction_id: None,
        observed_execution: None,
        support_boundary: chio_kernel::CapitalExecutionInstructionSupportBoundary::default(),
        evidence_refs: Vec::new(),
        description: "fixture payout transfer".to_string(),
    })
}

fn signed_liability_claim_payout_instruction_fixture(
    payout_instruction_id: &str,
    adjudication: chio_kernel::SignedLiabilityClaimAdjudication,
) -> chio_kernel::SignedLiabilityClaimPayoutInstruction {
    let subject_key = adjudication
        .body
        .dispute
        .body
        .provider_response
        .body
        .claim
        .body
        .bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .risk_package
        .body
        .subject_key
        .clone();
    let payout_amount = adjudication.body.awarded_amount.clone().unwrap();
    let capital_instruction = signed_capital_execution_instruction_fixture(
        &format!("capital-{payout_instruction_id}"),
        &subject_key,
        payout_amount.clone(),
    );

    sign_export(chio_kernel::LiabilityClaimPayoutInstructionArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        payout_instruction_id: payout_instruction_id.to_string(),
        issued_at: 1_700_000_950,
        adjudication,
        capital_instruction,
        payout_amount,
        note: Some("fixture payout instruction".to_string()),
    })
}

fn signed_liability_claim_payout_receipt_fixture(
    payout_receipt_id: &str,
    payout_instruction: chio_kernel::SignedLiabilityClaimPayoutInstruction,
) -> chio_kernel::SignedLiabilityClaimPayoutReceipt {
    let observed_amount = payout_instruction.body.payout_amount.clone();

    sign_export(chio_kernel::LiabilityClaimPayoutReceiptArtifact {
        schema: chio_kernel::LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        payout_receipt_id: payout_receipt_id.to_string(),
        issued_at: 1_700_001_000,
        payout_instruction,
        payout_receipt_ref: format!("receipt-ref-{payout_receipt_id}"),
        reconciliation_state: chio_kernel::LiabilityClaimPayoutReconciliationState::Matched,
        observed_execution: chio_kernel::CapitalExecutionObservation {
            observed_at: 1_700_010_500,
            external_reference_id: format!("ext-{payout_receipt_id}"),
            amount: observed_amount,
        },
        note: Some("fixture payout receipt".to_string()),
    })
}

#[test]
fn underwriting_decision_report_tracks_supersession_and_appeal_filters() {
    let path = unique_db_path("chio-underwriting-decision-report");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let subject_key = "subject-underwriting";

    let initial = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-1",
        1_700_000_100,
        chio_kernel::UnderwritingDecisionOutcome::Approve,
        chio_kernel::UnderwritingReviewState::Approved,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        None,
        Some(usd(500)),
    );
    let replacement = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-2",
        1_700_000_200,
        chio_kernel::UnderwritingDecisionOutcome::ReduceCeiling,
        chio_kernel::UnderwritingReviewState::Approved,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        Some("uwd-report-1"),
        Some(usd(300)),
    );
    let denied = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-3",
        1_700_000_150,
        chio_kernel::UnderwritingDecisionOutcome::Deny,
        chio_kernel::UnderwritingReviewState::Denied,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        None,
        None,
    );

    store.record_underwriting_decision(&initial).unwrap();
    store.record_underwriting_decision(&replacement).unwrap();
    store.record_underwriting_decision(&denied).unwrap();

    let accepted_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-1".to_string(),
            requested_by: "analyst@example.com".to_string(),
            reason: "updated evidence package".to_string(),
            note: Some("replacement requested".to_string()),
        })
        .unwrap();
    store
        .resolve_underwriting_appeal(&chio_kernel::UnderwritingAppealResolveRequest {
            appeal_id: accepted_appeal.appeal_id.clone(),
            resolution: chio_kernel::UnderwritingAppealResolution::Accepted,
            resolved_by: "uw-lead@example.com".to_string(),
            note: Some("replacement decision issued".to_string()),
            replacement_decision_id: Some("uwd-report-2".to_string()),
        })
        .unwrap();

    let open_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-2".to_string(),
            requested_by: "subject@example.com".to_string(),
            reason: "requesting improved terms".to_string(),
            note: None,
        })
        .unwrap();
    let rejected_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-3".to_string(),
            requested_by: "subject@example.com".to_string(),
            reason: "seeking reconsideration".to_string(),
            note: Some("no new evidence".to_string()),
        })
        .unwrap();
    store
        .resolve_underwriting_appeal(&chio_kernel::UnderwritingAppealResolveRequest {
            appeal_id: rejected_appeal.appeal_id.clone(),
            resolution: chio_kernel::UnderwritingAppealResolution::Rejected,
            resolved_by: "uw-lead@example.com".to_string(),
            note: Some("original denial stands".to_string()),
            replacement_decision_id: None,
        })
        .unwrap();

    let report = store
        .query_underwriting_decisions(&chio_kernel::UnderwritingDecisionQuery {
            agent_subject: Some(subject_key.to_string()),
            limit: Some(10),
            ..chio_kernel::UnderwritingDecisionQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_decisions, 3);
    assert_eq!(report.summary.returned_decisions, 3);
    assert_eq!(report.summary.active_decisions, 2);
    assert_eq!(report.summary.superseded_decisions, 1);
    assert_eq!(report.summary.open_appeals, 1);
    assert_eq!(report.summary.accepted_appeals, 1);
    assert_eq!(report.summary.rejected_appeals, 1);
    assert_eq!(report.summary.total_quoted_premium_units, 800);
    assert_eq!(
        report.summary.total_quoted_premium_currency.as_deref(),
        Some("USD")
    );
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(800)
    );

    let initial_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-1")
        .unwrap();
    assert_eq!(
        initial_row.lifecycle_state,
        chio_kernel::UnderwritingDecisionLifecycleState::Superseded
    );
    assert_eq!(initial_row.open_appeal_count, 0);
    assert_eq!(
        initial_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Accepted)
    );

    let replacement_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-2")
        .unwrap();
    assert_eq!(
        replacement_row.lifecycle_state,
        chio_kernel::UnderwritingDecisionLifecycleState::Active
    );
    assert_eq!(replacement_row.open_appeal_count, 1);
    assert_eq!(
        replacement_row.latest_appeal_id.as_deref(),
        Some(open_appeal.appeal_id.as_str())
    );
    assert_eq!(
        replacement_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Open)
    );

    let denied_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-3")
        .unwrap();
    assert_eq!(
        denied_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Rejected)
    );

    let open_report = store
        .query_underwriting_decisions(&chio_kernel::UnderwritingDecisionQuery {
            agent_subject: Some(subject_key.to_string()),
            appeal_status: Some(chio_kernel::UnderwritingAppealStatus::Open),
            limit: Some(10),
            ..chio_kernel::UnderwritingDecisionQuery::default()
        })
        .unwrap();
    assert_eq!(open_report.summary.matching_decisions, 1);
    assert_eq!(open_report.summary.open_appeals, 1);
    assert_eq!(open_report.decisions.len(), 1);
    assert_eq!(
        open_report.decisions[0].decision.body.decision_id,
        "uwd-report-2"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn credit_facility_report_tracks_effective_lifecycle_states() {
    let path = unique_db_path("chio-credit-facility-report");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let subject_key = "subject-credit";
    let far_future = 4_102_444_800;

    let original = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-1",
        1_700_000_100,
        far_future,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );
    let replacement = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-2",
        1_700_000_200,
        far_future,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        Some("cfd-report-1"),
    );
    let denied = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-3",
        1_700_000_300,
        far_future,
        chio_kernel::CreditFacilityDisposition::Deny,
        chio_kernel::CreditFacilityLifecycleState::Denied,
        None,
    );
    let expired = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-4",
        1_700_000_400,
        1,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );
    let manual_review = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-5",
        1_700_000_500,
        far_future,
        chio_kernel::CreditFacilityDisposition::ManualReview,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );

    store.record_credit_facility(&original).unwrap();
    store.record_credit_facility(&replacement).unwrap();
    store.record_credit_facility(&denied).unwrap();
    store.record_credit_facility(&expired).unwrap();
    store.record_credit_facility(&manual_review).unwrap();

    let report = store
        .query_credit_facilities(&chio_kernel::CreditFacilityListQuery {
            agent_subject: Some(subject_key.to_string()),
            limit: Some(10),
            ..chio_kernel::CreditFacilityListQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_facilities, 5);
    assert_eq!(report.summary.returned_facilities, 5);
    assert_eq!(report.summary.active_facilities, 2);
    assert_eq!(report.summary.superseded_facilities, 1);
    assert_eq!(report.summary.denied_facilities, 1);
    assert_eq!(report.summary.expired_facilities, 1);
    assert_eq!(report.summary.granted_facilities, 3);
    assert_eq!(report.summary.manual_review_facilities, 1);
    assert_eq!(
        report.facilities[0].facility.body.facility_id,
        "cfd-report-5"
    );

    let original_row = report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == "cfd-report-1")
        .unwrap();
    assert_eq!(
        original_row.lifecycle_state,
        chio_kernel::CreditFacilityLifecycleState::Superseded
    );
    assert_eq!(
        original_row.superseded_by_facility_id.as_deref(),
        Some("cfd-report-2")
    );

    let expired_only = store
        .query_credit_facilities(&chio_kernel::CreditFacilityListQuery {
            agent_subject: Some(subject_key.to_string()),
            lifecycle_state: Some(chio_kernel::CreditFacilityLifecycleState::Expired),
            limit: Some(10),
            ..chio_kernel::CreditFacilityListQuery::default()
        })
        .unwrap();
    assert_eq!(expired_only.summary.matching_facilities, 1);
    assert_eq!(expired_only.summary.expired_facilities, 1);
    assert_eq!(
        expired_only.facilities[0].facility.body.facility_id,
        "cfd-report-4"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn liability_claim_lifecycle_persists_package_through_payout_receipt() {
    thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let path = unique_db_path("chio-liability-claim-lifecycle");
            let mut store = SqliteReceiptStore::open(&path).unwrap();
            let subject_key = "subject-claim";
            let far_future = 4_102_444_800;

            let provider = signed_liability_provider(
                "lpr-claim-1",
                "carrier-claim",
                1_700_000_000,
                chio_kernel::LiabilityProviderLifecycleState::Active,
                None,
                true,
            );
            let quote_request =
                signed_liability_quote_request("lqr-claim-1", &provider, subject_key, "USD");
            let quote_response =
                signed_liability_quote_response("lqp-claim-1", quote_request.clone(), None);
            let placement = signed_liability_placement("lpl-claim-1", quote_response.clone());
            let bound_coverage = signed_liability_bound_coverage("lbc-claim-1", placement.clone());

            let facility = signed_credit_facility_fixture(
                subject_key,
                "cfd-claim-1",
                1_700_000_100,
                far_future,
                chio_kernel::CreditFacilityDisposition::Grant,
                chio_kernel::CreditFacilityLifecycleState::Active,
                None,
            );
            let bond = signed_credit_bond_fixture(
                subject_key,
                "cfd-claim-1",
                "bond-claim-1",
                1_700_000_200,
                far_future,
                chio_kernel::CreditBondDisposition::Lock,
                chio_kernel::CreditBondLifecycleState::Active,
                None,
            );
            let loss_event = signed_credit_loss_lifecycle_fixture(
                subject_key,
                "cfd-claim-1",
                "bond-claim-1",
                "loss-claim-1",
                1_700_000_300,
                chio_kernel::CreditLossLifecycleEventKind::Delinquency,
                chio_kernel::CreditBondLifecycleState::Impaired,
                usd(5_000),
            );

            store.record_liability_provider(&provider).unwrap();
            store
                .record_liability_quote_request(&quote_request)
                .unwrap();
            store
                .record_liability_quote_response(&quote_response)
                .unwrap();
            store.record_liability_placement(&placement).unwrap();
            store
                .record_liability_bound_coverage(&bound_coverage)
                .unwrap();
            store.record_credit_facility(&facility).unwrap();
            store.record_credit_bond(&bond).unwrap();
            store.record_credit_loss_lifecycle(&loss_event).unwrap();

            store
                .append_chio_receipt(&sample_receipt_with_id("claim-rcpt-1"))
                .unwrap();
            store
                .append_chio_receipt(&sample_receipt_with_id("claim-rcpt-2"))
                .unwrap();

            let missing_receipt_claim = signed_liability_claim_package_fixture(
                "claim-missing-receipt",
                bound_coverage.clone(),
                bond.clone(),
                loss_event.clone(),
                vec!["missing-claim-receipt".to_string()],
            );
            assert!(matches!(
                store.record_liability_claim_package(&missing_receipt_claim),
                Err(chio_kernel::ReceiptStoreError::NotFound(message))
                    if message.contains("missing-claim-receipt")
            ));

            let claim = signed_liability_claim_package_fixture(
                "claim-1",
                bound_coverage.clone(),
                bond.clone(),
                loss_event.clone(),
                vec!["claim-rcpt-1".to_string(), "claim-rcpt-2".to_string()],
            );
            store.record_liability_claim_package(&claim).unwrap();
            assert!(matches!(
                store.record_liability_claim_package(&claim),
                Err(chio_kernel::ReceiptStoreError::Conflict(message))
                    if message.contains("already exists")
            ));

            let response =
                signed_liability_claim_response_fixture("claim-response-1", claim, usd(3_000));
            store.record_liability_claim_response(&response).unwrap();

            let dispute = signed_liability_claim_dispute_fixture("claim-dispute-1", response);
            store.record_liability_claim_dispute(&dispute).unwrap();

            let adjudication = signed_liability_claim_adjudication_fixture(
                "claim-adjudication-1",
                dispute,
                usd(4_000),
            );
            store
                .record_liability_claim_adjudication(&adjudication)
                .unwrap();

            let payout_instruction = signed_liability_claim_payout_instruction_fixture(
                "claim-payout-instruction-1",
                adjudication,
            );
            store
                .record_liability_claim_payout_instruction(&payout_instruction)
                .unwrap();

            let payout_receipt = signed_liability_claim_payout_receipt_fixture(
                "claim-payout-receipt-1",
                payout_instruction,
            );
            store
                .record_liability_claim_payout_receipt(&payout_receipt)
                .unwrap();

            let connection = store.connection().unwrap();
            for table in [
                "liability_claim_packages",
                "liability_claim_responses",
                "liability_claim_disputes",
                "liability_claim_adjudications",
                "liability_claim_payout_instructions",
                "liability_claim_payout_receipts",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 1, "expected one row in {table}");
            }

            let stored_claim_id: String = connection
                .query_row(
                    "SELECT claim_id
                     FROM liability_claim_payout_receipts
                     WHERE payout_receipt_id = ?1",
                    ["claim-payout-receipt-1"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored_claim_id, "claim-1");

            let _ = fs::remove_file(path);
        })
        .unwrap()
        .join()
        .unwrap();
}
