#![allow(unused_imports)]

pub(super) use std::sync::{Arc, Barrier};
pub(super) use std::thread;
pub(super) use std::time::Duration;
pub(super) use std::time::{SystemTime, UNIX_EPOCH};

pub(super) use chio_core::canonical::{canonical_json_bytes, CanonicalBytes};
pub(super) use chio_core::capability::{
    governance::{
        GovernedCallChainContext, GovernedCallChainProvenance, GovernedProvenanceEvidenceClass,
        MeteredBillingQuote, MeteredSettlementMode,
    },
    scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
pub(super) use chio_core::crypto::Keypair;
#[cfg(feature = "pq")]
pub(super) use chio_core::crypto::{Ed25519Backend, HybridBackend, MlDsa65Backend, SigningBackend};
pub(super) use chio_core::merkle::MerkleTree;
pub(super) use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    economics::EconomicAmountBoundsReceiptMetadata, economics::EconomicAuthorizationMode,
    economics::EconomicAuthorizationReceiptMetadata,
    economics::EconomicAuthorizationReceiptMetadataVersion,
    economics::EconomicBudgetReceiptMetadata, economics::EconomicMerchantReceiptMetadata,
    economics::EconomicMeteringReceiptMetadata, economics::EconomicPayeeReceiptMetadata,
    economics::EconomicPayerReceiptMetadata, economics::EconomicPricingBasisReceiptMetadata,
    economics::EconomicRailReceiptMetadata, economics::EconomicSettlementReceiptMetadata,
    economics::FinancialReceiptMetadata, economics::SettlementStatus,
    governance::GovernedApprovalReceiptMetadata, governance::GovernedTransactionReceiptMetadata,
    governance::MeteredBillingReceiptMetadata, lineage::ChildRequestReceipt,
    lineage::ChildRequestReceiptBody, lineage::ReceiptLineageEndpoints,
    lineage::ReceiptLineageRelationKind, lineage::ReceiptLineageStatement,
    lineage::ReceiptLineageStatementBody, lineage::SignedExportEnvelope,
    metadata::ReceiptAttributionMetadata,
};
pub(super) use chio_core::session::{
    OperationKind, OperationTerminalState, RequestId, RequestLineageMode, RequestLineageRecord,
    SessionAnchorReference, SessionId,
};
pub(super) use chio_kernel::checkpoint::build_checkpoint_publication;
pub(super) use chio_kernel::{
    build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof, AnalyticsTimeBucket,
    BehavioralFeedQuery, EvidenceExportQuery, MeteredBillingEvidenceRecord,
    MeteredBillingReconciliationState, OperatorReportQuery, ReceiptAnalyticsQuery,
    SettlementReconciliationState,
};

pub(super) use super::super::*;

pub(super) use chio_test_support::prelude::*;

pub(super) fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

pub(super) fn sample_receipt() -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-test-001".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({})),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap()
}

pub(super) fn valid_tool_action(parameters: serde_json::Value) -> ToolCallAction {
    ToolCallAction::from_parameters(parameters).test_unwrap()
}

pub(super) fn sample_child_receipt() -> ChildRequestReceipt {
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
    .test_unwrap()
}

#[cfg(feature = "pq")]
pub(super) fn hybrid_backend(seed: [u8; 32]) -> HybridBackend {
    let keypair = Keypair::generate();
    let pq = MlDsa65Backend::from_seed(&seed);
    HybridBackend::new(Box::new(Ed25519Backend::new(keypair)), pq).test_unwrap()
}

#[cfg(feature = "pq")]
pub(super) fn sample_hybrid_receipt() -> ChioReceipt {
    let backend = hybrid_backend([7u8; 32]);
    ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: "rcpt-test-hybrid-store-001".to_string(),
            timestamp: 3,
            capability_id: "cap-hybrid-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({"hybrid": true})),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-hybrid-1".to_string(),
            policy_hash: "policy-hybrid-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: backend.public_key(),
            bbs_projection_version: None,
        },
        &backend,
    )
    .test_unwrap()
}

#[cfg(feature = "pq")]
pub(super) fn sample_hybrid_child_receipt() -> ChildRequestReceipt {
    let backend = hybrid_backend([8u8; 32]);
    ChildRequestReceipt::sign_with_backend(
        ChildRequestReceiptBody {
            id: "child-rcpt-test-hybrid-store-001".to_string(),
            timestamp: 4,
            session_id: SessionId::new("sess-hybrid-1"),
            parent_request_id: RequestId::new("parent-hybrid-1"),
            request_id: RequestId::new("child-hybrid-1"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-hybrid-1".to_string(),
            policy_hash: "policy-hybrid-1".to_string(),
            metadata: None,
            kernel_key: backend.public_key(),
        },
        &backend,
    )
    .test_unwrap()
}

pub(super) fn request_lineage_json(
    request_id: &str,
    session_anchor_id: &str,
    parent_request_id: Option<&str>,
) -> serde_json::Value {
    let mut record = RequestLineageRecord::new(
        RequestId::new(request_id),
        SessionAnchorReference::new(session_anchor_id, format!("{session_anchor_id}-hash")),
        OperationKind::ToolCall,
        if parent_request_id.is_some() {
            RequestLineageMode::LocalChild
        } else {
            RequestLineageMode::Root
        },
        1_710_000_000,
    );
    if let Some(parent_request_id) = parent_request_id {
        record = record.with_parent_request_id(RequestId::new(parent_request_id));
    }

    serde_json::to_value(record).test_unwrap()
}

pub(super) fn sample_receipt_with_id(id: &str) -> ChioReceipt {
    sample_receipt_with_id_and_timestamp(id, 1)
}

pub(super) fn sample_receipt_with_id_and_timestamp(id: &str, timestamp: u64) -> ChioReceipt {
    let keypair = receipt_test_keypair();
    sample_receipt_with_keypair(id, timestamp, &keypair)
}

pub(super) fn sample_receipt_with_keypair(
    id: &str,
    timestamp: u64,
    keypair: &Keypair,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({"receipt": id})),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_unwrap()
}

/// Thin wrapper over `sample_receipt_with_keypair` that pins the receipt body
/// `timestamp` (which drives retention aging). `seq` disambiguates receipts
/// that share a timestamp by folding into the receipt id, so each row is unique.
pub(super) fn sample_receipt_with_keypair_and_timestamp(
    id: &str,
    seq: u64,
    timestamp: u64,
    keypair: &Keypair,
) -> ChioReceipt {
    sample_receipt_with_keypair(&format!("{id}-{seq}"), timestamp, keypair)
}

pub(super) fn sample_receipt_with_keypair_and_tenant(
    id: &str,
    timestamp: u64,
    tenant_id: &str,
    keypair: &Keypair,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: format!("cap-{id}"),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({"receipt": id})),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: Some(tenant_id.to_string()),
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_unwrap()
}

pub(super) fn receipt_test_keypair() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

pub(super) fn signer(keypair: &Keypair, max_batch: u64) -> BackgroundCheckpointSigner {
    BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch,
    }
}

pub(super) fn sample_child_receipt_with_id_and_timestamp(
    id: &str,
    timestamp: u64,
) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    sample_child_receipt_with_keypair_and_timestamp(id, timestamp, &keypair)
}

pub(super) fn sample_child_receipt_with_keypair_and_timestamp(
    id: &str,
    timestamp: u64,
    keypair: &Keypair,
) -> ChildRequestReceipt {
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp,
            session_id: SessionId::new("sess-1"),
            parent_request_id: RequestId::new("parent-1"),
            request_id: RequestId::new(format!("child-{id}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{id}"),
            policy_hash: "policy-1".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        keypair,
    )
    .test_unwrap()
}

/// Thin wrapper over `sample_child_receipt_with_keypair_and_timestamp` that
/// folds `seq` into the receipt id, mirroring
/// `sample_receipt_with_keypair_and_timestamp`. `seq` disambiguates receipts
/// that share a timestamp band so each row is unique.
pub(super) fn sample_child_receipt_with_keypair_seq_and_timestamp(
    id: &str,
    seq: u64,
    timestamp: u64,
    keypair: &Keypair,
) -> ChildRequestReceipt {
    sample_child_receipt_with_keypair_and_timestamp(&format!("{id}-{seq}"), timestamp, keypair)
}

pub(super) fn canonical_receipt_bytes(
    store: &SqliteReceiptStore,
    start_seq: u64,
    end_seq: u64,
) -> Vec<Vec<u8>> {
    store
        .receipts_canonical_bytes_range(start_seq, end_seq)
        .test_unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect()
}

pub(super) fn insert_checkpoint_row(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
) {
    insert_checkpoint_row_with_statement_json(
        store,
        checkpoint,
        batch_end_seq,
        &serde_json::to_string(&checkpoint.body).test_unwrap(),
    );
}

pub(super) fn insert_checkpoint_row_with_statement_json(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
    statement_json: &str,
) {
    store
        .connection()
        .test_unwrap()
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
        .test_unwrap();
}

pub(super) fn load_claim_log_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, String, String, u64, u64)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp
            FROM claim_receipt_log_entries
            ORDER BY entry_seq ASC
            "#,
        )
        .test_unwrap();
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
        .test_unwrap();
    rows.map(|row| {
        let (entry_seq, receipt_id, receipt_kind, source_seq, timestamp) = row.test_unwrap();
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

pub(super) fn load_claim_log_identity(
    store: &SqliteReceiptStore,
    receipt_id: &str,
) -> (Option<String>, Option<String>) {
    let connection = store.connection().test_unwrap();
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
        .test_unwrap()
}

pub(super) fn tamper_persisted_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;")
        .test_unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .test_unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).test_unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).test_unwrap();
    connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
}

pub(super) fn tamper_claim_log_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;")
        .test_unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM claim_receipt_log_entries WHERE receipt_id = ?1 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .test_unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).test_unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).test_unwrap();
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
}

pub(super) fn load_checkpoint_tree_head_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, u64, u64, Option<String>)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256
            FROM checkpoint_tree_heads
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256) =
            row.test_unwrap();
        (
            checkpoint_seq as u64,
            batch_start_seq as u64,
            tree_size as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

pub(super) fn load_checkpoint_predecessor_witness_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, u64, String)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256
            FROM checkpoint_predecessor_witnesses
            ORDER BY witness_checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256) =
            row.test_unwrap();
        (
            predecessor_checkpoint_seq as u64,
            witness_checkpoint_seq as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

type CheckpointPublicationMetadataRow = (
    u64,
    String,
    String,
    u64,
    String,
    u64,
    u64,
    u64,
    Option<String>,
);

pub(super) fn load_checkpoint_publication_metadata_rows(
    store: &SqliteReceiptStore,
) -> Vec<CheckpointPublicationMetadataRow> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, publication_schema, merkle_root, published_at, kernel_key,
                   log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256
            FROM checkpoint_publication_metadata
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
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
        .test_unwrap();
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
        ) = row.test_unwrap();
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

pub(super) fn load_checkpoint_publication_trust_anchor_binding_rows(
    store: &SqliteReceiptStore,
) -> Vec<(
    u64,
    chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding,
)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, binding_json
            FROM checkpoint_publication_trust_anchor_bindings
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .test_unwrap();
    rows.map(|row| {
        let (checkpoint_seq, binding_json) = row.test_unwrap();
        (
            checkpoint_seq as u64,
            serde_json::from_str::<
                chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding,
            >(&binding_json)
            .test_unwrap(),
        )
    })
    .collect()
}

pub(super) fn seed_pre_projection_store(
    path: &std::path::Path,
    tool_receipts: &[ChioReceipt],
    child_receipts: &[ChildRequestReceipt],
    checkpoints: &[chio_kernel::KernelCheckpoint],
) {
    let mut connection = rusqlite::Connection::open(path).test_unwrap();
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
        .test_unwrap();

    let tx = connection.transaction().test_unwrap();
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
                support::decision_kind(receipt.decision.as_ref()),
                receipt.policy_hash,
                receipt.content_hash,
                serde_json::to_string(receipt).test_unwrap(),
            ],
        )
        .test_unwrap();
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
                serde_json::to_string(receipt).test_unwrap(),
            ],
        )
        .test_unwrap();
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
                serde_json::to_string(&checkpoint.body).test_unwrap(),
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )
        .test_unwrap();
    }
    tx.commit().test_unwrap();
}

pub(super) fn sign_export<T>(body: T) -> SignedExportEnvelope<T>
where
    T: serde::Serialize + Clone,
{
    let keypair = Keypair::generate();
    SignedExportEnvelope::sign(body, &keypair).test_unwrap()
}

pub(super) fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

pub(super) fn sample_liability_provider_report(
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

pub(super) fn signed_liability_provider(
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

pub(super) fn provider_policy_reference(
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
            chio_core::capability::scope::MonetaryAmount {
                units: amount.units,
                currency: currency.to_string(),
            }
        }),
        claims_supported: policy.claims_supported,
        quote_ttl_seconds: policy.quote_ttl_seconds,
        bound_coverage_supported: report.support_boundary.bound_coverage_supported,
    }
}

pub(super) fn sample_credit_scorecard_summary() -> chio_kernel::CreditScorecardSummary {
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

pub(super) fn sample_risk_package(
    subject_key: &str,
) -> chio_kernel::SignedCreditProviderRiskPackage {
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
    .test_unwrap();
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
    .test_unwrap();

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
                        chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
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
                highest_tier: Some(
                    chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
                ),
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
    .test_unwrap()
}

pub(super) fn signed_liability_quote_request(
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
        requested_coverage_amount: chio_core::capability::scope::MonetaryAmount {
            units: 10_000,
            currency: currency.to_string(),
        },
        requested_effective_from: 1_700_010_000,
        requested_effective_until: 1_700_020_000,
        risk_package: sample_risk_package(subject_key),
        notes: Some("initial market inquiry".to_string()),
    })
}

pub(super) fn signed_liability_quote_response(
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

pub(super) fn sample_credit_facility(subject_key: &str) -> chio_kernel::SignedCreditFacility {
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
                    chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
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

pub(super) fn sample_underwriting_input(subject_key: &str) -> chio_kernel::UnderwritingPolicyInput {
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
            highest_tier: Some(
                chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
            ),
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

pub(super) fn sample_underwriting_decision(
    subject_key: &str,
) -> chio_kernel::SignedUnderwritingDecision {
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

pub(super) fn sample_capital_book(subject_key: &str) -> chio_kernel::SignedCapitalBookReport {
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

pub(super) fn signed_liability_pricing_authority(
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

pub(super) fn signed_liability_placement(
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

pub(super) fn signed_liability_bound_coverage(
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

pub(super) fn signed_manual_review_auto_bind(
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

pub(super) fn signed_credit_facility_fixture(
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
                    chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
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

#[allow(clippy::too_many_arguments)]
pub(super) fn signed_underwriting_decision_fixture(
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

#[allow(clippy::too_many_arguments)]
pub(super) fn signed_credit_bond_fixture(
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

#[allow(clippy::too_many_arguments)]
pub(super) fn signed_credit_loss_lifecycle_fixture(
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

pub(super) fn signed_liability_claim_package_fixture(
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

pub(super) fn signed_liability_claim_response_fixture(
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

pub(super) fn signed_liability_claim_dispute_fixture(
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

pub(super) fn signed_liability_claim_adjudication_fixture(
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
        decision_rule_ref: None,
        roster_anchor_ref: None,
        evidence_refs: Vec::new(),
    })
}

pub(super) fn signed_capital_execution_instruction_fixture(
    instruction_id: &str,
    subject_key: &str,
    amount: MonetaryAmount,
) -> chio_kernel::SignedCapitalExecutionInstruction {
    let treasury = Keypair::generate();
    let custodian = Keypair::generate();
    let custodian_id = custodian.public_key().to_hex();
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
        authority_chain: vec![
            chio_kernel::CapitalExecutionAuthorityStep::signed(
                chio_kernel::CapitalExecutionRole::OperatorTreasury,
                &treasury,
                1_700_000_900,
                1_700_020_500,
                Some("fixture authority".to_string()),
            )
            .test_unwrap(),
            chio_kernel::CapitalExecutionAuthorityStep::signed(
                chio_kernel::CapitalExecutionRole::Custodian,
                &custodian,
                1_700_000_900,
                1_700_020_500,
                Some("fixture custody authority".to_string()),
            )
            .test_unwrap(),
        ],
        execution_window: chio_kernel::CapitalExecutionWindow {
            not_before: 1_700_010_000,
            not_after: 1_700_020_500,
        },
        rail: chio_kernel::CapitalExecutionRail {
            kind: chio_kernel::CapitalExecutionRailKind::Sandbox,
            rail_id: "rail-claim".to_string(),
            custody_provider_id: custodian_id,
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

pub(super) fn signed_liability_claim_payout_instruction_fixture(
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
    let payout_amount = adjudication.body.awarded_amount.clone().test_unwrap();
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

pub(super) fn signed_liability_claim_payout_receipt_fixture(
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

pub(super) const TRANSPARENCY_PROJECTION_GUARD_TRIGGER_NAMES: &[&str] = &[
    "chio_tool_receipts_reject_update",
    "chio_tool_receipts_reject_delete",
    "chio_child_receipts_reject_update",
    "chio_child_receipts_reject_delete",
    "claim_receipt_log_entries_reject_update",
    "claim_receipt_log_entries_reject_delete",
    "checkpoint_tree_heads_reject_update",
    "checkpoint_tree_heads_reject_delete",
    "checkpoint_predecessor_witnesses_reject_update",
    "checkpoint_predecessor_witnesses_reject_delete",
    "checkpoint_publication_metadata_reject_update",
    "checkpoint_publication_metadata_reject_delete",
    "checkpoint_publication_trust_anchor_bindings_reject_update",
    "checkpoint_publication_trust_anchor_bindings_reject_delete",
];

/// The `receipt_id` of the earliest-appended live tool receipt (lowest
/// `seq`). Used by retention tests to attach reconciliation rows to a
/// receipt that will fall inside an archival watermark.
pub(super) fn first_tool_receipt_id(
    store: &SqliteReceiptStore,
) -> Result<String, ReceiptStoreError> {
    let connection = store.reader_connection_for_test()?;
    Ok(connection.query_row(
        "SELECT receipt_id FROM chio_tool_receipts ORDER BY seq LIMIT 1",
        [],
        |row| row.get(0),
    )?)
}

pub(super) fn trigger_exists(store: &SqliteReceiptStore, name: &str) -> bool {
    let connection = store.connection().test_unwrap();
    let row: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            rusqlite::params![name],
            |row| row.get(0),
        )
        .optional()
        .test_unwrap();
    row.is_some()
}

pub(super) fn tamper_canonical_bytes_of_uncheckpointed_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    // Tamper the canonical-bytes (`raw_json`) columns on BOTH the
    // `chio_tool_receipts` source row and the `claim_receipt_log_entries`
    // projection row using the same mutation. Tampering only one of the
    // two would trip the
    // `validate_claim_receipt_log_projection_current()` drift check
    // before the uncheckpointed canonical-bytes range scan runs, masking
    // the corruption signal we are trying to surface from
    // `receipt_store_health()`.
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;
            DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;
            "#,
        )
        .test_unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .test_unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).test_unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).test_unwrap();
    connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 \
                 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
}
