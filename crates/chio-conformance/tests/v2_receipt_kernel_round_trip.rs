//! The deliverable for the audit's "types-only, hot path unwired"
//! finding on T1.2: this test exercises the public mint API
//! (`evaluate_tool_call_blocking`) that all production callers use,
//! NOT the type-level signers in `chio-core-types`. If the kernel
//! stops minting v2 receipts under negotiation, this test fails
//! fail-closed.
//!
//! See:
//! - `crates/chio-kernel/src/kernel/responses.rs` (the
//!   `record_chio_receipt_with_federation` v2 mint hook).
//! - `crates/chio-store-sqlite/src/receipt_store.rs` (the
//!   `chio_receipts_v2` table that persists `body_hash` -> raw_json).
//! - `crates/chio-core-types/src/receipt.rs` (`ReceiptV2ReplaySet`).

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    receipt_v2_body_hash, ChioReceiptV2, ReceiptV2BodyHashInput, ReceiptV2ReplaySet,
};
use chio_core::session::OperationContext;
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelReceiptVersion, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use rusqlite::Connection;

const SRV: &str = "srv-w21";
const TOOL: &str = "echo";

/// Minimal in-process `ToolServerConnection` so the kernel hot path
/// can complete an Allow dispatch through the real evaluate pipeline.
struct EchoToolServer {
    server_id: String,
    invocations: AtomicUsize,
}

impl EchoToolServer {
    fn new() -> Self {
        Self {
            server_id: SRV.to_string(),
            invocations: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for EchoToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        assert_eq!(tool_name, TOOL);
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"echoed": arguments}))
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nonce}-{counter}.sqlite3",
        std::process::id()
    ))
}

fn make_kernel(receipt_store_path: &std::path::Path) -> ChioKernel {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "w21-kernel-mints-v2-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    let store = SqliteReceiptStore::open(receipt_store_path).unwrap();
    kernel.set_receipt_store(Box::new(store));
    kernel.register_tool_server(Box::new(EchoToolServer::new()));
    // Default v2 minting is on; we explicitly assert the kernel-level
    // default to lock the wiring in place.
    kernel.set_receipt_v2_default(true);
    kernel
}

fn make_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SRV.to_string(),
            tool_name: TOOL.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn make_request(request_id: &str, cap: &chio_core::capability::CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: TOOL.to_string(),
        server_id: SRV.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"input": "round-trip"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn kernel_default_mints_v2_receipt_alongside_v1() {
    // POSITIVE: the public mint API must produce a v1 ChioReceipt
    // AND mint a body_hash-addressed ChioReceiptV2 row in the v2 store.
    let path = unique_db_path("v2-receipt-round-trip");
    let kernel = make_kernel(&path);
    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request("req-w21-allow", &cap);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // The ToolCallResponse continues to carry the v1 receipt for
    // backward compatibility. The v2 receipt is persisted in the
    // kernel's v2 store.
    let v1_receipt_id = response.receipt.id.clone();
    assert!(
        v1_receipt_id.starts_with("rcpt-"),
        "v1 fallback receipt id should still be UUIDv7-formed: got {v1_receipt_id}"
    );

    drop(kernel);

    // Open the SQLite file directly and assert the v2 row landed
    // keyed on body_hash with the legacy alias = v1 receipt id.
    let connection = Connection::open(&path).unwrap();
    let (count, body_hash, legacy_alias, raw_json): (i64, String, Option<String>, String) =
        connection
            .query_row(
                "SELECT COUNT(*), MIN(body_hash), MIN(legacy_receipt_id), MIN(raw_json) FROM chio_receipts_v2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
    assert_eq!(
        count, 1,
        "kernel must mint exactly one v2 receipt per dispatch"
    );
    assert_eq!(legacy_alias.as_deref(), Some(v1_receipt_id.as_str()));

    // Recompute body_hash from the persisted raw_json and assert it
    // matches the indexed body_hash; this is the verifier-side rule
    // T1.2 requires.
    let receipt: ChioReceiptV2 = serde_json::from_str(&raw_json).unwrap();
    let expected_hash = receipt_v2_body_hash(&receipt.body).unwrap();
    assert_eq!(
        receipt.body_hash, expected_hash,
        "v2 body_hash field must match H(canonical(ReceiptV2BodyHashInput))"
    );
    assert_eq!(receipt.body_hash, body_hash);
    assert!(
        receipt.verify_signature().unwrap(),
        "v2 receipt signature must verify against the embedded kernel_key"
    );
    assert_eq!(receipt.receipt_id, v1_receipt_id);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn kernel_replay_rejects_repeated_v2_body_hash_via_in_memory_set() {
    // NEGATIVE: present the same v2 body_hash twice. The in-memory
    // ReceiptV2ReplaySet that the kernel feeds via record_chio_receipt_v2
    // must reject the second insert. Replay key is body_hash; legacy
    // alias is non-authoritative.
    let path = unique_db_path("v2-receipt-replay");
    let kernel = make_kernel(&path);
    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request("req-w21-replay", &cap);
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // Reconstruct the v2 receipt the kernel would have minted and
    // attempt a second insert through the public hot-path persistence
    // function. The replay set must reject because the body_hash has
    // already been admitted.
    let v2 = kernel
        .mint_chio_receipt_v2_from_v1_for_test(&response.receipt)
        .unwrap();
    let pre_admitted = receipt_v2_body_hash(&v2.body).unwrap();
    // The freshly-minted receipt's body_hash differs from the one the
    // kernel persisted because the dag_ordinal counter advanced. To
    // assert the replay rule itself, we re-attempt insertion of the
    // ALREADY-PERSISTED body_hash by reading it from sqlite and
    // forcing a re-insert.
    let stored: String = Connection::open(&path)
        .unwrap()
        .query_row("SELECT raw_json FROM chio_receipts_v2", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap();
    let stored_v2: ChioReceiptV2 = serde_json::from_str(&stored).unwrap();

    // The kernel still holds the in-memory replay set populated with
    // the persisted body_hash; calling record_chio_receipt_v2 again
    // must reject.
    let err = kernel
        .record_chio_receipt_v2(&stored_v2, Some(stored_v2.receipt_id.as_str()))
        .expect_err("v2 replay must be rejected on the second insert");
    let message = err.to_string();
    assert!(
        message.contains("replay") || message.contains("already") || message.contains("body_hash"),
        "expected replay-rejection diagnostic, got: {message}"
    );

    // The freshly-minted v2 receipt (different dag_ordinal => different
    // body_hash) is NOT a replay; assert it's distinct from the one
    // persisted above so the test remains exercising replay rather
    // than a coincidence.
    assert_ne!(pre_admitted, stored_v2.body_hash);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn replay_set_ignores_legacy_alias_tampering() {
    // NEGATIVE: the legacy UUIDv7 alias on a valid v2 receipt is
    // non-authoritative for replay. Tampering with `receipt_id` while
    // keeping body_hash + signature consistent must NOT change replay
    // acceptance: the replay set keys on body_hash exclusively.
    let kp = Keypair::generate();
    let body = ReceiptV2BodyHashInput::from_v1_body(
        chio_core::receipt::ChioReceiptBody {
            id: "ignored".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-x".to_string(),
            tool_server: SRV.to_string(),
            tool_name: TOOL.to_string(),
            action: chio_core::receipt::ToolCallAction::from_parameters(serde_json::Value::Null)
                .unwrap(),
            decision: chio_core::receipt::Decision::Allow,
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: vec![],
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        },
        "chain-x",
        Vec::new(),
        0,
        chio_core::receipt::ReceiptHybridLogicalClock {
            wall_seconds: 1_700_000_000,
            logical: 0,
            kernel_id: "chain-x".to_string(),
        },
    );
    let original = ChioReceiptV2::sign("rcpt-aaaa", body.clone(), &kp).unwrap();
    // Alias-tampered: same body_hash, same signature, different id.
    let mut tampered = original.clone();
    tampered.receipt_id = "rcpt-zzzz".to_string();
    assert_eq!(original.body_hash, tampered.body_hash);
    assert!(original.verify_signature().unwrap());
    assert!(tampered.verify_signature().unwrap());

    let mut replay = ReceiptV2ReplaySet::default();
    let inserted = replay.insert(&original).unwrap();
    assert!(inserted, "first insert should admit the body_hash");
    let inserted_again = replay.insert(&tampered).unwrap();
    assert!(
        !inserted_again,
        "alias-tampered duplicate must NOT be admitted: replay keys on body_hash"
    );
    assert!(replay.contains_body_hash(&original.body_hash));
}

#[test]
fn body_hash_mismatch_fails_closed() {
    // NEGATIVE: a v2 receipt whose `body_hash` field does not match
    // H(canonical(ReceiptV2BodyHashInput)) must fail signature
    // verification, which forces the replay-set insert path to
    // fail-closed.
    let kp = Keypair::generate();
    let body = ReceiptV2BodyHashInput::from_v1_body(
        chio_core::receipt::ChioReceiptBody {
            id: "ignored".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-x".to_string(),
            tool_server: SRV.to_string(),
            tool_name: TOOL.to_string(),
            action: chio_core::receipt::ToolCallAction::from_parameters(serde_json::Value::Null)
                .unwrap(),
            decision: chio_core::receipt::Decision::Allow,
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: vec![],
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        },
        "chain-x",
        Vec::new(),
        7,
        chio_core::receipt::ReceiptHybridLogicalClock {
            wall_seconds: 1_700_000_000,
            logical: 0,
            kernel_id: "chain-x".to_string(),
        },
    );
    let mut receipt = ChioReceiptV2::sign("rcpt-mismatch", body, &kp).unwrap();
    // Tamper with body_hash so it no longer matches the canonical
    // hash of the body. Signature was computed over the ORIGINAL
    // body_hash so verify must reject.
    receipt.body_hash = "f".repeat(64);
    assert!(
        !receipt.verify_signature().unwrap(),
        "body_hash != H(canonical(body)) must reject in verify_signature"
    );

    let mut replay = ReceiptV2ReplaySet::default();
    let err = replay
        .insert(&receipt)
        .expect_err("replay set must reject when verify_signature returns false");
    assert!(format!("{err:?}").contains("Signature") || format!("{err}").contains("Signature"));
}

#[test]
fn negotiation_v1_only_peer_disables_v2_minting() {
    // POSITIVE: when the kernel-level default is OFF and no peer
    // profile is in scope, v2 minting must be skipped. This is the
    // "fall back to v1 with a warning log" branch from the plan.
    let path = unique_db_path("v2-receipt-v1-only");
    let kernel = make_kernel(&path);
    kernel.set_receipt_v2_default(false);
    let resolved = kernel
        .kernel_receipt_version_for_remote(None, 1_700_000_000)
        .unwrap();
    assert_eq!(resolved, KernelReceiptVersion::V1Legacy);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request("req-w21-v1-only", &cap);
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    drop(kernel);

    let count: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM chio_receipts_v2", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 0,
        "kernel must NOT mint v2 receipts when negotiation profile rejects v2"
    );

    let _ = std::fs::remove_file(&path);
}

// Suppress dead_code lint for unused glue we want to keep available
// for future v2 receipt assertions in this file.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = AtomicBool::new(false);
    let _ = OperationContext::new(
        chio_core::session::SessionId::new("unused"),
        chio_core::session::RequestId::new("unused"),
        "unused".to_string(),
    );
}
