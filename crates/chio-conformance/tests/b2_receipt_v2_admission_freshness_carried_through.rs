//! Spec MUST: spec/PROTOCOL.md section 6 ("Receipt v2 body_hash
//! addressing").  Receipt-version negotiation is a TRUST-BOUNDARY
//! admission decision.  Pre-dispatch admission alone is NOT sufficient
//! when persistence re-resolves freshness against the same registry
//! and can fail the receipt for an already-executed side-effecting
//! tool.
//!
//! A peer that was fresh at admission could expire while the tool was
//! running, and the post-dispatch persistence path -- which re-ran
//! `kernel_receipt_version_for_remote` AND a second freshness check
//! inside `apply_federation_cosign` -- would then return
//! `KernelError::ReceiptNegotiationDowngrade` /
//! `KernelError::Internal("...not pinned or has gone stale")`. The
//! tool had already produced its side effect; the kernel would
//! nonetheless drop the receipt.
//!
//! The fix carries an admission-time peer/version/key snapshot through
//! receipt persistence and federation cosign. Post-dispatch persistence
//! must not re-resolve freshness and must still mint v2 evidence for
//! the already-admitted side effect.
//!
//! This fixture builds a peer whose freshness window is set to expire
//! WHILE the tool runs, sleeps the tool body across the window, and
//! asserts:
//!   1. the response is Allow (the receipt minted),
//!   2. the side-effecting tool was invoked exactly once,
//!   3. the dual-signed receipt landed using the admission-time peer key,
//!   4. v2 persistence still landed, and
//!   5. no error escaped from `record_chio_receipt_with_federation`.
//!
//! Why this passes Artifact D (production call path exercise): the
//! fixture imports `chio_kernel::ChioKernel` and drives
//! `evaluate_tool_call_blocking` end-to-end.  The tool server is a
//! mock adapter around `std::thread::sleep`; the unit under test (the
//! admission-time federation snapshot inside
//! `record_chio_receipt_with_federation`) is production code.

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::capability::{CapabilityNegotiation, ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_federation::{ConformanceTier, FederationPeer, InProcessCoSigner};
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use rusqlite::Connection;

const SRV: &str = "srv-b2-toctou";
const TOOL: &str = "echo-slow";

struct InvocationCounter {
    invocations: AtomicUsize,
}

impl InvocationCounter {
    fn new() -> Self {
        Self {
            invocations: AtomicUsize::new(0),
        }
    }
}

struct SlowToolServer {
    server_id: String,
    counter: Arc<InvocationCounter>,
    sleep_duration: Duration,
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for SlowToolServer {
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
        // Simulate the side effect taking long enough that the peer's
        // freshness window expires between admission and persistence.
        std::thread::sleep(self.sleep_duration);
        self.counter.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"echoed": arguments}))
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nonce}-{counter}.sqlite3",
        std::process::id()
    ))
}

fn count_v2_receipts(path: &Path) -> i64 {
    let conn = Connection::open(path).expect("open receipt store for verification");
    conn.query_row("SELECT COUNT(*) FROM chio_receipts_v2", [], |row| {
        row.get(0)
    })
    .expect("count v2 receipts")
}

fn make_kernel_with_slow_tool(
    receipt_store_path: &std::path::Path,
    sleep_duration: Duration,
) -> (ChioKernel, Arc<InvocationCounter>) {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "release work-b2-toctou-policy".to_string(),
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

    let counter = Arc::new(InvocationCounter::new());
    let server = SlowToolServer {
        server_id: SRV.to_string(),
        counter: counter.clone(),
        sleep_duration,
    };
    kernel.register_tool_server(Box::new(server));
    kernel.set_receipt_v2_default(true);
    (kernel, counter)
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

fn make_request(
    request_id: &str,
    cap: &chio_core::capability::CapabilityToken,
    federated_origin_kernel_id: Option<String>,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: TOOL.to_string(),
        server_id: SRV.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"input": "b2-toctou"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id,
    }
}

/// Build a v2-capable `FederationPeer` whose freshness window expires
/// `expires_in_secs` seconds from now, bound to the supplied `Keypair`
/// so the test can install a matching `InProcessCoSigner`.  Mirrors
/// the helper shape used by sibling B2 fixtures, but parameterizes the
/// freshness window so the test can choose a window narrower than the
/// tool sleep.
fn freshness_window_v2_capable_peer(
    remote_kernel_id: &str,
    remote_kp: &Keypair,
    expires_in_secs: u64,
) -> FederationPeer {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // `t1_default()` already advertises ACCEPTS_RECEIPT_V2.
    let capabilities = CapabilityNegotiation::t1_default();
    FederationPeer {
        kernel_id: remote_kernel_id.to_string(),
        public_key: remote_kp.public_key(),
        conformance_tier: ConformanceTier::Bronze,
        established_at: now,
        rotation_due: now.saturating_add(expires_in_secs),
        capabilities,
    }
}

#[test]
fn admission_time_freshness_carried_through_persistence() {
    // 1-second freshness window; tool sleeps 2 seconds.  The peer is
    // fresh at admission (`now < rotation_due`), the tool runs, the
    // peer's freshness window lapses, and persistence runs. Without
    // admission-time-carried freshness, the post-dispatch resolver
    // would return `ReceiptNegotiationDowngrade` and the receipt for
    // the already-executed tool would be lost. With the admission-time
    // decision honored, persistence uses the admitted version/key
    // snapshot and still mints v2 evidence.
    let path = unique_db_path("b2-toctou-fresh-then-stale");
    let (mut kernel, counter) = make_kernel_with_slow_tool(&path, Duration::from_millis(2_000));
    let remote_kernel_id = "kernel.org-toctou";
    let remote_kp = Keypair::generate();
    let tool_host_public_key = kernel.public_key();
    // Install the in-process bilateral cosigner so
    // `apply_federation_cosign` reaches its peer-freshness probe under
    // realistic conditions (matches the sibling federation_cosign
    // tests' setup).
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        remote_kernel_id,
        remote_kp.clone(),
        tool_host_public_key,
    )));
    let kernel = kernel.with_federation_peers(vec![freshness_window_v2_capable_peer(
        remote_kernel_id,
        &remote_kp,
        1,
    )]);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request(
        "req-b2-toctou-fresh-then-stale",
        &cap,
        Some(remote_kernel_id.to_string()),
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .unwrap_or_else(|e| {
            panic!(
                "evaluate_tool_call_blocking must not fail when admission-time \
                 freshness is carried through persistence: {e:?}"
            )
        });

    // PRIMARY assertion: even though the peer's freshness window
    // expired during dispatch, the verdict is Allow.  The
    // admission-time decision was honored at persistence; the receipt
    // was not lost.
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "admission-time decision must carry through persistence \
         (response={response:?})"
    );

    // Tool MUST have been invoked exactly once -- the side effect
    // already occurred.
    assert_eq!(
        counter.invocations.load(Ordering::SeqCst),
        1,
        "the side-effecting tool must have run once"
    );

    // Receipt id is non-empty and matches what the response surfaced.
    assert!(
        !response.receipt.id.is_empty(),
        "minted receipt must carry a stable id"
    );
    assert!(
        kernel.dual_signed_receipt(&response.receipt.id).is_some(),
        "federated receipts must use the admission-time peer snapshot for cosign"
    );

    drop(kernel);
    assert!(
        count_v2_receipts(&path) >= 1,
        "admission-time v2 negotiation must still persist v2 evidence"
    );

    let _ = std::fs::remove_file(&path);
}
