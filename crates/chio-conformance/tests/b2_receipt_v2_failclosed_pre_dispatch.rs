//! Spec MUST: spec/PROTOCOL.md section 6 ("Receipt v2 body_hash
//! addressing"). The kernel MUST reject the dispatch itself when a
//! named federation peer is not pinned fresh under negotiated v2,
//! rather than executing the tool and refusing to mint the receipt
//! after the fact.
//!
//! Background: the receipt-version check previously lived only inside
//! `record_chio_receipt_with_federation`, which is called AFTER
//! `dispatch_tool_call_with_cost_sync`. A state-changing tool could
//! execute and then the kernel would refuse to mint the receipt -- not
//! fail-closed at the trust boundary. The named-peer freshness check
//! now runs in pre-dispatch admission inside
//! `evaluate_tool_call_sync_with_session_context`.
//!
//! This fixture asserts that when negotiated v2 + stale-pin peer, the
//! tool function is NEVER invoked. A `MockToolServer` increments a
//! counter on `invoke`; the counter must stay 0 after the rejection.
//!
//! Why this passes Artifact D (production call path exercise):
//!   The fixture imports `chio_kernel::ChioKernel` (the production
//!   kernel) directly and drives `evaluate_tool_call_blocking` end-to
//!   -end. The mock under measurement is a `ToolServerConnection`
//!   adapter around an atomic counter; the unit under test (the
//!   pre-dispatch admission gate) is production code.

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_federation::FederationPeer;
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;

const SRV: &str = "srv-b2-pre-dispatch";
const TOOL: &str = "echo";

/// Counts every call to `invoke`. Shared by the kernel-installed
/// `ToolServerConnection` and the test code so the assertion can
/// observe whether the production `evaluate_tool_call_blocking` path
/// reached the tool boundary.
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

struct CountingToolServer {
    server_id: String,
    counter: Arc<InvocationCounter>,
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for CountingToolServer {
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
        self.counter.invocations.fetch_add(1, Ordering::SeqCst);
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

fn make_kernel_with_counter(
    receipt_store_path: &std::path::Path,
) -> (ChioKernel, Arc<InvocationCounter>) {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "policy-b2-pre-dispatch".to_string(),
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
    let server = CountingToolServer {
        server_id: SRV.to_string(),
        counter: counter.clone(),
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
        arguments: serde_json::json!({"input": "b2-pre-dispatch"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id,
    }
}

/// Build a v2-capable `FederationPeer` whose pin freshness window has
/// already expired. Mirrors the helper in
/// `b2_receipt_v2_failclosed_under_negotiated_v2.rs`.
fn stale_v2_capable_peer(remote_kernel_id: &str) -> FederationPeer {
    let remote_kp = Keypair::generate();
    FederationPeer {
        kernel_id: remote_kernel_id.to_string(),
        public_key: remote_kp.public_key(),
        conformance_tier: chio_federation::ConformanceTier::Bronze,
        established_at: 1_700_000_000,
        rotation_due: 1_700_000_001,
        capabilities: chio_core::capability::CapabilityNegotiation::t1_default(),
    }
}

#[test]
fn negotiated_v2_with_stale_pin_does_not_invoke_tool() {
    // Stale-pin variant of the named-peer-not-pinned-fresh case. The
    // resolver returns `KernelError::ReceiptNegotiationDowngrade`,
    // which the new pre-dispatch admission gate maps to a structured
    // Deny verdict BEFORE `dispatch_tool_call_with_cost_sync` is ever
    // called.
    let path = unique_db_path("b2-pre-dispatch-stale");
    let (kernel, counter) = make_kernel_with_counter(&path);
    let remote_kernel_id = "kernel.org-stale-pre-dispatch";
    let kernel = kernel.with_federation_peers(vec![stale_v2_capable_peer(remote_kernel_id)]);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request(
        "req-b2-pre-dispatch-stale",
        &cap,
        Some(remote_kernel_id.to_string()),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    // The kernel must produce a Deny verdict for the stale-pin case.
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "stale-pin peer must be denied at admission, not allowed (response={response:?})"
    );

    // The PRIMARY assertion: the tool was NEVER invoked. If the
    // counter is > 0 the bug is back -- a state-changing tool would
    // have run before the kernel refused to mint a receipt.
    assert_eq!(
        counter.invocations.load(Ordering::SeqCst),
        0,
        "tool invocation counter MUST remain 0 when receipt-version negotiation fails closed; \
         saw {} invocations, indicating dispatch happened before the admission gate fired",
        counter.invocations.load(Ordering::SeqCst)
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn negotiated_v2_with_never_pinned_peer_does_not_invoke_tool() {
    // Never-pinned variant. The pre-dispatch admission must still
    // refuse to dispatch. R3 finding #4 (companion fixture) called out
    // that "not pinned fresh" must cover both stale and never-pinned;
    // we exercise both at the end-to-end layer.
    let path = unique_db_path("b2-pre-dispatch-never");
    let (kernel, counter) = make_kernel_with_counter(&path);
    let remote_kernel_id = "kernel.org-never-pinned-pre-dispatch";

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request(
        "req-b2-pre-dispatch-never",
        &cap,
        Some(remote_kernel_id.to_string()),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);

    assert_eq!(
        counter.invocations.load(Ordering::SeqCst),
        0,
        "tool invocation counter MUST remain 0 when named peer was never pinned; \
         saw {} invocations",
        counter.invocations.load(Ordering::SeqCst)
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn no_federated_origin_default_v2_dispatches_tool_normally() {
    // Sanity: when no federated origin is named and the kernel default
    // is v2, dispatch proceeds. The new admission gate must not
    // regress the no-remote path.
    let path = unique_db_path("b2-pre-dispatch-no-remote");
    let (kernel, counter) = make_kernel_with_counter(&path);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request("req-b2-pre-dispatch-no-remote", &cap, None);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    assert_eq!(
        counter.invocations.load(Ordering::SeqCst),
        1,
        "no-remote v2-default dispatch must invoke the tool exactly once"
    );

    let _ = std::fs::remove_file(&path);
}
