//! The sync `evaluate_tool_call` bridge must NOT fall back to
//! `futures::executor::block_on` when the surrounding Tokio runtime
//! is a current-thread runtime. That parks the runtime's only worker
//! thread and any tool-server future awaiting Tokio I/O deadlocks
//! silently. The bridge instead returns a typed
//! `KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime`.
//!
//! This fixture asserts the typed error surfaces from a real
//! current-thread Tokio runtime calling `evaluate_tool_call_blocking`.
//! No mocks of the unit under test: we drive the production
//! `ChioKernel::evaluate_tool_call_blocking` directly, with a real
//! `ToolServerConnection` registered. The current-thread runtime is
//! the production failure mode for any host that links Tokio with
//! `flavor = "current_thread"` (e.g. some axum / tonic test harnesses).

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;

const SRV: &str = "srv-sync-bridge";
const TOOL: &str = "echo";

struct EchoToolServer {
    server_id: String,
    invocations: AtomicUsize,
}

#[async_trait::async_trait]
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
        policy_hash: "policy-p0-002".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };
    let mut kernel = ChioKernel::new(config);
    let store = SqliteReceiptStore::open(receipt_store_path).unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();
    kernel.register_tool_server(Box::new(EchoToolServer {
        server_id: SRV.to_string(),
        invocations: AtomicUsize::new(0),
    }));
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

#[test]
fn current_thread_runtime_returns_typed_error_instead_of_deadlocking() {
    let path = unique_db_path("p0-002-current-thread");
    let kernel = make_kernel(&path);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-current-thread-bridge".to_string(),
        capability: cap.clone(),
        tool_name: TOOL.to_string(),
        server_id: SRV.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"input": "p0-002"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    // A current-thread Tokio runtime is the production deadlock case: the
    // bridge must surface a typed error rather than park forever.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");

    let outcome: Result<chio_kernel::ToolCallResponse, KernelError> = runtime.block_on(async {
        // The kernel's sync API is intentionally invoked from inside the
        // current-thread runtime, where a tool-server future awaiting Tokio
        // I/O would deadlock. The bridge must instead fail closed with a
        // typed error.
        kernel.evaluate_tool_call_blocking(&request)
    });

    // The kernel's tool-dispatch error handler maps Err(e) from the
    // bridge to a structured Deny ToolCallResponse whose reason
    // surfaces the typed `Display` text. Either form is acceptable
    // for fail-closed semantics; what matters is that the dispatch
    // does NOT hang and the typed information reaches the caller.
    match outcome {
        Err(KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime) => {
            // The kernel propagated the typed error directly.
        }
        Ok(response) => {
            assert_eq!(
                response.verdict,
                chio_kernel::Verdict::Deny,
                "current-thread sync bridge must produce a Deny verdict, not Allow"
            );
            let reason = response.reason.unwrap_or_default();
            assert!(
                reason.contains("sync tool-dispatch bridge")
                    || reason.contains("current-thread Tokio runtime"),
                "deny reason must surface the SyncBridgeIncompatible diagnostic; got: {reason}"
            );
        }
        Err(other) => panic!(
            "expected SyncBridgeIncompatibleWithCurrentThreadRuntime or Ok(Deny), got {other:?}; \
             the bridge must refuse current-thread runtimes fail-closed instead of \
             attempting `futures::executor::block_on` (silent deadlock on Tokio I/O)"
        ),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn no_runtime_attached_drives_future_to_completion() {
    // Sanity: when no Tokio runtime is active at all, the non-tokio
    // executor path is still safe (no surrounding reactor to collide
    // with). This is the path unit tests with synchronous in-process
    // tool servers rely on.
    let path = unique_db_path("p0-002-no-runtime");
    let kernel = make_kernel(&path);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-no-runtime-bridge".to_string(),
        capability: cap.clone(),
        tool_name: TOOL.to_string(),
        server_id: SRV.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"input": "p0-002-no-rt"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("no-runtime path must drive the synchronous in-process tool to completion");
    assert_eq!(response.verdict, chio_kernel::Verdict::Allow);

    let _ = std::fs::remove_file(&path);
}
