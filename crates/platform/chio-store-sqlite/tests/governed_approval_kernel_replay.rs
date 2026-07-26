use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::{
    capability::{
        governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
            GovernedTransactionIntent,
        },
        scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    },
    crypto::Keypair,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolInvocationCost,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteGovernedApprovalReplayStore;
use chio_test_support::prelude::*;

struct CostServer {
    id: String,
}

#[async_trait::async_trait]
impl ToolServerConnection for CostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            value,
            Some(ToolInvocationCost {
                units: 1,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        ))
    }
}

fn kernel_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "governed-approval-replay-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time is after the Unix epoch")
        .as_secs()
}

#[test]
fn governed_dispatch_replay_is_denied_after_store_reopen() {
    let tempdir = tempfile::tempdir().test_expect("tempdir creates");
    let path = tempdir.path().join("governed-approval-replay.sqlite3");
    let server = "durable-approval-replay-server";
    let tool = "compute";
    let kernel_keypair = Keypair::generate();
    let agent = Keypair::generate();

    let mut first_kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
    first_kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    first_kernel.set_governed_approval_replay_store(Box::new(
        SqliteGovernedApprovalReplayStore::open(&path).test_expect("replay store opens"),
    ));

    let amount = MonetaryAmount {
        units: 10,
        currency: "USD".to_string(),
    };
    let capability = first_kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: server.to_string(),
                    tool_name: tool.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![
                        Constraint::GovernedIntentRequired,
                        Constraint::RequireApprovalAbove { threshold_units: 1 },
                    ],
                    max_invocations: None,
                    max_cost_per_invocation: Some(amount.clone()),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .test_expect("capability issues");
    let request_id = "durable-approval-replay-request";
    let intent = GovernedTransactionIntent {
        id: "durable-approval-replay-intent".to_string(),
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        purpose: "prove replay marker survives restart".to_string(),
        max_amount: Some(amount),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let now = now_secs();
    let approval_token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{request_id}"),
            approver: kernel_keypair.public_key(),
            subject: capability.subject.clone(),
            governed_intent_hash: intent.binding_hash().test_expect("intent hashes"),
            request_id: request_id.to_string(),
            threshold_proposal_hash: None,
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(300),
            decision: GovernedApprovalDecision::Approved,
        },
        &kernel_keypair,
    )
    .test_expect("approval token signs");
    let request = ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({"operation": "settle"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: Some(approval_token),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let pre_dispatch_denial = first_kernel
        .evaluate_tool_call_blocking(&request)
        .test_expect("missing server denial evaluates");
    assert_eq!(pre_dispatch_denial.verdict, Verdict::Deny);
    assert!(
        pre_dispatch_denial
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not registered")),
        "{:?}",
        pre_dispatch_denial.reason
    );
    first_kernel.register_tool_server(Box::new(CostServer {
        id: server.to_string(),
    }));

    let first_response = first_kernel
        .evaluate_tool_call_blocking(&request)
        .test_expect("first dispatch evaluates");
    assert_eq!(
        first_response.verdict,
        Verdict::Allow,
        "{}",
        first_response
            .reason
            .as_deref()
            .unwrap_or("kernel supplied no reason")
    );
    drop(first_kernel);

    let mut reopened_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    reopened_kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    reopened_kernel.set_governed_approval_replay_store(Box::new(
        SqliteGovernedApprovalReplayStore::open(&path).test_expect("replay store reopens"),
    ));
    reopened_kernel.register_tool_server(Box::new(CostServer {
        id: server.to_string(),
    }));

    let replay_response = reopened_kernel
        .evaluate_tool_call_blocking(&request)
        .test_expect("replay dispatch evaluates");
    assert_eq!(replay_response.verdict, Verdict::Deny);
    assert!(replay_response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("approval token has already been consumed")));
}
