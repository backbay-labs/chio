#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::GuardEvidence,
};
use chio_core::session::{OperationContext, RequestId, SessionId};
use chio_kernel::{
    capability_matches_request, BudgetStore, ChioKernel, Guard, GuardContext, GuardDecision,
    InMemoryBudgetStore, InMemoryRevocationStore, KernelConfig, KernelError, NestedFlowBridge,
    ReceiptLog, RevocationStore, Session, ToolCallRequest, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use tokio::runtime::{Builder, Runtime};

const SERVER_ID: &str = "bench-dispatch-srv";
const TOOL_NAME: &str = "dispatch_allow";
const DENY_TOOL_NAME: &str = "dispatch_deny";

pub struct DispatchAllowFixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    deny_request: ToolCallRequest,
    runtime: Runtime,
    receipt_keypair: Keypair,
    receipt_body: ChioReceiptBody,
    signed_receipt: ChioReceipt,
    receipt_log: RefCell<ReceiptLog>,
    budget_store: InMemoryBudgetStore,
    revocation_store: InMemoryRevocationStore,
    revoked_capability_id: String,
    guard_request: ToolCallRequest,
    guard_scope: ChioScope,
    guard_agent_id: String,
    guard_server_id: String,
    allow_guard: BenchGuard,
    guard_pipeline: Vec<BenchGuard>,
    sessions: HashMap<String, Session>,
    session_id: String,
    session_context: OperationContext,
}

impl DispatchAllowFixture {
    pub fn new() -> Self {
        let mut kernel = ChioKernel::new(make_config());
        kernel.register_tool_server(Box::new(BenchToolServer));

        let subject = Keypair::generate();
        let capability = issue_capability(&kernel, &subject);
        let request = make_request(&capability);
        let deny_request = make_deny_request(&capability);
        let runtime = match Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => panic!("failed to build dispatch_allow benchmark runtime: {error}"),
        };
        let receipt_keypair = Keypair::generate();
        let receipt_body = make_receipt_body(&receipt_keypair, &capability);
        let receipt = sign_receipt(&receipt_body, &receipt_keypair);
        let receipt_log = RefCell::new(ReceiptLog::new());
        let budget_store = InMemoryBudgetStore::new();
        let revocation_store = InMemoryRevocationStore::new();
        let revoked_capability_id = "bench-revoked-capability".to_string();
        match revocation_store.revoke(&revoked_capability_id) {
            Ok(true) | Ok(false) => {}
            Err(error) => panic!("failed to seed revocation benchmark store: {error}"),
        }
        let guard_request = make_guard_request(&capability);
        let guard_scope = capability.scope.clone();
        let guard_agent_id = capability.subject.to_hex();
        let guard_server_id = SERVER_ID.to_string();
        let allow_guard = BenchGuard::new("bench-single-guard");
        let guard_pipeline = vec![
            BenchGuard::new("bench-guard-1"),
            BenchGuard::new("bench-guard-2"),
            BenchGuard::new("bench-guard-3"),
            BenchGuard::new("bench-guard-4"),
            BenchGuard::new("bench-guard-5"),
        ];
        let session_id = "bench-session".to_string();
        let session_context = OperationContext {
            session_id: SessionId::new(session_id.clone()),
            request_id: RequestId::new("bench-session-request"),
            agent_id: guard_agent_id.clone(),
            parent_request_id: None,
            progress_token: None,
        };
        let mut sessions = HashMap::new();
        sessions.insert(
            session_id.clone(),
            Session::new(
                SessionId::new(session_id.clone()),
                guard_agent_id.clone(),
                vec![capability.clone()],
            ),
        );

        let fixture = Self {
            kernel,
            request,
            deny_request,
            runtime,
            receipt_keypair,
            receipt_body,
            signed_receipt: receipt.clone(),
            receipt_log,
            budget_store,
            revocation_store,
            revoked_capability_id,
            guard_request,
            guard_scope,
            guard_agent_id,
            guard_server_id,
            allow_guard,
            guard_pipeline,
            sessions,
            session_id,
            session_context,
        };

        assert!(
            fixture.capability_signature_valid(),
            "capability signature fixture must verify"
        );
        assert!(
            fixture.capability_time_valid(),
            "capability time fixture must validate"
        );
        assert!(fixture.scope_matches(), "scope fixture must match request");
        assert!(
            receipt.verify_signature().unwrap_or(false),
            "receipt signing fixture must verify"
        );
        assert!(
            fixture.revocation_lookup_once(),
            "revocation fixture must find seeded capability"
        );
        assert!(
            fixture.budget_decrement_once(),
            "budget fixture must allow the seeded increment"
        );
        assert!(
            fixture.single_guard_once(),
            "single guard fixture must allow request"
        );
        assert!(
            fixture.guard_pipeline_5_once(),
            "five-guard fixture must allow request"
        );
        assert!(
            fixture.receipt_sign_once(),
            "receipt signing fixture must verify"
        );
        assert!(
            fixture.receipt_append_once() > 0,
            "receipt append fixture must append to the log"
        );
        assert!(
            fixture.dispatch_allow_once(),
            "dispatch allow fixture must produce an allow verdict"
        );
        assert!(
            fixture.dispatch_deny_once(),
            "dispatch deny fixture must produce a denial with reason"
        );
        assert!(
            fixture.session_lookup_once(),
            "session lookup fixture must find and validate context"
        );

        fixture
    }

    pub fn dispatch_allow_once(&self) -> bool {
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(&self.request));

        match response {
            Ok(response) if response.verdict == Verdict::Allow => true,
            Ok(response) => {
                let reason = response.reason.as_deref().unwrap_or("missing reason");
                panic!(
                    "dispatch_allow benchmark produced {:?}: {reason}",
                    response.verdict
                );
            }
            Err(error) => panic!("dispatch_allow benchmark request failed: {error}"),
        }
    }

    pub fn dispatch_deny_once(&self) -> bool {
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(&self.deny_request));

        match response {
            Ok(response) => response.verdict == Verdict::Deny && response.reason.is_some(),
            Err(error) => panic!("dispatch_deny benchmark request failed: {error}"),
        }
    }

    pub fn capability_signature_valid(&self) -> bool {
        match self.request.capability.verify_signature() {
            Ok(valid) => valid,
            Err(error) => panic!("capability verification benchmark failed: {error}"),
        }
    }

    pub fn capability_time_valid(&self) -> bool {
        let now = self.request.capability.issued_at.saturating_add(1);
        self.request.capability.validate_time(now).is_ok()
    }

    pub fn scope_matches(&self) -> bool {
        match capability_matches_request(
            &self.request.capability,
            &self.request.tool_name,
            &self.request.server_id,
            &self.request.arguments,
        ) {
            Ok(matches) => matches,
            Err(error) => panic!("scope match benchmark failed: {error}"),
        }
    }

    pub fn revocation_lookup_once(&self) -> bool {
        match self
            .revocation_store
            .is_revoked(&self.revoked_capability_id)
        {
            Ok(revoked) => revoked,
            Err(error) => panic!("revocation lookup benchmark failed: {error}"),
        }
    }

    pub fn budget_decrement_once(&self) -> bool {
        match self
            .budget_store
            .try_increment(&self.request.capability.id, 0, None)
        {
            Ok(allowed) => allowed,
            Err(error) => panic!("budget decrement benchmark failed: {error}"),
        }
    }

    pub fn single_guard_once(&self) -> bool {
        self.evaluate_guard(&self.allow_guard)
    }

    pub fn guard_pipeline_5_once(&self) -> bool {
        self.guard_pipeline
            .iter()
            .all(|guard| self.evaluate_guard(guard))
    }

    pub fn receipt_sign_once(&self) -> bool {
        sign_receipt(&self.receipt_body, &self.receipt_keypair)
            .verify_signature()
            .unwrap_or(false)
    }

    pub fn receipt_append_once(&self) -> usize {
        let mut log = self.receipt_log.borrow_mut();
        log.append(self.signed_receipt.clone());
        log.len()
    }

    pub fn session_lookup_once(&self) -> bool {
        self.sessions
            .get(&self.session_id)
            .is_some_and(|session| session.validate_context(&self.session_context).is_ok())
    }

    fn evaluate_guard(&self, guard: &BenchGuard) -> bool {
        let ctx = GuardContext {
            request: &self.guard_request,
            scope: &self.guard_scope,
            agent_id: &self.guard_agent_id,
            server_id: &self.guard_server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(0),
        };

        match guard.evaluate(&ctx) {
            Ok(verdict) => verdict == Verdict::Allow,
            Err(error) => panic!("guard benchmark failed: {error}"),
        }
    }
}

impl Default for DispatchAllowFixture {
    fn default() -> Self {
        Self::new()
    }
}

fn make_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "bench-dispatch-allow-policy".to_string(),
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
    }
}

fn issue_capability(kernel: &ChioKernel, subject: &Keypair) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };

    match kernel.issue_capability(&subject.public_key(), scope, 300) {
        Ok(capability) => capability,
        Err(error) => panic!("failed to issue dispatch_allow benchmark capability: {error}"),
    }
}

fn make_request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "bench-dispatch-allow".to_string(),
        capability: capability.clone(),
        tool_name: TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({
            "path": "/workspace/input.json",
            "operation": "read",
            "bytes": 4096,
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn make_deny_request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "bench-dispatch-deny".to_string(),
        capability: capability.clone(),
        tool_name: DENY_TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({
            "path": "/workspace/blocked.json",
            "operation": "write",
            "bytes": 8192,
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn make_guard_request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "bench-guard".to_string(),
        capability: capability.clone(),
        tool_name: TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({
            "path": "/workspace/guard.json",
            "operation": "read",
            "bytes": 2048,
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn make_receipt_body(keypair: &Keypair, capability: &CapabilityToken) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "bench-receipt".to_string(),
        timestamp: capability.issued_at.saturating_add(1),
        capability_id: capability.id.clone(),
        tool_server: SERVER_ID.to_string(),
        tool_name: TOOL_NAME.to_string(),
        action: match ToolCallAction::from_parameters(serde_json::json!({
            "path": "/workspace/input.json",
            "operation": "read",
            "bytes": 4096,
        })) {
            Ok(action) => action,
            Err(error) => panic!("failed to build receipt action fixture: {error}"),
        },
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::sha256_hex(br#"{"allowed":true}"#),
        policy_hash: "bench-dispatch-allow-policy".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "bench-single-guard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

fn sign_receipt(body: &ChioReceiptBody, keypair: &Keypair) -> ChioReceipt {
    match ChioReceipt::sign(body.clone(), keypair) {
        Ok(receipt) => receipt,
        Err(error) => panic!("receipt signing benchmark failed: {error}"),
    }
}

struct BenchGuard {
    name: &'static str,
}

impl BenchGuard {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl Guard for BenchGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        if ctx
            .request
            .arguments
            .get("operation")
            .and_then(|value| value.as_str())
            == Some("read")
        {
            Ok(GuardDecision::allow())
        } else {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }
}

struct BenchToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for BenchToolServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "allowed": true,
            "echo": arguments,
        }))
    }
}
