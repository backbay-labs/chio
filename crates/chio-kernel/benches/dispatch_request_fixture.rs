use chio_core::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use tokio::runtime::{Builder, Runtime};

const SERVER_ID: &str = "bench-dispatch-srv";
const TOOL_NAME: &str = "dispatch_allow";

pub struct DispatchAllowFixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    runtime: Runtime,
}

impl DispatchAllowFixture {
    pub fn new() -> Self {
        let mut kernel = ChioKernel::new(make_config());
        kernel.register_tool_server(Box::new(BenchToolServer));
        kernel.set_receipt_v2_default(false);

        let subject = Keypair::generate();
        let capability = issue_capability(&kernel, &subject);
        let request = make_request(&capability);
        let runtime = match Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => panic!("failed to build dispatch_allow benchmark runtime: {error}"),
        };

        Self {
            kernel,
            request,
            runtime,
        }
    }

    pub fn dispatch_allow_once(&self) -> bool {
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(&self.request));

        match response {
            Ok(response) => response.verdict == Verdict::Allow,
            Err(error) => panic!("dispatch_allow benchmark request failed: {error}"),
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
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
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
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
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
