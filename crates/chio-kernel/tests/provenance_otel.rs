use std::error::Error;

use chio_core::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

struct EchoServer {
    id: String,
    tools: Vec<String>,
}

impl EchoServer {
    fn new(id: &str, tools: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.iter().map(|tool| (*tool).to_string()).collect(),
        }
    }
}

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let _ = nested_flow_bridge;
        Ok(serde_json::json!({
            "server": self.id,
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

fn make_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
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

fn make_scope(server_id: &str, tool_name: &str) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
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

fn make_request(request_id: &str, capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({ "payload": "hello" }),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn kernel_and_capability() -> Result<(ChioKernel, CapabilityToken), KernelError> {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", &["echo"])));

    let agent_keypair = Keypair::generate();
    let capability =
        kernel.issue_capability(&agent_keypair.public_key(), make_scope("srv", "echo"), 300)?;
    Ok((kernel, capability))
}

#[test]
fn receipt_records_w3c_otel_trace_and_span_ids() -> Result<(), Box<dyn Error>> {
    let (kernel, capability) = kernel_and_capability()?;
    let request = make_request("req-provenance-otel", &capability);
    let trace_id = "0123456789abcdef0123456789abcdef";
    let span_id = "0123456789abcdef";

    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "provenance": {
                "otel": {
                    "trace_id": trace_id,
                    "span_id": span_id
                },
                "supply_chain": {
                    "sbom": {
                        "digest": "sha256:receipt-provenance"
                    }
                }
            }
        })),
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.verify_signature()?);

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert_eq!(metadata["provenance"]["otel"]["trace_id"], trace_id);
    assert_eq!(metadata["provenance"]["otel"]["span_id"], span_id);
    assert_eq!(
        metadata["provenance"]["supply_chain"]["sbom"]["digest"],
        "sha256:receipt-provenance"
    );

    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/schemas/receipt-provenance-v1.json");
    let schema = std::fs::read_to_string(schema_path)?;
    let schema: serde_json::Value = serde_json::from_str(&schema)?;
    assert_eq!(
        schema["properties"]["otel"]["properties"]["trace_id"]["pattern"],
        "^(?!0{32}$)[0-9a-f]{32}$"
    );
    assert_eq!(
        schema["properties"]["otel"]["properties"]["span_id"]["pattern"],
        "^(?!0{16}$)[0-9a-f]{16}$"
    );

    Ok(())
}

#[test]
fn receipt_rejects_all_zero_otel_ids() -> Result<(), Box<dyn Error>> {
    let (kernel, capability) = kernel_and_capability()?;
    let request = make_request("req-provenance-zero-otel", &capability);

    let error = match kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "provenance": {
                "otel": {
                    "trace_id": "00000000000000000000000000000000",
                    "span_id": "0123456789abcdef"
                }
            }
        })),
    ) {
        Ok(_) => {
            return Err(
                std::io::Error::other("zero trace id unexpectedly produced a response").into(),
            );
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("trace_id"),
        "unexpected error: {error}"
    );
    assert_eq!(kernel.receipt_log().len(), 0);

    Ok(())
}

#[test]
fn receipt_rejects_null_supply_chain() -> Result<(), Box<dyn Error>> {
    let (kernel, capability) = kernel_and_capability()?;
    let request = make_request("req-provenance-null-supply-chain", &capability);

    let error = match kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "provenance": {
                "otel": {
                    "trace_id": "0123456789abcdef0123456789abcdef",
                    "span_id": "0123456789abcdef"
                },
                "supply_chain": null
            }
        })),
    ) {
        Ok(_) => {
            return Err(std::io::Error::other(
                "null supply_chain unexpectedly produced a response",
            )
            .into());
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("supply_chain"),
        "unexpected error: {error}"
    );
    assert_eq!(kernel.receipt_log().len(), 0);

    Ok(())
}

#[test]
fn receipt_rejects_non_w3c_otel_trace_id() -> Result<(), Box<dyn Error>> {
    let (kernel, capability) = kernel_and_capability()?;
    let request = make_request("req-provenance-invalid-otel", &capability);

    let error = match kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "provenance": {
                "otel": {
                    "trace_id": "0123456789ABCDEF0123456789ABCDEF",
                    "span_id": "0123456789abcdef"
                }
            }
        })),
    ) {
        Ok(_) => {
            return Err(std::io::Error::other(
                "invalid receipt provenance unexpectedly produced a response",
            )
            .into());
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("trace_id"),
        "unexpected error: {error}"
    );
    assert_eq!(kernel.receipt_log().len(), 0);

    Ok(())
}
