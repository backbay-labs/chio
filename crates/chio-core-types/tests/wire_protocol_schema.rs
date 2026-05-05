#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, path::PathBuf};

use chio_core_types::{
    capability::{
        CapabilityToken, CapabilityTokenBody, ChioScope, MonetaryAmount, Operation, PromptGrant,
        ResourceGrant, ToolGrant,
    },
    crypto::Keypair,
    message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult},
    receipt::{ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction},
};
use serde::Serialize;
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn schema_root() -> PathBuf {
    repo_root().join("spec/schemas/chio-wire/v1")
}

fn load_schema(relative_path: &str) -> Value {
    let path = schema_root().join(relative_path);
    let contents = fs::read_to_string(&path).expect("schema file exists");
    serde_json::from_str(&contents).expect("schema parses as json")
}

fn to_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("value serializes")
}

fn assert_schema_accepts(relative_path: &str, instance: &Value) {
    let schema = load_schema(relative_path);
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    if let Err(error) = validator.validate(instance) {
        let mut details = vec![error.to_string()];
        details.extend(
            validator
                .iter_errors(instance)
                .skip(1)
                .map(|entry| entry.to_string()),
        );
        panic!(
            "schema `{relative_path}` rejected instance:\ninstance={}\nerrors={}",
            serde_json::to_string_pretty(instance).expect("instance pretty prints"),
            details.join(" | ")
        );
    }
}

fn make_token(kp: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-wire-001".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke, Operation::ReadResult],
                    constraints: vec![],
                    max_invocations: Some(5),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 25,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: Some(true),
                }],
                resource_grants: vec![ResourceGrant {
                    uri_pattern: "repo://docs/*".to_string(),
                    operations: vec![Operation::Read, Operation::Subscribe],
                }],
                prompt_grants: vec![PromptGrant {
                    prompt_name: "review:*".to_string(),
                    operations: vec![Operation::Get, Operation::Delegate],
                }],
            },
            issued_at: 1_710_000_000,
            expires_at: 1_710_000_600,
            delegation_chain: vec![],
        },
        kp,
    )
    .expect("token signs")
}

#[cfg(feature = "pq")]
fn make_hybrid_token() -> CapabilityToken {
    use chio_core_types::crypto::{Ed25519Backend, HybridBackend, MlDsa65Backend, SigningBackend};

    let classical = Ed25519Backend::new(Keypair::from_seed(&[5; 32]));
    let pq = MlDsa65Backend::from_seed(&[6; 32]);
    let backend = HybridBackend::new(Box::new(classical), pq).expect("hybrid backend");
    CapabilityToken::sign_with_backend(
        CapabilityTokenBody {
            id: "cap-wire-hybrid-001".to_string(),
            issuer: backend.public_key(),
            subject: backend.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1_710_000_000,
            expires_at: 1_710_000_600,
            delegation_chain: vec![],
        },
        &backend,
    )
    .expect("hybrid token signs")
}

fn make_receipt(kp: &Keypair, decision: Decision) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-wire-001".to_string(),
            timestamp: 1_710_000_100,
            capability_id: "cap-wire-001".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(json!({
                "message": "hello",
                "dry_run": true
            }))
            .expect("action"),
            decision,
            content_hash: "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93"
                .to_string(),
            policy_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ShellCommandGuard".to_string(),
                verdict: true,
                details: Some("allowed".to_string()),
            }],
            metadata: Some(json!({
                "surface": "wire-schema-test",
                "version": 1
            })),
            trust_level: chio_core_types::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        },
        kp,
    )
    .expect("receipt signs")
}

#[test]
fn wire_protocol_schema_cases_validate_live_serialization() {
    let kp = Keypair::from_seed(&[7; 32]);
    let token = make_token(&kp);

    let tool_call_request = AgentMessage::ToolCallRequest {
        id: "req-wire-001".to_string(),
        capability_token: Box::new(token.clone()),
        server_id: "srv".to_string(),
        tool: "echo".to_string(),
        params: json!({"message": "hello"}),
    };

    let result_ok = ToolCallResult::Ok {
        value: json!({"message": "world"}),
    };
    let result_stream_complete = ToolCallResult::StreamComplete { total_chunks: 3 };
    let result_cancelled = ToolCallResult::Cancelled {
        reason: "operator cancelled".to_string(),
        chunks_received: 2,
    };
    let result_incomplete = ToolCallResult::Incomplete {
        reason: "upstream stream interrupted".to_string(),
        chunks_received: 1,
    };
    let result_err_capability_denied = ToolCallResult::Err {
        error: ToolCallError::CapabilityDenied("signature mismatch".to_string()),
    };
    let result_err_capability_expired = ToolCallResult::Err {
        error: ToolCallError::CapabilityExpired,
    };
    let result_err_capability_revoked = ToolCallResult::Err {
        error: ToolCallError::CapabilityRevoked,
    };
    let result_err_policy_denied = ToolCallResult::Err {
        error: ToolCallError::PolicyDenied {
            guard: "ForbiddenPathGuard".to_string(),
            reason: "path is forbidden".to_string(),
        },
    };
    let result_err_tool_server = ToolCallResult::Err {
        error: ToolCallError::ToolServerError("upstream 500".to_string()),
    };
    let result_err_internal = ToolCallResult::Err {
        error: ToolCallError::InternalError("receipt signing failed".to_string()),
    };

    let cases = vec![
        (
            "agent/tool_call_request.schema.json",
            to_json(&tool_call_request),
        ),
        (
            "agent/list_capabilities.schema.json",
            to_json(&AgentMessage::ListCapabilities),
        ),
        (
            "agent/heartbeat.schema.json",
            to_json(&AgentMessage::Heartbeat),
        ),
        (
            "kernel/tool_call_chunk.schema.json",
            to_json(&KernelMessage::ToolCallChunk {
                id: "req-wire-001".to_string(),
                chunk_index: 0,
                data: json!({"delta": "hel"}),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-001".to_string(),
                result: result_ok.clone(),
                receipt: Box::new(make_receipt(&kp, Decision::Allow)),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-002".to_string(),
                result: result_stream_complete.clone(),
                receipt: Box::new(make_receipt(&kp, Decision::Allow)),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-003".to_string(),
                result: result_cancelled.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Cancelled {
                        reason: "operator cancelled".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-004".to_string(),
                result: result_incomplete.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Incomplete {
                        reason: "upstream stream interrupted".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-005".to_string(),
                result: result_err_capability_denied.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "CapabilityGuard".to_string(),
                        reason: "signature mismatch".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-006".to_string(),
                result: result_err_capability_expired.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "CapabilityGuard".to_string(),
                        reason: "capability expired".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-007".to_string(),
                result: result_err_capability_revoked.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "CapabilityGuard".to_string(),
                        reason: "capability revoked".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-008".to_string(),
                result: result_err_policy_denied.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "ForbiddenPathGuard".to_string(),
                        reason: "path is forbidden".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-009".to_string(),
                result: result_err_tool_server.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "Dispatch".to_string(),
                        reason: "upstream 500".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-010".to_string(),
                result: result_err_internal.clone(),
                receipt: Box::new(make_receipt(
                    &kp,
                    Decision::Deny {
                        guard: "Kernel".to_string(),
                        reason: "receipt signing failed".to_string(),
                    },
                )),
            }),
        ),
        (
            "kernel/capability_list.schema.json",
            to_json(&KernelMessage::CapabilityList {
                capabilities: vec![token.clone()],
            }),
        ),
        (
            "kernel/capability_revoked.schema.json",
            to_json(&KernelMessage::CapabilityRevoked {
                id: "cap-wire-001".to_string(),
            }),
        ),
        (
            "kernel/heartbeat.schema.json",
            to_json(&KernelMessage::Heartbeat),
        ),
        ("result/ok.schema.json", to_json(&result_ok)),
        (
            "result/stream_complete.schema.json",
            to_json(&result_stream_complete),
        ),
        ("result/cancelled.schema.json", to_json(&result_cancelled)),
        ("result/incomplete.schema.json", to_json(&result_incomplete)),
        ("result/err.schema.json", to_json(&result_err_policy_denied)),
        (
            "error/capability_denied.schema.json",
            to_json(&ToolCallError::CapabilityDenied(
                "signature mismatch".to_string(),
            )),
        ),
        (
            "error/capability_expired.schema.json",
            to_json(&ToolCallError::CapabilityExpired),
        ),
        (
            "error/capability_revoked.schema.json",
            to_json(&ToolCallError::CapabilityRevoked),
        ),
        (
            "error/policy_denied.schema.json",
            to_json(&ToolCallError::PolicyDenied {
                guard: "ForbiddenPathGuard".to_string(),
                reason: "path is forbidden".to_string(),
            }),
        ),
        (
            "error/tool_server_error.schema.json",
            to_json(&ToolCallError::ToolServerError("upstream 500".to_string())),
        ),
        (
            "error/internal_error.schema.json",
            to_json(&ToolCallError::InternalError(
                "receipt signing failed".to_string(),
            )),
        ),
    ];

    for (schema_path, instance) in cases {
        assert_schema_accepts(schema_path, &instance);
    }
}

#[cfg(feature = "pq")]
#[test]
fn capability_token_schema_accepts_live_hybrid_wire_values() {
    let token = make_hybrid_token();
    let instance = to_json(&token);
    assert_eq!(instance["algorithm"], "hybrid");
    assert!(instance["issuer"]
        .as_str()
        .expect("issuer string")
        .starts_with("hybrid:"));
    assert!(instance["signature"]
        .as_str()
        .expect("signature string")
        .starts_with("hybrid:"));
    assert_schema_accepts("capability/token.schema.json", &instance);
}
