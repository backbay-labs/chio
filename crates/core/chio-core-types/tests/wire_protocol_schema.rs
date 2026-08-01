#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, path::PathBuf};

use chio_core_types::{
    capability::{
        scope::{ChioScope, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    crypto::Keypair,
    message::{
        AgentMessage, ExecutionNonce, KernelMessage, NonceBinding, SignedExecutionNonce,
        ToolCallError, ToolCallResult,
    },
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::TrustLevel,
        metadata::GuardEvidence,
        signing::{
            BbsReceiptSignature, CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1,
            CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM, CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA,
        },
    },
};
use serde::Serialize;
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
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
    let schema_path = schema_root().join(relative_path);
    let schema = load_schema(relative_path);
    let validator = validator_for_schema(&schema_path, &schema);
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

fn assert_schema_rejects(relative_path: &str, instance: &Value) {
    let schema_path = schema_root().join(relative_path);
    let schema = load_schema(relative_path);
    let validator = validator_for_schema(&schema_path, &schema);
    assert!(
        !validator.is_valid(instance),
        "schema `{relative_path}` unexpectedly accepted instance:\n{}",
        serde_json::to_string_pretty(instance).expect("instance pretty prints")
    );
}

#[test]
fn protocol_primitives_shared_fixtures_match_authoritative_schemas() {
    let corpus_path = repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json");
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(corpus_path).expect("protocol-primitives fixture corpus exists"),
    )
    .expect("protocol-primitives fixture corpus parses");
    let cases = corpus["cases"]
        .as_array()
        .expect("fixture cases are an array");

    for case in cases {
        let schema_file = case["schema_file"]
            .as_str()
            .expect("fixture schema_file is a string");
        let instance = &case["instance"];
        if case["valid"].as_bool().expect("fixture valid is a boolean") {
            assert_schema_accepts(schema_file, instance);
        } else {
            assert_schema_rejects(schema_file, instance);
        }
    }
}

#[test]
fn protocol_primitives_schema_conditions_fail_closed() {
    let corpus_path = repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json");
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(corpus_path).expect("protocol-primitives fixture corpus exists"),
    )
    .expect("protocol-primitives fixture corpus parses");
    let cases = corpus["cases"]
        .as_array()
        .expect("fixture cases are an array");
    let fixture = |name: &str| {
        cases
            .iter()
            .find(|case| case["name"] == name)
            .unwrap_or_else(|| panic!("fixture `{name}` exists"))["instance"]
            .clone()
    };

    assert_schema_rejects(
        "capability/aggregate-invocation-budget.schema.json",
        &json!({
            "scope": "delegation_family",
            "max_invocations": 3
        }),
    );
    assert_schema_rejects(
        "capability/aggregate-invocation-budget.schema.json",
        &json!({
            "scope": "capability",
            "max_invocations": 3,
            "root_binding": {}
        }),
    );

    let mut direct = fixture("capability-with-direct-cumulative-approval");
    direct["scope"]["grants"][0]["constraints"][0]["value"]["cumulative_approval_root_binding"] =
        json!({});
    assert_schema_rejects("capability/token.schema.json", &direct);

    let mut delegable = fixture("capability-with-direct-cumulative-approval");
    delegable["scope"]["grants"][0]["operations"] = json!(["invoke", "delegate"]);
    assert_schema_rejects("capability/token.schema.json", &delegable);

    let approval = fixture("governed-approval-token");
    let request = json!({
        "type": "tool_call_request",
        "id": "request-1",
        "capability_token": fixture("capability-with-aggregate-budget"),
        "server_id": "server-1",
        "tool": "tool-1",
        "params": {},
        "threshold_approval_proposal": fixture("threshold-proposal"),
        "approval_tokens": vec![approval; 33]
    });
    assert_schema_rejects("agent/tool_call_request.schema.json", &request);
}

fn validator_for_schema(schema_path: &std::path::Path, schema: &Value) -> jsonschema::Validator {
    fn add_schema_resources(directory: &std::path::Path, resources: &mut Vec<(String, Value)>) {
        for entry in fs::read_dir(directory).expect("schema directory is readable") {
            let path = entry.expect("schema directory entry is readable").path();
            if path.is_dir() {
                add_schema_resources(&path, resources);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let value: Value = serde_json::from_str(
                    &fs::read_to_string(&path).expect("schema resource is readable"),
                )
                .expect("schema resource parses");
                if let Some(id) = value["$id"].as_str() {
                    resources.push((id.to_string(), value));
                }
            }
        }
    }

    let base_uri = schema_path
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .map(|parent| {
            let mut path = parent.to_string_lossy().replace('\\', "/");
            if !path.starts_with('/') {
                path.insert(0, '/');
            }
            if !path.ends_with('/') {
                path.push('/');
            }
            format!("file://{path}")
        })
        .expect("schema parent canonicalizes");
    let mut resources = Vec::new();
    add_schema_resources(&schema_root(), &mut resources);
    let mut registry = jsonschema::Registry::new();
    for (uri, resource) in &resources {
        registry = registry
            .add(uri.as_str(), resource)
            .expect("schema resource registers");
    }
    let registry = registry.prepare().expect("schema registry prepares");
    jsonschema::options()
        .with_registry(&registry)
        .with_base_uri(base_uri)
        .build(schema)
        .expect("schema compiles")
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
            aggregate_invocation_budget: None,
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
            aggregate_invocation_budget: None,
        },
        &backend,
    )
    .expect("hybrid token signs")
}

fn make_receipt(kp: &Keypair, decision: Decision) -> ChioReceipt {
    ChioReceipt::sign(make_receipt_body(kp, decision), kp).expect("receipt signs")
}

fn bbs_signature_fixture() -> BbsReceiptSignature {
    BbsReceiptSignature {
        schema: CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA.to_string(),
        projection_version: CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string(),
        algorithm: CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM.to_string(),
        ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
        issuer_fingerprint: "issuer:wire-schema:bbs".to_string(),
        issuer_public_key_hex: "11".repeat(96),
        message_count: 14,
        signature_hex: "22".repeat(80),
    }
}

fn make_bbs_receipt(kp: &Keypair) -> ChioReceipt {
    let mut body = make_receipt_body(kp, Decision::Allow);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
    ChioReceipt::sign_with_bbs(body, kp, bbs_signature_fixture()).expect("BBS receipt signs")
}

fn make_receipt_body(kp: &Keypair, decision: Decision) -> ChioReceiptBody {
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
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        decision: Some(decision),
        content_hash: "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93"
            .to_string(),
        policy_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ShellCommandGuard".to_string(),
            verdict: true,
            details: Some("allowed".to_string()),
        }],
        metadata: Some(json!({
            "surface": "wire-schema-test",
            "version": 1
        })),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    }
}

fn make_execution_nonce(kp: &Keypair) -> SignedExecutionNonce {
    SignedExecutionNonce {
        nonce: ExecutionNonce {
            schema: "chio.execution_nonce.v1".to_string(),
            nonce_id: "nonce-wire-001".to_string(),
            issued_at: 1_000,
            expires_at: 1_030,
            bound_to: NonceBinding {
                subject_id: "agent-wire-001".to_string(),
                request_id: "req-wire-001".to_string(),
                capability_id: "cap-wire-001".to_string(),
                tool_server: "srv".to_string(),
                tool_name: "echo".to_string(),
                parameter_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            },
            reserved_hold_id: None,
            reserving_request_id: None,
        },
        signature: kp.sign(b"wire-execution-nonce"),
    }
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
        params: Box::new(json!({"message": "hello"})),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: Some(Box::new(make_execution_nonce(&kp))),
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
                execution_nonce: Some(Box::new(make_execution_nonce(&kp))),
            }),
        ),
        (
            "kernel/tool_call_response.schema.json",
            to_json(&KernelMessage::ToolCallResponse {
                id: "req-wire-002".to_string(),
                result: result_stream_complete.clone(),
                receipt: Box::new(make_receipt(&kp, Decision::Allow)),
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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
                execution_nonce: None,
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

#[test]
fn receipt_schema_accepts_bound_bbs_signature_and_rejects_malformed_bindings() {
    let kp = Keypair::from_seed(&[37; 32]);
    let instance = to_json(&make_bbs_receipt(&kp));

    assert_eq!(
        instance
            .get("bbs_projection_version")
            .and_then(Value::as_str),
        Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1)
    );
    assert_schema_accepts("receipt/record.schema.json", &instance);

    let mut missing_projection = instance.clone();
    missing_projection
        .as_object_mut()
        .expect("receipt object")
        .remove("bbs_projection_version");
    assert_schema_rejects("receipt/record.schema.json", &missing_projection);

    let mut missing_signature = instance.clone();
    missing_signature
        .as_object_mut()
        .expect("receipt object")
        .remove("bbs_signature");
    assert_schema_rejects("receipt/record.schema.json", &missing_signature);

    let mut odd_length_public_key = instance.clone();
    odd_length_public_key["bbs_signature"]["issuer_public_key_hex"] = json!("abc");
    assert_schema_rejects("receipt/record.schema.json", &odd_length_public_key);

    let mut unsupported_ciphersuite = instance.clone();
    unsupported_ciphersuite["bbs_signature"]["ciphersuite"] =
        json!("BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_");
    assert_schema_rejects("receipt/record.schema.json", &unsupported_ciphersuite);

    let mut wrong_message_count = instance;
    wrong_message_count["bbs_signature"]["message_count"] = json!(13);
    assert_schema_rejects("receipt/record.schema.json", &wrong_message_count);
}

#[test]
fn tool_call_response_schema_rejects_allow_shaped_trace_receipts() {
    let kp = Keypair::from_seed(&[31; 32]);
    let mut instance = to_json(&KernelMessage::ToolCallResponse {
        id: "req-wire-trace".to_string(),
        result: ToolCallResult::Incomplete {
            reason: "provider trace only".to_string(),
            chunks_received: 0,
        },
        receipt: Box::new(make_receipt(&kp, Decision::Allow)),
        execution_nonce: None,
    });

    {
        let receipt = instance
            .get_mut("receipt")
            .and_then(Value::as_object_mut)
            .expect("receipt object");
        receipt.insert(
            "receipt_kind".to_string(),
            Value::String("trace_observation".to_string()),
        );
        receipt.insert(
            "boundary_class".to_string(),
            Value::String("detect_only".to_string()),
        );
        receipt.insert(
            "trust_level".to_string(),
            Value::String("verified".to_string()),
        );
        receipt.insert(
            "observation_outcome".to_string(),
            Value::String("observed".to_string()),
        );
        receipt.remove("decision");
    }
    assert_schema_accepts("kernel/tool_call_response.schema.json", &instance);

    instance
        .get_mut("receipt")
        .and_then(Value::as_object_mut)
        .expect("receipt object")
        .insert(
            "decision".to_string(),
            json!({
                "verdict": "allow"
            }),
        );
    assert_schema_rejects("kernel/tool_call_response.schema.json", &instance);
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
