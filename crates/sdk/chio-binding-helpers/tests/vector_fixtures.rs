use std::fs;
use std::path::{Path, PathBuf};

use chio_binding_helpers::{
    canonicalize_json_str, capability_body_canonical_json, receipt_body_canonical_json,
    sha256_hex_utf8, sign_json_str_ed25519, sign_utf8_message_ed25519,
    signed_manifest_body_canonical_json, verify_capability, verify_json_str_signature_ed25519,
    verify_receipt, verify_receipt_json_with_trusted_signer_hex,
    verify_receipt_with_trusted_signers, verify_signed_manifest, verify_utf8_message_ed25519,
    CapabilityVerification, ManifestVerification, ReceiptVerification,
};
use chio_core::{
    capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Constraint, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    receipt::body::chio_receipt_id,
    receipt::body::ChioReceipt,
    receipt::body::ChioReceiptBody,
    receipt::decision::Decision,
    receipt::decision::ToolCallAction,
    receipt::kinds::BoundaryClass,
    receipt::kinds::ObservationOutcome,
    receipt::kinds::ReceiptKind,
    receipt::kinds::RedactionMode,
    receipt::kinds::ToolOrigin,
    receipt::kinds::TrustLevel,
    receipt::metadata::GuardEvidence,
    sha256_hex, Keypair,
};
use chio_manifest::{
    sign_manifest, LatencyHint, RequiredPermissions, SignedManifest,
    ToolDefinition as SignedManifestToolDefinition, ToolManifest as SignedToolManifest,
};
use serde_json::{json, Value};

use chio_test_support::ctx::TestUnwrap;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .test_unwrap("crate is nested under repo root")
        .to_path_buf()
}

fn canonical_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/canonical/v1.json")
}

fn receipt_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/receipt/v1.json")
}

fn capability_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/capability/v1.json")
}

fn hashing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/hashing/v1.json")
}

fn manifest_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/manifest/v1.json")
}

fn signing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/signing/v1.json")
}

fn pretty_json(value: &Value) -> String {
    let mut rendered = serde_json::to_string_pretty(value).test_unwrap("serialize fixture");
    rendered.push('\n');
    rendered
}

fn assert_fixture_matches(path: &Path, actual: &Value) {
    let expected = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    let rendered = pretty_json(actual);
    assert_eq!(
        expected,
        rendered,
        "fixture {} is out of date",
        path.display()
    );
}

fn canonical_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "object_key_sorting",
                "description": "Object keys are sorted lexicographically in canonical output.",
                "input_json": "{\"z\":1,\"a\":2,\"m\":3}",
                "canonical_json": "{\"a\":2,\"m\":3,\"z\":1}"
            },
            {
                "id": "nested_structures",
                "description": "Nested objects and arrays preserve structure while object keys are canonicalized.",
                "input_json": "{\"tool\":\"read\",\"params\":{\"path\":\"/tmp/demo\",\"flags\":[\"read\",\"text\"]},\"enabled\":true}",
                "canonical_json": "{\"enabled\":true,\"params\":{\"flags\":[\"read\",\"text\"],\"path\":\"/tmp/demo\"},\"tool\":\"read\"}"
            },
            {
                "id": "number_formatting",
                "description": "Numbers follow RFC 8785 / ECMAScript shortest-form rendering.",
                "input_json": "{\"whole\":1.0,\"small\":1e-7,\"big\":1e21,\"negative_zero\":-0.0}",
                "canonical_json": "{\"big\":1e+21,\"negative_zero\":0,\"small\":1e-7,\"whole\":1}"
            },
            {
                "id": "utf16_key_ordering",
                "description": "Object keys are sorted by UTF-16 code units, not UTF-8 bytes.",
                "input_json": "{\"\\ue000\":1,\"\\ud800\\udc00\":2}",
                "canonical_json": "{\"\u{10000}\":2,\"\u{e000}\":1}"
            },
            {
                "id": "string_escaping",
                "description": "Strings use minimal JSON escaping in canonical output.",
                "input_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}",
                "canonical_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}"
            }
        ]
    })
}

fn base_receipt_body(
    id: &str,
    action: ToolCallAction,
    decision: Decision,
    keypair: &Keypair,
) -> ChioReceiptBody {
    ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1710000200,
        capability_id: "cap-bindings-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision: Some(decision),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-bindings-v1".to_string(),
        evidence: vec![
            GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: Some("path allowed".to_string()),
            },
            GuardEvidence {
                guard_name: "SecretLeakGuard".to_string(),
                verdict: true,
                details: Some("no secrets detected".to_string()),
            },
        ],
        metadata: Some(json!({
            "surface": "bindings-vectors",
            "version": 1
        })),
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

fn observation_receipt_body(
    id: &str,
    action: ToolCallAction,
    receipt_kind: ReceiptKind,
    boundary_class: BoundaryClass,
    observation_outcome: ObservationOutcome,
    trust_level: TrustLevel,
    keypair: &Keypair,
) -> ChioReceiptBody {
    ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1710000200,
        capability_id: "cap-bindings-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision: None,
        receipt_kind,
        boundary_class,
        observation_outcome: Some(observation_outcome),
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-bindings-v1".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ObservationRecorder".to_string(),
            verdict: true,
            details: Some("recorded without mediated authorization".to_string()),
        }],
        metadata: Some(json!({
            "surface": "bindings-vectors",
            "version": 1
        })),
        trust_level,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

fn forged_semantically_invalid_receipt(
    mut body: ChioReceiptBody,
    keypair: &Keypair,
    context: &str,
) -> ChioReceipt {
    body.id = chio_receipt_id(&body).test_unwrap(context);
    let (signature, _bytes) = keypair
        .sign_canonical(&body)
        .test_unwrap("sign invalid semantic receipt fixture");
    ChioReceipt {
        id: body.id,
        timestamp: body.timestamp,
        capability_id: body.capability_id,
        tool_server: body.tool_server,
        tool_name: body.tool_name,
        action: body.action,
        decision: body.decision,
        receipt_kind: body.receipt_kind,
        boundary_class: body.boundary_class,
        observation_outcome: body.observation_outcome,
        tool_origin: body.tool_origin,
        redaction_mode: body.redaction_mode,
        actor_chain: body.actor_chain,
        content_hash: body.content_hash,
        policy_hash: body.policy_hash,
        evidence: body.evidence,
        metadata: body.metadata,
        trust_level: body.trust_level,
        tenant_id: body.tenant_id,
        bbs_projection_version: None,
        kernel_key: body.kernel_key,
        bbs_signature: None,
        algorithm: None,
        signature,
    }
}

fn receipt_cases() -> Vec<Value> {
    let seed = [7u8; 32];
    let keypair = Keypair::from_seed(&seed);

    let allow_action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/roadmap.md",
        "mode": "read"
    }))
    .test_unwrap("allow action");
    let allow_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-allow",
            allow_action,
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("allow receipt");
    let allow_verification = verify_receipt(&allow_receipt).test_unwrap("allow verification");

    let deny_action = ToolCallAction::from_parameters(json!({
        "path": "/etc/shadow",
        "mode": "read"
    }))
    .test_unwrap("deny action");
    let deny_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-deny",
            deny_action,
            Decision::Deny {
                reason: "path is forbidden".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
            },
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("deny receipt");
    let deny_verification = verify_receipt(&deny_receipt).test_unwrap("deny verification");

    let mut invalid_hash_action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/private.md",
        "mode": "read"
    }))
    .test_unwrap("invalid hash action");
    invalid_hash_action.parameter_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let invalid_hash_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-invalid-hash",
            invalid_hash_action,
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("invalid hash receipt");
    let invalid_hash_verification =
        verify_receipt(&invalid_hash_receipt).test_unwrap("invalid hash verification");

    let mut invalid_signature_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-invalid-signature",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .test_unwrap("invalid signature action"),
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("invalid signature receipt");
    invalid_signature_receipt.policy_hash = "policy-bindings-v1-tampered".to_string();
    let invalid_signature_verification =
        verify_receipt(&invalid_signature_receipt).test_unwrap("invalid signature verification");

    let trace_receipt = ChioReceipt::sign(
        observation_receipt_body(
            "rcpt-bindings-trace",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .test_unwrap("trace action"),
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            ObservationOutcome::Observed,
            TrustLevel::Verified,
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("trace observation receipt");
    let trace_verification = verify_receipt(&trace_receipt).test_unwrap("trace verification");

    let advisory_receipt = ChioReceipt::sign(
        observation_receipt_body(
            "rcpt-bindings-advisory",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/private.md",
                "mode": "read"
            }))
            .test_unwrap("advisory action"),
            ReceiptKind::AdvisoryEvaluation,
            BoundaryClass::AdvisoryOnly,
            ObservationOutcome::Evaluated,
            TrustLevel::Advisory,
            &keypair,
        ),
        &keypair,
    )
    .test_unwrap("advisory evaluation receipt");
    let advisory_verification =
        verify_receipt(&advisory_receipt).test_unwrap("advisory verification");

    let mut trace_with_decision_receipt = trace_receipt.clone();
    trace_with_decision_receipt.decision = Some(Decision::Allow);
    let trace_with_decision_verification = verify_receipt(&trace_with_decision_receipt)
        .test_unwrap("trace with decision verification");

    let mut mediated_missing_decision_receipt = allow_receipt.clone();
    mediated_missing_decision_receipt.decision = None;
    let mediated_missing_decision_verification = verify_receipt(&mediated_missing_decision_receipt)
        .test_unwrap("mediated missing decision verification");

    let advisory_with_decision_receipt = forged_semantically_invalid_receipt(
        ChioReceiptBody {
            decision: Some(Decision::Allow),
            ..observation_receipt_body(
                "rcpt-bindings-advisory-with-decision",
                ToolCallAction::from_parameters(json!({
                    "path": "/workspace/docs/private.md",
                    "mode": "read"
                }))
                .test_unwrap("advisory with decision action"),
                ReceiptKind::AdvisoryEvaluation,
                BoundaryClass::AdvisoryOnly,
                ObservationOutcome::Evaluated,
                TrustLevel::Advisory,
                &keypair,
            )
        },
        &keypair,
        "advisory with decision id",
    );
    let advisory_with_decision_verification = verify_receipt(&advisory_with_decision_receipt)
        .test_unwrap("advisory with decision verification");

    let trace_missing_observation_receipt = forged_semantically_invalid_receipt(
        ChioReceiptBody {
            observation_outcome: None,
            ..observation_receipt_body(
                "rcpt-bindings-trace-missing-observation",
                ToolCallAction::from_parameters(json!({
                    "path": "/workspace/docs/roadmap.md",
                    "mode": "read"
                }))
                .test_unwrap("trace missing observation action"),
                ReceiptKind::TraceObservation,
                BoundaryClass::DetectOnly,
                ObservationOutcome::Observed,
                TrustLevel::Verified,
                &keypair,
            )
        },
        &keypair,
        "trace missing observation id",
    );
    let trace_missing_observation_verification = verify_receipt(&trace_missing_observation_receipt)
        .test_unwrap("trace missing observation verification");

    let advisory_missing_observation_receipt = forged_semantically_invalid_receipt(
        ChioReceiptBody {
            observation_outcome: None,
            ..observation_receipt_body(
                "rcpt-bindings-advisory-missing-observation",
                ToolCallAction::from_parameters(json!({
                    "path": "/workspace/docs/private.md",
                    "mode": "read"
                }))
                .test_unwrap("advisory missing observation action"),
                ReceiptKind::AdvisoryEvaluation,
                BoundaryClass::AdvisoryOnly,
                ObservationOutcome::Evaluated,
                TrustLevel::Advisory,
                &keypair,
            )
        },
        &keypair,
        "advisory missing observation id",
    );
    let advisory_missing_observation_verification =
        verify_receipt(&advisory_missing_observation_receipt)
            .test_unwrap("advisory missing observation verification");

    let mediated_with_observation_receipt = forged_semantically_invalid_receipt(
        ChioReceiptBody {
            observation_outcome: Some(ObservationOutcome::Observed),
            ..base_receipt_body(
                "rcpt-bindings-mediated-with-observation",
                ToolCallAction::from_parameters(json!({
                    "path": "/workspace/docs/roadmap.md",
                    "mode": "read"
                }))
                .test_unwrap("mediated with observation action"),
                Decision::Allow,
                &keypair,
            )
        },
        &keypair,
        "mediated with observation id",
    );
    let mediated_with_observation_verification = verify_receipt(&mediated_with_observation_receipt)
        .test_unwrap("mediated with observation verification");

    let trace_wrong_trust_receipt = forged_semantically_invalid_receipt(
        observation_receipt_body(
            "rcpt-bindings-trace-wrong-trust",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .test_unwrap("trace wrong trust action"),
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            ObservationOutcome::Observed,
            TrustLevel::Mediated,
            &keypair,
        ),
        &keypair,
        "trace wrong trust id",
    );
    let trace_wrong_trust_verification =
        verify_receipt(&trace_wrong_trust_receipt).test_unwrap("trace wrong trust verification");

    let cannot_see_runtime_receipt = forged_semantically_invalid_receipt(
        observation_receipt_body(
            "rcpt-bindings-cannot-see",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .test_unwrap("cannot see action"),
            ReceiptKind::TraceObservation,
            BoundaryClass::CannotSee,
            ObservationOutcome::Observed,
            TrustLevel::Verified,
            &keypair,
        ),
        &keypair,
        "cannot see id",
    );
    let cannot_see_runtime_verification =
        verify_receipt(&cannot_see_runtime_receipt).test_unwrap("cannot see verification");

    vec![
        receipt_case_value(
            "allow_receipt",
            "Valid allow receipt with matching signature and parameter hash.",
            &allow_receipt,
            allow_verification,
        ),
        receipt_case_value(
            "deny_receipt",
            "Valid deny receipt with matching signature and parameter hash.",
            &deny_receipt,
            deny_verification,
        ),
        receipt_case_value(
            "signed_receipt_with_invalid_parameter_hash",
            "Receipt is signed correctly but carries a bad action parameter hash.",
            &invalid_hash_receipt,
            invalid_hash_verification,
        ),
        receipt_case_value(
            "tampered_receipt_signature",
            "Receipt payload was modified after signing, so signature verification fails.",
            &invalid_signature_receipt,
            invalid_signature_verification,
        ),
        receipt_case_value(
            "trace_observation_receipt",
            "Valid trace observation has no decision and is never authorizing.",
            &trace_receipt,
            trace_verification,
        ),
        receipt_case_value(
            "advisory_evaluation_receipt",
            "Valid advisory evaluation has no decision and is never authorizing.",
            &advisory_receipt,
            advisory_verification,
        ),
        receipt_case_value(
            "trace_observation_with_decision",
            "A trace observation carrying an allow-shaped decision is not signable or authoritative.",
            &trace_with_decision_receipt,
            trace_with_decision_verification,
        ),
        receipt_case_value(
            "mediated_receipt_missing_decision",
            "A mediated receipt without a decision is not signable or authoritative.",
            &mediated_missing_decision_receipt,
            mediated_missing_decision_verification,
        ),
        receipt_case_value(
            "advisory_evaluation_with_decision",
            "An advisory evaluation carrying an allow-shaped decision has a valid id but is not signable.",
            &advisory_with_decision_receipt,
            advisory_with_decision_verification,
        ),
        receipt_case_value(
            "trace_observation_missing_observation_outcome",
            "A trace observation without an observation outcome has a valid id but is not signable.",
            &trace_missing_observation_receipt,
            trace_missing_observation_verification,
        ),
        receipt_case_value(
            "advisory_evaluation_missing_observation_outcome",
            "An advisory evaluation without an observation outcome has a valid id but is not signable.",
            &advisory_missing_observation_receipt,
            advisory_missing_observation_verification,
        ),
        receipt_case_value(
            "mediated_decision_with_observation_outcome",
            "A mediated decision carrying an observation outcome has a valid id but is not signable.",
            &mediated_with_observation_receipt,
            mediated_with_observation_verification,
        ),
        receipt_case_value(
            "trace_observation_wrong_trust_level",
            "A trace observation using mediated trust has a valid id but is not signable.",
            &trace_wrong_trust_receipt,
            trace_wrong_trust_verification,
        ),
        receipt_case_value(
            "cannot_see_runtime_receipt",
            "The cannot_see planning boundary is not a valid signed runtime receipt boundary.",
            &cannot_see_runtime_receipt,
            cannot_see_runtime_verification,
        ),
    ]
}

fn receipt_case_value(
    id: &str,
    description: &str,
    receipt: &ChioReceipt,
    verification: ReceiptVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "receipt": receipt,
        "receipt_body_canonical_json": receipt_body_canonical_json(receipt).test_unwrap("canonical receipt body"),
        "expected": {
            "signature_valid": verification.signature_valid,
            "parameter_hash_valid": verification.parameter_hash_valid,
            "receipt_id_valid": verification.receipt_id_valid,
            "decision": verification.decision,
            "receipt_kind": verification.receipt_kind,
            "boundary_class": verification.boundary_class,
            "trust_level": receipt.trust_level.as_str(),
            "result": verification.result,
            "authorized": verification.authorized,
            "signer_key_hex": verification.signer_key_hex,
            "signer_trusted": verification.signer_trusted,
            "ok": verification.ok,
        }
    })
}

fn receipt_vector_fixture() -> Value {
    let seed = [7u8; 32];
    let keypair = Keypair::from_seed(&seed);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": keypair.seed_hex(),
        "cases": receipt_cases(),
    })
}

fn hashing_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "empty_utf8",
                "description": "SHA-256 of the empty UTF-8 string.",
                "input_utf8": "",
                "sha256_hex": sha256_hex_utf8("")
            },
            {
                "id": "hello_utf8",
                "description": "SHA-256 of a simple ASCII string.",
                "input_utf8": "hello",
                "sha256_hex": sha256_hex_utf8("hello")
            },
            {
                "id": "unicode_utf8",
                "description": "SHA-256 operates on UTF-8 bytes for non-ASCII strings too.",
                "input_utf8": "chio 🔐",
                "sha256_hex": sha256_hex_utf8("chio 🔐")
            }
        ]
    })
}

fn signing_utf8_case_value(
    id: &str,
    description: &str,
    input_utf8: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_utf8": input_utf8,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_json_case_value(
    id: &str,
    description: &str,
    input_json: &str,
    canonical_json: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_json": input_json,
        "canonical_json": canonical_json,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_vector_fixture() -> Value {
    let seed_hex = "09".repeat(32);
    let signed_utf8 =
        sign_utf8_message_ed25519("hello chio", &seed_hex).test_unwrap("sign utf8 message");
    let signed_json =
        sign_json_str_ed25519("{\"z\":1,\"a\":2}", &seed_hex).test_unwrap("sign json string");

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": seed_hex,
        "utf8_cases": [
            signing_utf8_case_value(
                "valid_utf8_message",
                "A UTF-8 message signs and verifies with a deterministic Ed25519 seed.",
                "hello chio",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                true,
            ),
            signing_utf8_case_value(
                "tampered_utf8_message",
                "The same signature fails if the UTF-8 message bytes change.",
                "hello chio!",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                false,
            ),
        ],
        "json_cases": [
            signing_json_case_value(
                "valid_canonical_json_message",
                "Signing raw JSON first canonicalizes it, then signs the canonical bytes.",
                "{\"z\":1,\"a\":2}",
                &signed_json.canonical_json,
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                true,
            ),
            signing_json_case_value(
                "tampered_canonical_json_message",
                "Verification fails if the JSON payload changes after signing.",
                "{\"z\":2,\"a\":2}",
                &canonicalize_json_str("{\"z\":2,\"a\":2}").test_unwrap("canonicalize tampered json"),
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                false,
            ),
        ],
    })
}

fn sample_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            operations: vec![Operation::Invoke, Operation::ReadResult],
            constraints: vec![Constraint::PathPrefix("/workspace/".to_string())],
            max_invocations: Some(3),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    }
}

fn signed_delegation_link(
    capability_id: &str,
    delegator: &Keypair,
    delegatee: &Keypair,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        delegator,
    )
    .test_unwrap("delegation link")
}

fn base_capability_body(
    id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    issued_at: u64,
    expires_at: u64,
    delegation_chain: Vec<DelegationLink>,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: sample_scope(),
        issued_at,
        expires_at,
        delegation_chain,
        aggregate_invocation_budget: None,
    }
}

fn capability_case_value(
    id: &str,
    description: &str,
    capability: &CapabilityToken,
    verify_at: u64,
    verification: CapabilityVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "verify_at": verify_at,
        "capability": capability,
        "capability_body_canonical_json": capability_body_canonical_json(capability).test_unwrap("canonical capability body"),
        "expected": {
            "signature_valid": verification.signature_valid,
            "delegation_chain_shape_valid": verification.delegation_chain_shape_valid,
            "time_valid": verification.time_valid,
            "time_status": verification.time_status,
        }
    })
}

fn capability_cases() -> Vec<Value> {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    let valid_delegation_link =
        signed_delegation_link("cap-bindings-valid", &issuer, &delegatee, 1710000250);
    let valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-valid",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![valid_delegation_link],
        ),
        &issuer,
    )
    .test_unwrap("valid capability");
    let valid_verify_at = 1710000400;
    let valid_verification = verify_capability(&valid_capability, valid_verify_at, Some(4))
        .test_unwrap("valid capability verification");

    let expired_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-expired",
            &issuer,
            &subject,
            1710000000,
            1710000100,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("expired capability");
    let expired_verify_at = 1710000400;
    let expired_verification = verify_capability(&expired_capability, expired_verify_at, Some(4))
        .test_unwrap("expired capability verification");

    let not_yet_valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-not-yet-valid",
            &issuer,
            &subject,
            1710000600,
            1710001200,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("not yet valid capability");
    let not_yet_valid_verify_at = 1710000400;
    let not_yet_valid_verification =
        verify_capability(&not_yet_valid_capability, not_yet_valid_verify_at, Some(4))
            .test_unwrap("not yet valid capability verification");

    let mut tampered_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-invalid-signature",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("tampered capability");
    tampered_capability.scope.grants[0].tool_name = "file_write".to_string();
    let tampered_verify_at = 1710000400;
    let tampered_verification =
        verify_capability(&tampered_capability, tampered_verify_at, Some(4))
            .test_unwrap("tampered capability verification");

    let mut invalid_delegation_link =
        signed_delegation_link("cap-bindings-broken-chain", &issuer, &delegatee, 1710000300);
    invalid_delegation_link.timestamp = 1710000301;
    let broken_chain_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-broken-chain",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![invalid_delegation_link],
        ),
        &issuer,
    )
    .test_unwrap("broken chain capability");
    let broken_chain_verify_at = 1710000400;
    let broken_chain_verification =
        verify_capability(&broken_chain_capability, broken_chain_verify_at, Some(4))
            .test_unwrap("broken chain capability verification");

    vec![
        capability_case_value(
            "valid_delegated_capability",
            "Capability is signed correctly, valid at the verification time, and carries a valid delegation link.",
            &valid_capability,
            valid_verify_at,
            valid_verification,
        ),
        capability_case_value(
            "expired_capability",
            "Capability signature is valid, but the token is expired at verification time.",
            &expired_capability,
            expired_verify_at,
            expired_verification,
        ),
        capability_case_value(
            "not_yet_valid_capability",
            "Capability signature is valid, but the token is not yet valid at verification time.",
            &not_yet_valid_capability,
            not_yet_valid_verify_at,
            not_yet_valid_verification,
        ),
        capability_case_value(
            "tampered_capability_signature",
            "Capability payload was modified after signing, so signature verification fails.",
            &tampered_capability,
            tampered_verify_at,
            tampered_verification,
        ),
        capability_case_value(
            "broken_delegation_chain_signature",
            "Capability was signed after embedding a delegation link whose own signature no longer matches.",
            &broken_chain_capability,
            broken_chain_verify_at,
            broken_chain_verification,
        ),
    ]
}

fn capability_vector_fixture() -> Value {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "issuer_seed_hex": issuer.seed_hex(),
        "subject_seed_hex": subject.seed_hex(),
        "delegatee_seed_hex": delegatee.seed_hex(),
        "cases": capability_cases(),
    })
}

fn sample_signed_manifest(public_key: String, tool_names: &[&str]) -> SignedToolManifest {
    SignedToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "srv-bindings-demo".to_string(),
        name: "Bindings Demo".to_string(),
        description: Some("Manifest vector for bindings-core SDK fixtures".to_string()),
        version: "1.0.0".to_string(),
        tools: tool_names
            .iter()
            .map(|tool_name| SignedManifestToolDefinition {
                name: (*tool_name).to_string(),
                description: format!("Tool definition for {tool_name}"),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "ok": { "type": "boolean" }
                    }
                })),
                pricing: None,
                has_side_effects: *tool_name == "file_write",
                latency_hint: Some(if *tool_name == "file_read" {
                    LatencyHint::Fast
                } else {
                    LatencyHint::Moderate
                }),
            })
            .collect(),
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/workspace".to_string()]),
            write_paths: Some(vec!["/workspace/output".to_string()]),
            network_hosts: Some(vec!["api.example.com".to_string()]),
            environment_variables: Some(vec!["CHIO_ENV".to_string()]),
        }),
        public_key,
    }
}

fn signed_manifest_with_manual_signature(
    manifest: SignedToolManifest,
    signer: &Keypair,
) -> SignedManifest {
    let (signature, _bytes) = signer
        .sign_canonical(&manifest)
        .test_unwrap("manual manifest signature");
    SignedManifest {
        manifest,
        signature,
        signer_key: signer.public_key(),
    }
}

fn manifest_case_value(
    id: &str,
    description: &str,
    signed_manifest: &SignedManifest,
    verification: ManifestVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "signed_manifest": signed_manifest,
        "manifest_body_canonical_json": signed_manifest_body_canonical_json(signed_manifest).test_unwrap("canonical manifest body"),
        "expected": {
            "structure_valid": verification.structure_valid,
            "signature_valid": verification.signature_valid,
            "embedded_public_key_valid": verification.embedded_public_key_valid,
            "embedded_public_key_matches_signer": verification.embedded_public_key_matches_signer,
        }
    })
}

fn manifest_cases() -> Vec<Value> {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    let valid_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .test_unwrap("valid signed manifest");
    let valid_verification =
        verify_signed_manifest(&valid_signed_manifest).test_unwrap("valid manifest verification");

    let mut tampered_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .test_unwrap("tampered signed manifest");
    tampered_signed_manifest.manifest.version = "1.0.1".to_string();
    let tampered_verification = verify_signed_manifest(&tampered_signed_manifest)
        .test_unwrap("tampered manifest verification");

    let mismatched_key_signed_manifest = signed_manifest_with_manual_signature(
        sample_signed_manifest(alternate.public_key().to_hex(), &["file_read"]),
        &server,
    );
    let mismatched_key_verification = verify_signed_manifest(&mismatched_key_signed_manifest)
        .test_unwrap("mismatched key manifest verification");

    let duplicate_tool_manifest =
        sample_signed_manifest(server.public_key().to_hex(), &["file_read", "file_read"]);
    let duplicate_tool_signed_manifest =
        signed_manifest_with_manual_signature(duplicate_tool_manifest, &server);
    let duplicate_tool_verification = verify_signed_manifest(&duplicate_tool_signed_manifest)
        .test_unwrap("duplicate tool manifest verification");

    let invalid_embedded_key_signed_manifest = signed_manifest_with_manual_signature(
        sample_signed_manifest("not-a-public-key".to_string(), &["file_read", "file_write"]),
        &server,
    );
    let invalid_embedded_key_verification =
        verify_signed_manifest(&invalid_embedded_key_signed_manifest)
            .test_unwrap("invalid embedded key manifest verification");

    vec![
        manifest_case_value(
            "valid_signed_manifest",
            "Signed manifest is structurally valid, signature-valid, and its embedded public key matches the signer.",
            &valid_signed_manifest,
            valid_verification,
        ),
        manifest_case_value(
            "tampered_manifest_signature",
            "Manifest payload was modified after signing, so signature verification fails while structure remains valid.",
            &tampered_signed_manifest,
            tampered_verification,
        ),
        manifest_case_value(
            "mismatched_embedded_public_key",
            "Manifest is signed correctly, but the manifest.public_key field does not match the signer key carried alongside the signature.",
            &mismatched_key_signed_manifest,
            mismatched_key_verification,
        ),
        manifest_case_value(
            "duplicate_tool_name_manifest",
            "Manifest signature is valid, but validation fails because tool names are not unique.",
            &duplicate_tool_signed_manifest,
            duplicate_tool_verification,
        ),
        manifest_case_value(
            "invalid_embedded_public_key",
            "Manifest signature is valid, but the embedded public_key field is not a parseable Ed25519 key.",
            &invalid_embedded_key_signed_manifest,
            invalid_embedded_key_verification,
        ),
    ]
}

fn manifest_vector_fixture() -> Value {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "server_seed_hex": server.seed_hex(),
        "alternate_seed_hex": alternate.seed_hex(),
        "cases": manifest_cases(),
    })
}

// On-disk JSON is the source of truth; the in-Rust generators cover a subset
// of cases. The #[ignore] tests below regenerate the checked-in files when run
// manually (`cargo test -- --ignored`).

#[test]
#[ignore = "on-disk canonical corpus is the source of truth; run to regenerate after editing the fixture builder"]
fn canonical_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&canonical_fixture_path(), &canonical_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn hashing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&hashing_fixture_path(), &hashing_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn receipt_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&receipt_fixture_path(), &receipt_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn signing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&signing_fixture_path(), &signing_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn capability_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&capability_fixture_path(), &capability_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; manifest_vector_fixture() is a regenerator helper for a subset of cases"]
fn manifest_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&manifest_fixture_path(), &manifest_vector_fixture());
}

// Re-sign the checked-in capability corpus in place after a capability
// signing-schema change. The signed body carries the schema string, so a
// schema change invalidates every stored signature. Only capabilities whose
// own signature is meant to verify are re-signed; the intentionally tampered
// cases keep their invalid signatures (a corrupted signature stays invalid
// under any schema). Run with `--ignored`, then refreeze the manifest
// with `cargo xtask freeze-vectors`.
#[test]
#[ignore = "regenerator: re-sign capability vectors after a signing-schema change; run with --ignored"]
fn rebless_capability_vector_signatures() {
    use std::collections::HashMap;
    let path = capability_fixture_path();
    let raw = fs::read_to_string(&path).test_unwrap("read capability fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse capability fixture");

    let mut by_pub: HashMap<String, Keypair> = HashMap::new();
    for seed_field in [
        "issuer_seed_hex",
        "subject_seed_hex",
        "delegatee_seed_hex",
        "alt_seed_1_hex",
        "alt_seed_2_hex",
        "alt_seed_3_hex",
        "alt_seed_4_hex",
    ] {
        if let Some(hex) = fixture[seed_field].as_str() {
            let keypair = Keypair::from_seed_hex(hex).test_unwrap("seed hex");
            by_pub.insert(keypair.public_key().to_hex(), keypair);
        }
    }

    let mut replacements: Vec<(String, String)> = Vec::new();
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        if !case["expected"]["signature_valid"]
            .as_bool()
            .unwrap_or(false)
        {
            continue;
        }
        let issuer_hex = case["capability"]["issuer"].as_str().test_unwrap("issuer");
        let keypair = by_pub
            .get(issuer_hex)
            .unwrap_or_else(|| panic!("no seed keypair for issuer {issuer_hex}"));
        let token: CapabilityToken =
            serde_json::from_value(case["capability"].clone()).test_unwrap("parse capability");
        let resigned = CapabilityToken::sign(token.body(), keypair).test_unwrap("re-sign");
        let resigned_value = serde_json::to_value(&resigned).test_unwrap("serialize resigned");
        let old_sig = case["capability"]["signature"]
            .as_str()
            .test_unwrap("old signature")
            .to_string();
        let new_sig = resigned_value["signature"]
            .as_str()
            .test_unwrap("new signature")
            .to_string();
        if old_sig != new_sig {
            replacements.push((old_sig, new_sig));
        }
    }

    let mut text = raw;
    for (old, new) in &replacements {
        assert_eq!(
            text.matches(old.as_str()).count(),
            1,
            "stored signature {old} is not unique; cannot re-bless in place"
        );
        text = text.replace(old.as_str(), new.as_str());
    }
    fs::write(&path, text).test_unwrap("write capability fixture");
    eprintln!(
        "re-signed {} capability vector signatures",
        replacements.len()
    );
}

#[test]
fn canonical_fixture_cases_round_trip_through_public_api() {
    let fixture = canonical_vector_fixture();
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let input = case["input_json"].as_str().test_unwrap("input_json");
        let expected = case["canonical_json"]
            .as_str()
            .test_unwrap("canonical_json");
        let actual = canonicalize_json_str(input).test_unwrap("canonicalize case");
        assert_eq!(actual, expected, "canonical case {}", case["id"]);
    }
}

#[test]
fn hashing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the test exercises every case regardless of
    // whether the in-Rust generator has been updated.
    let raw = fs::read_to_string(hashing_fixture_path()).test_unwrap("read hashing fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse hashing fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let input = case["input_utf8"].as_str().test_unwrap("input_utf8");
        let expected = case["sha256_hex"].as_str().test_unwrap("sha256_hex");
        let actual = sha256_hex_utf8(input);
        assert_eq!(actual, expected, "hashing case {}", case["id"]);
    }
}

#[test]
fn receipt_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the round-trip covers every case.
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let receipt: ChioReceipt =
            serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
        let expected: ReceiptVerification =
            serde_json::from_value(case["expected"].clone()).test_unwrap("parse expectation");
        let actual = verify_receipt(&receipt).test_unwrap("verify receipt case");
        let actual_value = serde_json::to_value(&actual).test_unwrap("serialize verification");
        assert_eq!(
            actual_value["trust_level"], case["receipt"]["trust_level"],
            "receipt case {}",
            case["id"]
        );
        assert_eq!(actual, expected, "receipt case {}", case["id"]);
    }
}

#[test]
fn receipt_fixture_allow_case_passes_with_trusted_signer() {
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    let case = fixture["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["id"] == "allow_receipt")
        .test_unwrap("allow case");
    let receipt: ChioReceipt =
        serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
    let actual =
        verify_receipt_with_trusted_signers(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .test_unwrap("verify receipt with trusted signer");

    assert!(actual.signature_valid);
    assert!(actual.parameter_hash_valid);
    assert!(actual.receipt_id_valid);
    assert!(actual.signer_trusted);
    assert!(actual.ok);
    assert!(actual.authorized);
}

#[test]
fn receipt_fixture_allow_case_passes_with_json_trusted_signer_hex() {
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    let case = fixture["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["id"] == "allow_receipt")
        .test_unwrap("allow case");
    let receipt_json =
        serde_json::to_string(&case["receipt"]).test_unwrap("serialize receipt case");
    let trusted_signer_hex = vec![case["receipt"]["kernel_key"]
        .as_str()
        .test_unwrap("kernel_key")
        .to_string()];
    let actual = verify_receipt_json_with_trusted_signer_hex(&receipt_json, &trusted_signer_hex)
        .test_unwrap("verify receipt json with trusted signer hex");

    assert!(actual.signature_valid);
    assert!(actual.parameter_hash_valid);
    assert!(actual.receipt_id_valid);
    assert!(actual.signer_trusted);
    assert!(actual.ok);
    assert!(actual.authorized);
}

#[test]
fn signing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. Per-case `signing_key_seed_hex` overrides pin
    // the keypair for cases that use an alternate seed; honoring them makes the
    // round-trip exact for those cases.
    let raw = fs::read_to_string(signing_fixture_path()).test_unwrap("read signing fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse signing fixture");
    let global_seed_hex = fixture["signing_key_seed_hex"]
        .as_str()
        .test_unwrap("signing_key_seed_hex");

    for case in fixture["utf8_cases"]
        .as_array()
        .test_unwrap("utf8_cases array")
    {
        let input = case["input_utf8"].as_str().test_unwrap("input_utf8");
        let public_key_hex = case["public_key_hex"]
            .as_str()
            .test_unwrap("public_key_hex");
        let signature_hex = case["signature_hex"].as_str().test_unwrap("signature_hex");
        let expected_verify = case["expected_verify"]
            .as_bool()
            .test_unwrap("expected_verify");
        let seed_hex = case["signing_key_seed_hex"]
            .as_str()
            .unwrap_or(global_seed_hex);

        if expected_verify {
            let signed = sign_utf8_message_ed25519(input, seed_hex).test_unwrap("sign utf8 case");
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "utf8 sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "utf8 sign {}",
                case["id"]
            );
        }

        let actual = verify_utf8_message_ed25519(input, public_key_hex, signature_hex)
            .test_unwrap("verify utf8 case");
        assert_eq!(actual, expected_verify, "utf8 verify {}", case["id"]);
    }

    for case in fixture["json_cases"]
        .as_array()
        .test_unwrap("json_cases array")
    {
        let input = case["input_json"].as_str().test_unwrap("input_json");
        let canonical_json = case["canonical_json"]
            .as_str()
            .test_unwrap("canonical_json");
        let public_key_hex = case["public_key_hex"]
            .as_str()
            .test_unwrap("public_key_hex");
        let signature_hex = case["signature_hex"].as_str().test_unwrap("signature_hex");
        let expected_verify = case["expected_verify"]
            .as_bool()
            .test_unwrap("expected_verify");
        let seed_hex = case["signing_key_seed_hex"]
            .as_str()
            .unwrap_or(global_seed_hex);

        assert_eq!(
            canonicalize_json_str(input).test_unwrap("canonicalize json case"),
            canonical_json,
            "json canonical {}",
            case["id"]
        );

        if expected_verify {
            let signed = sign_json_str_ed25519(input, seed_hex).test_unwrap("sign json case");
            assert_eq!(
                signed.canonical_json, canonical_json,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "json sign {}",
                case["id"]
            );
        }

        let actual = verify_json_str_signature_ed25519(input, public_key_hex, signature_hex)
            .test_unwrap("verify json case");
        assert_eq!(actual, expected_verify, "json verify {}", case["id"]);
    }
}

#[test]
fn capability_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. The shared `expected` field is depth-agnostic so
    // cross-language consumers can compare against the same vectors. Cases with
    // depth-aware behavior carry an optional `max_delegation_depth` plus
    // `expected_with_max_delegation_depth` pair; this test asserts both branches when present.
    let raw = fs::read_to_string(capability_fixture_path()).test_unwrap("read capability fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse capability fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let capability: CapabilityToken =
            serde_json::from_value(case["capability"].clone()).test_unwrap("parse capability case");
        let verify_at = case["verify_at"].as_u64().test_unwrap("verify_at");
        let expected: CapabilityVerification = serde_json::from_value(case["expected"].clone())
            .test_unwrap("parse capability expectation");

        // Depth-agnostic verification: every consumer in the cross-language
        // matrix (chio-go, chio-py, chio-ts) runs this exact assertion.
        let actual_no_depth =
            verify_capability(&capability, verify_at, None).test_unwrap("verify capability case");
        assert_eq!(
            actual_no_depth, expected,
            "capability case {} (no max depth)",
            case["id"]
        );

        // Optional depth-aware branch: only Rust currently parameterizes
        // max_delegation_depth, so we gate on the presence of the per-case
        // override fields.
        if let Some(max_depth) = case
            .get("max_delegation_depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
        {
            let depth_expected_value = case
                .get("expected_with_max_delegation_depth")
                .cloned()
                .unwrap_or_else(|| case["expected"].clone());
            let depth_expected: CapabilityVerification =
                serde_json::from_value(depth_expected_value)
                    .test_unwrap("parse depth-aware capability expectation");
            let actual_with_depth = verify_capability(&capability, verify_at, Some(max_depth))
                .test_unwrap("verify capability case (max depth)");
            assert_eq!(
                actual_with_depth, depth_expected,
                "capability case {} (max_delegation_depth={})",
                case["id"], max_depth
            );
        }
    }
}

#[test]
fn manifest_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus as ground truth.
    let raw = std::fs::read_to_string(manifest_fixture_path()).test_unwrap("read manifest fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse manifest fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let signed_manifest: SignedManifest =
            serde_json::from_value(case["signed_manifest"].clone())
                .test_unwrap("parse signed manifest case");
        let expected: ManifestVerification = serde_json::from_value(case["expected"].clone())
            .test_unwrap("parse manifest expectation");
        let actual =
            verify_signed_manifest(&signed_manifest).test_unwrap("verify signed manifest case");
        assert_eq!(actual, expected, "manifest case {}", case["id"]);
    }
}

#[test]
#[ignore = "helper for regenerating checked-in vector fixtures during development"]
fn print_vector_fixtures_for_bootstrap() {
    println!("--- canonical fixture ---");
    println!("{}", pretty_json(&canonical_vector_fixture()));
    println!("--- hashing fixture ---");
    println!("{}", pretty_json(&hashing_vector_fixture()));
    println!("--- receipt fixture ---");
    println!("{}", pretty_json(&receipt_vector_fixture()));
    println!("--- signing fixture ---");
    println!("{}", pretty_json(&signing_vector_fixture()));
    println!("--- capability fixture ---");
    println!("{}", pretty_json(&capability_vector_fixture()));
    println!("--- manifest fixture ---");
    println!("{}", pretty_json(&manifest_vector_fixture()));
}
