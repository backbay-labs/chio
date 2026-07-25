use super::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityTokenBody,
};
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::{decision::Decision, decision::ToolCallAction, kinds::TrustLevel};
use chio_kernel_core::passport_verify::{
    PortablePassportBody, PortablePassportEnvelope, PORTABLE_PASSPORT_SCHEMA,
};
use std::ffi::CString;

use serde_json::json;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

fn make_capability_at(
    subject: &Keypair,
    issuer: &Keypair,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
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
    };
    let body = CapabilityTokenBody {
        id: "cap-1".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

fn make_delegated_capability(
    id: &str,
    parent_id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> CapabilityToken {
    let mut body = make_capability_at(subject, issuer, ISSUED_AT, EXPIRES_AT).body();
    body.id = id.to_string();
    body.delegation_chain = vec![DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: ISSUED_AT,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        issuer,
    )
    .unwrap()];
    CapabilityToken::sign(body, issuer).unwrap()
}

fn parent_budget_snapshot(parent_id: &str) -> serde_json::Value {
    json!({
        "parent_token_id": parent_id,
        "parent_share_bps": 10_000,
        "admitted_children": [],
    })
}

fn oversubscribed_budget_snapshot(parent_id: &str) -> serde_json::Value {
    json!({
        "parent_token_id": parent_id,
        "parent_share_bps": 10_000,
        "admitted_children": [
            {
                "child_token_id": "cap-sibling",
                "share_bps": 1,
            }
        ],
    })
}

#[test]
fn seed_budget_registry_rejects_blank_parent_token_id() {
    let snapshot = ParentBudgetSnapshot {
        parent_token_id: " ".to_string(),
        parent_share_bps: 10_000,
        admitted_children: Vec::new(),
    };
    let mut registry = InMemoryBudgetRegistry::new();

    let error = seed_budget_registry(&mut registry, &[snapshot]).unwrap_err();

    match error {
        KernelFfiError::InvalidCapability(message) => {
            assert!(message.contains("parent_token_id"));
        }
        other => panic!("expected InvalidCapability, got {other:?}"),
    }
}

fn evaluate_envelope_at(
    tool_name: &str,
    issued_at: u64,
    expires_at: u64,
    now_secs: Option<u64>,
) -> String {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_at(&subject, &issuer, issued_at, expires_at);
    let mut envelope = json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-1",
            "tool_name": tool_name,
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"}
        }
    });
    if let Some(now_secs) = now_secs {
        envelope["now_secs"] = json!(now_secs);
    }
    envelope.to_string()
}

fn evaluate_envelope(tool_name: &str) -> String {
    evaluate_envelope_at(tool_name, ISSUED_AT, EXPIRES_AT, Some(ISSUED_AT + 1))
}

fn passport_envelope_at(issuer: &Keypair, issued_at: u64, expires_at: u64) -> String {
    let payload = json!({
        "schema": "chio.agent-passport.v1",
        "subject": "did:chio:agent-epoch",
        "trustTier": "epoch",
    });
    let body = PortablePassportBody {
        schema: PORTABLE_PASSPORT_SCHEMA.to_string(),
        subject: "did:chio:agent-epoch".to_string(),
        issuer: issuer.public_key(),
        issued_at,
        expires_at,
        payload_canonical_bytes: canonical_json_bytes(&payload).unwrap(),
    };
    let (signature, _) = issuer.sign_canonical(&body).unwrap();
    serde_json::to_string(&PortablePassportEnvelope { body, signature }).unwrap()
}

#[test]
fn fixed_clock_helpers_preserve_epoch_zero_and_negative_sentinel() {
    assert_eq!(fixed_clock_from_secs(0).unwrap().now_unix_secs(), 0);
    assert!(fixed_clock_from_secs(-1).is_none());
}

#[test]
fn evaluate_allows_matching_capability() {
    let output = evaluate_json_str(&evaluate_envelope("echo")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["verdict"], "allow");
    assert_eq!(value["matched_grant_index"], 0);
}

#[test]
fn evaluate_rejects_unsupported_authorization_extensions() {
    let mut envelope: serde_json::Value = serde_json::from_str(&evaluate_envelope("echo")).unwrap();
    envelope["request"]["threshold_approval_proposal"] = json!({"opaque": true});

    let error = evaluate_json_str(&envelope.to_string())
        .expect_err("unsupported authorization extension must fail closed");

    assert!(matches!(
        error,
        KernelFfiError::InvalidCapability(message)
            if message.contains("cannot authenticate governed approvals")
    ));
}

#[test]
fn evaluate_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let envelope = json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-delegated",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"}
        },
        "now_secs": ISSUED_AT + 1,
        "parent_budget_snapshots": [parent_budget_snapshot("cap-parent")]
    });

    let output = evaluate_json_str(&envelope.to_string()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(value["verdict"], "allow");
    assert_eq!(value["matched_grant_index"], 0);
}

#[test]
fn evaluate_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let envelope = json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-delegated-oversub",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"}
        },
        "now_secs": ISSUED_AT + 1,
        "parent_budget_snapshots": [oversubscribed_budget_snapshot("cap-parent")]
    });

    let output = evaluate_json_str(&envelope.to_string()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(value["verdict"], "deny");
    assert!(value["reason"]
        .as_str()
        .unwrap()
        .contains("budget split rejected"));
}

#[test]
fn evaluate_honors_epoch_zero_clock() {
    let output = evaluate_json_str(&evaluate_envelope_at("echo", 0, 10, Some(0))).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["verdict"], "allow");
}

#[test]
fn evaluate_accepts_u64_now_secs_above_i64_max() {
    let output = evaluate_json_str(&evaluate_envelope_at(
        "echo",
        0,
        u64::MAX,
        Some(i64::MAX as u64 + 1),
    ))
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["verdict"], "allow");
}

#[test]
fn verify_passport_honors_epoch_zero_clock() {
    let issuer = Keypair::generate();
    let envelope = passport_envelope_at(&issuer, 0, 10);

    let output = verify_passport_json_str(&envelope, &issuer.public_key().to_hex(), 0).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["evaluated_at"], 0);
    assert_eq!(value["issued_at"], 0);
    assert_eq!(value["expires_at"], 10);
}

#[test]
fn verify_capability_honors_epoch_zero_clock() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_at(&subject, &issuer, 0, 10);
    let token_json = serde_json::to_string(&capability).unwrap();

    let output = verify_capability_json_str(&token_json, &issuer.public_key().to_hex(), 0).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["id"], "cap-1");
    assert_eq!(value["evaluated_at"], 0);
    assert_eq!(value["issued_at"], 0);
    assert_eq!(value["expires_at"], 10);
}

#[test]
fn verify_capability_context_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let envelope = json!({
        "token": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "now_secs": ISSUED_AT as i64 + 1,
        "parent_budget_snapshots": [parent_budget_snapshot("cap-parent")]
    });

    let output = verify_capability_with_context_json_str(&envelope.to_string()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(value["id"], "cap-child");
    assert_eq!(value["subject_hex"], subject.public_key().to_hex());
}

#[test]
fn verify_capability_context_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let envelope = json!({
        "token": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "now_secs": ISSUED_AT as i64 + 1,
        "parent_budget_snapshots": [oversubscribed_budget_snapshot("cap-parent")]
    });

    let error = verify_capability_with_context_json_str(&envelope.to_string()).unwrap_err();

    match error {
        KernelFfiError::InvalidCapability(message) => {
            assert!(message.contains("sibling-sum budget split"));
        }
        other => panic!("expected InvalidCapability, got {other:?}"),
    }
}

#[test]
fn verify_capability_context_rejects_malformed_trust_root_issuer() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_at(&subject, &issuer, ISSUED_AT, EXPIRES_AT);
    let envelope = json!({
        "token": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "now_secs": ISSUED_AT as i64 + 1,
        "capability_trust_roots": {
            "not-a-public-key": "scope-hash"
        }
    });

    let error = verify_capability_with_context_json_str(&envelope.to_string()).unwrap_err();

    match error {
        KernelFfiError::InvalidHex(message) => {
            assert!(message.contains("capability trust root issuer"));
        }
        other => panic!("expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn evaluate_rejects_empty_trust_root_scope_hash() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_at(&subject, &issuer, ISSUED_AT, EXPIRES_AT);
    let envelope = json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-trust-root-empty",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"}
        },
        "now_secs": ISSUED_AT + 1,
        "capability_trust_roots": {
            issuer.public_key().to_hex(): ""
        }
    });

    let error = evaluate_json_str(&envelope.to_string()).unwrap_err();

    match error {
        KernelFfiError::InvalidCapability(message) => {
            assert!(message.contains("capability_trust_roots"));
        }
        other => panic!("expected InvalidCapability, got {other:?}"),
    }
}

#[test]
fn verify_capability_uses_supplied_time_for_expiration() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_at(&subject, &issuer, 0, 10);
    let token_json = serde_json::to_string(&capability).unwrap();

    let error =
        verify_capability_json_str(&token_json, &issuer.public_key().to_hex(), 11).unwrap_err();
    assert!(matches!(error, KernelFfiError::InvalidCapability(_)));
}

#[test]
fn evaluate_denies_out_of_scope_tool() {
    let output = evaluate_json_str(&evaluate_envelope("delete-all")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["verdict"], "deny");
    assert!(value["reason"]
        .as_str()
        .unwrap()
        .contains("not in capability scope"));
}

#[test]
fn evaluate_reports_invalid_json() {
    let error = evaluate_json_str("{not-json").unwrap_err();
    assert!(matches!(error, KernelFfiError::InvalidJson(_)));
}

#[test]
fn null_pointer_returns_null_argument_status() {
    let result = chio_kernel_evaluate_json(ptr::null());
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_NULL_ARGUMENT);
    assert_eq!(result.error_code, CHIO_KERNEL_FFI_ERROR_INTERNAL);
    chio_kernel_buffer_free(result.data);
}

fn make_receipt_body_json(keypair: &Keypair, content_hash: String) -> String {
    let body = ChioReceiptBody {
        id: "rcpt-cpp-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash,
        policy_hash: "0".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    serde_json::to_string(&body).unwrap()
}

/// Read a Rust-owned result buffer into an owned `String` and free it.
fn take_result_string(result: &ChioKernelFfiResult) -> String {
    if result.data.ptr.is_null() || result.data.len == 0 {
        return String::new();
    }
    // SAFETY: the buffer was produced by `ChioKernelFfiBuffer::from_string`
    // over UTF-8 bytes with exactly this pointer and length.
    let bytes = unsafe { std::slice::from_raw_parts(result.data.ptr, result.data.len) };
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn ffi_sign_receipt_recompute_accepts_matching_content() {
    // WYSIWYS: drive the PUBLIC C ABI signer end-to-end. A matching
    // content+hash pair signs and verifies.
    let keypair = Keypair::generate();
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = sha256_hex(&canonical_content);
    let body_json = make_receipt_body_json(&keypair, content_hash);

    let body_c = CString::new(body_json).unwrap();
    let content_c = CString::new(hex::encode(&canonical_content)).unwrap();
    let seed_c = CString::new(keypair.seed_hex()).unwrap();

    let result =
        chio_kernel_sign_receipt_json(body_c.as_ptr(), content_c.as_ptr(), seed_c.as_ptr());
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_OK, "status");
    let signed = take_result_string(&result);
    chio_kernel_buffer_free(result.data);

    let receipt: ChioReceipt = serde_json::from_str(&signed).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, keypair.public_key());
}

#[test]
fn ffi_sign_receipt_refuses_render_a_sign_b() {
    // WYSIWYS render-A/sign-B regression at the C++ ABI boundary.
    // The body claims hash(B) while the canonical content handed to the public
    // C ABI signer is A; the recompute-and-refuse gate MUST reject it
    // fail-closed. Without the fix (relaying the trusted body without
    // recomputing) the forged receipt would be signed and returned OK.
    let keypair = Keypair::generate();
    let content_a = br#"{"shown":"to-the-human"}"#.to_vec();
    let hash_b = sha256_hex(br#"{"secretly":"signed-instead"}"#);
    let body_json = make_receipt_body_json(&keypair, hash_b);

    let body_c = CString::new(body_json).unwrap();
    let content_c = CString::new(hex::encode(&content_a)).unwrap();
    let seed_c = CString::new(keypair.seed_hex()).unwrap();

    let result =
        chio_kernel_sign_receipt_json(body_c.as_ptr(), content_c.as_ptr(), seed_c.as_ptr());
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_ERROR, "must fail");
    assert_eq!(result.error_code, CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED);
    let message = take_result_string(&result);
    chio_kernel_buffer_free(result.data);
    assert!(message.contains("WYSIWYS refused"), "got: {message}");
}

#[test]
fn ffi_sign_receipt_relay_signs_without_preimage() {
    // The explicitly named relay ABI forwards a trusted body
    // without a content preimage; it trusts `content_hash`.
    let keypair = Keypair::generate();
    let body_json = make_receipt_body_json(&keypair, "0".repeat(64));

    let body_c = CString::new(body_json).unwrap();
    let seed_c = CString::new(keypair.seed_hex()).unwrap();

    let result =
        chio_kernel_sign_receipt_relaying_trusted_body_json(body_c.as_ptr(), seed_c.as_ptr());
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_OK, "relay status");
    let signed = take_result_string(&result);
    chio_kernel_buffer_free(result.data);

    let receipt: ChioReceipt = serde_json::from_str(&signed).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, keypair.public_key());
}

#[test]
fn ffi_abi_version_is_two_so_two_arg_clients_fail_closed() {
    // `chio_kernel_sign_receipt_json` gained a third pointer arg
    // (`canonical_content_hex`). The ABI version MUST advance from 1 to 2 so an
    // old 2-arg client that gates on `chio_kernel_ffi_abi_version()` refuses to
    // link instead of calling the 3-arg symbol with a missing third pointer.
    assert_eq!(CHIO_CPP_KERNEL_FFI_ABI_VERSION, 2);
    assert_eq!(chio_kernel_ffi_abi_version(), 2);

    let result = chio_kernel_build_info();
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_OK);
    let info = take_result_string(&result);
    chio_kernel_buffer_free(result.data);
    let value: serde_json::Value = serde_json::from_str(&info).unwrap();
    assert_eq!(value["abi_version"], 2);
}
