#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cross-FFI parity between the mobile UniFFI-facing Rust surface and the
//! plain C ABI used by `chio-cpp-kernel-ffi`.

#[path = "../../../sdk/chio-cpp-kernel-ffi/src/lib.rs"]
mod chio_cpp_kernel_ffi;

use std::ffi::CString;

use chio_core_types::capability::{
    attenuation::delegate,
    features::{CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, CUMULATIVE_APPROVAL_BUDGET},
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::delegation_receipt::ScopeAttenuation;
use chio_kernel_mobile::{
    evaluate as mobile_evaluate, verify_capability_with_context as mobile_verify_capability,
};
use serde::Deserialize;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const EVAL_TIME: u64 = 1_700_000_100;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Deserialize)]
struct ParityCase {
    name: String,
    request_id: String,
    tool_name: String,
    server_id: String,
    arguments: serde_json::Value,
    expected_verdict: String,
}

fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
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
        id: "cap-cross-ffi".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

fn aggregate_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(AGGREGATE_INVOCATION_BUDGET.to_string(), true);
    peer
}

fn cumulative_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(CUMULATIVE_APPROVAL_BUDGET.to_string(), true);
    peer
}

fn aggregate_family_fixture() -> TestResult<(
    Keypair,
    Keypair,
    CapabilityToken,
    CapabilityToken,
    CapabilityToken,
)> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_body = make_capability(&root_subject, &issuer).body();
    root_body.id = "cap-cross-ffi-aggregate-root".to_string();
    root_body
        .scope
        .grants
        .first_mut()
        .ok_or_else(|| std::io::Error::other("aggregate root grant missing"))?
        .operations
        .push(Operation::Delegate);
    let root = CapabilityToken::sign_aggregate_family_root(root_body.clone(), 4, &issuer)?;
    let mut child_body = make_capability(&delegatee, &issuer).body();
    child_body.id = "cap-cross-ffi-aggregate-child".to_string();
    let receipt = delegate(
        &root,
        &child_body.scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        ISSUED_AT + 1,
        [11_u8; 16],
    )?;
    child_body.issued_at = ISSUED_AT + 1;
    child_body.delegation_chain = receipt.complete_chain();
    child_body.aggregate_invocation_budget = root.aggregate_invocation_budget.clone();
    let child = CapabilityToken::sign(child_body, &issuer)?;

    root_body.id = "cap-cross-ffi-aggregate-wrong-root".to_string();
    root_body.subject = Keypair::generate().public_key();
    let wrong_root = CapabilityToken::sign_aggregate_family_root(root_body, 4, &issuer)?;
    Ok((issuer, delegatee, root, child, wrong_root))
}

fn cumulative_family_fixture(
) -> TestResult<(Keypair, CapabilityToken, CapabilityToken, CapabilityToken)> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_body = make_capability(&root_subject, &issuer).body();
    root_body.id = "cap-cross-ffi-cumulative-root".to_string();
    let root_grant = root_body
        .scope
        .grants
        .first_mut()
        .ok_or_else(|| std::io::Error::other("cumulative root grant missing"))?;
    root_grant.operations.push(Operation::Delegate);
    root_grant
        .constraints
        .push(cumulative_constraint(100, None));
    let root = CapabilityToken::sign_cumulative_approval_family_root(root_body.clone(), &issuer)?;
    let binding = root
        .scope
        .grants
        .first()
        .and_then(|grant| grant.constraints.first())
        .and_then(Constraint::cumulative_approval_root_binding)
        .cloned()
        .ok_or_else(|| std::io::Error::other("cumulative root binding missing"))?;

    let mut child_body = make_capability(&delegatee, &issuer).body();
    child_body.id = "cap-cross-ffi-cumulative-child".to_string();
    child_body.scope.grants[0]
        .constraints
        .push(cumulative_constraint(80, Some(binding)));
    let receipt = delegate(
        &root,
        &child_body.scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        ISSUED_AT + 1,
        [12_u8; 16],
    )?;
    child_body.issued_at = ISSUED_AT + 1;
    child_body.delegation_chain = receipt.complete_chain();
    let child = CapabilityToken::sign(child_body, &issuer)?;

    root_body.id = "cap-cross-ffi-cumulative-wrong-root".to_string();
    root_body.subject = Keypair::generate().public_key();
    let wrong_root = CapabilityToken::sign_cumulative_approval_family_root(root_body, &issuer)?;
    Ok((issuer, root, child, wrong_root))
}

fn cumulative_constraint(
    threshold_units: u64,
    root_binding: Option<
        chio_core_types::capability::cumulative_approval::CumulativeApprovalRootBinding,
    >,
) -> Constraint {
    Constraint::RequireCumulativeApprovalAbove {
        threshold: MonetaryAmount {
            units: threshold_units,
            currency: "USD".to_string(),
        },
        approval_budget_id: "budget-1".to_string(),
        approval_budget_epoch: 1,
        cumulative_approval_root_binding: root_binding.map(Box::new),
    }
}

fn parent_budget_snapshot(parent_id: &str) -> serde_json::Value {
    serde_json::json!({
        "parent_token_id": parent_id,
        "parent_share_bps": 10_000,
        "admitted_children": [],
    })
}

fn build_request_json(
    case: &ParityCase,
    capability: &CapabilityToken,
    issuer: &Keypair,
    subject: &Keypair,
) -> String {
    serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": case.request_id,
            "tool_name": case.tool_name,
            "server_id": case.server_id,
            "agent_id": subject.public_key().to_hex(),
            "arguments": case.arguments,
        },
        "now_secs": EVAL_TIME,
    })
    .to_string()
}

fn take_ffi_buffer(buffer: chio_cpp_kernel_ffi::ChioKernelFfiBuffer) -> String {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return String::new();
    }
    // SAFETY: the C ABI result owns a valid buffer allocated by
    // `chio-cpp-kernel-ffi`; copy before returning ownership to the ABI.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len).to_vec() };
    chio_cpp_kernel_ffi::chio_kernel_buffer_free(buffer);
    String::from_utf8(bytes).unwrap()
}

fn cpp_evaluate(request_json: &str) -> String {
    let request_c = CString::new(request_json).unwrap();
    let result = chio_cpp_kernel_ffi::chio_kernel_evaluate_json(request_c.as_ptr());
    let output = take_ffi_buffer(result.data);
    assert_eq!(
        result.status,
        chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_OK,
        "C ABI status={} error_code={} output={}",
        result.status,
        result.error_code,
        output
    );
    output
}

fn cpp_verify_capability(request_json: &str) -> TestResult<(i32, i32, String)> {
    let request_c = CString::new(request_json)?;
    let result =
        chio_cpp_kernel_ffi::chio_kernel_verify_capability_with_context_json(request_c.as_ptr());
    let status = result.status;
    let error_code = result.error_code;
    let output = take_ffi_buffer(result.data);
    Ok((status, error_code, output))
}

#[test]
fn mobile_uniffi_and_cpp_c_abi_return_byte_equal_verdicts() {
    let cases: Vec<ParityCase> =
        serde_json::from_str(include_str!("fixtures/parity/evaluate_cases.json")).unwrap();
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    for case in cases {
        let request_json = build_request_json(&case, &capability, &issuer, &subject);
        let mobile = mobile_evaluate(request_json.clone()).unwrap();
        let cpp = cpp_evaluate(&request_json);

        assert_eq!(
            mobile.as_bytes(),
            cpp.as_bytes(),
            "{} verdict JSON differed between mobile UniFFI and C ABI",
            case.name
        );

        let verdict: serde_json::Value = serde_json::from_str(&mobile).unwrap();
        assert_eq!(
            verdict["verdict"], case.expected_verdict,
            "{} expected verdict mismatch",
            case.name
        );
    }
}

#[test]
fn mobile_and_cpp_enforce_negotiated_aggregate_root_evidence() -> TestResult {
    let (issuer, subject, root, child, wrong_root) = aggregate_family_fixture()?;
    let verify_request = |direct_root_capability: Option<&CapabilityToken>| {
        serde_json::json!({
            "token": child,
            "trusted_issuers": [issuer.public_key().to_hex()],
            "now_secs": EVAL_TIME as i64,
            "peer_capabilities": aggregate_peer(),
            "direct_root_capability": direct_root_capability,
            "parent_budget_snapshots": [parent_budget_snapshot(&root.id)],
        })
        .to_string()
    };

    let valid_request = verify_request(Some(&root));
    let mobile_verified = mobile_verify_capability(valid_request.clone())?;
    assert_eq!(mobile_verified.id, child.id);
    let (status, error_code, output) = cpp_verify_capability(&valid_request)?;
    assert_eq!(status, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_OK);
    assert_eq!(error_code, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_ERROR_NONE);
    let cpp_verified: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(cpp_verified["id"], child.id);

    let missing_request = verify_request(None);
    let mobile_missing = match mobile_verify_capability(missing_request.clone()) {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other(
                "mobile accepted delegated aggregate budget without root evidence",
            )
            .into());
        }
    };
    assert!(mobile_missing.to_string().contains("direct-root"));
    let (status, error_code, output) = cpp_verify_capability(&missing_request)?;
    assert_eq!(status, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_ERROR);
    assert_eq!(
        error_code,
        chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY
    );
    assert!(output.contains("direct-root"));

    let mismatch_request = verify_request(Some(&wrong_root));
    let mobile_mismatch = match mobile_verify_capability(mismatch_request.clone()) {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other(
                "mobile accepted mismatched aggregate root evidence",
            )
            .into());
        }
    };
    assert!(mobile_mismatch
        .to_string()
        .contains("does not originate from the authenticated root"));
    let (status, error_code, output) = cpp_verify_capability(&mismatch_request)?;
    assert_eq!(status, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_ERROR);
    assert_eq!(
        error_code,
        chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY
    );
    assert!(output.contains("does not originate from the authenticated root"));

    let evaluation_request = serde_json::json!({
        "capability": child,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-cross-ffi-aggregate",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"},
        },
        "now_secs": EVAL_TIME,
        "peer_capabilities": aggregate_peer(),
        "direct_root_capability": root,
        "parent_budget_snapshots": [parent_budget_snapshot("cap-cross-ffi-aggregate-root")],
    })
    .to_string();
    let mobile = mobile_evaluate(evaluation_request.clone())?;
    let cpp = cpp_evaluate(&evaluation_request);
    assert_eq!(mobile, cpp);
    let verdict: serde_json::Value = serde_json::from_str(&mobile)?;
    assert_eq!(verdict["verdict"], "deny");
    assert!(verdict["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains(
            "capability feature unsupported on this runtime: aggregate invocation enforcement"
        )));
    Ok(())
}

#[test]
fn mobile_and_cpp_enforce_negotiated_cumulative_root_evidence() -> TestResult {
    let (issuer, root, child, wrong_root) = cumulative_family_fixture()?;
    let verify_request = |direct_root_capability: Option<&CapabilityToken>| {
        serde_json::json!({
            "token": child,
            "trusted_issuers": [issuer.public_key().to_hex()],
            "now_secs": EVAL_TIME as i64,
            "peer_capabilities": cumulative_peer(),
            "direct_root_capability": direct_root_capability,
            "parent_budget_snapshots": [parent_budget_snapshot(&root.id)],
        })
        .to_string()
    };

    let valid_request = verify_request(Some(&root));
    let mobile_verified = mobile_verify_capability(valid_request.clone())?;
    assert_eq!(mobile_verified.id, child.id);
    let (status, error_code, output) = cpp_verify_capability(&valid_request)?;
    assert_eq!(status, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_OK);
    assert_eq!(error_code, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_ERROR_NONE);
    let cpp_verified: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(cpp_verified["id"], child.id);

    for (supplied_root, expected) in [
        (None, "direct-root"),
        (
            Some(&wrong_root),
            "does not originate from the authenticated root",
        ),
    ] {
        let request = verify_request(supplied_root);
        let mobile_error = match mobile_verify_capability(request.clone()) {
            Err(error) => error,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "mobile accepted invalid cumulative root evidence",
                )
                .into());
            }
        };
        assert!(
            mobile_error.to_string().contains(expected),
            "{mobile_error}"
        );

        let (status, error_code, output) = cpp_verify_capability(&request)?;
        assert_eq!(status, chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_STATUS_ERROR);
        assert_eq!(
            error_code,
            chio_cpp_kernel_ffi::CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY
        );
        assert!(output.contains(expected), "{output}");
    }

    for (name, supplied_root, expected) in [
        (
            "valid",
            Some(&root),
            "capability feature unsupported on this runtime: cumulative approval enforcement",
        ),
        ("missing", None, "direct-root"),
        (
            "mismatched",
            Some(&wrong_root),
            "does not originate from the authenticated root",
        ),
    ] {
        let evaluation_request = serde_json::json!({
            "capability": child,
            "trusted_issuers": [issuer.public_key().to_hex()],
            "request": {
                "request_id": format!("req-cross-ffi-cumulative-{name}"),
                "tool_name": "echo",
                "server_id": "srv-a",
                "agent_id": child.subject.to_hex(),
                "arguments": {"msg": "hello"},
            },
            "now_secs": EVAL_TIME,
            "peer_capabilities": cumulative_peer(),
            "direct_root_capability": supplied_root,
            "parent_budget_snapshots": [parent_budget_snapshot(&root.id)],
        })
        .to_string();
        let mobile = mobile_evaluate(evaluation_request.clone())?;
        let cpp = cpp_evaluate(&evaluation_request);
        assert_eq!(mobile, cpp, "{name}");
        let verdict: serde_json::Value = serde_json::from_str(&mobile)?;
        assert_eq!(verdict["verdict"], "deny", "{name}");
        let reason = verdict["reason"].as_str().unwrap_or_default();
        assert!(reason.contains(expected), "{name}: {reason}");
    }
    Ok(())
}
