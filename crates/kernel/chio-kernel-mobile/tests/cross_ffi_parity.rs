#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cross-FFI parity between the mobile UniFFI-facing Rust surface and the
//! plain C ABI used by `chio-cpp-kernel-ffi`.

#[path = "../../../sdk/chio-cpp-kernel-ffi/src/lib.rs"]
mod chio_cpp_kernel_ffi;

use std::ffi::CString;

use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_kernel_mobile::evaluate as mobile_evaluate;
use serde::Deserialize;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const EVAL_TIME: u64 = 1_700_000_100;

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
    };
    CapabilityToken::sign(body, issuer).unwrap()
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
