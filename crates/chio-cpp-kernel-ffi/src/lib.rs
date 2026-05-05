//! C ABI for the Chio C++ offline kernel package.
//!
//! This crate mirrors the mobile adapter's JSON-in / JSON-out shape, but uses
//! a plain C ABI that the C++ SDK can link without exposing UniFFI or Rust
//! concepts in public C++ headers.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::CapabilityToken;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey};
use chio_core_types::receipt::ChioReceiptBody;
use chio_kernel_core::passport_verify::{verify_passport as core_verify_passport, VerifyError};
use chio_kernel_core::{
    evaluate as core_evaluate, sign_receipt as core_sign_receipt,
    verify_capability as core_verify_capability, CapabilityError, Clock, EvaluateInput, FixedClock,
    Guard, PortableToolCallRequest, ReceiptSigningError, Verdict,
};
use serde::{Deserialize, Serialize};

pub const CHIO_CPP_KERNEL_FFI_ABI_VERSION: u32 = 1;

pub const CHIO_KERNEL_FFI_STATUS_OK: i32 = 0;
pub const CHIO_KERNEL_FFI_STATUS_ERROR: i32 = 1;
pub const CHIO_KERNEL_FFI_STATUS_PANIC: i32 = 2;
pub const CHIO_KERNEL_FFI_STATUS_NULL_ARGUMENT: i32 = 3;

pub const CHIO_KERNEL_FFI_ERROR_NONE: i32 = 0;
pub const CHIO_KERNEL_FFI_ERROR_INVALID_JSON: i32 = 1;
pub const CHIO_KERNEL_FFI_ERROR_INVALID_HEX: i32 = 2;
pub const CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY: i32 = 3;
pub const CHIO_KERNEL_FFI_ERROR_INVALID_PASSPORT: i32 = 4;
pub const CHIO_KERNEL_FFI_ERROR_KEY_MISMATCH: i32 = 5;
pub const CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED: i32 = 6;
pub const CHIO_KERNEL_FFI_ERROR_INTERNAL: i32 = 255;

#[repr(C)]
pub struct ChioKernelFfiBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct ChioKernelFfiResult {
    pub status: i32,
    pub error_code: i32,
    pub data: ChioKernelFfiBuffer,
}

impl ChioKernelFfiBuffer {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_string(value: String) -> Self {
        let bytes = value.into_bytes();
        if bytes.is_empty() {
            return Self::empty();
        }
        let mut boxed = bytes.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self { ptr, len }
    }
}

#[derive(Debug)]
enum KernelFfiError {
    InvalidJson(String),
    InvalidHex(String),
    InvalidCapability(String),
    InvalidPassport(String),
    KernelKeyMismatch(String),
    SigningFailed(String),
    Internal(String),
}

impl KernelFfiError {
    fn code(&self) -> i32 {
        match self {
            Self::InvalidJson(_) => CHIO_KERNEL_FFI_ERROR_INVALID_JSON,
            Self::InvalidHex(_) => CHIO_KERNEL_FFI_ERROR_INVALID_HEX,
            Self::InvalidCapability(_) => CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY,
            Self::InvalidPassport(_) => CHIO_KERNEL_FFI_ERROR_INVALID_PASSPORT,
            Self::KernelKeyMismatch(_) => CHIO_KERNEL_FFI_ERROR_KEY_MISMATCH,
            Self::SigningFailed(_) => CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED,
            Self::Internal(_) => CHIO_KERNEL_FFI_ERROR_INTERNAL,
        }
    }

    fn message(self) -> String {
        match self {
            Self::InvalidJson(message)
            | Self::InvalidHex(message)
            | Self::InvalidCapability(message)
            | Self::InvalidPassport(message)
            | Self::KernelKeyMismatch(message)
            | Self::SigningFailed(message)
            | Self::Internal(message) => message,
        }
    }

    fn invalid_json(context: &str, error: impl std::fmt::Display) -> Self {
        Self::InvalidJson(format!("{context}: {error}"))
    }

    fn invalid_hex(context: &str, error: impl std::fmt::Display) -> Self {
        Self::InvalidHex(format!("{context}: {error}"))
    }

    fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        Self::Internal(format!("{context}: {error}"))
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Debug, Deserialize)]
struct EvaluateRequestEnvelope {
    capability: serde_json::Value,
    trusted_issuers: Vec<String>,
    request: EvaluateRequestBody,
    #[serde(default)]
    now_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct EvaluateRequestBody {
    request_id: String,
    tool_name: String,
    server_id: String,
    agent_id: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct EvaluateResponse {
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_grant_index: Option<usize>,
}

#[derive(Debug, Serialize)]
struct VerifiedCapabilityResponse {
    id: String,
    subject_hex: String,
    issuer_hex: String,
    scope_json: String,
    issued_at: u64,
    expires_at: u64,
    evaluated_at: u64,
}

#[derive(Debug, Serialize)]
struct PortablePassportResponse {
    subject: String,
    issuer_hex: String,
    issued_at: u64,
    expires_at: u64,
    evaluated_at: u64,
    payload_canonical_hex: String,
}

fn ok_string(value: String) -> ChioKernelFfiResult {
    ChioKernelFfiResult {
        status: CHIO_KERNEL_FFI_STATUS_OK,
        error_code: CHIO_KERNEL_FFI_ERROR_NONE,
        data: ChioKernelFfiBuffer::from_string(value),
    }
}

fn err_string(status: i32, error_code: i32, message: String) -> ChioKernelFfiResult {
    ChioKernelFfiResult {
        status,
        error_code,
        data: ChioKernelFfiBuffer::from_string(message),
    }
}

fn run_ffi<F>(f: F) -> ChioKernelFfiResult
where
    F: FnOnce() -> Result<String, KernelFfiError>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => ok_string(value),
        Ok(Err(error)) => err_string(CHIO_KERNEL_FFI_STATUS_ERROR, error.code(), error.message()),
        Err(_) => err_string(
            CHIO_KERNEL_FFI_STATUS_PANIC,
            CHIO_KERNEL_FFI_ERROR_INTERNAL,
            "panic while executing Chio kernel FFI helper".to_string(),
        ),
    }
}

fn read_c_str(ptr: *const c_char, name: &str) -> Result<String, ChioKernelFfiResult> {
    if ptr.is_null() {
        return Err(err_string(
            CHIO_KERNEL_FFI_STATUS_NULL_ARGUMENT,
            CHIO_KERNEL_FFI_ERROR_INTERNAL,
            format!("{name} must not be null"),
        ));
    }
    // SAFETY: caller promises a valid NUL-terminated C string.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().map(str::to_owned).map_err(|error| {
        err_string(
            CHIO_KERNEL_FFI_STATUS_ERROR,
            CHIO_KERNEL_FFI_ERROR_INVALID_JSON,
            format!("{name} must be valid UTF-8: {error}"),
        )
    })
}

fn serialize<T: Serialize>(value: &T) -> Result<String, KernelFfiError> {
    serde_json::to_string(value).map_err(|error| KernelFfiError::internal("serialize JSON", error))
}

fn public_key_from_hex(value: &str, context: &str) -> Result<PublicKey, KernelFfiError> {
    PublicKey::from_hex(value).map_err(|error| KernelFfiError::invalid_hex(context, error))
}

fn fixed_clock_from_secs(now_secs: i64) -> Option<FixedClock> {
    if now_secs < 0 {
        None
    } else {
        Some(FixedClock::new(now_secs as u64))
    }
}

fn evaluate_json_str(request_json: &str) -> Result<String, KernelFfiError> {
    let parsed: EvaluateRequestEnvelope = serde_json::from_str(request_json)
        .map_err(|error| KernelFfiError::invalid_json("evaluate request", error))?;

    let capability: CapabilityToken = serde_json::from_value(parsed.capability)
        .map_err(|error| KernelFfiError::invalid_json("capability token", error))?;

    let mut trusted = Vec::with_capacity(parsed.trusted_issuers.len());
    for issuer in &parsed.trusted_issuers {
        trusted.push(public_key_from_hex(issuer, "trusted issuer")?);
    }

    let portable_request = PortableToolCallRequest {
        request_id: parsed.request.request_id,
        tool_name: parsed.request.tool_name,
        server_id: parsed.request.server_id,
        agent_id: parsed.request.agent_id,
        arguments: parsed.request.arguments,
    };

    let fixed_clock = parsed.now_secs.map(FixedClock::new);
    let system_clock = SystemClock;
    let clock: &dyn Clock = match &fixed_clock {
        Some(clock) => clock,
        None => &system_clock,
    };
    let guards: &[&dyn Guard] = &[];

    let verdict = core_evaluate(EvaluateInput {
        request: &portable_request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock,
        guards,
        session_filesystem_roots: None,
    });

    let response = match verdict.verdict {
        Verdict::Allow => EvaluateResponse {
            verdict: "allow",
            reason: None,
            matched_grant_index: verdict.matched_grant_index,
        },
        Verdict::Deny => EvaluateResponse {
            verdict: "deny",
            reason: verdict.reason,
            matched_grant_index: verdict.matched_grant_index,
        },
        Verdict::PendingApproval => EvaluateResponse {
            verdict: "deny",
            reason: Some(
                "kernel-core returned PendingApproval; C++ kernel FFI treats as fail-closed deny"
                    .to_string(),
            ),
            matched_grant_index: verdict.matched_grant_index,
        },
    };

    serialize(&response)
}

fn sign_receipt_json_str(
    body_json: &str,
    signing_seed_hex: &str,
) -> Result<String, KernelFfiError> {
    let body: ChioReceiptBody = serde_json::from_str(body_json)
        .map_err(|error| KernelFfiError::invalid_json("receipt body", error))?;

    let keypair = Keypair::from_seed_hex(signing_seed_hex)
        .map_err(|error| KernelFfiError::invalid_hex("signing seed", error))?;
    let backend = Ed25519Backend::new(keypair);

    let receipt = core_sign_receipt(body, &backend).map_err(|error| match error {
        ReceiptSigningError::KernelKeyMismatch => KernelFfiError::KernelKeyMismatch(
            "receipt body kernel_key does not match the public key derived from the signing seed"
                .to_string(),
        ),
        ReceiptSigningError::SigningFailed(message) => KernelFfiError::SigningFailed(message),
    })?;

    serialize(&receipt)
}

fn verify_capability_json_str(
    token_json: &str,
    authority_pub_hex: &str,
    now_secs: i64,
) -> Result<String, KernelFfiError> {
    let token: CapabilityToken = serde_json::from_str(token_json)
        .map_err(|error| KernelFfiError::invalid_json("capability token", error))?;
    let authority = public_key_from_hex(authority_pub_hex, "authority public key")?;
    let fixed_clock = fixed_clock_from_secs(now_secs);
    let system_clock = SystemClock;
    let clock: &dyn Clock = match &fixed_clock {
        Some(clock) => clock,
        None => &system_clock,
    };

    let verified =
        core_verify_capability(&token, &[authority], clock).map_err(|error| match error {
            CapabilityError::UntrustedIssuer => KernelFfiError::InvalidCapability(
                "capability issuer is not in the trusted authority set".to_string(),
            ),
            CapabilityError::InvalidSignature => KernelFfiError::InvalidCapability(
                "capability signature failed to verify".to_string(),
            ),
            CapabilityError::CryptoFloorRejected(message) => KernelFfiError::InvalidCapability(
                format!("capability crypto floor rejected: {message}"),
            ),
            CapabilityError::NotYetValid => {
                KernelFfiError::InvalidCapability("capability is not yet valid".to_string())
            }
            CapabilityError::Expired => {
                KernelFfiError::InvalidCapability("capability has expired".to_string())
            }
            CapabilityError::AttenuationViolation(message) => KernelFfiError::InvalidCapability(
                format!("capability rejected by chain binding: {message}"),
            ),
            CapabilityError::BudgetSplitRejected(err) => KernelFfiError::InvalidCapability(
                format!("capability rejected by sibling-sum budget split: {err}"),
            ),
            CapabilityError::Internal(message) => {
                KernelFfiError::Internal(format!("capability verification failed: {message}"))
            }
            CapabilityError::SchemaExceedsNegotiatedCeiling {
                token_schema,
                peer_max,
            } => KernelFfiError::InvalidCapability(format!(
                "capability token schema {token_schema} exceeds peer-negotiated ceiling {peer_max}"
            )),
        })?;

    let scope_json = serde_json::to_string(&verified.scope)
        .map_err(|error| KernelFfiError::internal("serialize capability scope", error))?;

    serialize(&VerifiedCapabilityResponse {
        id: verified.id,
        subject_hex: verified.subject_hex,
        issuer_hex: verified.issuer_hex,
        scope_json,
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        evaluated_at: verified.evaluated_at,
    })
}

fn verify_passport_json_str(
    envelope_json: &str,
    issuer_pub_hex: &str,
    now_secs: i64,
) -> Result<String, KernelFfiError> {
    let issuer = public_key_from_hex(issuer_pub_hex, "authority public key")?;
    let fixed_clock = fixed_clock_from_secs(now_secs);
    let system_clock = SystemClock;
    let clock: &dyn Clock = match &fixed_clock {
        Some(clock) => clock,
        None => &system_clock,
    };

    let verified =
        core_verify_passport(envelope_json.as_bytes(), &[issuer], clock).map_err(|error| {
            match error {
                VerifyError::InvalidEnvelope(message) => {
                    KernelFfiError::InvalidPassport(format!("invalid envelope: {message}"))
                }
                VerifyError::InvalidSchema => KernelFfiError::InvalidPassport(
                    "envelope schema tag does not match portable passport v1".to_string(),
                ),
                VerifyError::MissingSubject => {
                    KernelFfiError::InvalidPassport("envelope subject is empty".to_string())
                }
                VerifyError::InvalidValidityWindow => KernelFfiError::InvalidPassport(
                    "envelope validity window is inverted".to_string(),
                ),
                VerifyError::UntrustedIssuer => KernelFfiError::InvalidPassport(
                    "envelope issuer is not in the trusted authority set".to_string(),
                ),
                VerifyError::InvalidSignature => KernelFfiError::InvalidPassport(
                    "envelope signature failed to verify".to_string(),
                ),
                VerifyError::NotYetValid => {
                    KernelFfiError::InvalidPassport("envelope is not yet valid".to_string())
                }
                VerifyError::Expired => {
                    KernelFfiError::InvalidPassport("envelope has expired".to_string())
                }
                VerifyError::Internal(message) => {
                    KernelFfiError::Internal(format!("passport verification failed: {message}"))
                }
            }
        })?;

    serialize(&PortablePassportResponse {
        subject: verified.subject,
        issuer_hex: verified.issuer.to_hex(),
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        evaluated_at: verified.evaluated_at,
        payload_canonical_hex: hex::encode(&verified.payload_canonical_bytes),
    })
}

#[no_mangle]
pub extern "C" fn chio_kernel_ffi_abi_version() -> u32 {
    CHIO_CPP_KERNEL_FFI_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn chio_kernel_build_info() -> ChioKernelFfiResult {
    #[derive(Serialize)]
    struct BuildInfo<'a> {
        crate_name: &'a str,
        crate_version: &'a str,
        abi_version: u32,
        target: String,
        features: Vec<&'a str>,
    }

    let info = BuildInfo {
        crate_name: env!("CARGO_PKG_NAME"),
        crate_version: env!("CARGO_PKG_VERSION"),
        abi_version: CHIO_CPP_KERNEL_FFI_ABI_VERSION,
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        features: Vec::new(),
    };
    run_ffi(|| serialize(&info))
}

#[no_mangle]
pub extern "C" fn chio_kernel_buffer_free(buffer: ChioKernelFfiBuffer) {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return;
    }
    // SAFETY: all non-empty buffers returned by this crate come from
    // `Vec::into_boxed_slice` with exactly this pointer and length.
    unsafe {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len));
    }
}

#[no_mangle]
pub extern "C" fn chio_kernel_evaluate_json(request_json: *const c_char) -> ChioKernelFfiResult {
    let request_json = match read_c_str(request_json, "request_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| evaluate_json_str(&request_json))
}

#[no_mangle]
pub extern "C" fn chio_kernel_sign_receipt_json(
    body_json: *const c_char,
    signing_seed_hex: *const c_char,
) -> ChioKernelFfiResult {
    let body_json = match read_c_str(body_json, "body_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signing_seed_hex = match read_c_str(signing_seed_hex, "signing_seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| sign_receipt_json_str(&body_json, &signing_seed_hex))
}

#[no_mangle]
pub extern "C" fn chio_kernel_verify_capability_json(
    token_json: *const c_char,
    authority_pub_hex: *const c_char,
    now_secs: i64,
) -> ChioKernelFfiResult {
    let token_json = match read_c_str(token_json, "token_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let authority_pub_hex = match read_c_str(authority_pub_hex, "authority_pub_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| verify_capability_json_str(&token_json, &authority_pub_hex, now_secs))
}

#[no_mangle]
pub extern "C" fn chio_kernel_verify_passport_json(
    envelope_json: *const c_char,
    issuer_pub_hex: *const c_char,
    now_secs: i64,
) -> ChioKernelFfiResult {
    let envelope_json = match read_c_str(envelope_json, "envelope_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let issuer_pub_hex = match read_c_str(issuer_pub_hex, "issuer_pub_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| verify_passport_json_str(&envelope_json, &issuer_pub_hex, now_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use chio_kernel_core::passport_verify::{
        PortablePassportBody, PortablePassportEnvelope, PORTABLE_PASSPORT_SCHEMA,
    };
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
        };
        CapabilityToken::sign(body, issuer).unwrap()
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

        let output =
            verify_capability_json_str(&token_json, &issuer.public_key().to_hex(), 0).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["id"], "cap-1");
        assert_eq!(value["evaluated_at"], 0);
        assert_eq!(value["issued_at"], 0);
        assert_eq!(value["expires_at"], 10);
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
}
