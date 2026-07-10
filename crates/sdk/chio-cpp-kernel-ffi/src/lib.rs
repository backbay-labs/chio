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

use chio_core_types::capability::{
    attenuation::ScopeHash, crypto_floor::CapabilityCryptoFloor, features::CapabilityNegotiation,
    token::CapabilityToken,
};
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey};
use chio_core_types::receipt::body::ChioReceiptBody;
use chio_kernel_core::passport_verify::{verify_passport as core_verify_passport, VerifyError};
use chio_kernel_core::{
    evaluate_with_full_floor, sign_receipt as core_sign_receipt,
    sign_receipt_relaying_trusted_body as core_relay_trusted_body, verify_capability_full,
    BudgetRegistry, BudgetSplitError, CapabilityError, Clock, EvaluateInput, FixedClock, Guard,
    InMemoryBudgetRegistry, PortableToolCallRequest, ReceiptSigningError, Verdict,
};
use serde::{Deserialize, Serialize};

/// C ABI version of this kernel FFI surface.
///
/// Bumped from 1 to 2 when `chio_kernel_sign_receipt_json` gained a third
/// pointer argument (`canonical_content_hex`, the WYSIWYS preimage). The symbol
/// name is unchanged, so an old 2-arg client linked against v1 would call the
/// 3-arg symbol with a missing third pointer (undefined behavior). Clients that
/// gate on `chio_kernel_ffi_abi_version()` now fail closed against this v2
/// surface instead of invoking the signer with a dangling argument.
pub const CHIO_CPP_KERNEL_FFI_ABI_VERSION: u32 = 2;

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
    /// Optional peer-negotiated feature profile. Defaults to `t1_default`
    /// with current chain-binding semantics when omitted.
    #[serde(default)]
    peer_capabilities: Option<CapabilityNegotiation>,
    /// Optional chain-binding trust roots, keyed by issuer hex. Attenuated or
    /// delegated tokens require an entry here; absent issuers fail-closed.
    #[serde(default)]
    capability_trust_roots: std::collections::BTreeMap<String, ScopeHash>,
    /// Optional parent-budget snapshots used to seed sibling-sum
    /// enforcement before delegated tokens are evaluated.
    #[serde(default)]
    parent_budget_snapshots: Vec<ParentBudgetSnapshot>,
}

#[derive(Debug, Deserialize)]
struct VerifyCapabilityRequestEnvelope {
    token: serde_json::Value,
    trusted_issuers: Vec<String>,
    #[serde(default)]
    now_secs: Option<i64>,
    #[serde(default)]
    peer_capabilities: Option<CapabilityNegotiation>,
    #[serde(default)]
    capability_trust_roots: std::collections::BTreeMap<String, ScopeHash>,
    #[serde(default)]
    parent_budget_snapshots: Vec<ParentBudgetSnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
struct ParentBudgetSnapshot {
    parent_token_id: String,
    parent_share_bps: u16,
    #[serde(default)]
    admitted_children: Vec<AdmittedChildBudget>,
}

#[derive(Debug, Clone, Deserialize)]
struct AdmittedChildBudget {
    child_token_id: String,
    share_bps: u16,
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

fn decode_trusted_issuers(values: &[String]) -> Result<Vec<PublicKey>, KernelFfiError> {
    let mut trusted = Vec::with_capacity(values.len());
    for issuer in values {
        trusted.push(public_key_from_hex(issuer, "trusted issuer")?);
    }
    Ok(trusted)
}

fn validate_capability_trust_roots(
    roots: &std::collections::BTreeMap<String, ScopeHash>,
) -> Result<(), KernelFfiError> {
    for (issuer_hex, scope_hash) in roots {
        public_key_from_hex(issuer_hex, "capability trust root issuer")?;
        validate_trust_root_scope_hash("capability_trust_roots[].scope_hash", scope_hash)?;
    }
    Ok(())
}

fn validate_trust_root_scope_hash(field: &str, value: &str) -> Result<(), KernelFfiError> {
    if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(KernelFfiError::InvalidCapability(format!(
            "{field} must be non-empty, unpadded, and control-free"
        )));
    }
    Ok(())
}

fn seed_budget_registry(
    budgets: &mut InMemoryBudgetRegistry,
    snapshots: &[ParentBudgetSnapshot],
) -> Result<(), KernelFfiError> {
    for snapshot in snapshots {
        validate_budget_token_id(
            "parent_budget_snapshots[].parent_token_id",
            &snapshot.parent_token_id,
        )?;
        budgets
            .register_parent(snapshot.parent_token_id.clone(), snapshot.parent_share_bps)
            .map_err(|error| budget_seed_error("parent budget snapshot", &error))?;
        for child in &snapshot.admitted_children {
            validate_budget_token_id(
                "parent_budget_snapshots[].admitted_children[].child_token_id",
                &child.child_token_id,
            )?;
            budgets
                .try_admit_child(
                    snapshot.parent_token_id.as_str(),
                    child.child_token_id.clone(),
                    child.share_bps,
                )
                .map_err(|error| budget_seed_error("admitted child budget snapshot", &error))?;
        }
    }
    Ok(())
}

fn validate_budget_token_id(field: &str, value: &str) -> Result<(), KernelFfiError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(KernelFfiError::InvalidCapability(format!(
            "{field} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

fn budget_seed_error(context: &str, error: &BudgetSplitError) -> KernelFfiError {
    KernelFfiError::InvalidCapability(format!("{context}: {error}"))
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

    let trusted = decode_trusted_issuers(&parsed.trusted_issuers)?;
    validate_capability_trust_roots(&parsed.capability_trust_roots)?;

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

    // Route through `evaluate_with_full_floor` so feature validation and
    // chain-binding checks are exercised on the same hot path that already
    // enforces the crypto floor and time bounds.
    let peer_profile = parsed
        .peer_capabilities
        .clone()
        .unwrap_or_else(CapabilityNegotiation::t1_default);
    let trust_root_map = parsed.capability_trust_roots.clone();
    let trust_resolver = move |issuer: &PublicKey| -> Option<ScopeHash> {
        trust_root_map.get(&issuer.to_hex()).cloned()
    };
    // Seed the per-request registry from caller-owned parent snapshots
    // so delegated tokens can be evaluated without fabricating missing
    // parent shares.
    let mut budgets = InMemoryBudgetRegistry::new();
    seed_budget_registry(&mut budgets, &parsed.parent_budget_snapshots)?;
    let verdict = evaluate_with_full_floor(
        EvaluateInput {
            request: &portable_request,
            capability: &capability,
            trusted_issuers: &trusted,
            clock,
            guards,
            session_filesystem_roots: None,
        },
        CapabilityCryptoFloor::AllowClassical,
        &peer_profile,
        &trust_resolver,
        &mut budgets,
    );

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

/// Map a kernel-core [`ReceiptSigningError`] onto the C++ FFI error surface.
fn map_signing_error(error: ReceiptSigningError) -> KernelFfiError {
    match error {
        ReceiptSigningError::KernelKeyMismatch => KernelFfiError::KernelKeyMismatch(
            "receipt body kernel_key does not match the public key derived from the signing seed"
                .to_string(),
        ),
        // WYSIWYS mismatch. The public signer recomputes `content_hash`
        // over the caller-supplied canonical content preimage inside the trust
        // boundary and produces this variant on a render-A / sign-B mismatch.
        // Surfaced as a distinct, fail-closed signing failure.
        ReceiptSigningError::ContentHashMismatch { recomputed, claimed } => {
            KernelFfiError::SigningFailed(format!(
                "receipt content_hash mismatch: body claimed {claimed} but signer recomputed {recomputed} over the canonical content (WYSIWYS refused)"
            ))
        }
        ReceiptSigningError::SigningFailed(message) => KernelFfiError::SigningFailed(message),
    }
}

/// PUBLIC WYSIWYS signer (fail-closed): recompute `content_hash` over the
/// caller-supplied canonical content preimage inside the trust boundary and
/// refuse on mismatch.
///
/// `canonical_content_hex` is the lowercase-hex encoding of the exact
/// byte preimage `body.content_hash` was derived from. This signer does NOT
/// relay a trusted body; callers that only forward an upstream-minted body and
/// cannot carry the preimage must use [`sign_receipt_relaying_trusted_body_json_str`]
/// through the trusted-body relay seam.
fn sign_receipt_json_str(
    body_json: &str,
    canonical_content_hex: &str,
    signing_seed_hex: &str,
) -> Result<String, KernelFfiError> {
    let body: ChioReceiptBody = serde_json::from_str(body_json)
        .map_err(|error| KernelFfiError::invalid_json("receipt body", error))?;

    let canonical_content = hex::decode(canonical_content_hex.trim_start_matches("0x"))
        .map_err(|error| KernelFfiError::invalid_hex("canonical content", error))?;

    let keypair = Keypair::from_seed_hex(signing_seed_hex)
        .map_err(|error| KernelFfiError::invalid_hex("signing seed", error))?;
    let backend = Ed25519Backend::new(keypair);

    let receipt =
        core_sign_receipt(body, &backend, &canonical_content).map_err(map_signing_error)?;

    serialize(&receipt)
}

/// Relay-sign an already-minted, upstream-trusted receipt body.
///
/// This is NOT the default public signer.
///
/// Trusts the caller-supplied `body.content_hash` and does NOT recompute it,
/// routing through `chio_kernel_core::sign_receipt_relaying_trusted_body`. Use
/// only to forward a body an upstream trusted producer already minted (where the
/// WYSIWYS recompute already ran). Content-bearing callers MUST use
/// [`sign_receipt_json_str`] instead so the recompute gate runs.
fn sign_receipt_relaying_trusted_body_json_str(
    body_json: &str,
    signing_seed_hex: &str,
) -> Result<String, KernelFfiError> {
    let body: ChioReceiptBody = serde_json::from_str(body_json)
        .map_err(|error| KernelFfiError::invalid_json("receipt body", error))?;

    let keypair = Keypair::from_seed_hex(signing_seed_hex)
        .map_err(|error| KernelFfiError::invalid_hex("signing seed", error))?;
    let backend = Ed25519Backend::new(keypair);

    let receipt = core_relay_trusted_body(body, &backend).map_err(map_signing_error)?;

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

    verify_capability_with_parts(
        token,
        vec![authority],
        Some(now_secs),
        CapabilityNegotiation::t1_default(),
        std::collections::BTreeMap::new(),
        &[],
    )
}

fn verify_capability_with_context_json_str(request_json: &str) -> Result<String, KernelFfiError> {
    let parsed: VerifyCapabilityRequestEnvelope = serde_json::from_str(request_json)
        .map_err(|error| KernelFfiError::invalid_json("verify capability request", error))?;
    let token: CapabilityToken = serde_json::from_value(parsed.token)
        .map_err(|error| KernelFfiError::invalid_json("capability token", error))?;
    let trusted = decode_trusted_issuers(&parsed.trusted_issuers)?;
    let peer_profile = parsed
        .peer_capabilities
        .clone()
        .unwrap_or_else(CapabilityNegotiation::t1_default);

    verify_capability_with_parts(
        token,
        trusted,
        parsed.now_secs,
        peer_profile,
        parsed.capability_trust_roots,
        &parsed.parent_budget_snapshots,
    )
}

fn verify_capability_with_parts(
    token: CapabilityToken,
    trusted: Vec<PublicKey>,
    now_secs: Option<i64>,
    peer_profile: CapabilityNegotiation,
    capability_trust_roots: std::collections::BTreeMap<String, ScopeHash>,
    parent_budget_snapshots: &[ParentBudgetSnapshot],
) -> Result<String, KernelFfiError> {
    validate_capability_trust_roots(&capability_trust_roots)?;
    let fixed_clock = now_secs.and_then(fixed_clock_from_secs);
    let system_clock = SystemClock;
    let clock: &dyn Clock = match &fixed_clock {
        Some(clock) => clock,
        None => &system_clock,
    };

    let trust_resolver = |issuer: &PublicKey| -> Option<ScopeHash> {
        capability_trust_roots.get(&issuer.to_hex()).cloned()
    };
    let mut budgets = InMemoryBudgetRegistry::new();
    seed_budget_registry(&mut budgets, parent_budget_snapshots)?;
    let verified = verify_capability_full(
        &token,
        &trusted,
        clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer_profile,
        &trust_resolver,
        &mut budgets,
    )
    .map_err(|error| match error {
        CapabilityError::UntrustedIssuer => KernelFfiError::InvalidCapability(
            "capability issuer is not in the trusted authority set".to_string(),
        ),
        CapabilityError::InvalidSignature => {
            KernelFfiError::InvalidCapability("capability signature failed to verify".to_string())
        }
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
        CapabilityError::BudgetSplitRejected(err) => KernelFfiError::InvalidCapability(format!(
            "capability rejected by sibling-sum budget split: {err}"
        )),
        CapabilityError::Internal(message) => {
            KernelFfiError::Internal(format!("capability verification failed: {message}"))
        }
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

/// PUBLIC WYSIWYS signer (fail-closed). `canonical_content_hex` is the
/// lowercase-hex preimage `content_hash` was derived from; the signer recomputes
/// the hash inside the trust boundary and refuses on mismatch. This
/// does NOT relay a trusted body; use
/// `chio_kernel_sign_receipt_relaying_trusted_body_json` for the relay seam.
#[no_mangle]
pub extern "C" fn chio_kernel_sign_receipt_json(
    body_json: *const c_char,
    canonical_content_hex: *const c_char,
    signing_seed_hex: *const c_char,
) -> ChioKernelFfiResult {
    let body_json = match read_c_str(body_json, "body_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let canonical_content_hex = match read_c_str(canonical_content_hex, "canonical_content_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signing_seed_hex = match read_c_str(signing_seed_hex, "signing_seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| sign_receipt_json_str(&body_json, &canonical_content_hex, &signing_seed_hex))
}

/// Relay-sign an already-minted, upstream-trusted receipt body. This is NOT the
/// default public signer. Trusts the caller-supplied `content_hash` and
/// does NOT recompute it. Content-bearing callers MUST use
/// `chio_kernel_sign_receipt_json` instead so the WYSIWYS recompute gate runs.
#[no_mangle]
pub extern "C" fn chio_kernel_sign_receipt_relaying_trusted_body_json(
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
    run_ffi(|| sign_receipt_relaying_trusted_body_json_str(&body_json, &signing_seed_hex))
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
pub extern "C" fn chio_kernel_verify_capability_with_context_json(
    request_json: *const c_char,
) -> ChioKernelFfiResult {
    let request_json = match read_c_str(request_json, "request_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| verify_capability_with_context_json_str(&request_json))
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
mod tests;
