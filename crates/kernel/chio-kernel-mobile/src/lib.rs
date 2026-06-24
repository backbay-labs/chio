//! Mobile FFI for the Chio kernel core.
//!
//! This adapter wraps the portable [`chio_kernel_core`](chio_kernel_core)
//! surface in an ergonomic, JSON-in / JSON-out Rust API and projects it
//! across the C ABI using UniFFI. The UDL file in
//! `src/chio_kernel_mobile.udl` drives binding generation for Swift
//! (iOS) and Kotlin (Android); see `bindings/README.md` for the bindgen
//! workflow.
//!
//! # Why JSON-in / JSON-out
//!
//! Chio's type graph (capability tokens, scopes, receipts, passport
//! envelopes) is large and deeply nested. Projecting every field into
//! UDL would double the FFI surface for zero additional safety: the
//! app-side Chio SDK already knows how to serialize these types, and
//! the kernel-core entry points accept the parsed Rust structs. We
//! marshal once via serde at the boundary and keep the UDL interface
//! small.
//!
//! # Exposed entry points
//!
//! - [`evaluate`] -- evaluate a tool-call request against a capability.
//! - [`sign_receipt`] -- sign an `ChioReceiptBody` with a 32-byte seed.
//! - [`verify_capability`] -- offline capability verification.
//! - [`verify_passport`] -- offline portable-passport envelope
//!   verification.
//! - [`attest_app_attest`] -- App Attest challenge entry point.
//! - [`verify_app_attest_evidence`] -- App Attest evidence verifier.
//! - [`attest_play_integrity`] -- Play Integrity challenge entry point.
//! - [`verify_play_integrity_evidence`] -- Play Integrity JWS verifier.
//! - [`verify_mobile_receipt`] -- mobile attestation receipt verifier.
//!
//! # Offline guarantees
//!
//! None of these entry points perform I/O. A mobile app can invoke
//! the pure-verification entry points while offline -- for example to gate a sensitive tool
//! call with a cached capability and queue the resulting receipt for
//! upload when connectivity returns.
//!
//! # `unsafe` posture
//!
//! The crate source itself contains no `unsafe` code. UniFFI's
//! build-script-generated scaffolding declares `#[no_mangle]`
//! `extern "C"` symbols (required for the C ABI that Swift and Kotlin
//! link against); that is trusted generated code, not crate-author
//! code. We therefore do not apply `#![deny(unsafe_code)]` at the
//! crate root because it would also reject the generated scaffolding.
//! An equivalent hand-written lint applies to every module in this
//! crate via `#![forbid(unsafe_code)]` on each module below except
//! where the scaffolding is pulled in.

// UniFFI-generated scaffolding (included at the bottom of this file)
// emits a `const UNIFFI_META_CONST_UDL_*` item preceded by a doc
// comment that has a blank line between it and the item. Rustc +
// clippy in the strict workspace configuration flag that as
// `empty-line-after-doc-comments`; since we don't author the
// generated file, we allow it crate-wide here.
#![allow(clippy::empty_line_after_doc_comments)]

mod clock;
mod errors;
mod rng;

pub use clock::MobileClock;
pub use errors::ChioMobileError;
pub use rng::MobileRng;

use serde::{Deserialize, Serialize};

use chio_core_types::capability::{
    attenuation::ScopeHash, crypto_floor::CapabilityCryptoFloor, features::CapabilityNegotiation,
    token::CapabilityToken,
};
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey};
use chio_core_types::receipt::body::ChioReceiptBody;
use chio_custody_hw::{
    verify_app_attest, verify_mobile_receipt_chain, verify_play_integrity,
    AppAttestVerificationInput, AttestationError, PlayIntegrityVerificationInput,
};
use chio_kernel_core::passport_verify::{verify_passport as core_verify_passport, VerifyError};
use chio_kernel_core::{
    evaluate_with_full_floor, sign_receipt as core_sign_receipt, verify_capability_full,
    BudgetRegistry, BudgetSplitError, CapabilityError, Clock, EvaluateInput, FixedClock, Guard,
    InMemoryBudgetRegistry, PortableToolCallRequest, ReceiptSigningError, Verdict,
};

// ---------------------------------------------------------------------------
// UniFFI record types (mirror `VerifiedCapability` / `VerifiedPassport`).
// ---------------------------------------------------------------------------

/// Verified capability snapshot projected across the FFI.
///
/// Mirrors [`chio_kernel_core::VerifiedCapability`] but swaps the
/// structured `ChioScope` for its canonical JSON encoding. Mobile
/// callers that want to inspect the scope pass `scope_json` through
/// their host-side Chio SDK decoder.
#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    pub id: String,
    pub subject_hex: String,
    pub issuer_hex: String,
    pub scope_json: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evaluated_at: u64,
}

/// Verified portable-passport envelope metadata projected across the FFI.
///
/// Mirrors [`chio_kernel_core::passport_verify::VerifiedPassport`] with
/// the payload byte blob rendered as lowercase hex so Swift / Kotlin
/// can surface it as `Data` / `ByteArray` after a single decode.
#[derive(Debug, Clone)]
pub struct PortablePassportMetadata {
    pub subject: String,
    pub issuer_hex: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evaluated_at: u64,
    pub payload_canonical_hex: String,
}

// ---------------------------------------------------------------------------
// `evaluate` wire format.
// ---------------------------------------------------------------------------

/// Shape of the JSON object accepted by [`evaluate`].
///
/// Deliberately flat so mobile hosts can build it with `serde_json::json!`
/// (Swift / Kotlin) without extra envelope types.
#[derive(Debug, Deserialize)]
struct EvaluateRequest {
    /// Capability token JSON (serialized `CapabilityToken`).
    capability: serde_json::Value,
    /// Trusted issuer public keys, lowercase hex (Ed25519).
    trusted_issuers: Vec<String>,
    /// Portable tool-call request.
    request: EvaluateRequestBody,
    /// Optional Unix timestamp. `None` / missing / <= 0 falls back to
    /// [`MobileClock`].
    #[serde(default)]
    now_secs: Option<i64>,
    /// Optional peer-negotiated feature profile. When omitted, mobile
    /// defaults to a single-trusted-CA `t1_default` profile with current
    /// chain-binding semantics enabled.
    #[serde(default)]
    peer_capabilities: Option<CapabilityNegotiation>,
    /// Optional chain-binding trust roots, keyed by issuer hex. Attenuated or
    /// delegated tokens require an entry; absent issuers fail-closed.
    #[serde(default)]
    capability_trust_roots: std::collections::BTreeMap<String, ScopeHash>,
    /// Optional parent-budget snapshots used to seed sibling-sum
    /// enforcement before delegated tokens are evaluated.
    #[serde(default)]
    parent_budget_snapshots: Vec<ParentBudgetSnapshot>,
}

/// Shape of the JSON object accepted by [`verify_capability_with_context`].
#[derive(Debug, Deserialize)]
struct VerifyCapabilityRequest {
    /// Capability token JSON (serialized `CapabilityToken`).
    token: serde_json::Value,
    /// Trusted issuer public keys, lowercase hex (Ed25519).
    trusted_issuers: Vec<String>,
    /// Optional Unix timestamp. `None` / missing / < 0 falls back to
    /// [`MobileClock`].
    #[serde(default)]
    now_secs: Option<i64>,
    /// Optional peer-negotiated profile.
    #[serde(default)]
    peer_capabilities: Option<CapabilityNegotiation>,
    /// Optional chain-binding trust roots, keyed by issuer hex.
    #[serde(default)]
    capability_trust_roots: std::collections::BTreeMap<String, ScopeHash>,
    /// Optional parent-budget snapshots used to seed sibling-sum
    /// enforcement before delegated tokens are verified.
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

/// Tool-call request payload.
#[derive(Debug, Deserialize)]
struct EvaluateRequestBody {
    request_id: String,
    tool_name: String,
    server_id: String,
    agent_id: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

/// Shape of the JSON object returned by [`evaluate`].
#[derive(Debug, Serialize)]
struct EvaluateResponse {
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_grant_index: Option<usize>,
}

// ---------------------------------------------------------------------------
// FFI entry points.
// ---------------------------------------------------------------------------

fn decode_hex_argument(label: &str, value: &str) -> Result<Vec<u8>, ChioMobileError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.is_empty() {
        return Err(ChioMobileError::InvalidHex {
            message: format!("{label}: value must not be empty"),
        });
    }
    hex::decode(trimmed).map_err(|error| ChioMobileError::InvalidHex {
        message: format!("{label}: {error}"),
    })
}

fn map_attestation_error(error: AttestationError) -> ChioMobileError {
    ChioMobileError::AttestationRejected {
        message: format!("{}: {error}", error.urn()),
    }
}

fn chio_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

fn fixed_clock_from_secs(now_secs: i64) -> Option<FixedClock> {
    if now_secs < 0 {
        None
    } else {
        Some(FixedClock::new(now_secs as u64))
    }
}

fn seed_budget_registry(
    budgets: &mut InMemoryBudgetRegistry,
    snapshots: &[ParentBudgetSnapshot],
) -> Result<(), ChioMobileError> {
    for snapshot in snapshots {
        budgets
            .register_parent(snapshot.parent_token_id.clone(), snapshot.parent_share_bps)
            .map_err(|error| budget_seed_error("parent budget snapshot", &error))?;
        for child in &snapshot.admitted_children {
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

fn budget_seed_error(context: &str, error: &BudgetSplitError) -> ChioMobileError {
    ChioMobileError::InvalidCapability {
        message: format!("{context}: {error}"),
    }
}

fn decode_trusted_issuers(values: &[String]) -> Result<Vec<PublicKey>, ChioMobileError> {
    values
        .iter()
        .map(|hex_str| {
            PublicKey::from_hex(hex_str).map_err(|error| ChioMobileError::InvalidHex {
                message: format!("trusted issuer: {error}"),
            })
        })
        .collect()
}

/// Evaluate a tool-call request against a capability token.
///
/// Input: a JSON object matching [`EvaluateRequest`]. Output: a JSON
/// object describing the verdict. Returns an error only when the
/// inputs cannot be parsed; a kernel-core `Deny` verdict is encoded
/// in the JSON response so callers can render the reason without
/// unwrapping an exception.
pub fn evaluate(request_json: String) -> Result<String, ChioMobileError> {
    let parsed: EvaluateRequest =
        serde_json::from_str(&request_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("evaluate request: {error}"),
        })?;

    let capability: CapabilityToken =
        serde_json::from_value(parsed.capability).map_err(|error| {
            ChioMobileError::InvalidJson {
                message: format!("capability token: {error}"),
            }
        })?;

    let trusted = decode_trusted_issuers(&parsed.trusted_issuers)?;

    let portable_request = PortableToolCallRequest {
        request_id: parsed.request.request_id,
        tool_name: parsed.request.tool_name,
        server_id: parsed.request.server_id,
        agent_id: parsed.request.agent_id,
        arguments: parsed.request.arguments,
    };

    // Clock selection: if the host supplied a positive `now_secs` we
    // honour it (useful for deterministic testing harnesses on the
    // Swift/Kotlin side); otherwise fall back to `MobileClock`.
    let fixed_clock: Option<FixedClock> = match parsed.now_secs {
        Some(secs) if secs > 0 => Some(FixedClock::new(secs as u64)),
        _ => None,
    };
    let mobile_clock = MobileClock::new();
    let clock: &dyn Clock = match &fixed_clock {
        Some(c) => c,
        None => &mobile_clock,
    };

    // Mobile callers don't register custom guards today; the kernel
    // core still runs the full check pipeline (signature, time,
    // subject binding, scope) with an empty guard slice.
    let guards: &[&dyn Guard] = &[];

    // Route through `evaluate_with_full_floor` so attenuated or delegated
    // tokens are bound to a registered trust-root scope hash before dispatch.
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
                "kernel-core returned PendingApproval; mobile FFI treats as fail-closed deny"
                    .to_string(),
            ),
            matched_grant_index: verdict.matched_grant_index,
        },
    };

    serde_json::to_string(&response).map_err(|error| ChioMobileError::Internal {
        message: format!("serialize evaluate response: {error}"),
    })
}

/// Sign a receipt body with the Ed25519 seed `signing_seed_hex`.
///
/// The receipt body's `kernel_key` must equal the public key derived
/// from the seed; otherwise the kernel-core signer fails fast with
/// [`ReceiptSigningError::KernelKeyMismatch`].
///
/// Returns the signed `ChioReceipt` as JSON so the caller can queue it
/// for upload to the receipt-log sink.
pub fn sign_receipt(
    body_json: String,
    signing_seed_hex: String,
) -> Result<String, ChioMobileError> {
    let body: ChioReceiptBody =
        serde_json::from_str(&body_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("receipt body: {error}"),
        })?;

    let seed_bytes = decode_hex_argument("signing seed", &signing_seed_hex)?;
    if seed_bytes.len() != 32 {
        return Err(ChioMobileError::InvalidHex {
            message: format!(
                "signing seed: expected 32-byte Ed25519 seed, got {} bytes",
                seed_bytes.len()
            ),
        });
    }
    if seed_bytes.iter().all(|byte| *byte == 0) {
        return Err(ChioMobileError::WeakEntropy {
            message: "refusing to sign with an all-zero Ed25519 seed".to_string(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let keypair = Keypair::from_seed(&seed);
    let backend = Ed25519Backend::new(keypair);

    let receipt = core_sign_receipt(body, &backend).map_err(|error| match error {
        ReceiptSigningError::KernelKeyMismatch => ChioMobileError::KernelKeyMismatch {
            message: "receipt body kernel_key does not match the public key derived from the signing seed".to_string(),
        },
        ReceiptSigningError::SigningFailed(msg) => ChioMobileError::SigningFailed { message: msg },
    })?;

    serde_json::to_string(&receipt).map_err(|error| ChioMobileError::Internal {
        message: format!("serialize signed receipt: {error}"),
    })
}

/// Verify a capability token against a single trusted authority key.
///
/// Uses [`MobileClock`] to evaluate the time-bound window. Adapters
/// that need a pinned clock should call [`evaluate`] with `now_secs`
/// populated instead.
pub fn verify_capability(
    token_json: String,
    authority_pub_hex: String,
) -> Result<VerifiedCapability, ChioMobileError> {
    let token: CapabilityToken =
        serde_json::from_str(&token_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("capability token: {error}"),
        })?;

    let authority =
        PublicKey::from_hex(&authority_pub_hex).map_err(|error| ChioMobileError::InvalidHex {
            message: format!("authority public key: {error}"),
        })?;

    verify_capability_with_parts(
        token,
        vec![authority],
        None,
        CapabilityNegotiation::t1_default(),
        std::collections::BTreeMap::new(),
        &[],
    )
}

/// Verify a capability token with the full portable JSON context.
///
/// This entry point complements [`verify_capability`] by giving mobile
/// hosts a way to pass trust roots and parent-budget snapshots for
/// delegated tokens.
pub fn verify_capability_with_context(
    request_json: String,
) -> Result<VerifiedCapability, ChioMobileError> {
    let parsed: VerifyCapabilityRequest =
        serde_json::from_str(&request_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("verify capability request: {error}"),
        })?;
    let token: CapabilityToken =
        serde_json::from_value(parsed.token).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("capability token: {error}"),
        })?;
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
) -> Result<VerifiedCapability, ChioMobileError> {
    let fixed_clock = now_secs.and_then(fixed_clock_from_secs);
    let mobile_clock = MobileClock::new();
    let clock: &dyn Clock = match &fixed_clock {
        Some(clock) => clock,
        None => &mobile_clock,
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
        CapabilityError::UntrustedIssuer => ChioMobileError::InvalidCapability {
            message: "capability issuer is not in the trusted authority set".to_string(),
        },
        CapabilityError::InvalidSignature => ChioMobileError::InvalidCapability {
            message: "capability signature failed to verify".to_string(),
        },
        CapabilityError::NotYetValid => ChioMobileError::InvalidCapability {
            message: "capability is not yet valid".to_string(),
        },
        CapabilityError::Expired => ChioMobileError::InvalidCapability {
            message: "capability has expired".to_string(),
        },
        CapabilityError::CryptoFloorRejected(message) => ChioMobileError::InvalidCapability {
            message: format!("capability crypto floor rejected: {message}"),
        },
        CapabilityError::AttenuationViolation(message) => ChioMobileError::InvalidCapability {
            message: format!("capability rejected by chain binding: {message}"),
        },
        CapabilityError::BudgetSplitRejected(err) => ChioMobileError::InvalidCapability {
            message: format!("capability rejected by sibling-sum budget split: {err}"),
        },
        CapabilityError::Internal(msg) => ChioMobileError::Internal {
            message: format!("capability verification failed: {msg}"),
        },
    })?;

    let scope_json =
        serde_json::to_string(&verified.scope).map_err(|error| ChioMobileError::Internal {
            message: format!("serialize capability scope: {error}"),
        })?;

    Ok(VerifiedCapability {
        id: verified.id,
        subject_hex: verified.subject_hex,
        issuer_hex: verified.issuer_hex,
        scope_json,
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        evaluated_at: verified.evaluated_at,
    })
}

/// Verify a portable passport envelope.
///
/// `envelope_json` is the JSON-encoded `PortablePassportEnvelope`;
/// `issuer_pub_hex` is the trusted authority public key. When
/// `now_secs <= 0` the implementation falls back to [`MobileClock`].
pub fn verify_passport(
    envelope_json: String,
    issuer_pub_hex: String,
    now_secs: i64,
) -> Result<PortablePassportMetadata, ChioMobileError> {
    let issuer =
        PublicKey::from_hex(&issuer_pub_hex).map_err(|error| ChioMobileError::InvalidHex {
            message: format!("authority public key: {error}"),
        })?;

    let fixed_clock: Option<FixedClock> = if now_secs > 0 {
        Some(FixedClock::new(now_secs as u64))
    } else {
        None
    };
    let mobile_clock = MobileClock::new();
    let clock: &dyn Clock = match &fixed_clock {
        Some(c) => c,
        None => &mobile_clock,
    };

    let verified =
        core_verify_passport(envelope_json.as_bytes(), &[issuer], clock).map_err(|error| {
            match error {
                VerifyError::InvalidEnvelope(msg) => ChioMobileError::InvalidPassport {
                    message: format!("invalid envelope: {msg}"),
                },
                VerifyError::InvalidSchema => ChioMobileError::InvalidPassport {
                    message: "envelope schema tag does not match portable passport v1".to_string(),
                },
                VerifyError::MissingSubject => ChioMobileError::InvalidPassport {
                    message: "envelope subject is empty".to_string(),
                },
                VerifyError::InvalidValidityWindow => ChioMobileError::InvalidPassport {
                    message: "envelope validity window is inverted".to_string(),
                },
                VerifyError::UntrustedIssuer => ChioMobileError::InvalidPassport {
                    message: "envelope issuer is not in the trusted authority set".to_string(),
                },
                VerifyError::InvalidSignature => ChioMobileError::InvalidPassport {
                    message: "envelope signature failed to verify".to_string(),
                },
                VerifyError::NotYetValid => ChioMobileError::InvalidPassport {
                    message: "envelope is not yet valid".to_string(),
                },
                VerifyError::Expired => ChioMobileError::InvalidPassport {
                    message: "envelope has expired".to_string(),
                },
                VerifyError::Internal(msg) => ChioMobileError::Internal {
                    message: format!("passport verification failed: {msg}"),
                },
            }
        })?;

    Ok(PortablePassportMetadata {
        subject: verified.subject,
        issuer_hex: verified.issuer.to_hex(),
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        evaluated_at: verified.evaluated_at,
        payload_canonical_hex: hex::encode(&verified.payload_canonical_bytes),
    })
}

/// Produce an App Attest challenge envelope bound to `challenge_hex`.
///
/// The iOS host app still calls DeviceCheck to produce the platform
/// attestation object. This entry point returns the exact server
/// challenge envelope the native platform evidence must bind to before
/// `verify_app_attest_evidence` accepts it.
pub fn attest_app_attest(key_id: String, challenge_hex: String) -> Result<String, ChioMobileError> {
    let challenge = decode_hex_argument("App Attest challenge", &challenge_hex)?;
    if key_id.trim().is_empty() {
        return Err(ChioMobileError::AttestationRejected {
            message: "App Attest key_id is empty".to_string(),
        });
    }

    serde_json::to_string(&serde_json::json!({
        "schema": "chio.mobile.app-attest.challenge.v1",
        "platform": "app_attest",
        "key_id": key_id,
        "challenge_hex": hex::encode(&challenge),
        "challenge_sha256": hex::encode(chio_hash(&challenge)),
        "verifier": "chio-custody-hw::attestation::verify_app_attest",
        "status": "requires_platform_evidence"
    }))
    .map_err(|error| ChioMobileError::Internal {
        message: format!("serialize App Attest challenge envelope: {error}"),
    })
}

/// Verify App Attest platform evidence against the issued challenge.
pub fn verify_app_attest_evidence(
    key_id: String,
    challenge_hex: String,
    app_id: String,
    attestation_cbor_hex: String,
    previous_counter: i64,
) -> Result<String, ChioMobileError> {
    let challenge = decode_hex_argument("App Attest challenge", &challenge_hex)?;
    let attestation_cbor =
        decode_hex_argument("App Attest attestation object", &attestation_cbor_hex)?;
    let previous_counter = if previous_counter < 0 {
        None
    } else {
        let counter = u32::try_from(previous_counter).map_err(|error| {
            ChioMobileError::AttestationRejected {
                message: format!("App Attest previous_counter: {error}"),
            }
        })?;
        Some(counter)
    };
    let verified = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &attestation_cbor,
        key_id: &key_id,
        challenge: &challenge,
        app_id: &app_id,
        previous_counter,
        production: true,
        allow_development_fixture: false,
    })
    .map_err(map_attestation_error)?;

    serde_json::to_string(&serde_json::json!({
        "schema": "chio.mobile.attestation-evidence.v1",
        "platform": "app_attest",
        "key_id": verified.key_id,
        "app_id": verified.app_id,
        "counter": verified.counter,
        "challenge_hash": verified.challenge_hash_hex,
        "app_id_hash": verified.app_id_hash_hex,
        "credential_public_key_sha256": verified.credential_public_key_sha256_hex,
        "apple_root_sha256": verified.root_fingerprint_sha256_hex
    }))
    .map_err(|error| ChioMobileError::Internal {
        message: format!("serialize App Attest evidence envelope: {error}"),
    })
}

/// Produce a Play Integrity challenge envelope bound to `nonce_hex`.
///
/// The Android host app still calls the Play Integrity API to produce the
/// JWS. This entry point returns the nonce envelope that the JWS must bind
/// to before `verify_play_integrity_evidence` accepts it.
pub fn attest_play_integrity(nonce_hex: String) -> Result<String, ChioMobileError> {
    let nonce = decode_hex_argument("Play Integrity nonce", &nonce_hex)?;
    serde_json::to_string(&serde_json::json!({
        "schema": "chio.mobile.play-integrity.challenge.v1",
        "platform": "play_integrity",
        "nonce_hex": hex::encode(&nonce),
        "nonce_sha256": hex::encode(chio_hash(&nonce)),
        "verifier": "chio-custody-hw::attestation::verify_play_integrity",
        "status": "requires_platform_evidence"
    }))
    .map_err(|error| ChioMobileError::Internal {
        message: format!("serialize Play Integrity challenge envelope: {error}"),
    })
}

/// Verify a Play Integrity JWS against an issuer nonce and JWKS.
pub fn verify_play_integrity_evidence(
    token: String,
    expected_nonce: String,
    expected_package_name: String,
    expected_audience: String,
    jwks_json: String,
) -> Result<String, ChioMobileError> {
    let verified = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: &expected_nonce,
        expected_package_name: &expected_package_name,
        expected_audience: &expected_audience,
        jwks_json: &jwks_json,
        allow_caller_supplied_jwks: false,
    })
    .map_err(map_attestation_error)?;

    serde_json::to_string(&serde_json::json!({
        "schema": "chio.mobile.attestation-evidence.v1",
        "platform": "play_integrity",
        "package_name": verified.package_name,
        "nonce": verified.nonce,
        "app_recognition_verdict": verified.app_recognition_verdict,
        "device_recognition_verdict": verified.device_recognition_verdict
    }))
    .map_err(|error| ChioMobileError::Internal {
        message: format!("serialize Play Integrity evidence envelope: {error}"),
    })
}

/// Shape-check a mobile receipt against App Attest or Play Integrity evidence.
///
/// This does not authorize a capability or prove device integrity. It returns
/// an explicit non-authoritative status until full receipt-chain verification
/// is wired to trusted issuer pins and challenge binding.
pub fn verify_mobile_receipt(
    receipt_json: String,
    evidence_json: String,
) -> Result<String, ChioMobileError> {
    let _: serde_json::Value =
        serde_json::from_str(&receipt_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("mobile receipt: {error}"),
        })?;
    let _: serde_json::Value =
        serde_json::from_str(&evidence_json).map_err(|error| ChioMobileError::InvalidJson {
            message: format!("mobile attestation evidence: {error}"),
        })?;

    let verified = verify_mobile_receipt_chain(&receipt_json, &evidence_json)
        .map_err(map_attestation_error)?;
    serde_json::to_string(&serde_json::json!({
        "schema": "chio.mobile.receipt-verification.v1",
        "status": "shape_only",
        "receipt_kind": "trace_observation",
        "boundary_class": "detect_only",
        "result": "observed",
        "authoritative": false,
        "authorized": false,
        "receipt_schema": verified.receipt_schema,
        "evidence_schema": verified.evidence_schema,
        "platform": verified.platform
    }))
    .map_err(|error| ChioMobileError::Internal {
        message: format!("serialize mobile receipt verification: {error}"),
    })
}

// ---------------------------------------------------------------------------
// UniFFI scaffolding inclusion.
// ---------------------------------------------------------------------------
//
// This macro pulls in the `extern "C"` shim that `build.rs` writes
// into `$OUT_DIR`. The file name matches the UDL stem; UniFFI looks
// up the scaffolding by that key. Must live at the crate root so the
// generated symbols are visible to the linker.
uniffi::include_scaffolding!("chio_kernel_mobile");
