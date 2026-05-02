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
//! small (seven functions, two records, one error enum).
//!
//! # Exposed entry points
//!
//! - [`evaluate`] -- evaluate a tool-call request against a capability.
//! - [`sign_receipt`] -- sign an `ChioReceiptBody` with a 32-byte seed.
//! - [`verify_capability`] -- offline capability verification.
//! - [`verify_passport`] -- offline portable-passport envelope
//!   verification.
//! - [`attest_app_attest`] -- App Attest evidence entry point shell.
//! - [`attest_play_integrity`] -- Play Integrity evidence entry point
//!   shell.
//! - [`verify_mobile_receipt`] -- mobile attestation receipt verifier
//!   shell.
//!
//! # Offline guarantees
//!
//! None of these entry points perform I/O. A mobile app can invoke
//! all seven while offline -- for example to gate a sensitive tool
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

use chio_core_types::capability::CapabilityToken;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey};
use chio_core_types::receipt::ChioReceiptBody;
use chio_kernel_core::passport_verify::{verify_passport as core_verify_passport, VerifyError};
use chio_kernel_core::{
    evaluate as core_evaluate, sign_receipt as core_sign_receipt,
    verify_capability as core_verify_capability, CapabilityError, Clock, EvaluateInput, FixedClock,
    Guard, PortableToolCallRequest, ReceiptSigningError, Verdict,
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

    let trusted: Vec<PublicKey> = parsed
        .trusted_issuers
        .iter()
        .map(|hex_str| {
            PublicKey::from_hex(hex_str).map_err(|error| ChioMobileError::InvalidHex {
                message: format!("trusted issuer: {error}"),
            })
        })
        .collect::<Result<_, _>>()?;

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

    let keypair =
        Keypair::from_seed_hex(&signing_seed_hex).map_err(|error| ChioMobileError::InvalidHex {
            message: format!("signing seed: {error}"),
        })?;
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

    let clock = MobileClock::new();
    let verified =
        core_verify_capability(&token, &[authority], &clock).map_err(|error| match error {
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

/// Produce an App Attest evidence envelope bound to `challenge_hex`.
///
/// M07 P1 exposes the stable UniFFI entry point and validates the
/// boundary arguments. The platform verifier is wired in M07 P2; until
/// then the call fails closed with a typed unavailable error.
pub fn attest_app_attest(key_id: String, challenge_hex: String) -> Result<String, ChioMobileError> {
    let challenge = decode_hex_argument("App Attest challenge", &challenge_hex)?;
    if key_id.trim().is_empty() {
        return Err(ChioMobileError::AttestationUnavailable {
            message: "App Attest verifier pending M07.P2 platform wiring; key_id is empty"
                .to_string(),
        });
    }

    Err(ChioMobileError::AttestationUnavailable {
        message: format!(
            "App Attest verifier pending M07.P2 platform wiring; challenge_bytes={}",
            challenge.len()
        ),
    })
}

/// Produce a Play Integrity evidence envelope bound to `nonce_hex`.
///
/// M07 P1 exposes the stable UniFFI entry point and validates the
/// nonce encoding. The Android verifier is wired in M07 P3; until then
/// the call fails closed with a typed unavailable error.
pub fn attest_play_integrity(nonce_hex: String) -> Result<String, ChioMobileError> {
    let nonce = decode_hex_argument("Play Integrity nonce", &nonce_hex)?;
    Err(ChioMobileError::AttestationUnavailable {
        message: format!(
            "Play Integrity verifier pending M07.P3 platform wiring; nonce_bytes={}",
            nonce.len()
        ),
    })
}

/// Verify a mobile receipt against App Attest or Play Integrity evidence.
///
/// M07 P1 validates both JSON envelopes and reserves the fail-closed
/// entry point. M07 P4 wires the shared receipt-chain verifier.
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

    Err(ChioMobileError::AttestationUnavailable {
        message: "mobile receipt verifier pending M07.P4 receipt-chain wiring".to_string(),
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
