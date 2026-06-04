//! Browser (wasm-bindgen) bindings over the portable Chio kernel core.
//!
//! This crate exposes portable entry points to browser JavaScript /
//! TypeScript through `wasm-bindgen`. Each entry point accepts and
//! returns serde-serialized JSON so the same canonical `ToolCallRequest`
//! / `Verdict` / `CapabilityToken` / `ChioReceipt` shapes flow across
//! the wasm boundary unchanged.
//!
//! # Platform adapters
//!
//! - [`BrowserClock`] routes `chio_kernel_core::Clock` through
//!   `js_sys::Date::now()`.
//! - [`WebCryptoRng`] routes `chio_kernel_core::Rng` through
//!   `window.crypto.getRandomValues(...)`.
//!
//! Both adapters live alongside this module. They are cheap to
//! construct; each wasm entry point instantiates fresh copies rather
//! than carrying mutable state across calls.
//!
//! # no_std posture
//!
//! The crate is `no_std + alloc` by source. `wasm-bindgen`, `js-sys`,
//! `web-sys`, and `serde-wasm-bindgen` are all host crates that would
//! pull `std` if enabled; we gate them on `cfg(target_arch = "wasm32")`
//! so native `cargo test -p chio-kernel-browser` does not need them and
//! the native target compiles the pure-logic helpers alone. The wasm
//! entry points are themselves gated behind `#[cfg(target_arch =
//! "wasm32")]` for the same reason.
//!
//! # Fail-closed design
//!
//! Every entry point maps a malformed JSON input, a missing Web Crypto
//! global, a signing-key mismatch, or a verification failure into a
//! structured `Err(JsValue)`. The browser never sees a silent deny or a
//! signed receipt with a zeroed seed: the JS caller receives a rich
//! error message describing which step failed.

#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

pub mod clock;
pub mod rng;

pub use clock::BrowserClock;
pub use rng::{WebCryptoRng, WebCryptoRngError};

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{CapabilityNegotiation, CapabilityToken, ScopeHash};
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, SigningBackend};
use chio_core_types::receipt::{chio_receipt_id, ChioReceipt, ChioReceiptBody, Decision};
use chio_kernel_core::{
    evaluate_with_full_floor as core_evaluate_with_full_floor, sign_receipt as core_sign_receipt,
    verify_capability_full, BudgetRegistry, BudgetSplitError, EvaluateInput,
    InMemoryBudgetRegistry, PortableToolCallRequest, VerifiedCapability,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Portable JSON-over-wire shapes
// ---------------------------------------------------------------------------
//
// These mirror the `chio-kernel-core` types but use the `no_std + alloc`
// serde path. The wasm bindings deserialize input JSON into these shapes,
// translate them into the kernel-core types, run the evaluation, then
// serialize the result back to JSON for the JS caller. Keeping the wire
// types alongside the bindings makes the boundary contract explicit.

/// Wire shape matching [`PortableToolCallRequest`].
///
/// Declared locally so the wasm bindings have a stable wire contract
/// independent of the kernel-core types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequestJson {
    pub request_id: String,
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
}

impl From<ToolCallRequestJson> for PortableToolCallRequest {
    fn from(value: ToolCallRequestJson) -> Self {
        PortableToolCallRequest {
            request_id: value.request_id,
            tool_name: value.tool_name,
            server_id: value.server_id,
            agent_id: value.agent_id,
            arguments: value.arguments,
        }
    }
}

/// Root envelope accepted by [`evaluate_pure`] (and the wasm entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequestJson {
    /// The tool call request.
    pub request: ToolCallRequestJson,
    /// The capability authorising the call.
    pub capability: CapabilityToken,
    /// Trusted issuer public keys (hex-encoded). Typically the
    /// capability authority plus the session-scoped CA.
    pub trusted_issuers_hex: Vec<String>,
    /// Optional pinned unix-seconds clock override. When `None`, the
    /// adapter reads `Date::now()` via [`BrowserClock`]. Test harnesses
    /// use this to pin the clock for reproducible acceptance checks.
    #[serde(default)]
    pub clock_override_unix_secs: Option<u64>,
    /// Optional session filesystem roots, forwarded to guards.
    #[serde(default)]
    pub session_filesystem_roots: Option<Vec<String>>,
    /// Optional peer-negotiated capability feature profile. When omitted,
    /// the browser kernel evaluates against `CapabilityNegotiation::t1_default()`.
    #[serde(default)]
    pub peer_capabilities: Option<CapabilityNegotiation>,
    /// Optional chain-binding trust roots, keyed by issuer hex. Tokens with
    /// attenuation, budget sharing, scope attenuation, or delegation require an
    /// issuer entry; absent issuers fail closed.
    #[serde(default)]
    pub capability_trust_roots: BTreeMap<String, ScopeHash>,
    /// Optional parent-budget snapshots used to seed sibling-sum
    /// enforcement before evaluating delegated tokens.
    #[serde(default)]
    pub parent_budget_snapshots: Vec<ParentBudgetSnapshotJson>,
}

/// Parent budget state supplied by portable callers before a delegated
/// child token is evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentBudgetSnapshotJson {
    /// Parent capability id that appears in the delegated token's last
    /// delegation link.
    pub parent_token_id: String,
    /// Parent share in basis points.
    pub parent_share_bps: u16,
    /// Siblings already admitted under this parent.
    #[serde(default)]
    pub admitted_children: Vec<AdmittedChildBudgetJson>,
}

/// Already-admitted child budget share in a parent snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittedChildBudgetJson {
    /// Child capability id already admitted under the parent.
    pub child_token_id: String,
    /// Child share in basis points.
    pub share_bps: u16,
}

/// Wire shape for the result of [`evaluate_pure`]. Flattens the fields
/// of [`chio_kernel_core::EvaluationVerdict`] so the JS caller can
/// consume a plain object without reaching into Rust enum tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationVerdictJson {
    /// `"deny"` or `"pending_approval"` for browser capability-only
    /// evaluation. An empty guard pipeline never emits authoritative
    /// `"allow"` at this boundary.
    pub verdict: String,
    /// Raw kernel-core capability and scope verdict before the browser
    /// authority downgrade. Callers may use this for diagnostics, not
    /// as execution authorization.
    pub capability_verdict: String,
    /// Deny reason when `verdict == "deny"`.
    pub reason: Option<String>,
    /// Whether this evaluation result is authoritative authorization.
    /// Browser capability-only evaluation always reports `false`.
    pub authorized: bool,
    /// Machine-readable reason for the authorization state.
    pub authorization_basis: String,
    /// Whether a guard pipeline participated in the authorization.
    pub guards_evaluated: bool,
    /// Index of the matched grant on allow or after guard denial.
    pub matched_grant_index: Option<usize>,
    /// Subject hex-encoded public key (populated when the capability
    /// signature + time-bound checks passed).
    pub subject_hex: Option<String>,
    /// Issuer hex-encoded public key.
    pub issuer_hex: Option<String>,
    /// Capability id.
    pub capability_id: Option<String>,
    /// Unix-seconds timestamp the kernel core used for time checks.
    pub evaluated_at: Option<u64>,
}

impl EvaluationVerdictJson {
    fn from_core(value: chio_kernel_core::EvaluationVerdict) -> Self {
        let capability_verdict = match value.verdict {
            chio_kernel_core::Verdict::Allow => "allow",
            chio_kernel_core::Verdict::Deny => "deny",
            chio_kernel_core::Verdict::PendingApproval => "pending_approval",
        };
        let (verdict_str, reason, authorization_basis) = match value.verdict {
            chio_kernel_core::Verdict::Allow => (
                "pending_approval",
                Some(
                    "capability-only browser evaluation requires a mediated prevent receipt before execution"
                        .to_string(),
                ),
                "capability_only",
            ),
            chio_kernel_core::Verdict::Deny => ("deny", value.reason, "denied"),
            chio_kernel_core::Verdict::PendingApproval => {
                ("pending_approval", value.reason, "pending_approval")
            }
        };
        let (subject_hex, issuer_hex, capability_id, evaluated_at) = match value.verified {
            Some(verified) => (
                Some(verified.subject_hex),
                Some(verified.issuer_hex),
                Some(verified.id),
                Some(verified.evaluated_at),
            ),
            None => (None, None, None, None),
        };
        Self {
            verdict: verdict_str.to_string(),
            capability_verdict: capability_verdict.to_string(),
            reason,
            authorized: false,
            authorization_basis: authorization_basis.to_string(),
            guards_evaluated: false,
            matched_grant_index: value.matched_grant_index,
            subject_hex,
            issuer_hex,
            capability_id,
            evaluated_at,
        }
    }
}

/// Wire shape for [`sign_receipt_pure`] inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignReceiptRequestJson {
    /// The receipt body to sign.
    pub body: ChioReceiptBody,
}

/// Wire shape for [`verify_capability_pure`] inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCapabilityRequestJson {
    /// The capability token to verify.
    pub token: CapabilityToken,
    /// Trusted authority public keys, hex-encoded.
    pub trusted_issuers_hex: Vec<String>,
    /// Optional pinned unix-seconds clock override. When `None`, the
    /// adapter reads `Date::now()` via [`BrowserClock`].
    #[serde(default)]
    pub clock_override_unix_secs: Option<u64>,
    /// Optional peer-negotiated capability feature profile. When omitted,
    /// the browser kernel evaluates against `CapabilityNegotiation::t1_default()`.
    #[serde(default)]
    pub peer_capabilities: Option<CapabilityNegotiation>,
    /// Optional chain-binding trust roots, keyed by issuer hex. Attenuated or
    /// delegated tokens require an entry for their issuer; absent issuers
    /// fail-closed.
    #[serde(default)]
    pub capability_trust_roots: BTreeMap<String, ScopeHash>,
    /// Optional parent-budget snapshots used to seed sibling-sum
    /// enforcement before verifying delegated tokens.
    #[serde(default)]
    pub parent_budget_snapshots: Vec<ParentBudgetSnapshotJson>,
}

/// Wire shape for [`verify_capability_pure`] outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedCapabilityJson {
    pub id: String,
    pub subject_hex: String,
    pub issuer_hex: String,
    pub scope: chio_core_types::capability::ChioScope,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evaluated_at: u64,
}

impl From<VerifiedCapability> for VerifiedCapabilityJson {
    fn from(value: VerifiedCapability) -> Self {
        Self {
            id: value.id,
            subject_hex: value.subject_hex,
            issuer_hex: value.issuer_hex,
            scope: value.scope,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            evaluated_at: value.evaluated_at,
        }
    }
}

/// Wire shape for [`verify_receipt_pure`] outputs.
///
/// Carries a structured outcome rather than a bare `bool` so the JS
/// caller can discriminate between "signature verified, decision is
/// `allow`", "signature verified, decision is `deny`", and "signature
/// did not verify". The receipt envelope is round-tripped on the way
/// out so the browser does not need to re-parse it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReceiptResultJson {
    /// `true` when the receipt's Ed25519 signature verifies against the
    /// embedded `kernel_key`, the parameter hash is valid, and the
    /// `kernel_key` appears in the supplied trusted issuer set. Callers
    /// must provide at least one trusted issuer before a receipt can be
    /// marked trusted.
    pub ok: bool,
    /// Lowercase hex of the receipt's `kernel_key`.
    pub signer_key_hex: String,
    /// Receipt id, surfaced for telemetry / dedup.
    pub receipt_id: String,
    /// `true` when the receipt id matches the content-addressed id
    /// derived from the canonical receipt body.
    pub receipt_id_valid: bool,
    /// Snake_case decision verdict: `"allow"`, `"deny"`, `"cancelled"`,
    /// or `"incomplete"`.
    pub decision: String,
    /// Current v1 semantic receipt kind.
    pub receipt_kind: String,
    /// Current v1 runtime boundary class.
    pub boundary_class: String,
    /// Human-facing semantic result label.
    pub result: String,
    /// `true` only for mediated prevent-boundary allow receipts.
    pub authorized: bool,
    /// `true` when the parameter hash on the embedded `ToolCallAction`
    /// matches the canonical hash of the parameters.
    pub parameter_hash_valid: bool,
    /// `true` when the signature math verified. Distinct from `ok`
    /// because `ok` also requires explicit issuer pinning.
    pub signature_valid: bool,
    /// `true` when the signer appears in a non-empty trusted issuer
    /// set. Empty trusted issuer sets report signature status only and
    /// never mark the signer trusted.
    pub signer_trusted: bool,
}

/// Structured error returned across the wasm boundary when an entry
/// point fails. Carries both a machine-readable `code` and a
/// human-readable `message` so the browser caller can route errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingError {
    pub code: String,
    pub message: String,
}

impl BindingError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure (platform-agnostic) core helpers
// ---------------------------------------------------------------------------
//
// These are the actual verdict / sign / verify implementations. They
// accept the wire shapes plus an injected clock so the wasm layer below
// is a thin adapter. Native unit tests exercise these directly without
// pulling wasm-bindgen.

/// Decode a list of hex-encoded public keys.
fn decode_trusted_issuers(hex_list: &[String]) -> Result<Vec<PublicKey>, BindingError> {
    hex_list
        .iter()
        .map(|hex_str| {
            PublicKey::from_hex(hex_str)
                .map_err(|e| BindingError::new("invalid_issuer_hex", e.to_string()))
        })
        .collect()
}

fn seed_budget_registry(
    budgets: &mut InMemoryBudgetRegistry,
    snapshots: &[ParentBudgetSnapshotJson],
) -> Result<(), BindingError> {
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

fn budget_seed_error(context: &str, error: &BudgetSplitError) -> BindingError {
    BindingError::new("invalid_budget_snapshot", format!("{context}: {error}"))
}

/// Pure in-process evaluation used by both the wasm binding and the
/// native unit tests. The clock is injected by the caller so the
/// browser adapter can wire `Date::now()` while tests pin a fixed
/// value via `FixedClock`.
pub fn evaluate_pure(
    input: EvaluateRequestJson,
    clock: &dyn chio_kernel_core::Clock,
) -> Result<EvaluationVerdictJson, BindingError> {
    let trusted = decode_trusted_issuers(&input.trusted_issuers_hex)?;
    let portable_request: PortableToolCallRequest = input.request.into();
    let peer_profile = input
        .peer_capabilities
        .clone()
        .unwrap_or_else(CapabilityNegotiation::t1_default);
    let trust_root_map = input.capability_trust_roots.clone();
    let trust_resolver = move |issuer: &PublicKey| -> Option<ScopeHash> {
        trust_root_map.get(&issuer.to_hex()).cloned()
    };
    let mut budgets = InMemoryBudgetRegistry::new();
    seed_budget_registry(&mut budgets, &input.parent_budget_snapshots)?;

    // If the caller pinned a clock override, honour it; otherwise use
    // the injected browser/test clock. We can't return a `&dyn Clock`
    // pointing to a stack local, so we branch over the call site.
    let verdict = match input.clock_override_unix_secs {
        Some(pinned) => {
            let fixed = chio_kernel_core::FixedClock::new(pinned);
            core_evaluate_with_full_floor(
                EvaluateInput {
                    request: &portable_request,
                    capability: &input.capability,
                    trusted_issuers: &trusted,
                    clock: &fixed,
                    guards: &[],
                    session_filesystem_roots: input.session_filesystem_roots.as_deref(),
                },
                chio_core_types::capability::CapabilityCryptoFloor::AllowClassical,
                &peer_profile,
                &trust_resolver,
                &mut budgets,
            )
        }
        None => core_evaluate_with_full_floor(
            EvaluateInput {
                request: &portable_request,
                capability: &input.capability,
                trusted_issuers: &trusted,
                clock,
                guards: &[],
                session_filesystem_roots: input.session_filesystem_roots.as_deref(),
            },
            chio_core_types::capability::CapabilityCryptoFloor::AllowClassical,
            &peer_profile,
            &trust_resolver,
            &mut budgets,
        ),
    };

    Ok(EvaluationVerdictJson::from_core(verdict))
}

/// Pure receipt-signing helper. Builds an `Ed25519Backend` from the
/// supplied seed (which the wasm binding mints via Web Crypto) and
/// delegates to `chio_kernel_core::sign_receipt`.
pub fn sign_receipt_pure(
    input: SignReceiptRequestJson,
    signing_seed: &[u8; 32],
) -> Result<chio_core_types::receipt::ChioReceipt, BindingError> {
    // Refuse to sign with a zero seed. This guards against the
    // fail-closed fallback in `WebCryptoRng::fill_bytes` -- the adapter
    // fills the destination with zeros when `getRandomValues` threw.
    // Signing with a deterministic zero key would produce a valid
    // Ed25519 signature but the private key would be recoverable by
    // any party holding the zero seed, defeating receipt integrity.
    if signing_seed.iter().all(|byte| *byte == 0) {
        return Err(BindingError::new(
            "weak_entropy",
            "refusing to sign: Web Crypto returned a zero-filled seed (entropy source failed)",
        ));
    }

    let keypair = Keypair::from_seed(signing_seed);
    let backend = Ed25519Backend::new(keypair);

    // The kernel-core sign path refuses to sign if the body's
    // `kernel_key` does not match the backend. For the browser use
    // case we always sign with a fresh ephemeral key, so we force
    // the body's `kernel_key` to match the backend we just built.
    let mut body = input.body;
    body.kernel_key = backend.public_key();

    core_sign_receipt(body, &backend)
        .map_err(|error| BindingError::new("receipt_signing_failed", format_signing(&error)))
}

/// Pure capability-verification helper.
///
/// Hot-path wiring routes through [`verify_capability_full`] so negotiated
/// feature validation and chain-binding checks are enforced alongside
/// signature, floor, and time-bound checks. Callers that omit the peer profile
/// inherit `CapabilityNegotiation::t1_default()`; callers that omit
/// `capability_trust_roots` fail closed for attenuated or delegated tokens
/// because no issuer has a registered authority hash.
pub fn verify_capability_pure(
    input: VerifyCapabilityRequestJson,
    clock: &dyn chio_kernel_core::Clock,
) -> Result<VerifiedCapabilityJson, BindingError> {
    let trusted = decode_trusted_issuers(&input.trusted_issuers_hex)?;
    let crypto_floor = chio_core_types::capability::CapabilityCryptoFloor::AllowClassical;
    let peer_profile = input
        .peer_capabilities
        .clone()
        .unwrap_or_else(CapabilityNegotiation::t1_default);
    let trust_root_map = input.capability_trust_roots.clone();
    let trust_resolver = move |issuer: &PublicKey| -> Option<ScopeHash> {
        trust_root_map.get(&issuer.to_hex()).cloned()
    };

    // Seed the per-request registry from caller-owned parent snapshots
    // so delegated tokens can be verified without fabricating missing
    // parent shares.
    let mut budgets = InMemoryBudgetRegistry::new();
    seed_budget_registry(&mut budgets, &input.parent_budget_snapshots)?;
    let result = match input.clock_override_unix_secs {
        Some(pinned) => {
            let fixed = chio_kernel_core::FixedClock::new(pinned);
            verify_capability_full(
                &input.token,
                &trusted,
                &fixed,
                crypto_floor,
                &peer_profile,
                &trust_resolver,
                &mut budgets,
            )
        }
        None => verify_capability_full(
            &input.token,
            &trusted,
            clock,
            crypto_floor,
            &peer_profile,
            &trust_resolver,
            &mut budgets,
        ),
    };

    match result {
        Ok(verified) => Ok(VerifiedCapabilityJson::from(verified)),
        Err(error) => Err(BindingError::new(
            "capability_verification_failed",
            capability_error_message(&error),
        )),
    }
}

/// Pure receipt-verification helper. Parses a canonical-JSON receipt
/// envelope, runs the embedded-key signature check, optionally pins the
/// signer to a trusted-issuer set, and returns a structured outcome.
///
/// `trusted_issuers` must contain the signer before `ok` can be true.
/// An empty slice means "signature-only verification": the signature
/// and parameter hash fields still report their mathematical status,
/// but the receipt is not marked trusted.
///
/// Verification is fail-closed in the sense that a malformed envelope,
/// a parameter-hash mismatch, or a signature that does not verify
/// produces an `ok: false` result. The function never panics on
/// malformed input; it returns a structured error instead.
pub fn verify_receipt_pure(
    envelope: &[u8],
    trusted_issuers: &[PublicKey],
) -> Result<VerifyReceiptResultJson, BindingError> {
    let receipt: ChioReceipt = serde_json::from_slice(envelope).map_err(|error| {
        BindingError::new(
            "invalid_receipt_envelope",
            format!("could not parse receipt envelope as JSON: {error}"),
        )
    })?;

    let signer_key_hex = receipt.kernel_key.to_hex();
    let receipt_id = receipt.id.clone();
    let computed_receipt_id = chio_receipt_id(&receipt.body()).map_err(|error| {
        BindingError::new(
            "receipt_id_check_failed",
            format!("receipt id check could not run: {error}"),
        )
    })?;
    let receipt_id_valid = computed_receipt_id == receipt_id;
    let decision_str = match &receipt.decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
    .to_string();

    let parameter_hash_valid = receipt.action.verify_hash().map_err(|error| {
        BindingError::new(
            "parameter_hash_check_failed",
            format!("parameter hash check could not run: {error}"),
        )
    })?;

    let signature_valid = receipt.verify_signature().map_err(|error| {
        BindingError::new(
            "signature_check_failed",
            format!("signature verification could not run: {error}"),
        )
    })?;

    let signer_trusted = !trusted_issuers.is_empty()
        && trusted_issuers
            .iter()
            .any(|issuer| issuer == &receipt.kernel_key);

    let semantics = receipt.semantic_fields();
    let semantic_authorized = semantics.is_authorized(receipt.decision.as_ref());
    let result = semantics
        .result_label(receipt.decision.as_ref())
        .to_string();
    let receipt_kind = semantics.receipt_kind.as_str().to_string();
    let boundary_class = semantics.boundary_class.as_str().to_string();

    let ok = signature_valid && parameter_hash_valid && receipt_id_valid && signer_trusted;
    let authorized = semantic_authorized && ok;

    Ok(VerifyReceiptResultJson {
        ok,
        signer_key_hex,
        receipt_id,
        receipt_id_valid,
        decision: decision_str,
        receipt_kind,
        boundary_class,
        result,
        authorized,
        parameter_hash_valid,
        signature_valid,
        signer_trusted,
    })
}

/// Produce a human-readable message for a
/// [`chio_kernel_core::CapabilityError`] without going through the
/// std-only `thiserror`-generated `Display` impl on
/// `chio_core_types::Error`.
fn capability_error_message(error: &chio_kernel_core::CapabilityError) -> String {
    match error {
        chio_kernel_core::CapabilityError::UntrustedIssuer => {
            "capability issuer is not in the trusted set".to_string()
        }
        chio_kernel_core::CapabilityError::InvalidSignature => {
            "capability signature did not verify".to_string()
        }
        chio_kernel_core::CapabilityError::CryptoFloorRejected(msg) => {
            let mut out = String::from("capability rejected by crypto floor: ");
            out.push_str(msg);
            out
        }
        chio_kernel_core::CapabilityError::NotYetValid => {
            "capability is not yet valid (clock is before issued_at)".to_string()
        }
        chio_kernel_core::CapabilityError::Expired => {
            "capability has expired (clock is at or after expires_at)".to_string()
        }
        chio_kernel_core::CapabilityError::AttenuationViolation(msg) => {
            let mut out = String::from("capability rejected by chain binding: ");
            out.push_str(msg);
            out
        }
        chio_kernel_core::CapabilityError::BudgetSplitRejected(err) => {
            let mut out = String::from("capability rejected by sibling-sum budget split: ");
            out.push_str(&err.to_string());
            out
        }
        chio_kernel_core::CapabilityError::Internal(msg) => {
            let mut out = String::from("capability verification failed: ");
            out.push_str(msg);
            out
        }
    }
}

/// Stringify a [`chio_kernel_core::ReceiptSigningError`] without pulling
/// in the `thiserror` `Display` chain.
fn format_signing(error: &chio_kernel_core::ReceiptSigningError) -> String {
    match error {
        chio_kernel_core::ReceiptSigningError::KernelKeyMismatch => {
            "receipt body kernel_key does not match the signing backend".to_string()
        }
        chio_kernel_core::ReceiptSigningError::SigningFailed(reason) => {
            let mut out = String::from("receipt signing failed: ");
            out.push_str(reason);
            out
        }
    }
}

/// Decode a 32-byte Ed25519 seed from lowercase hex (with or without a
/// leading `0x`). Shared between the wasm entry point and the native
/// smoke tests.
pub fn decode_seed_hex(hex_str: &str) -> Result<[u8; 32], BindingError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() != 64 {
        return Err(BindingError::new(
            "invalid_seed_hex",
            format!(
                "expected 64-hex-character Ed25519 seed, got {} characters",
                stripped.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    let bytes = stripped.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = from_hex_nibble(bytes[idx]).map_err(|reason| {
            BindingError::new(
                "invalid_seed_hex",
                format!("seed has non-hex character: {reason}"),
            )
        })?;
        let lo = from_hex_nibble(bytes[idx + 1]).map_err(|reason| {
            BindingError::new(
                "invalid_seed_hex",
                format!("seed has non-hex character: {reason}"),
            )
        })?;
        out[idx / 2] = (hi << 4) | lo;
        idx += 2;
    }
    Ok(out)
}

fn from_hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("non-hex character"),
    }
}

/// Lowercase-hex encoder shared by the wasm seed-minting entry and the
/// native unit tests.
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    const NIBBLES: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(NIBBLES[(byte >> 4) as usize]);
        out.push(NIBBLES[(byte & 0x0f) as usize]);
    }
    out
}

/// Parse the second argument of [`wasm::verify_capability`] -- either a
/// single hex-encoded authority key or a JSON array of hex keys.
pub fn parse_authority_input(raw: &str) -> Result<Vec<String>, BindingError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BindingError::new(
            "invalid_authority_input",
            "authority input was empty",
        ));
    }
    if trimmed.starts_with('[') {
        let values = serde_json::from_str::<Vec<String>>(trimmed).map_err(|error| {
            BindingError::new(
                "invalid_authority_input",
                format!("authority input must be hex or JSON array of hex: {error}"),
            )
        })?;
        return normalize_authority_array(values);
    }
    Ok(alloc::vec![trimmed.to_string()])
}

fn normalize_authority_array(values: Vec<String>) -> Result<Vec<String>, BindingError> {
    if values.is_empty() {
        return Err(BindingError::new(
            "invalid_authority_input",
            "authority input array was empty",
        ));
    }

    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(BindingError::new(
                "invalid_authority_input",
                "authority input array contained an empty key",
            ));
        }
        normalized.push(trimmed.to_string());
    }
    Ok(normalized)
}

// ---------------------------------------------------------------------------
// wasm-bindgen entry points
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    //! Browser entry points. Compiled only for `wasm32-*` targets so the
    //! host `cargo test -p chio-kernel-browser` can still run without a
    //! wasm toolchain.

    use super::*;
    use chio_kernel_core::Rng as _;
    use wasm_bindgen::prelude::*;

    fn to_js_error(error: &BindingError) -> JsValue {
        serde_wasm_bindgen::to_value(error).unwrap_or_else(|_| JsValue::from_str(&error.message))
    }

    fn parse_json<T: for<'de> Deserialize<'de>>(label: &str, raw: &str) -> Result<T, JsValue> {
        serde_json::from_str::<T>(raw).map_err(|error| {
            let err = BindingError::new("invalid_json_input", format!("{label}: {error}"));
            to_js_error(&err)
        })
    }

    fn encode_result<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(value).map_err(|error| {
            let err = BindingError::new(
                "encode_result_failed",
                format!("could not serialize wasm result: {error}"),
            );
            to_js_error(&err)
        })
    }

    /// Evaluate a tool call request against a capability.
    ///
    /// Accepts the JSON serialization of [`EvaluateRequestJson`] and
    /// returns an [`EvaluationVerdictJson`]. The underlying
    /// `chio_kernel_core::evaluate` runs with an empty guard pipeline --
    /// browser evaluations today target offline-capability checks; a
    /// capability-only success is therefore downgraded to
    /// `pending_approval` instead of authoritative `allow`.
    #[wasm_bindgen]
    pub fn evaluate(request_json: &str) -> Result<JsValue, JsValue> {
        let request: EvaluateRequestJson = parse_json("evaluate request", request_json)?;
        let clock = BrowserClock::new();
        let verdict = evaluate_pure(request, &clock).map_err(|err| to_js_error(&err))?;
        encode_result(&verdict)
    }

    /// Sign a receipt body.
    ///
    /// The `signing_seed_hex` parameter carries a 32-byte Ed25519 seed
    /// as lowercase hex (optionally `0x`-prefixed). Callers that want
    /// the browser to mint a fresh seed per receipt should call
    /// [`mint_signing_seed_hex`] first and pass the result in here.
    #[wasm_bindgen]
    pub fn sign_receipt(body_json: &str, signing_seed_hex: &str) -> Result<JsValue, JsValue> {
        let input: SignReceiptRequestJson = parse_json("sign_receipt body", body_json)?;
        let seed = decode_seed_hex(signing_seed_hex).map_err(|err| to_js_error(&err))?;
        let receipt = sign_receipt_pure(input, &seed).map_err(|err| to_js_error(&err))?;
        encode_result(&receipt)
    }

    /// Verify a capability token against a trusted issuer set.
    ///
    /// `authority_pub_hex` may be either a single hex-encoded key or a
    /// JSON array of hex-encoded keys. The single-key form is the
    /// common case so we branch on the first character.
    #[wasm_bindgen]
    pub fn verify_capability(
        token_json: &str,
        authority_pub_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let trusted_issuers_hex =
            parse_authority_input(authority_pub_hex).map_err(|err| to_js_error(&err))?;
        let token = parse_json::<CapabilityToken>("verify_capability token", token_json)?;
        let request = VerifyCapabilityRequestJson {
            token,
            trusted_issuers_hex,
            clock_override_unix_secs: None,
            peer_capabilities: Some(CapabilityNegotiation::v1_default()),
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: Vec::new(),
        };
        let clock = BrowserClock::new();
        let verified = verify_capability_pure(request, &clock).map_err(|err| to_js_error(&err))?;
        encode_result(&verified)
    }

    /// Verify a capability token with full portable context.
    ///
    /// Accepts the JSON serialization of [`VerifyCapabilityRequestJson`],
    /// including trust roots and parent-budget snapshots for delegated
    /// tokens. The legacy [`verify_capability`] helper remains available
    /// for single-authority v1 checks.
    #[wasm_bindgen]
    pub fn verify_capability_with_context(request_json: &str) -> Result<JsValue, JsValue> {
        let request: VerifyCapabilityRequestJson =
            parse_json("verify_capability request", request_json)?;
        let clock = BrowserClock::new();
        let verified = verify_capability_pure(request, &clock).map_err(|err| to_js_error(&err))?;
        encode_result(&verified)
    }

    /// Verify a Chio receipt envelope.
    ///
    /// `envelope` is the canonical-JSON serialization of a
    /// `ChioReceipt`. `trusted_issuers` is a JS value that the browser
    /// caller may pass as:
    ///
    /// - `undefined` / `null` -- run signature and parameter-hash checks
    ///   only; `ok` remains `false` because no trusted issuer was pinned.
    /// - a JS string -- a single hex-encoded Ed25519 public key.
    /// - a JS array of strings -- multiple hex-encoded keys; the
    ///   receipt's `kernel_key` MUST appear in the set for `ok` to be
    ///   `true`.
    ///
    /// The function returns a [`VerifyReceiptResultJson`] on success
    /// (with `ok` differentiating the verified path from the
    /// signature-bad path) and a [`BindingError`] (`Err(JsValue)`) when
    /// the envelope itself could not be parsed as a receipt.
    #[wasm_bindgen]
    pub fn verify_receipt(envelope: &[u8], trusted_issuers: &JsValue) -> Result<JsValue, JsValue> {
        let trusted_hex = parse_trusted_issuers_jsvalue(trusted_issuers)?;
        let trusted = decode_trusted_issuers(&trusted_hex).map_err(|err| to_js_error(&err))?;
        let result = verify_receipt_pure(envelope, &trusted).map_err(|err| to_js_error(&err))?;
        encode_result(&result)
    }

    /// Decode the `trusted_issuers` argument of [`verify_receipt`] into
    /// a `Vec<String>` of hex-encoded keys.
    fn parse_trusted_issuers_jsvalue(value: &JsValue) -> Result<Vec<String>, JsValue> {
        if value.is_undefined() || value.is_null() {
            return Ok(Vec::new());
        }
        if let Some(single) = value.as_string() {
            return Ok(alloc::vec![single]);
        }
        // Anything else: try to round-trip through serde-wasm-bindgen
        // as a `Vec<String>`. `serde_wasm_bindgen::from_value` accepts
        // both JS arrays and ES2017 iterables produced by Web APIs.
        serde_wasm_bindgen::from_value::<Vec<String>>(value.clone()).map_err(|error| {
            to_js_error(&BindingError::new(
                "invalid_trusted_issuers",
                format!(
                    "trusted_issuers must be undefined, a hex string, or an array of hex strings: {error}"
                ),
            ))
        })
    }

    /// Mint a fresh 32-byte signing seed using the browser's Web Crypto
    /// RNG and return it as lowercase hex. Surfaces entropy-source
    /// failures as structured errors instead of silently returning a
    /// zero-filled seed.
    #[wasm_bindgen]
    pub fn mint_signing_seed_hex() -> Result<String, JsValue> {
        let rng = WebCryptoRng::try_new().map_err(|error| {
            to_js_error(&BindingError::new(
                "webcrypto_unavailable",
                format!("{error}"),
            ))
        })?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        if seed.iter().all(|b| *b == 0) {
            return Err(to_js_error(&BindingError::new(
                "weak_entropy",
                "Web Crypto returned a zero-filled seed; refusing to use it",
            )));
        }
        Ok(hex_encode_lower(&seed))
    }
}

// ---------------------------------------------------------------------------
// Native unit tests (pure helpers)
// ---------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use chio_core_types::capability::{
        compute_attenuation_witness, scope_hash, AttenuationProof, CapabilityToken,
        CapabilityTokenAttenuationBody, CapabilityTokenBody, ChioScope, DelegationLink,
        DelegationLinkBody, Operation, ToolGrant,
    };
    use chio_core_types::crypto::Keypair;
    use chio_core_types::receipt::{
        BoundaryClass, ChioReceiptBody, Decision, ReceiptKind, RedactionMode, ToolCallAction,
        ToolOrigin, TrustLevel,
    };
    use chio_kernel_core::FixedClock;

    const ISSUED_AT: u64 = 1_700_000_000;
    const EXPIRES_AT: u64 = 1_700_100_000;

    fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
        CapabilityToken::sign(make_capability_body("cap-1", subject, issuer), issuer).unwrap()
    }

    fn make_delegated_capability(
        id: &str,
        parent_id: &str,
        subject: &Keypair,
        issuer: &Keypair,
    ) -> CapabilityToken {
        let body = make_capability_body(id, subject, issuer);
        let parent_scope_hash = scope_hash(&body.scope).unwrap();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.public_key(),
                attenuations: std::vec![],
                timestamp: ISSUED_AT,
                scope_hash: Some(parent_scope_hash.clone()),
            },
            issuer,
        )
        .unwrap();
        let proof = AttenuationProof {
            parent_scope_hash,
            child_scope_hash: scope_hash(&body.scope).unwrap(),
            normalized_subset_proof: compute_attenuation_witness(&body.scope, &body.scope).unwrap(),
        };
        let mut body = body;
        body.delegation_chain = std::vec![parent_link];
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body,
                caveats: std::vec![],
                scope_attenuations: std::vec![],
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            issuer,
        )
        .unwrap()
    }

    fn trust_roots_for_scope(issuer: &Keypair, scope: &ChioScope) -> BTreeMap<String, ScopeHash> {
        let mut roots = BTreeMap::new();
        roots.insert(issuer.public_key().to_hex(), scope_hash(scope).unwrap());
        roots
    }

    fn parent_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshotJson {
        ParentBudgetSnapshotJson {
            parent_token_id: parent_id.to_string(),
            parent_share_bps: 10_000,
            admitted_children: std::vec![],
        }
    }

    fn oversubscribed_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshotJson {
        ParentBudgetSnapshotJson {
            parent_token_id: parent_id.to_string(),
            parent_share_bps: 10_000,
            admitted_children: std::vec![AdmittedChildBudgetJson {
                child_token_id: "cap-sibling".to_string(),
                share_bps: 1,
            }],
        }
    }

    fn make_capability_body(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityTokenBody {
        let scope = ChioScope {
            grants: std::vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "echo".to_string(),
                operations: std::vec![Operation::Invoke],
                constraints: std::vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: std::vec![],
            prompt_grants: std::vec![],
        };
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            delegation_chain: std::vec![],
        }
    }

    fn make_v2_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
        let body = make_capability_body("cap-v2", subject, issuer);
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&body.scope).expect("parent scope hash"),
            child_scope_hash: scope_hash(&body.scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(&body.scope, &body.scope)
                .expect("attenuation witness"),
        };
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body,
                caveats: std::vec![],
                scope_attenuations: std::vec![],
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            issuer,
        )
        .unwrap()
    }

    fn make_request_json(subject: &Keypair) -> ToolCallRequestJson {
        ToolCallRequestJson {
            request_id: "req-1".to_string(),
            tool_name: "echo".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: subject.public_key().to_hex(),
            arguments: serde_json::json!({"msg": "hello"}),
        }
    }

    #[test]
    fn evaluate_pure_allow_path() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_capability(&subject, &issuer);
        let request = make_request_json(&subject);

        let input = EvaluateRequestJson {
            request,
            capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: std::vec![],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
        assert_eq!(verdict.verdict, "pending_approval");
        assert_eq!(verdict.capability_verdict, "allow");
        assert!(!verdict.authorized);
        assert_eq!(verdict.authorization_basis, "capability_only");
        assert!(!verdict.guards_evaluated);
        assert!(verdict
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("mediated prevent receipt"));
        assert_eq!(verdict.matched_grant_index, Some(0));
        assert!(verdict.subject_hex.is_some());
        assert!(verdict.issuer_hex.is_some());
        assert_eq!(verdict.capability_id.as_deref(), Some("cap-1"));
    }

    #[test]
    fn evaluate_pure_deny_on_expired_capability() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_capability(&subject, &issuer);
        let request = make_request_json(&subject);

        let input = EvaluateRequestJson {
            request,
            capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(EXPIRES_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: std::vec![],
        };
        let clock = FixedClock::new(EXPIRES_AT + 1);

        let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
        assert_eq!(verdict.verdict, "deny");
        assert!(verdict
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("expired"));
    }

    #[test]
    fn evaluate_pure_v2_without_trust_root_fails_closed() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_v2_capability(&subject, &issuer);
        let request = make_request_json(&subject);

        let input = EvaluateRequestJson {
            request,
            capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: std::vec![],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
        assert_eq!(verdict.verdict, "deny");
        assert!(verdict
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("no trust-root scope hash"));
    }

    #[test]
    fn evaluate_pure_allows_delegated_token_with_parent_budget_snapshot() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
        let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);
        let request = make_request_json(&subject);

        let input = EvaluateRequestJson {
            request,
            capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            capability_trust_roots,
            parent_budget_snapshots: std::vec![parent_budget_snapshot("cap-parent")],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");

        assert_eq!(verdict.verdict, "pending_approval");
        assert_eq!(verdict.capability_verdict, "allow");
        assert!(!verdict.authorized);
        assert_eq!(verdict.capability_id.as_deref(), Some("cap-child"));
    }

    #[test]
    fn evaluate_pure_rejects_oversubscribed_delegated_sibling() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
        let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);
        let request = make_request_json(&subject);

        let input = EvaluateRequestJson {
            request,
            capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            capability_trust_roots,
            parent_budget_snapshots: std::vec![oversubscribed_budget_snapshot("cap-parent")],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");

        assert_eq!(verdict.verdict, "deny");
        assert!(verdict
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("budget split rejected"));
    }

    #[test]
    fn verify_capability_pure_untrusted() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let other = Keypair::generate();
        let capability = make_capability(&subject, &issuer);

        let input = VerifyCapabilityRequestJson {
            token: capability,
            trusted_issuers_hex: std::vec![other.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            peer_capabilities: None,
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: std::vec![],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let err = verify_capability_pure(input, &clock).expect_err("must reject untrusted issuer");
        assert_eq!(err.code, "capability_verification_failed");
        assert!(err.message.contains("not in the trusted set"));
    }

    #[test]
    fn verify_capability_pure_allows_delegated_token_with_parent_budget_snapshot() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
        let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);

        let input = VerifyCapabilityRequestJson {
            token: capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            peer_capabilities: None,
            capability_trust_roots,
            parent_budget_snapshots: std::vec![parent_budget_snapshot("cap-parent")],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let verified = verify_capability_pure(input, &clock).expect("verify delegated token");

        assert_eq!(verified.id, "cap-child");
    }

    #[test]
    fn verify_capability_pure_rejects_oversubscribed_delegated_sibling() {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
        let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);

        let input = VerifyCapabilityRequestJson {
            token: capability,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            peer_capabilities: None,
            capability_trust_roots,
            parent_budget_snapshots: std::vec![oversubscribed_budget_snapshot("cap-parent")],
        };
        let clock = FixedClock::new(ISSUED_AT + 1);

        let err = verify_capability_pure(input, &clock)
            .expect_err("oversubscribed sibling must be rejected");

        assert_eq!(err.code, "capability_verification_failed");
        assert!(err.message.contains("sibling-sum budget split"));
    }

    #[test]
    fn sign_receipt_pure_round_trip() {
        let seed = [1u8; 32];
        let body = ChioReceiptBody {
            id: "rcpt-1".to_string(),
            timestamp: ISSUED_AT,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: std::vec![],
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: std::vec![],
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            // Placeholder; sign_receipt_pure replaces this with the seed's public key.
            kernel_key: Keypair::generate().public_key(),
        };

        let receipt =
            sign_receipt_pure(SignReceiptRequestJson { body }, &seed).expect("sign_receipt_pure");
        assert!(receipt.verify_signature().unwrap());

        let seed_pubkey = Keypair::from_seed(&seed).public_key();
        assert_eq!(receipt.kernel_key, seed_pubkey);
    }

    #[test]
    fn sign_receipt_pure_refuses_zero_seed() {
        let seed = [0u8; 32];
        let body = ChioReceiptBody {
            id: "rcpt-1".to_string(),
            timestamp: ISSUED_AT,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: std::vec![],
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: std::vec![],
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: Keypair::generate().public_key(),
        };

        let err = sign_receipt_pure(SignReceiptRequestJson { body }, &seed)
            .expect_err("must refuse zero seed");
        assert_eq!(err.code, "weak_entropy");
    }

    #[test]
    fn decode_seed_hex_round_trip() {
        let bytes = [0xa5u8; 32];
        let hex_encoded = hex_encode_lower(&bytes);
        let decoded = decode_seed_hex(&hex_encoded).expect("decode");
        assert_eq!(decoded, bytes);

        let with_prefix = std::format!("0x{}", hex_encoded);
        let decoded_prefixed = decode_seed_hex(&with_prefix).expect("decode prefixed");
        assert_eq!(decoded_prefixed, bytes);
    }

    #[test]
    fn decode_seed_hex_rejects_wrong_length() {
        let err = decode_seed_hex("deadbeef").expect_err("must reject short input");
        assert_eq!(err.code, "invalid_seed_hex");
    }

    #[test]
    fn parse_authority_input_accepts_single_and_array() {
        let single = parse_authority_input("deadbeef").expect("single");
        assert_eq!(single, std::vec!["deadbeef".to_string()]);

        let multi = parse_authority_input("[\"aa\",\"bb\"]").expect("array");
        assert_eq!(multi, std::vec!["aa".to_string(), "bb".to_string()]);

        assert!(parse_authority_input("").is_err());
    }

    #[test]
    fn parse_authority_input_rejects_empty_array() {
        let result = parse_authority_input("[]");

        assert!(matches!(
            result,
            Err(BindingError { code, .. }) if code == "invalid_authority_input"
        ));
    }

    fn make_signed_receipt(seed: [u8; 32]) -> chio_core_types::receipt::ChioReceipt {
        let body = ChioReceiptBody {
            id: "rcpt-verify-pure".to_string(),
            timestamp: ISSUED_AT,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"msg": "verify"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: std::vec![],
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: std::vec![],
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: Keypair::generate().public_key(),
        };
        sign_receipt_pure(SignReceiptRequestJson { body }, &seed).unwrap()
    }

    #[test]
    fn verify_receipt_pure_signature_only_without_trust_pinning() {
        let receipt = make_signed_receipt([7u8; 32]);
        let envelope = serde_json::to_vec(&receipt).unwrap();

        let result = verify_receipt_pure(&envelope, &[]).expect("verify_receipt_pure");
        assert!(!result.ok);
        assert!(result.signature_valid);
        assert!(result.parameter_hash_valid);
        assert!(!result.signer_trusted);
        assert_eq!(result.decision, "allow");
        assert_eq!(result.receipt_id.len(), 64);
        assert!(result
            .receipt_id
            .chars()
            .all(|value| value.is_ascii_hexdigit()));
        assert!(result.receipt_id_valid);
        assert_eq!(result.receipt_kind, "mediated_decision");
        assert_eq!(result.boundary_class, "prevent");
        assert_eq!(result.result, "Authorized");
        assert!(!result.authorized);
        assert_eq!(result.signer_key_hex, receipt.kernel_key.to_hex());
    }

    #[test]
    fn verify_receipt_pure_allow_path_with_pinned_trusted_signer() {
        let receipt = make_signed_receipt([9u8; 32]);
        let envelope = serde_json::to_vec(&receipt).unwrap();

        let result = verify_receipt_pure(&envelope, core::slice::from_ref(&receipt.kernel_key))
            .expect("verify_receipt_pure");
        assert!(result.ok);
        assert!(result.signer_trusted);
        assert!(result.authorized);
    }

    #[test]
    fn verify_receipt_pure_rejects_untrusted_signer() {
        let receipt = make_signed_receipt([11u8; 32]);
        let envelope = serde_json::to_vec(&receipt).unwrap();
        let other = Keypair::generate().public_key();

        let result = verify_receipt_pure(&envelope, std::slice::from_ref(&other))
            .expect("verify_receipt_pure");
        assert!(!result.ok);
        assert!(result.signature_valid);
        assert!(!result.signer_trusted);
    }

    #[test]
    fn verify_receipt_pure_rejects_tampered_signature() {
        let receipt = make_signed_receipt([13u8; 32]);
        let mut envelope: serde_json::Value = serde_json::to_value(&receipt).unwrap();
        // Flip the first hex character of the signature so the math fails.
        let sig = envelope["signature"].as_str().unwrap().to_string();
        let mut tampered = sig.clone();
        let first = if tampered.as_bytes()[0] == b'a' {
            '0'
        } else {
            'a'
        };
        tampered.replace_range(0..1, &first.to_string());
        envelope["signature"] = serde_json::Value::String(tampered);
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let result = verify_receipt_pure(&bytes, &[]).expect("verify_receipt_pure");
        assert!(!result.ok);
        assert!(!result.signature_valid);
    }

    #[test]
    fn verify_receipt_pure_rejects_malformed_envelope() {
        let err = verify_receipt_pure(b"not a receipt", &[])
            .expect_err("malformed envelope must surface as an error");
        assert_eq!(err.code, "invalid_receipt_envelope");
    }
}
