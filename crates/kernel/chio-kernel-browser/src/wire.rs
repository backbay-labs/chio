use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{
    attenuation::ScopeHash, features::CapabilityNegotiation, token::CapabilityToken,
};
use chio_core_types::receipt::body::ChioReceiptBody;
use chio_kernel_core::{PortableToolCallRequest, VerifiedCapability};
use serde::{Deserialize, Serialize};

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

/// Root envelope accepted by [`crate::evaluate_pure`] and the wasm entry.
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
    /// adapter reads `Date::now()` via [`crate::BrowserClock`]. Test
    /// harnesses use this to pin the clock for reproducible checks.
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

/// Wire shape for the result of [`crate::evaluate_pure`]. Flattens the
/// fields of [`chio_kernel_core::EvaluationVerdict`] so the JS caller can
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
    pub(crate) fn from_core(value: chio_kernel_core::EvaluationVerdict) -> Self {
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

/// Wire shape for [`crate::sign_receipt_pure`] inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignReceiptRequestJson {
    /// The receipt body to sign.
    pub body: ChioReceiptBody,

    /// The exact canonical content preimage `body.content_hash` was derived
    /// from, carried across the wasm-bindgen boundary as raw bytes (a JSON
    /// array of `u8`).
    ///
    /// WYSIWYS (BAC-539): the public signer `sign_receipt_pure` recomputes
    /// `sha256_hex(canonical_content)` inside the signer and refuses to sign
    /// when it disagrees with `body.content_hash`, so a browser/mobile caller
    /// can no longer render content A while signing a body claiming hash(B).
    /// This preimage is therefore REQUIRED for public signing: when it is
    /// absent (`None`), `sign_receipt_pure` fails closed with
    /// `canonical_content_required` and does NOT fall back to trusting
    /// `body.content_hash`. Callers that only forward an upstream-minted body
    /// and do not hold the preimage must instead call the explicitly named
    /// relay seam `sign_receipt_relaying_trusted_body_pure`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_content: Option<Vec<u8>>,
}

/// Wire shape for [`crate::verify_capability_pure`] inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCapabilityRequestJson {
    /// The capability token to verify.
    pub token: CapabilityToken,
    /// Trusted authority public keys, hex-encoded.
    pub trusted_issuers_hex: Vec<String>,
    /// Optional pinned unix-seconds clock override. When `None`, the
    /// adapter reads `Date::now()` via [`crate::BrowserClock`].
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

/// Wire shape for [`crate::verify_capability_pure`] outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedCapabilityJson {
    pub id: String,
    pub subject_hex: String,
    pub issuer_hex: String,
    pub scope: chio_core_types::capability::scope::ChioScope,
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

/// Wire shape for [`crate::verify_receipt_pure`] outputs.
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
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}
