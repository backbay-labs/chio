use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{attenuation::ScopeHash, features::CapabilityNegotiation};
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, SigningBackend};
use chio_core_types::receipt::{body::chio_receipt_id, body::ChioReceipt, decision::Decision};
use chio_kernel_core::{
    evaluate_with_full_floor as core_evaluate_with_full_floor, sign_receipt as core_sign_receipt,
    sign_receipt_relaying_trusted_body as core_relay_trusted_body, verify_capability_full,
    BudgetRegistry, BudgetSplitError, EvaluateInput, InMemoryBudgetRegistry,
    PortableToolCallRequest,
};

use crate::wire::{
    BindingError, EvaluateRequestJson, EvaluationVerdictJson, ParentBudgetSnapshotJson,
    SignReceiptRequestJson, VerifiedCapabilityJson, VerifyCapabilityRequestJson,
    VerifyReceiptResultJson,
};

/// Decode a list of hex-encoded public keys.
pub(crate) fn decode_trusted_issuers(hex_list: &[String]) -> Result<Vec<PublicKey>, BindingError> {
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
                chio_core_types::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical,
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
            chio_core_types::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical,
            &peer_profile,
            &trust_resolver,
            &mut budgets,
        ),
    };

    Ok(EvaluationVerdictJson::from_core(verdict))
}

/// Pure receipt-signing helper. Builds an `Ed25519Backend` from the supplied
/// seed (which the wasm binding mints via Web Crypto) and signs the body.
///
/// WYSIWYS (BAC-539): this is the PUBLIC browser-boundary signer, so it is
/// fail-closed. The caller MUST carry the canonical content preimage across the
/// wasm-bindgen boundary (`SignReceiptRequestJson::canonical_content`); the
/// signer then routes through the production recompute-and-refuse primitive
/// `chio_kernel_core::sign_receipt`, which recomputes
/// `sha256_hex(canonical_content)` *inside the signer* and refuses to sign when
/// it disagrees with `body.content_hash`. That closes the render-A / sign-B
/// forgery at the browser boundary: a caller can no longer show content A while
/// putting hash(B) in the body.
///
/// When the preimage is absent (`None`), this signer REFUSES (fail-closed)
/// instead of silently relaying a trusted body. The trusted-body relay is no
/// longer reachable through the default public signer; callers that genuinely
/// only forward an already-minted upstream body (the FFI/WASM relay seam tracked
/// under BAC-601) must call the explicitly named
/// [`sign_receipt_relaying_trusted_body_pure`] instead.
pub fn sign_receipt_pure(
    input: SignReceiptRequestJson,
    signing_seed: &[u8; 32],
) -> Result<chio_core_types::receipt::body::ChioReceipt, BindingError> {
    if signing_seed.iter().all(|byte| *byte == 0) {
        return Err(BindingError::new(
            "weak_entropy",
            "refusing to sign: Web Crypto returned a zero-filled seed (entropy source failed)",
        ));
    }

    // Fail-closed: the public signer requires the canonical content preimage so
    // the recompute-and-refuse gate can run. Without it we cannot prove the body
    // hashes what the human was shown, so we refuse rather than fall back to the
    // trusted-body relay (BAC-539 / round-3 review).
    let canonical_content = input.canonical_content.ok_or_else(|| {
        BindingError::new(
            "canonical_content_required",
            "refusing to sign: canonical content preimage is required for public WYSIWYS signing (use sign_receipt_relaying_trusted_body_pure for the trusted-upstream-body relay seam)",
        )
    })?;

    let keypair = Keypair::from_seed(signing_seed);
    let backend = Ed25519Backend::new(keypair);

    let mut body = input.body;
    body.kernel_key = backend.public_key();

    core_sign_receipt(body, &backend, &canonical_content)
        .map_err(|error| BindingError::new("receipt_signing_failed", format_signing(&error)))
}

/// Trusted-upstream-body relay signer (the BAC-601 seam), NOT the default public
/// signer.
///
/// This is the explicit, auditable forwarding path for callers that only relay
/// an already-minted upstream body and genuinely cannot carry the content
/// preimage. It trusts the caller-supplied `body.content_hash` and routes
/// through `chio_kernel_core::sign_receipt_relaying_trusted_body`, which does NOT
/// recompute `content_hash`. Because it cannot prove WYSIWYS, it must never be
/// the default public signer; content-bearing browser callers that construct
/// receipts at the boundary MUST use [`sign_receipt_pure`] so the recompute gate
/// runs.
pub fn sign_receipt_relaying_trusted_body_pure(
    input: SignReceiptRequestJson,
    signing_seed: &[u8; 32],
) -> Result<chio_core_types::receipt::body::ChioReceipt, BindingError> {
    if signing_seed.iter().all(|byte| *byte == 0) {
        return Err(BindingError::new(
            "weak_entropy",
            "refusing to sign: Web Crypto returned a zero-filled seed (entropy source failed)",
        ));
    }

    let keypair = Keypair::from_seed(signing_seed);
    let backend = Ed25519Backend::new(keypair);

    let mut body = input.body;
    body.kernel_key = backend.public_key();

    core_relay_trusted_body(body, &backend)
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
    let crypto_floor =
        chio_core_types::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical;
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

fn format_signing(error: &chio_kernel_core::ReceiptSigningError) -> String {
    match error {
        chio_kernel_core::ReceiptSigningError::KernelKeyMismatch => {
            "receipt body kernel_key does not match the signing backend".to_string()
        }
        // WYSIWYS mismatch (BAC-539). When the browser caller carries the
        // canonical content preimage (`SignReceiptRequestJson::canonical_content`),
        // `sign_receipt_pure` routes through `chio_kernel_core::sign_receipt`,
        // which recomputes `content_hash` inside the signer and produces this
        // variant on a render-A / sign-B mismatch. Surfaced as a distinct,
        // fail-closed error string. Callers using the trusted-relay seam with no
        // preimage will never reach this arm.
        chio_kernel_core::ReceiptSigningError::ContentHashMismatch {
            recomputed,
            claimed,
        } => {
            format!(
                "receipt content_hash mismatch: body claimed {claimed} but signer recomputed {recomputed} over the canonical content (WYSIWYS refused)"
            )
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

/// Parse either a single hex-encoded authority key or a JSON array of
/// hex keys.
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
