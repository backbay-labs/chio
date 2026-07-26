//! Browser entry points. Compiled only for `wasm32-*` targets so the
//! host `cargo test -p chio-kernel-browser` can still run without a
//! wasm toolchain.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use chio_core_types::capability::{features::CapabilityNegotiation, token::CapabilityToken};
use chio_kernel_core::Rng as _;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::pure::{
    decode_seed_hex, decode_trusted_issuers, evaluate_pure, hex_encode_lower,
    parse_authority_input, sign_receipt_pure, sign_receipt_relaying_trusted_body_pure,
    verify_capability_pure, verify_receipt_pure,
};
use crate::wire::{
    BindingError, EvaluateRequestJson, SignReceiptRequestJson, VerifyCapabilityRequestJson,
};
use crate::{BrowserClock, WebCryptoRng};

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
/// returns an [`crate::EvaluationVerdictJson`]. The underlying
/// `chio_kernel_core::evaluate` runs with an empty guard pipeline. Browser
/// evaluations today target offline-capability checks; a capability-only
/// success is therefore downgraded to `pending_approval` instead of
/// authoritative `allow`.
#[wasm_bindgen]
pub fn evaluate(request_json: &str) -> Result<JsValue, JsValue> {
    let request: EvaluateRequestJson = parse_json("evaluate request", request_json)?;
    let clock = BrowserClock::new();
    let verdict = evaluate_pure(request, &clock).map_err(|err| to_js_error(&err))?;
    encode_result(&verdict)
}

/// Sign a receipt body (PUBLIC WYSIWYS signer; fail-closed).
///
/// The `signing_seed_hex` parameter carries a 32-byte Ed25519 seed
/// as lowercase hex (optionally `0x`-prefixed). Callers that want
/// the browser to mint a fresh seed per receipt should call
/// [`mint_signing_seed_hex`] first and pass the result in here.
///
/// WYSIWYS: the JSON body MUST include the `canonical_content`
/// preimage so the signer recomputes `content_hash` inside the trust boundary
/// and refuses on mismatch. A body without `canonical_content` is refused; it
/// does NOT silently relay a trusted body. Callers that only forward an
/// upstream-minted body through the relay seam must call
/// [`sign_receipt_relaying_trusted_body`].
#[wasm_bindgen]
pub fn sign_receipt(body_json: &str, signing_seed_hex: &str) -> Result<JsValue, JsValue> {
    let input: SignReceiptRequestJson = parse_json("sign_receipt body", body_json)?;
    let seed = decode_seed_hex(signing_seed_hex).map_err(|err| to_js_error(&err))?;
    let receipt = sign_receipt_pure(input, &seed).map_err(|err| to_js_error(&err))?;
    encode_result(&receipt)
}

/// Relay-sign an already-minted, upstream-trusted receipt body.
///
/// This is NOT the default public signer. It trusts the caller-supplied
/// `content_hash` and does not recompute it, so it must only be used to forward
/// a body an upstream trusted producer already minted (where the WYSIWYS
/// recompute already ran). Content-bearing callers that construct receipts at
/// the boundary MUST use [`sign_receipt`] instead so the recompute gate runs.
#[wasm_bindgen]
pub fn sign_receipt_relaying_trusted_body(
    body_json: &str,
    signing_seed_hex: &str,
) -> Result<JsValue, JsValue> {
    let input: SignReceiptRequestJson =
        parse_json("sign_receipt_relaying_trusted_body body", body_json)?;
    let seed = decode_seed_hex(signing_seed_hex).map_err(|err| to_js_error(&err))?;
    let receipt =
        sign_receipt_relaying_trusted_body_pure(input, &seed).map_err(|err| to_js_error(&err))?;
    encode_result(&receipt)
}

/// Verify a capability token against a trusted issuer set.
///
/// `authority_pub_hex` may be either a single hex-encoded key or a
/// JSON array of hex-encoded keys. The single-key form is the common
/// case so we branch on the first character.
#[wasm_bindgen]
pub fn verify_capability(token_json: &str, authority_pub_hex: &str) -> Result<JsValue, JsValue> {
    let trusted_issuers_hex =
        parse_authority_input(authority_pub_hex).map_err(|err| to_js_error(&err))?;
    let token = parse_json::<CapabilityToken>("verify_capability token", token_json)?;
    let request = VerifyCapabilityRequestJson {
        token,
        trusted_issuers_hex,
        clock_override_unix_secs: None,
        peer_capabilities: Some(CapabilityNegotiation::t1_default()),
        direct_root_capability: None,
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
/// tokens. The [`verify_capability`] helper remains available for
/// single-authority v1 checks.
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
/// `envelope` is the canonical-JSON serialization of a `ChioReceipt`.
/// `trusted_issuers` is a JS value that the browser caller may pass as:
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

fn parse_trusted_issuers_jsvalue(value: &JsValue) -> Result<Vec<String>, JsValue> {
    if value.is_undefined() || value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(single) = value.as_string() {
        return Ok(alloc::vec![single]);
    }
    serde_wasm_bindgen::from_value::<Vec<String>>(value.clone()).map_err(|error| {
        to_js_error(&BindingError::new(
            "invalid_trusted_issuers",
            format!(
                "trusted_issuers must be undefined, a hex string, or an array of hex strings: {error}"
            ),
        ))
    })
}

/// Mint a fresh 32-byte signing seed using the browser's Web Crypto RNG
/// and return it as lowercase hex. Surfaces entropy-source failures as
/// structured errors instead of silently returning a zero-filled seed.
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
