//! Issuer-side capability signing.
//!
//! The mint path takes the canonical-JSON encoding of an unsigned
//! [`PasskeyCapability`] (the envelope with `signature = ""`) and detaches a
//! signature over those exact bytes via a `chio_core_types::SigningBackend`.
//! The resulting hex-encoded signature is written into the capability's
//! `signature` field; the rest of the envelope is byte-identical to the
//! pre-signed form, so the kernel-side verifier can reconstruct the message
//! by clearing `signature` to `""` before re-canonicalising.
//!
//! # Crypto floor
//!
//! `crypto_floor=allow_classical` MUST preserve byte-identity with
//! classical signatures. The mint path is generic over `SigningBackend`,
//! so the same call site works with:
//!
//! - [`chio_core_types::crypto::Ed25519Backend`] (default classical),
//! - the FIPS-gated P-256 / P-384 backends, and
//! - [`chio_core_types::pq::HybridBackend`] (gated on the `pq` feature).
//!
//! The unsigned canonical envelope is identical across modes; only the bytes
//! the `signature` slot ultimately holds differ.
//!
//! # Trust contract
//!
//! - The signed capability MUST be produced from the canonical-JSON bytes of
//!   the envelope WITH `signature = ""`. Verifiers reconstruct the message
//!   the same way.
//! - Empty signatures NEVER verify. The signing function refuses to return
//!   `Ok(_)` with an empty signature; the kernel verifier refuses to accept
//!   any capability whose `signature` is empty.

use chio_core_types::crypto::SigningBackend;

use crate::capability::PasskeyCapability;
use crate::error::CustodyError;

/// Sign `capability` in place using `backend`, replacing its `signature`
/// field with the hex-encoded detached signature over the canonical-JSON
/// bytes of the envelope (with `signature = ""`).
///
/// Fail-closed: any encoding or signing failure returns
/// [`CustodyError::Encoding`]. The function refuses to return `Ok(_)` if the
/// backend produces an empty signature.
pub fn sign_capability(
    capability: &mut PasskeyCapability,
    backend: &dyn SigningBackend,
) -> Result<(), CustodyError> {
    // Canonical bytes are computed over the unsigned envelope. Clearing the
    // signature slot ensures resigning a previously-signed capability does
    // not embed the old signature in the message.
    capability.signature = String::new();
    let canonical = capability.to_canonical_json()?;

    let signature = backend
        .sign_bytes(&canonical)
        .map_err(|err| CustodyError::Encoding(format!("issuer sign_bytes failed: {err}")))?;

    let hex = signature.to_hex();
    if hex.is_empty() {
        return Err(CustodyError::Encoding(
            "issuer signing backend returned empty signature".into(),
        ));
    }
    capability.signature = hex;
    Ok(())
}

/// Reconstruct the canonical-JSON message that was signed for `capability`.
///
/// This is the inverse of [`sign_capability`]'s message construction step.
/// Verifiers call this to recover the bytes covered by the detached
/// signature.
pub fn signing_message(capability: &PasskeyCapability) -> Result<Vec<u8>, CustodyError> {
    let mut shadow = capability.clone();
    shadow.signature = String::new();
    shadow.to_canonical_json()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::ScopeSet;
    use chio_core_types::crypto::{Ed25519Backend, Keypair};
    use chrono::{TimeZone, Utc};

    fn fixed_iat() -> chrono::DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 29, 0, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_iat fixture must construct"),
        }
    }

    fn fixture_cap() -> PasskeyCapability {
        PasskeyCapability::new_stub_unsigned(
            "urn:chio:audience:kernel",
            "AAAA",
            ScopeSet::new(["tool:read", "tool:write"]),
            "nonce-1",
            fixed_iat(),
        )
    }

    #[test]
    fn sign_capability_populates_signature_with_ed25519_backend() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[7u8; 32]));
        let mut cap = fixture_cap();
        assert_eq!(cap.signature, "");
        if let Err(e) = sign_capability(&mut cap, &backend) {
            panic!("sign must succeed: {e}");
        }
        assert!(
            !cap.signature.is_empty(),
            "signed capability must carry a signature"
        );
    }

    #[test]
    fn signing_message_clears_signature_slot_for_byte_stability() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[7u8; 32]));
        let mut cap = fixture_cap();
        let pre = match signing_message(&cap) {
            Ok(b) => b,
            Err(e) => panic!("pre signing_message must encode: {e}"),
        };
        if let Err(e) = sign_capability(&mut cap, &backend) {
            panic!("sign must succeed: {e}");
        }
        let post = match signing_message(&cap) {
            Ok(b) => b,
            Err(e) => panic!("post signing_message must encode: {e}"),
        };
        assert_eq!(
            pre, post,
            "signing message must be invariant to whether `signature` is populated"
        );
    }

    #[test]
    fn resigning_overwrites_prior_signature() {
        let backend_a = Ed25519Backend::new(Keypair::from_seed(&[1u8; 32]));
        let backend_b = Ed25519Backend::new(Keypair::from_seed(&[2u8; 32]));
        let mut cap = fixture_cap();
        if let Err(e) = sign_capability(&mut cap, &backend_a) {
            panic!("first sign must succeed: {e}");
        }
        let first = cap.signature.clone();
        if let Err(e) = sign_capability(&mut cap, &backend_b) {
            panic!("second sign must succeed: {e}");
        }
        assert_ne!(first, cap.signature, "resign must overwrite, not append");
    }
}
