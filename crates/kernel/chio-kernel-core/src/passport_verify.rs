//! Portable passport verification.
//!
//! This module is the "the WASM-compiled kernel verifies the passport"
//! surface. It is pure compute over a minimal portable passport
//! envelope: given bytes on the wire, a trusted authority key set, and a
//! clock, it answers "is this envelope signed by a trusted authority,
//! well-formed, and currently inside its validity window?".
//!
//! # Scope (what this module does NOT do)
//!
//! The native `chio-credentials` crate owns the full passport format
//! (embedded reputation credentials, merkle roots, enterprise identity
//! provenance, issuer-chain validation, cross-issuer portfolios,
//! lifecycle resolution). None of that lives in `chio-kernel-core`:
//! `chio-credentials` pulls `std`, `chrono`, and `chio-reputation`, which
//! would break the `no_std + alloc` posture of this crate.
//!
//! What `passport_verify` offers instead is the thin trust primitive the
//! portable kernel actually needs at runtime: a signed wire envelope
//! that a browser / mobile / edge adapter can verify offline with the
//! same cryptographic path the native sidecar uses. The envelope wraps
//! an arbitrary JSON payload, so adapters can attach whatever passport
//! shape they want and still reuse the same pure-compute verify.
//!
//! # `no_std` status
//!
//! This module imports only `chio_core_types::crypto::PublicKey` /
//! `Signature` / `canonical_json_bytes` and the kernel-core
//! [`Clock`](crate::clock::Clock) trait. It contains zero `std::*`
//! imports. It participates in the same scripted portability proof as the
//! rest of `chio-kernel-core`: host plus `wasm32-unknown-unknown` builds with
//! `--no-default-features` via `scripts/check-portable-kernel.sh`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{PublicKey, Signature};

use crate::clock::Clock;

/// Schema tag for the portable passport envelope. Versioned so future
/// envelope shapes can evolve without breaking older verifiers.
pub const PORTABLE_PASSPORT_SCHEMA: &str = "chio.portable-agent-passport.v1";

/// Body of a portable passport envelope.
///
/// The `payload_canonical_bytes` field carries the opaque canonical-JSON
/// serialization of the native passport (or any projection of it) that
/// the envelope authenticates. Keeping the payload as a byte blob means
/// verification is independent of the passport schema the adapter uses
/// on top -- relying parties only need to know they received bytes
/// signed by a trusted issuer inside the validity window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortablePassportBody {
    /// Schema identifier; must equal [`PORTABLE_PASSPORT_SCHEMA`].
    pub schema: String,
    /// Subject identifier (typically the agent DID) the passport binds to.
    pub subject: String,
    /// Issuer public key that signed this envelope.
    pub issuer: PublicKey,
    /// Unix timestamp (seconds) the envelope was issued at.
    pub issued_at: u64,
    /// Unix timestamp (seconds) the envelope expires at.
    pub expires_at: u64,
    /// Canonical-JSON bytes of the authenticated payload.
    #[serde(with = "payload_bytes_hex")]
    pub payload_canonical_bytes: Vec<u8>,
}

/// Signed portable passport envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortablePassportEnvelope {
    pub body: PortablePassportBody,
    pub signature: Signature,
}

/// The subset of a verified portable passport that callers actually
/// need downstream. Mirrors [`crate::VerifiedCapability`] in shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPassport {
    /// Subject identifier the envelope binds to.
    pub subject: String,
    /// Issuer public key that signed the envelope.
    pub issuer: PublicKey,
    /// Unix timestamp the envelope was issued at.
    pub issued_at: u64,
    /// Unix timestamp the envelope expires at.
    pub expires_at: u64,
    /// Clock value at which verification succeeded.
    pub evaluated_at: u64,
    /// Canonical-JSON bytes of the authenticated payload (caller may
    /// decode these into the native `AgentPassport` or any other
    /// projection downstream).
    pub payload_canonical_bytes: Vec<u8>,
}

/// Errors raised by [`verify_passport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Envelope bytes could not be parsed as a signed portable passport.
    InvalidEnvelope(String),
    /// Envelope schema tag did not equal [`PORTABLE_PASSPORT_SCHEMA`].
    InvalidSchema,
    /// Subject field was empty.
    MissingSubject,
    /// `issued_at` is strictly greater than `expires_at`.
    InvalidValidityWindow,
    /// Issuer public key is not in the trusted authority set.
    UntrustedIssuer,
    /// Canonical-JSON signature did not verify against the issuer key.
    InvalidSignature,
    /// Envelope is not yet valid (clock is before `issued_at`).
    NotYetValid,
    /// Envelope has expired (clock is at or after `expires_at`).
    Expired,
    /// Internal canonical-JSON failure while re-hashing the envelope body.
    Internal(String),
}

/// Verify a portable passport envelope.
///
/// Performs four checks:
/// 1. `envelope_bytes` parses as a [`PortablePassportEnvelope`].
/// 2. The issuer is in `authority_keys`.
/// 3. The envelope signature is valid over the canonical-JSON form of
///    its body.
/// 4. The current time (from `clock`) is within
///    `[issued_at, expires_at)`.
///
/// On success returns a [`VerifiedPassport`] snapshot. This is
/// deliberately pure: there is no revocation lookup, no payload
/// decoding, and no issuer-chain validation. Those stay in the native
/// `chio-credentials` / `chio-kernel` path.
pub fn verify_passport(
    envelope_bytes: &[u8],
    authority_keys: &[PublicKey],
    clock: &dyn Clock,
) -> Result<VerifiedPassport, VerifyError> {
    let envelope: PortablePassportEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|error| VerifyError::InvalidEnvelope(error.to_string()))?;
    verify_parsed_passport(&envelope, authority_keys, clock)
}

/// Verify an already-parsed portable passport envelope. Useful for
/// adapters that materialize the envelope from a non-JSON transport
/// (CBOR, protobuf, etc.) before handing it to the kernel core.
pub fn verify_parsed_passport(
    envelope: &PortablePassportEnvelope,
    authority_keys: &[PublicKey],
    clock: &dyn Clock,
) -> Result<VerifiedPassport, VerifyError> {
    if envelope.body.schema != PORTABLE_PASSPORT_SCHEMA {
        return Err(VerifyError::InvalidSchema);
    }
    if envelope.body.subject.is_empty() {
        return Err(VerifyError::MissingSubject);
    }
    if envelope.body.issued_at > envelope.body.expires_at {
        return Err(VerifyError::InvalidValidityWindow);
    }
    if !authority_keys.contains(&envelope.body.issuer) {
        return Err(VerifyError::UntrustedIssuer);
    }

    let body_bytes = canonical_json_bytes(&envelope.body)
        .map_err(|error| VerifyError::Internal(error.to_string()))?;
    if !envelope
        .body
        .issuer
        .verify(&body_bytes, &envelope.signature)
    {
        return Err(VerifyError::InvalidSignature);
    }

    let now = clock.now_unix_secs();
    if now < envelope.body.issued_at {
        return Err(VerifyError::NotYetValid);
    }
    if now >= envelope.body.expires_at {
        return Err(VerifyError::Expired);
    }

    Ok(VerifiedPassport {
        subject: envelope.body.subject.clone(),
        issuer: envelope.body.issuer.clone(),
        issued_at: envelope.body.issued_at,
        expires_at: envelope.body.expires_at,
        evaluated_at: now,
        payload_canonical_bytes: envelope.body.payload_canonical_bytes.clone(),
    })
}

/// Hex (de)serialization for the payload byte blob. JSON can't carry a
/// raw `Vec<u8>` round-trippably, and Chio already uses lowercase hex
/// for `Signature` / `PublicKey` wire encoding, so the envelope payload
/// follows the same convention.
mod payload_bytes_hex {
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        encode_hex(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        decode_hex(&hex_str).map_err(serde::de::Error::custom)
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let hi = NIBBLES[(byte >> 4) as usize];
            let lo = NIBBLES[(byte & 0x0f) as usize];
            out.push(hi);
            out.push(lo);
        }
        out
    }

    fn decode_hex(hex_str: &str) -> Result<Vec<u8>, &'static str> {
        if !hex_str.len().is_multiple_of(2) {
            return Err("odd-length hex string");
        }
        let bytes_in = hex_str.as_bytes();
        let mut out = Vec::with_capacity(bytes_in.len() / 2);
        let mut idx = 0;
        while idx < bytes_in.len() {
            let hi = from_hex_nibble(bytes_in[idx])?;
            let lo = from_hex_nibble(bytes_in[idx + 1])?;
            out.push((hi << 4) | lo);
            idx += 2;
        }
        Ok(out)
    }

    const NIBBLES: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    fn from_hex_nibble(byte: u8) -> Result<u8, &'static str> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}
