//! Apple App Attest verifier.
//!
//! P2 accepts a compact CBOR map fixture shape that mirrors the fields
//! Chio consumes from Apple's WebAuthn-style App Attest object. Real
//! device fixtures land later in the milestone, but this verifier is
//! already fail-closed on CBOR shape, app binding, challenge binding,
//! key binding, and the pinned Apple App Attestation root fingerprint.

use coset::cbor::Value as CborValue;
use sha2::{Digest, Sha256};

use super::apple_root::{validate_pinned_apple_root, APPLE_APP_ATTEST_ROOT_SHA256};
use super::errors::AttestationError;

pub const APP_ATTEST_FORMAT: &str = "apple-appattest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestVerificationInput<'a> {
    pub attestation_cbor: &'a [u8],
    pub key_id: &'a str,
    pub challenge: &'a [u8],
    pub app_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAppAttest {
    pub key_id: String,
    pub app_id: String,
    pub app_id_hash_hex: String,
    pub challenge_hash_hex: String,
    pub root_fingerprint_sha256_hex: String,
    pub credential_public_key_sha256_hex: String,
}

pub fn verify_app_attest(
    input: AppAttestVerificationInput<'_>,
) -> Result<VerifiedAppAttest, AttestationError> {
    validate_pinned_apple_root()?;

    let value: CborValue = coset::cbor::de::from_reader(input.attestation_cbor)
        .map_err(|error| AttestationError::InvalidCbor(format!("attestation object: {error}")))?;
    let map = match value {
        CborValue::Map(map) => map,
        _ => {
            return Err(AttestationError::InvalidCbor(
                "attestation object is not a CBOR map".to_string(),
            ))
        }
    };

    let format = text_field(&map, "format")?;
    if format != APP_ATTEST_FORMAT {
        return Err(AttestationError::UnsupportedFormat(format.to_string()));
    }

    let key_id = text_field(&map, "key_id")?;
    if key_id != input.key_id {
        return Err(AttestationError::KeyIdMismatch);
    }

    let app_id_hash = bytes_field(&map, "app_id_hash")?;
    let expected_app_hash = sha256(input.app_id.as_bytes());
    if app_id_hash != expected_app_hash {
        return Err(AttestationError::AppIdentifierMismatch);
    }

    let challenge_hash = bytes_field(&map, "challenge_hash")?;
    let expected_challenge_hash = sha256(input.challenge);
    if challenge_hash != expected_challenge_hash {
        return Err(AttestationError::ChallengeMismatch);
    }

    let root_fingerprint = bytes_field(&map, "root_fingerprint_sha256")?;
    if root_fingerprint != APPLE_APP_ATTEST_ROOT_SHA256 {
        return Err(AttestationError::InvalidRoot(
            "attestation root fingerprint mismatch".to_string(),
        ));
    }

    let credential_public_key = bytes_field(&map, "credential_public_key")?;
    if credential_public_key.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "credential_public_key must not be empty".to_string(),
        ));
    }

    Ok(VerifiedAppAttest {
        key_id: key_id.to_string(),
        app_id: input.app_id.to_string(),
        app_id_hash_hex: hex::encode(app_id_hash),
        challenge_hash_hex: hex::encode(challenge_hash),
        root_fingerprint_sha256_hex: hex::encode(root_fingerprint),
        credential_public_key_sha256_hex: hex::encode(sha256(credential_public_key)),
    })
}

fn text_field<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Result<&'a str, AttestationError> {
    match field(map, name)? {
        CborValue::Text(value) => Ok(value.as_str()),
        _ => Err(AttestationError::InvalidCbor(format!(
            "{name} must be text"
        ))),
    }
}

fn bytes_field<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Result<&'a [u8], AttestationError> {
    match field(map, name)? {
        CborValue::Bytes(value) => Ok(value.as_slice()),
        _ => Err(AttestationError::InvalidCbor(format!(
            "{name} must be bytes"
        ))),
    }
}

fn field<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Result<&'a CborValue, AttestationError> {
    map.iter()
        .find_map(|(key, value)| match key {
            CborValue::Text(text) if text == name => Some(value),
            _ => None,
        })
        .ok_or(AttestationError::MissingField(name))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
