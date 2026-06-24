//! Apple App Attest verifier.
//!
//! The production path accepts Apple's WebAuthn-style attestation object:
//! `fmt`, `authData`, and `attStmt.x5c`. It validates the certificate
//! chain to the pinned Apple App Attestation root, binds the server
//! challenge through Apple's nonce extension, checks the app id hash,
//! binds the attestation leaf public key to the credential public key in
//! `authData` (WebAuthn registration step 6), enforces counter
//! monotonicity when the caller supplies a prior counter, and requires the
//! credential id to match the platform key id.
//!
//! Production callers set [`AppAttestVerificationInput::production`] so that
//! the sandbox and development App Attest AAGUIDs are rejected: only the
//! production environment AAGUID is honoured in a shipped build.
//!
//! Synthetic fixtures (the compact-map development shape) are compiled out
//! of production binaries entirely. They exist only under `cfg(test)` or
//! the `dev-fixtures` feature, and even then the caller must additionally
//! set `allow_development_fixture`. In a build without that cfg the
//! development path is unreachable and fails closed.

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use coset::cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::apple_root::{
    apple_app_attest_root_der, validate_pinned_apple_root, APPLE_APP_ATTEST_ROOT_SHA256,
};
use super::errors::AttestationError;

pub const APP_ATTEST_FORMAT: &str = "apple-appattest";
const APP_ATTEST_NONCE_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";
const AUTH_DATA_HEADER_LEN: usize = 37;
const AAGUID_LEN: usize = 16;
const CREDENTIAL_ID_LEN_BYTES: usize = 2;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const APP_ATTEST_PRODUCTION_AAGUID: &[u8; AAGUID_LEN] = b"appattest\0\0\0\0\0\0\0";
const APP_ATTEST_SANDBOX_AAGUID: &[u8; AAGUID_LEN] = b"appattestsandbox";
const APP_ATTEST_DEVELOPMENT_AAGUID: &[u8; AAGUID_LEN] = b"appattestdevelop";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestVerificationInput<'a> {
    pub attestation_cbor: &'a [u8],
    pub key_id: &'a str,
    pub challenge: &'a [u8],
    pub app_id: &'a str,
    pub previous_counter: Option<u32>,
    /// When `true`, only the production App Attest AAGUID is accepted; the
    /// sandbox and development AAGUIDs are rejected. Shipped callers set
    /// this so a sandbox-attested key cannot be presented as production
    /// custody evidence.
    ///
    /// SECURITY (BAC-601, should-fix): this is a *runtime-only* switch with no
    /// `cfg` backstop. A prod binary that constructs this input with
    /// `production: false` re-enables the sandbox/development AAGUIDs at
    /// runtime - there is no compile-time guarantee that shipped callers pass
    /// `true`. Production entry points should hard-code `production: true` (or
    /// wrap construction in a hardened constructor) rather than threading the
    /// flag through from request data. Tracked for hardening under BAC-601.
    pub production: bool,
    /// Opt-in for the synthetic development-fixture compact-map shape.
    /// This only has any effect when the crate is compiled with the
    /// `dev-fixtures` feature or under `cfg(test)`; in a production build
    /// the development path does not exist and the flag is ignored
    /// (fails closed).
    pub allow_development_fixture: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAppAttest {
    pub key_id: String,
    pub app_id: String,
    pub counter: u32,
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

    if field_optional(&map, "fmt").is_some() {
        return verify_webauthn_app_attest(input, &map);
    }

    verify_compact_map(input, &map)
}

/// Dispatch the non-WebAuthn (compact-map) attestation shape.
///
/// In production builds the development fixture does not exist, so any
/// attestation object lacking the WebAuthn `fmt` field is rejected. The
/// fixture path is only linked under `cfg(test)` or the `dev-fixtures`
/// feature, and even then requires `allow_development_fixture`.
#[cfg(any(test, feature = "dev-fixtures"))]
fn verify_compact_map(
    input: AppAttestVerificationInput<'_>,
    map: &[(CborValue, CborValue)],
) -> Result<VerifiedAppAttest, AttestationError> {
    verify_development_fixture(input, map)
}

#[cfg(not(any(test, feature = "dev-fixtures")))]
fn verify_compact_map(
    _input: AppAttestVerificationInput<'_>,
    _map: &[(CborValue, CborValue)],
) -> Result<VerifiedAppAttest, AttestationError> {
    Err(AttestationError::InvalidCbor(
        "attestation object is missing the WebAuthn fmt field; the development \
         fixture path is not available in production builds"
            .to_string(),
    ))
}

fn verify_webauthn_app_attest(
    input: AppAttestVerificationInput<'_>,
    map: &[(CborValue, CborValue)],
) -> Result<VerifiedAppAttest, AttestationError> {
    let format = text_field(map, "fmt")?;
    if format != APP_ATTEST_FORMAT {
        return Err(AttestationError::UnsupportedFormat(format.to_string()));
    }

    let auth_data = bytes_field(map, "authData")?;
    let parsed_auth_data = parse_auth_data(auth_data, input.production)?;
    let expected_app_hash = sha256(input.app_id.as_bytes());
    if parsed_auth_data.app_id_hash != expected_app_hash {
        return Err(AttestationError::AppIdentifierMismatch);
    }
    enforce_attestation_counter(input.previous_counter, parsed_auth_data.counter)?;
    let key_id_bytes = decode_key_id(input.key_id)?;
    if key_id_bytes != parsed_auth_data.credential_id {
        return Err(AttestationError::KeyIdMismatch);
    }
    let credential_key_point = parse_cose_ec2_point(parsed_auth_data.credential_public_key)?;

    let challenge_hash = sha256(input.challenge);
    let expected_nonce = apple_nonce(auth_data, &challenge_hash);
    let att_stmt = map_field(map, "attStmt")?;
    let cert_chain = x5c_field(att_stmt)?;
    let leaf_point = validate_apple_cert_chain(&cert_chain, &expected_nonce)?;

    // WebAuthn registration step 6: the attestation leaf certificate's
    // public key MUST match the credential public key in authData.
    // Without this binding an attacker could wrap a legitimately
    // Apple-signed attestation cert around an attacker-chosen credential
    // key. The comparison is on the raw EC point (X || Y).
    if leaf_point != credential_key_point {
        return Err(AttestationError::CredentialKeyMismatch);
    }

    Ok(VerifiedAppAttest {
        key_id: input.key_id.to_string(),
        app_id: input.app_id.to_string(),
        counter: parsed_auth_data.counter,
        app_id_hash_hex: hex::encode(parsed_auth_data.app_id_hash),
        challenge_hash_hex: hex::encode(challenge_hash),
        root_fingerprint_sha256_hex: hex::encode(APPLE_APP_ATTEST_ROOT_SHA256),
        credential_public_key_sha256_hex: hex::encode(sha256(
            parsed_auth_data.credential_public_key,
        )),
    })
}

#[cfg(any(test, feature = "dev-fixtures"))]
fn verify_development_fixture(
    input: AppAttestVerificationInput<'_>,
    map: &[(CborValue, CborValue)],
) -> Result<VerifiedAppAttest, AttestationError> {
    if input.production {
        return Err(AttestationError::InvalidCbor(
            "development fixture format is rejected in production".to_string(),
        ));
    }
    if !input.allow_development_fixture {
        return Err(AttestationError::InvalidCbor(
            "development fixture format is disabled".to_string(),
        ));
    }

    let format = text_field(map, "format")?;
    if format != APP_ATTEST_FORMAT {
        return Err(AttestationError::UnsupportedFormat(format.to_string()));
    }

    let key_id = text_field(map, "key_id")?;
    if key_id != input.key_id {
        return Err(AttestationError::KeyIdMismatch);
    }

    let app_id_hash = bytes_field(map, "app_id_hash")?;
    let expected_app_hash = sha256(input.app_id.as_bytes());
    if app_id_hash != expected_app_hash {
        return Err(AttestationError::AppIdentifierMismatch);
    }

    let challenge_hash = bytes_field(map, "challenge_hash")?;
    let expected_challenge_hash = sha256(input.challenge);
    if challenge_hash != expected_challenge_hash {
        return Err(AttestationError::ChallengeMismatch);
    }

    let root_fingerprint = bytes_field(map, "root_fingerprint_sha256")?;
    if root_fingerprint != APPLE_APP_ATTEST_ROOT_SHA256 {
        return Err(AttestationError::InvalidRoot(
            "attestation root fingerprint mismatch".to_string(),
        ));
    }
    let counter = u32_field(map, "counter")?;
    enforce_counter(input.previous_counter, counter)?;

    let credential_public_key = bytes_field(map, "credential_public_key")?;
    if credential_public_key.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "credential_public_key must not be empty".to_string(),
        ));
    }

    Ok(VerifiedAppAttest {
        key_id: key_id.to_string(),
        app_id: input.app_id.to_string(),
        counter,
        app_id_hash_hex: hex::encode(app_id_hash),
        challenge_hash_hex: hex::encode(challenge_hash),
        root_fingerprint_sha256_hex: hex::encode(root_fingerprint),
        credential_public_key_sha256_hex: hex::encode(sha256(credential_public_key)),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthData<'a> {
    app_id_hash: &'a [u8],
    counter: u32,
    credential_id: Vec<u8>,
    credential_public_key: &'a [u8],
}

fn parse_auth_data(
    auth_data: &[u8],
    production: bool,
) -> Result<ParsedAuthData<'_>, AttestationError> {
    let min_len = AUTH_DATA_HEADER_LEN + AAGUID_LEN + CREDENTIAL_ID_LEN_BYTES;
    if auth_data.len() < min_len {
        return Err(AttestationError::InvalidCbor(format!(
            "authData must be at least {min_len} bytes"
        )));
    }
    let flags = auth_data[32];
    if flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
        return Err(AttestationError::MissingField("attestedCredentialData"));
    }
    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let aaguid = &auth_data[AUTH_DATA_HEADER_LEN..AUTH_DATA_HEADER_LEN + AAGUID_LEN];
    validate_app_attest_aaguid(aaguid, production)?;
    let credential_len_offset = AUTH_DATA_HEADER_LEN + AAGUID_LEN;
    let credential_len = u16::from_be_bytes([
        auth_data[credential_len_offset],
        auth_data[credential_len_offset + 1],
    ]) as usize;
    let credential_id_offset = credential_len_offset + CREDENTIAL_ID_LEN_BYTES;
    let credential_key_offset = credential_id_offset + credential_len;
    if credential_len == 0 || auth_data.len() <= credential_key_offset {
        return Err(AttestationError::InvalidCbor(
            "authData credential id or public key is empty".to_string(),
        ));
    }

    Ok(ParsedAuthData {
        app_id_hash: &auth_data[..32],
        counter,
        credential_id: auth_data[credential_id_offset..credential_key_offset].to_vec(),
        credential_public_key: &auth_data[credential_key_offset..],
    })
}

/// COSE key type identifier for EC2 keys (RFC 8152 `kty` = 2).
const COSE_KTY_EC2: i128 = 2;
/// COSE EC2 curve identifier for NIST P-256 (RFC 8152 `crv` = 1).
const COSE_CRV_P256: i128 = 1;
/// COSE key parameter labels (RFC 8152 / RFC 9053).
const COSE_LABEL_KTY: i128 = 1;
const COSE_LABEL_CRV: i128 = -1;
const COSE_LABEL_X: i128 = -2;
const COSE_LABEL_Y: i128 = -3;
/// Byte length of a single P-256 affine coordinate.
const P256_COORD_LEN: usize = 32;

/// Parse the credential public key (a COSE EC2 P-256 key) from authData and
/// return its raw affine point as `X || Y` (64 bytes). The leaf attestation
/// certificate's public key is compared against this value to satisfy
/// WebAuthn registration step 6.
fn parse_cose_ec2_point(bytes: &[u8]) -> Result<[u8; P256_COORD_LEN * 2], AttestationError> {
    let value: CborValue = coset::cbor::de::from_reader(bytes).map_err(|error| {
        AttestationError::InvalidCbor(format!("credential public key: {error}"))
    })?;
    let CborValue::Map(map) = value else {
        return Err(AttestationError::InvalidCbor(
            "credential public key must be a COSE key map".to_string(),
        ));
    };
    if map.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "credential public key map is empty".to_string(),
        ));
    }
    if cose_int_label(&map, COSE_LABEL_KTY)? != COSE_KTY_EC2 {
        return Err(AttestationError::InvalidCbor(
            "credential public key is not a COSE EC2 key".to_string(),
        ));
    }
    if cose_int_label(&map, COSE_LABEL_CRV)? != COSE_CRV_P256 {
        return Err(AttestationError::InvalidCbor(
            "credential public key is not on curve P-256".to_string(),
        ));
    }
    let x = cose_coordinate(&map, COSE_LABEL_X)?;
    let y = cose_coordinate(&map, COSE_LABEL_Y)?;
    let mut point = [0_u8; P256_COORD_LEN * 2];
    point[..P256_COORD_LEN].copy_from_slice(&x);
    point[P256_COORD_LEN..].copy_from_slice(&y);
    Ok(point)
}

fn cose_int_label(map: &[(CborValue, CborValue)], label: i128) -> Result<i128, AttestationError> {
    match cose_label_value(map, label)? {
        CborValue::Integer(value) => Ok(i128::from(*value)),
        _ => Err(AttestationError::InvalidCbor(
            "COSE key label is not an integer".to_string(),
        )),
    }
}

fn cose_coordinate(
    map: &[(CborValue, CborValue)],
    label: i128,
) -> Result<[u8; P256_COORD_LEN], AttestationError> {
    let CborValue::Bytes(bytes) = cose_label_value(map, label)? else {
        return Err(AttestationError::InvalidCbor(
            "COSE EC2 coordinate must be a byte string".to_string(),
        ));
    };
    let coordinate: [u8; P256_COORD_LEN] = bytes.as_slice().try_into().map_err(|_| {
        AttestationError::InvalidCbor(format!(
            "COSE EC2 coordinate must be {P256_COORD_LEN} bytes"
        ))
    })?;
    Ok(coordinate)
}

fn cose_label_value(
    map: &[(CborValue, CborValue)],
    label: i128,
) -> Result<&CborValue, AttestationError> {
    map.iter()
        .find_map(|(key, value)| match key {
            CborValue::Integer(found) if i128::from(*found) == label => Some(value),
            _ => None,
        })
        .ok_or(AttestationError::InvalidCbor(
            "COSE key is missing a required label".to_string(),
        ))
}

/// Extract the uncompressed EC point (`X || Y`) from an X.509 leaf
/// certificate's SubjectPublicKeyInfo. App Attest leaf certs carry a
/// P-256 key whose subjectPublicKey is `0x04 || X || Y`.
fn leaf_ec2_point(
    leaf: &X509Certificate<'_>,
) -> Result<[u8; P256_COORD_LEN * 2], AttestationError> {
    let spki = leaf
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let expected_len = 1 + P256_COORD_LEN * 2;
    if spki.len() != expected_len || spki[0] != 0x04 {
        return Err(AttestationError::CertificateChainInvalid(
            "leaf certificate public key is not an uncompressed P-256 point".to_string(),
        ));
    }
    let mut point = [0_u8; P256_COORD_LEN * 2];
    point.copy_from_slice(&spki[1..]);
    Ok(point)
}

fn enforce_counter(previous_counter: Option<u32>, counter: u32) -> Result<(), AttestationError> {
    if let Some(previous) = previous_counter {
        if counter <= previous {
            return Err(AttestationError::CounterRollback);
        }
    }
    Ok(())
}

fn enforce_attestation_counter(
    previous_counter: Option<u32>,
    counter: u32,
) -> Result<(), AttestationError> {
    if previous_counter.is_none() && counter != 0 {
        return Err(AttestationError::InvalidCbor(
            "attestation counter must be zero".to_string(),
        ));
    }
    enforce_counter(previous_counter, counter)
}

fn validate_app_attest_aaguid(aaguid: &[u8], production: bool) -> Result<(), AttestationError> {
    if aaguid == APP_ATTEST_PRODUCTION_AAGUID {
        return Ok(());
    }
    if aaguid == APP_ATTEST_SANDBOX_AAGUID || aaguid == APP_ATTEST_DEVELOPMENT_AAGUID {
        if production {
            return Err(AttestationError::InvalidCbor(
                "authData AAGUID is a non-production (sandbox/development) App Attest \
                 environment, which is rejected in production"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    Err(AttestationError::InvalidCbor(
        "authData AAGUID is not an Apple App Attest environment".to_string(),
    ))
}

fn decode_key_id(key_id: &str) -> Result<Vec<u8>, AttestationError> {
    if key_id.trim().is_empty() {
        return Err(AttestationError::KeyIdMismatch);
    }
    if let Ok(decoded) = Base64UrlUnpadded::decode_vec(key_id) {
        return Ok(decoded);
    }
    if let Ok(decoded) = Base64::decode_vec(key_id) {
        return Ok(decoded);
    }
    if key_id.len().is_multiple_of(2) && key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(key_id).map_err(|_| AttestationError::KeyIdMismatch);
    }
    Err(AttestationError::KeyIdMismatch)
}

fn apple_nonce(auth_data: &[u8], challenge_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(challenge_hash);
    hasher.finalize().into()
}

fn validate_apple_cert_chain(
    cert_chain: &[&[u8]],
    expected_nonce: &[u8; 32],
) -> Result<[u8; P256_COORD_LEN * 2], AttestationError> {
    if cert_chain.is_empty() {
        return Err(AttestationError::MissingField("attStmt.x5c"));
    }
    let root_der = apple_app_attest_root_der()?;
    let (_, root) = X509Certificate::from_der(&root_der).map_err(|error| {
        AttestationError::CertificateChainInvalid(format!("Apple root DER parse failed: {error}"))
    })?;
    let certs = parse_cert_chain(cert_chain)?;
    let leaf = certs
        .first()
        .ok_or(AttestationError::MissingField("attStmt.x5c"))?;
    validate_cert_time(leaf)?;
    validate_leaf_nonce(leaf, expected_nonce)?;
    let leaf_point = leaf_ec2_point(leaf)?;

    for window in certs.windows(2) {
        let child = &window[0];
        let issuer = &window[1];
        validate_cert_time(issuer)?;
        if child.issuer().to_string() != issuer.subject().to_string() {
            return Err(AttestationError::CertificateChainInvalid(
                "certificate issuer does not match parent subject".to_string(),
            ));
        }
        child
            .verify_signature(Some(&issuer.tbs_certificate.subject_pki))
            .map_err(|error| {
                AttestationError::CertificateChainInvalid(format!(
                    "certificate signature failed: {error}"
                ))
            })?;
    }

    let last = certs
        .last()
        .ok_or(AttestationError::MissingField("attStmt.x5c"))?;
    let last_der = cert_chain
        .last()
        .ok_or(AttestationError::MissingField("attStmt.x5c"))?;
    let last_fingerprint: [u8; 32] = Sha256::digest(last_der).into();
    if last_fingerprint == APPLE_APP_ATTEST_ROOT_SHA256 {
        if certs.len() == 1 {
            return Err(AttestationError::CertificateChainInvalid(
                "x5c must contain a leaf certificate, not only the root".to_string(),
            ));
        }
        last.verify_signature(None).map_err(|error| {
            AttestationError::CertificateChainInvalid(format!(
                "Apple root self-signature failed: {error}"
            ))
        })?;
        return Ok(leaf_point);
    }

    if last.issuer().to_string() != root.subject().to_string() {
        return Err(AttestationError::CertificateChainInvalid(
            "certificate chain does not terminate at Apple App Attestation Root CA".to_string(),
        ));
    }
    last.verify_signature(Some(&root.tbs_certificate.subject_pki))
        .map_err(|error| {
            AttestationError::CertificateChainInvalid(format!(
                "certificate signature to Apple root failed: {error}"
            ))
        })?;
    Ok(leaf_point)
}

fn parse_cert_chain<'a>(
    cert_chain: &[&'a [u8]],
) -> Result<Vec<X509Certificate<'a>>, AttestationError> {
    let mut certs = Vec::with_capacity(cert_chain.len());
    for der in cert_chain {
        let (_, cert) = X509Certificate::from_der(der).map_err(|error| {
            AttestationError::CertificateChainInvalid(format!("x5c DER parse failed: {error}"))
        })?;
        certs.push(cert);
    }
    Ok(certs)
}

fn validate_cert_time(cert: &X509Certificate<'_>) -> Result<(), AttestationError> {
    if !cert.validity().is_valid() {
        return Err(AttestationError::CertificateChainInvalid(format!(
            "certificate is outside validity window: {}",
            cert.subject()
        )));
    }
    Ok(())
}

fn validate_leaf_nonce(
    leaf: &X509Certificate<'_>,
    expected_nonce: &[u8; 32],
) -> Result<(), AttestationError> {
    let extension = leaf
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == APP_ATTEST_NONCE_EXTENSION_OID)
        .ok_or(AttestationError::MissingField("apple nonce extension"))?;
    if !der_contains_octet_string(extension.value, expected_nonce, 0) {
        return Err(AttestationError::ChallengeMismatch);
    }
    Ok(())
}

fn der_contains_octet_string(input: &[u8], expected: &[u8], depth: u8) -> bool {
    if depth > 8 {
        return false;
    }
    let mut rest = input;
    while !rest.is_empty() {
        let Some((tag, value, next)) = read_der_tlv(rest) else {
            return false;
        };
        if tag == 0x04 && value == expected {
            return true;
        }
        if tag & 0xC0 == 0x80 && value == expected {
            return true;
        }
        if tag & 0x20 != 0 && der_contains_octet_string(value, expected, depth + 1) {
            return true;
        }
        rest = next;
    }
    false
}

fn read_der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let len_byte = input[1];
    let (len, value_offset) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), 2)
    } else {
        let len_len = usize::from(len_byte & 0x7f);
        if len_len == 0 || len_len > 4 || input.len() < 2 + len_len {
            return None;
        }
        let mut parsed_len = 0usize;
        for byte in &input[2..2 + len_len] {
            parsed_len = parsed_len
                .checked_mul(256)?
                .checked_add(usize::from(*byte))?;
        }
        (parsed_len, 2 + len_len)
    };
    let end = value_offset.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[value_offset..end], &input[end..]))
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

#[cfg(any(test, feature = "dev-fixtures"))]
fn u32_field(map: &[(CborValue, CborValue)], name: &'static str) -> Result<u32, AttestationError> {
    match field(map, name)? {
        CborValue::Integer(value) => {
            let as_i128 = i128::from(*value);
            if as_i128 < 0 || as_i128 > i128::from(u32::MAX) {
                return Err(AttestationError::InvalidCbor(format!(
                    "{name} must fit in u32"
                )));
            }
            Ok(as_i128 as u32)
        }
        _ => Err(AttestationError::InvalidCbor(format!(
            "{name} must be an integer"
        ))),
    }
}

fn map_field<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Result<&'a [(CborValue, CborValue)], AttestationError> {
    match field(map, name)? {
        CborValue::Map(value) => Ok(value.as_slice()),
        _ => Err(AttestationError::InvalidCbor(format!("{name} must be map"))),
    }
}

fn x5c_field(map: &[(CborValue, CborValue)]) -> Result<Vec<&[u8]>, AttestationError> {
    let value = field(map, "x5c")?;
    let CborValue::Array(entries) = value else {
        return Err(AttestationError::InvalidCbor(
            "attStmt.x5c must be array".to_string(),
        ));
    };
    let mut certs = Vec::with_capacity(entries.len());
    for entry in entries {
        let CborValue::Bytes(bytes) = entry else {
            return Err(AttestationError::InvalidCbor(
                "attStmt.x5c entries must be bytes".to_string(),
            ));
        };
        certs.push(bytes.as_slice());
    }
    Ok(certs)
}

fn field<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Result<&'a CborValue, AttestationError> {
    field_optional(map, name).ok_or(AttestationError::MissingField(name))
}

fn field_optional<'a>(
    map: &'a [(CborValue, CborValue)],
    name: &'static str,
) -> Option<&'a CborValue> {
    map.iter().find_map(|(key, value)| match key {
        CborValue::Text(text) if text == name => Some(value),
        _ => None,
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cose_ec2_p256(x: &[u8], y: &[u8]) -> Vec<u8> {
        let value = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(x.to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(y.to_vec()),
            ),
        ]);
        let mut bytes = Vec::new();
        match coset::cbor::ser::into_writer(&value, &mut bytes) {
            Ok(()) => bytes,
            Err(error) => panic!("encode COSE key: {error}"),
        }
    }

    #[test]
    fn parse_cose_ec2_point_extracts_x_then_y() {
        let x = [0x11_u8; 32];
        let y = [0x22_u8; 32];
        let point = match parse_cose_ec2_point(&cose_ec2_p256(&x, &y)) {
            Ok(point) => point,
            Err(error) => panic!("expected a parsed point, got {error:?}"),
        };
        assert_eq!(&point[..32], &x);
        assert_eq!(&point[32..], &y);
    }

    #[test]
    fn parse_cose_ec2_point_distinguishes_distinct_keys() {
        // WebAuthn step 6 compares the credential public key against the
        // attestation leaf key. Two different credential keys must map to
        // different points so a substituted key is detectable.
        let a = match parse_cose_ec2_point(&cose_ec2_p256(&[0x01; 32], &[0x02; 32])) {
            Ok(point) => point,
            Err(error) => panic!("parse key a: {error:?}"),
        };
        let b = match parse_cose_ec2_point(&cose_ec2_p256(&[0x03; 32], &[0x04; 32])) {
            Ok(point) => point,
            Err(error) => panic!("parse key b: {error:?}"),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn parse_cose_ec2_point_rejects_wrong_curve() {
        // crv(-1) = P-384(2) instead of P-256(1).
        let value = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(2.into()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(vec![0x11; 32]),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(vec![0x22; 32]),
            ),
        ]);
        let mut bytes = Vec::new();
        if let Err(error) = coset::cbor::ser::into_writer(&value, &mut bytes) {
            panic!("encode COSE key: {error}");
        }
        assert!(matches!(
            parse_cose_ec2_point(&bytes),
            Err(AttestationError::InvalidCbor(_))
        ));
    }

    #[test]
    fn parse_cose_ec2_point_rejects_short_coordinate() {
        let bytes = cose_ec2_p256(&[0x11; 31], &[0x22; 32]);
        assert!(matches!(
            parse_cose_ec2_point(&bytes),
            Err(AttestationError::InvalidCbor(_))
        ));
    }

    #[test]
    fn parse_cose_ec2_point_rejects_non_ec2_kty() {
        // kty(1) = OKP(1) instead of EC2(2).
        let value = CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer(1.into()),
        )]);
        let mut bytes = Vec::new();
        if let Err(error) = coset::cbor::ser::into_writer(&value, &mut bytes) {
            panic!("encode COSE key: {error}");
        }
        assert!(matches!(
            parse_cose_ec2_point(&bytes),
            Err(AttestationError::InvalidCbor(_))
        ));
    }

    #[test]
    fn leaf_ec2_point_rejects_non_p256_certificate() {
        // The pinned Apple root is a real X.509 cert with a P-384 key, so
        // its SubjectPublicKeyInfo is not a 65-byte uncompressed P-256
        // point. `leaf_ec2_point` must reject it rather than mis-bind.
        let der = match apple_app_attest_root_der() {
            Ok(der) => der,
            Err(error) => panic!("decode pinned Apple root: {error:?}"),
        };
        let (_, cert) = match X509Certificate::from_der(&der) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parse pinned Apple root: {error}"),
        };
        assert!(matches!(
            leaf_ec2_point(&cert),
            Err(AttestationError::CertificateChainInvalid(_))
        ));
    }

    #[test]
    fn validate_app_attest_aaguid_rejects_sandbox_and_development_in_production() {
        for aaguid in [APP_ATTEST_SANDBOX_AAGUID, APP_ATTEST_DEVELOPMENT_AAGUID] {
            assert!(
                validate_app_attest_aaguid(aaguid, false).is_ok(),
                "sandbox/development AAGUID should be accepted outside production"
            );
            assert!(matches!(
                validate_app_attest_aaguid(aaguid, true),
                Err(AttestationError::InvalidCbor(_))
            ));
        }
        // The production AAGUID is always accepted.
        assert!(validate_app_attest_aaguid(APP_ATTEST_PRODUCTION_AAGUID, true).is_ok());
    }
}
