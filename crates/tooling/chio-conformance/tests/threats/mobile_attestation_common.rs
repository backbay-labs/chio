use std::error::Error;

use base64ct::{Base64UrlUnpadded, Encoding};
use chio_custody_hw::attestation::apple_root::APPLE_APP_ATTEST_ROOT_SHA256;
use chio_custody_hw::attestation::google_root::{
    play_integrity_encoding_key, GOOGLE_PLAY_INTEGRITY_ISSUER, GOOGLE_PLAY_INTEGRITY_ROOT_KID,
};
use chio_custody_hw::{APP_ATTEST_FORMAT, PLAY_RECOGNIZED};
use coset::cbor::Value as CborValue;
use jsonwebtoken::{encode, Algorithm, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const APP_ID: &str = "TEAMID1234.dev.chio.patient";
pub const KEY_ID: &str = "app-attest-key-1";
pub const CHALLENGE: &[u8] = b"fresh-server-challenge";
pub const PUBLIC_KEY: &[u8] = b"synthetic-credential-public-key";
pub const PACKAGE: &str = "dev.chio.patient";
pub const NONCE: &str = "issuer-nonce-1";
pub const AUDIENCE: &str = "chio-mobile-issuer";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestClaims {
    nonce: String,
    app_integrity: TestAppIntegrity,
    device_integrity: TestDeviceIntegrity,
    aud: String,
    iss: String,
    exp: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestAppIntegrity {
    app_recognition_verdict: String,
    package_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestDeviceIntegrity {
    device_recognition_verdict: Vec<String>,
}

pub fn app_attest_fixture(
    app_id: &str,
    key_id: &str,
    challenge: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let entries = vec![
        (
            CborValue::Text("format".to_string()),
            CborValue::Text(APP_ATTEST_FORMAT.to_string()),
        ),
        (
            CborValue::Text("key_id".to_string()),
            CborValue::Text(key_id.to_string()),
        ),
        (
            CborValue::Text("app_id_hash".to_string()),
            CborValue::Bytes(sha256(app_id.as_bytes()).to_vec()),
        ),
        (
            CborValue::Text("challenge_hash".to_string()),
            CborValue::Bytes(sha256(challenge).to_vec()),
        ),
        (
            CborValue::Text("root_fingerprint_sha256".to_string()),
            CborValue::Bytes(APPLE_APP_ATTEST_ROOT_SHA256.to_vec()),
        ),
        (
            CborValue::Text("counter".to_string()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Text("credential_public_key".to_string()),
            CborValue::Bytes(PUBLIC_KEY.to_vec()),
        ),
    ];
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut bytes)?;
    Ok(bytes)
}

pub fn webauthn_fixture(
    app_id: &str,
    credential_id: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&sha256(app_id.as_bytes()));
    auth_data.push(0x40);
    auth_data.extend_from_slice(&1_u32.to_be_bytes());
    auth_data.extend_from_slice(b"appattest\0\0\0\0\0\0\0");
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose_key()?);

    let entries = vec![
        (
            CborValue::Text("fmt".to_string()),
            CborValue::Text(APP_ATTEST_FORMAT.to_string()),
        ),
        (
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(auth_data),
        ),
        (
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(vec![(
                CborValue::Text("x5c".to_string()),
                CborValue::Array(vec![]),
            )]),
        ),
        (
            CborValue::Text("clientChallengeHash".to_string()),
            CborValue::Bytes(sha256(challenge).to_vec()),
        ),
    ];
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut bytes)?;
    Ok(bytes)
}

pub fn encoded_key_id(credential_id: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(credential_id)
}

pub fn signed_play_integrity_token(
    nonce: &str,
    audience: &str,
    device_verdicts: &[&str],
    exp: u64,
) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(GOOGLE_PLAY_INTEGRITY_ROOT_KID.to_string());
    let claims = TestClaims {
        nonce: nonce.to_string(),
        app_integrity: TestAppIntegrity {
            app_recognition_verdict: PLAY_RECOGNIZED.to_string(),
            package_name: PACKAGE.to_string(),
        },
        device_integrity: TestDeviceIntegrity {
            device_recognition_verdict: device_verdicts
                .iter()
                .map(|verdict| (*verdict).to_string())
                .collect(),
        },
        aud: audience.to_string(),
        iss: GOOGLE_PLAY_INTEGRITY_ISSUER.to_string(),
        exp,
    };
    encode(&header, &claims, &play_integrity_encoding_key()?).map_err(Into::into)
}

pub fn future_exp() -> Result<u64, Box<dyn Error>> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() + 3_600)
        .map_err(Into::into)
}

fn cose_key() -> Result<Vec<u8>, Box<dyn Error>> {
    // COSE EC2 P-256 credential public key: kty(1)=EC2(2), alg(3)=ES256(-7),
    // crv(-1)=P-256(1), x(-2), y(-3). The coordinates are arbitrary 32-byte
    // synthetic values; the threat tests only exercise pre-chain rejection
    // paths, which fire before the leaf-key binding check.
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
            CborValue::Bytes(vec![0x11; 32]),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(vec![0x22; 32]),
        ),
    ]);
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
