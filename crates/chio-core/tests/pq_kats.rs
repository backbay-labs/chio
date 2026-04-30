#![cfg(feature = "pq")]

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use chio_core::crypto::{MlDsa65Backend, ML_DSA_65_PUBLIC_KEY_LEN};
use chio_core::pq::{verify_mldsa65_signature, ML_DSA_65_SECRET_KEY_LEN};
use serde::Deserialize;

const KAT_FIXTURE: &str = include_str!("fixtures/pq/mldsa65_kat.json");

#[derive(Deserialize)]
struct KatFixture {
    source_commit: String,
    source_sha256: SourceHashes,
    parameter_set: String,
    keygen: KeygenCase,
    siggen: SiggenCase,
    sigver: SigverGroup,
}

#[derive(Deserialize)]
struct SourceHashes {
    keygen: String,
    siggen: String,
    sigver: String,
}

#[derive(Deserialize)]
struct KeygenCase {
    seed: String,
    pk: String,
    sk: String,
}

#[derive(Deserialize)]
struct SiggenCase {
    sk: String,
    message: String,
    rnd: Option<String>,
    signature: String,
}

#[derive(Deserialize)]
struct SigverGroup {
    pk: String,
    tests: Vec<SigverCase>,
}

#[derive(Deserialize)]
struct SigverCase {
    message: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

#[test]
fn mldsa65_replays_nist_keygen_vector() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.source_commit,
        "65370b861b96efd30dfe0daae607bde26a78a5c8"
    );
    assert_eq!(
        fixture.source_sha256.keygen,
        "2313cda283d8e7ebd196c04a211c30fd9c471f99ae7e1af844e75683071a4043"
    );
    assert_eq!(fixture.parameter_set, "ML-DSA-65");

    let seed = hex_array::<32>(&fixture.keygen.seed)?;
    let backend = MlDsa65Backend::from_seed(&seed);

    assert_eq_hex(&backend.public_key_bytes(), &fixture.keygen.pk)?;
    assert_eq_hex(&backend.secret_key_bytes(), &fixture.keygen.sk)?;
    Ok(())
}

#[test]
fn mldsa65_replays_nist_siggen_vector() -> Result<(), Box<dyn Error>> {
    let fixture = siggen_fixture()?;
    assert_eq!(
        fixture.source_sha256.siggen,
        "f4004278e7dcf0ddaaad3dcef06dd2445ec8b488e546cc376e1b9bcdfd9802de"
    );

    let secret_key = hex_array::<ML_DSA_65_SECRET_KEY_LEN>(&fixture.siggen.sk)?;
    let message = hex_vec(&fixture.siggen.message)?;
    let seed = match fixture.siggen.rnd.as_deref() {
        Some(rnd) => hex_array::<32>(rnd)?,
        None => [0u8; 32],
    };
    let backend = MlDsa65Backend::from_secret_key_bytes(&secret_key)?;
    let signature = backend.sign_bytes_with_seed(&message, &seed)?;

    assert_eq!(
        hex::encode(signature),
        fixture.siggen.signature.to_lowercase()
    );
    Ok(())
}

#[test]
fn mldsa65_replays_nist_sigver_vectors() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.source_sha256.sigver,
        "033a8b8a5f45d7a9b158b493efa5502a1fa697b00ee66037e11d84d5a30ab93a"
    );

    let public_key = hex_array::<ML_DSA_65_PUBLIC_KEY_LEN>(&fixture.sigver.pk)?;
    for case in fixture.sigver.tests {
        let message = hex_vec(&case.message)?;
        let signature = hex_vec(&case.signature)?;
        assert_eq!(
            verify_mldsa65_signature(&public_key, &message, &signature),
            case.test_passed
        );
    }
    Ok(())
}

fn fixture() -> Result<KatFixture, Box<dyn Error>> {
    let mut stream = serde_json::Deserializer::from_str(KAT_FIXTURE).into_iter();
    let Some(first) = stream.next() else {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "empty KAT fixture",
        )));
    };
    Ok(first?)
}

fn siggen_fixture() -> Result<KatFixture, Box<dyn Error>> {
    for value in serde_json::Deserializer::from_str(KAT_FIXTURE).into_iter() {
        let fixture: KatFixture = value?;
        if fixture.siggen.rnd.is_some() {
            return Ok(fixture);
        }
    }
    Err(Box::new(IoError::new(
        ErrorKind::InvalidData,
        "KAT fixture does not contain deterministic siggen rnd",
    )))
}

fn hex_vec(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(hex::decode(input)?)
}

fn hex_array<const N: usize>(input: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = hex_vec(input)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("expected {N} bytes, got {}", bytes.len()),
        )) as Box<dyn Error>
    })
}

fn assert_eq_hex(actual: &[u8], expected_hex: &str) -> Result<(), Box<dyn Error>> {
    let expected = hex_vec(expected_hex)?;
    assert_eq!(actual, expected.as_slice());
    Ok(())
}
