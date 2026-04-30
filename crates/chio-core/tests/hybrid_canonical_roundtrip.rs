use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use chio_core::{
    crypto::{
        canonical_json_string, sha256_hex, HYBRID_ED25519_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN,
    },
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, PublicKey, Signature, SigningBackend,
};
use serde::Deserialize;

const GOLDEN: &str = include_str!("golden/hybrid_signature_v1.json");

#[derive(Debug, Deserialize)]
struct HybridGolden {
    schema: String,
    message: String,
    alg_set: String,
    classical_seed_hex: String,
    pq_seed_hex: String,
    public_key_prefix: String,
    public_key_sha256: String,
    signature_prefix: String,
    canonical_public_key_json_sha256: String,
}

#[test]
fn hybrid_signature_round_trips_through_wire_encoding() -> Result<(), Box<dyn Error>> {
    let golden = golden()?;
    let backend = backend(&golden)?;
    let public_key = backend.public_key();
    let signature = backend.sign_bytes(golden.message.as_bytes())?;

    let restored_public_key = PublicKey::from_hex(&public_key.to_hex())?;
    let restored_signature = Signature::from_hex(&signature.to_hex())?;

    assert_eq!(public_key, restored_public_key);
    assert_eq!(signature, restored_signature);
    assert!(restored_public_key.verify(golden.message.as_bytes(), &restored_signature));
    assert!(public_key.to_hex().starts_with(&golden.public_key_prefix));
    assert!(signature.to_hex().starts_with(&golden.signature_prefix));
    Ok(())
}

#[test]
fn hybrid_canonical_json_matches_golden_prefix_and_shape() -> Result<(), Box<dyn Error>> {
    let golden = golden()?;
    let backend = backend(&golden)?;
    let public_key = backend.public_key();
    let public_key_hex = public_key.to_hex();
    let canonical = canonical_json_string(&public_key)?;

    assert_eq!(
        sha256_hex(public_key_hex.as_bytes()),
        golden.public_key_sha256
    );
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        golden.canonical_public_key_json_sha256
    );
    assert_eq!(golden.schema, "chio.hybrid-signature.v1");
    assert_eq!(golden.alg_set, HYBRID_ED25519_MLDSA65);
    let (_classical, pq_public_key, alg_set) = hybrid_wire_parts(&public_key_hex)?;
    assert_eq!(alg_set, golden.alg_set);
    assert_eq!(hex::decode(pq_public_key)?.len(), ML_DSA_65_PUBLIC_KEY_LEN);

    let signature = backend.sign_bytes(golden.message.as_bytes())?;
    let signature_hex = signature.to_hex();
    let (_classical_signature, pq_signature, signature_alg_set) =
        hybrid_wire_parts(&signature_hex)?;
    assert_eq!(signature_alg_set, golden.alg_set);
    assert_eq!(hex::decode(pq_signature)?.len(), ML_DSA_65_SIGNATURE_LEN);
    Ok(())
}

fn golden() -> Result<HybridGolden, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN)?)
}

fn backend(golden: &HybridGolden) -> Result<HybridBackend, Box<dyn Error>> {
    let classical_seed = hex_array::<32>(&golden.classical_seed_hex)?;
    let pq_seed = hex_array::<32>(&golden.pq_seed_hex)?;
    Ok(HybridBackend::new(
        Box::new(Ed25519Backend::new(Keypair::from_seed(&classical_seed))),
        MlDsa65Backend::from_seed(&pq_seed),
    )?)
}

fn hybrid_wire_parts(wire: &str) -> Result<(&str, &str, &str), Box<dyn Error>> {
    let rest = wire.strip_prefix("hybrid:").ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("hybrid wire missing prefix: {wire}"),
        )
    })?;
    let mut parts = rest.rsplitn(3, ':');
    let alg_set = parts
        .next()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "hybrid wire missing alg_set"))?;
    let pq = parts
        .next()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "hybrid wire missing pq half"))?;
    let classical = parts.next().ok_or_else(|| {
        IoError::new(ErrorKind::InvalidData, "hybrid wire missing classical half")
    })?;
    Ok((classical, pq, alg_set))
}

fn hex_array<const N: usize>(input: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = hex::decode(input)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("expected {N} bytes, got {}", bytes.len()),
        )) as Box<dyn Error>
    })
}
