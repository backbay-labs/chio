#![cfg(feature = "pq")]

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use chio_core_types::{
    crypto::{HYBRID_ED25519_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN},
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, PublicKey, Signature, SigningBackend,
};

const MESSAGE: &[u8] = b"m03 hybrid bit flip property";

fn hybrid_fixture() -> Result<(PublicKey, Signature), Box<dyn Error>> {
    let classical = Box::new(Ed25519Backend::new(Keypair::from_seed(&[3u8; 32])));
    let pq = MlDsa65Backend::from_seed(&[7u8; 32]);
    let backend = HybridBackend::new(classical, pq)?;
    let public_key = backend.public_key();
    let signature = backend.sign_bytes(MESSAGE)?;
    assert!(public_key.verify(MESSAGE, &signature));
    Ok((public_key, signature))
}

#[test]
fn bit_flip_in_classical_half_rejects() -> Result<(), Box<dyn Error>> {
    let (public_key, signature) = hybrid_fixture()?;
    let mut parts = hybrid_parts(&signature.to_hex())?;
    parts.classical = flip_first_hex_digit(&parts.classical)?;
    let tampered = parse_signature(&parts)?;

    assert!(!public_key.verify(MESSAGE, &tampered));
    Ok(())
}

#[test]
fn bit_flip_in_pq_half_rejects() -> Result<(), Box<dyn Error>> {
    let (public_key, signature) = hybrid_fixture()?;
    let mut parts = hybrid_parts(&signature.to_hex())?;
    parts.pq = flip_first_hex_digit(&parts.pq)?;
    let tampered = parse_signature(&parts)?;

    assert!(!public_key.verify(MESSAGE, &tampered));
    Ok(())
}

#[test]
fn alg_set_tampering_rejects() -> Result<(), Box<dyn Error>> {
    let (_public_key, signature) = hybrid_fixture()?;
    let mut parts = hybrid_parts(&signature.to_hex())?;
    parts.alg_set = "p256+mldsa65".to_string();
    let wire = format!("hybrid:{}:{}:{}", parts.classical, parts.pq, parts.alg_set);

    assert!(Signature::from_hex(&wire).is_err());
    Ok(())
}

#[test]
fn malformed_hybrid_lengths_reject() -> Result<(), Box<dyn Error>> {
    let (public_key, signature) = hybrid_fixture()?;
    let mut parts = hybrid_parts(&signature.to_hex())?;
    parts.pq.truncate(parts.pq.len() - 2);
    let wire = format!("hybrid:{}:{}:{}", parts.classical, parts.pq, parts.alg_set);

    assert!(Signature::from_hex(&wire).is_err());
    assert!(PublicKey::from_hybrid_parts(
        Keypair::from_seed(&[3u8; 32]).public_key(),
        &[0u8; ML_DSA_65_PUBLIC_KEY_LEN - 1],
        HYBRID_ED25519_MLDSA65,
    )
    .is_err());
    assert!(Signature::from_hybrid_parts(
        Keypair::from_seed(&[3u8; 32]).sign(MESSAGE),
        &[0u8; ML_DSA_65_SIGNATURE_LEN - 1],
        HYBRID_ED25519_MLDSA65,
    )
    .is_err());
    assert!(public_key.verify(MESSAGE, &signature));
    Ok(())
}

struct HybridParts {
    classical: String,
    pq: String,
    alg_set: String,
}

fn hybrid_parts(wire: &str) -> Result<HybridParts, Box<dyn Error>> {
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
    Ok(HybridParts {
        classical: classical.to_string(),
        pq: pq.to_string(),
        alg_set: alg_set.to_string(),
    })
}

fn parse_signature(parts: &HybridParts) -> Result<Signature, Box<dyn Error>> {
    let wire = format!("hybrid:{}:{}:{}", parts.classical, parts.pq, parts.alg_set);
    Ok(Signature::from_hex(&wire)?)
}

fn flip_first_hex_digit(input: &str) -> Result<String, Box<dyn Error>> {
    let mut out = input.to_string();
    let first = input
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "empty hex string"))?;
    let replacement = match first {
        b'0' => '1',
        _ => '0',
    };
    out.replace_range(0..1, &replacement.to_string());
    Ok(out)
}
