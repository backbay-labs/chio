#![cfg(feature = "tee-quotes")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::vec_init_then_push)]

//! Nitro root-rotation regression and corpus integration coverage.
//!
//! AWS rotates the Nitro root rarely but it has happened. This file
//! pins the rotation mitigation: when the embedded root flips, fixtures
//! signed under the previous root are rejected. The cabundle leaf
//! presented in those fixtures is a fixture-only marker that
//! deliberately differs from the leaf the new chain vouches for, so
//! the verifier rejects with [`AttestError::TrustRoot`] before any
//! cryptographic work runs.
//!
//! The same file also asserts the corpus contract: every fixture under
//! `fixtures/quotes/nitro/` re-hashes to its manifest entry, every
//! positive fixture verifies, and every negative fixture rejects with
//! the expected fail-closed reason.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chio_attest_verify::nitro::{NitroCollateral, NitroVerifier};
use chio_attest_verify::{
    AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier, TeeKind,
};
use chio_core_types::crypto::Keypair;
use p384::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const FIXTURES_DIR: &str = "fixtures/quotes/nitro";
const KERNEL_SEED: [u8; 32] = [9u8; 32];
const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
const PINNED_PCR0: [u8; 48] = [0x77u8; 48];
const NITRO_ATTESTATION_KEY_SEED: [u8; 48] = [0x42u8; 48];
const NITRO_INTERMEDIATE_FIXTURE: &[u8] = b"aws-nitro-intermediate-fixture";

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_DIR)
}

fn manifest_text() -> String {
    fs::read_to_string(fixtures_root().join("MANIFEST.toml"))
        .expect("MANIFEST.toml must exist; run the generate_nitro_fixtures example to regenerate")
}

fn aws_nitro_root_bytes() -> Vec<u8> {
    let pem = include_bytes!("../fixtures/nitro/aws-nitro-root.pem");
    pem.to_vec()
}

fn nitro_attestation_public_key() -> Vec<u8> {
    let signing_key = SigningKey::from_bytes((&NITRO_ATTESTATION_KEY_SEED).into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);
    verifying_key.to_encoded_point(false).as_bytes().to_vec()
}

/// A synthetic "rotated" root. Different bytes from the embedded
/// real root, so the verifier rejects fixtures whose chain anchors
/// at the original root.
fn rotated_root_bytes() -> Vec<u8> {
    b"-----BEGIN CERTIFICATE-----\nROTATED-ROOT-FIXTURE-G2\n-----END CERTIFICATE-----\n".to_vec()
}

fn collateral_at(now: SystemTime) -> NitroCollateral {
    NitroCollateral::new(
        aws_nitro_root_bytes(),
        vec![
            nitro_attestation_public_key(),
            NITRO_INTERMEDIATE_FIXTURE.to_vec(),
            aws_nitro_root_bytes(),
        ],
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

/// Collateral whose embedded root has rotated to G2; the chain still
/// terminates at the new root, but its leaf is a different byte
/// fixture so any document presenting the old leaf fails the
/// chain-leaf byte-match check.
fn rotated_collateral_at(now: SystemTime) -> NitroCollateral {
    NitroCollateral::new(
        rotated_root_bytes(),
        vec![
            b"aws-nitro-leaf-under-new-root".to_vec(),
            b"aws-nitro-intermediate-under-new-root".to_vec(),
            rotated_root_bytes(),
        ],
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

fn verifier_at(now: SystemTime) -> NitroVerifier {
    NitroVerifier::with_verification_time(collateral_at(now), PINNED_PCR0, now)
}

fn rotated_verifier_at(now: SystemTime) -> NitroVerifier {
    NitroVerifier::with_verification_time(rotated_collateral_at(now), PINNED_PCR0, now)
}

#[derive(Debug)]
struct ManifestEntry {
    path: String,
    role: String,
    role_tag: String,
    sha256: String,
}

fn parse_fixture_entries(manifest: &str) -> Vec<ManifestEntry> {
    let value: toml::Value = toml::from_str(manifest).expect("manifest is valid TOML");
    let raw = value
        .get("fixture")
        .and_then(|v| v.as_array())
        .expect("manifest has fixture array");
    raw.iter()
        .map(|entry| ManifestEntry {
            path: entry
                .get("path")
                .and_then(|v| v.as_str())
                .expect("fixture.path")
                .to_owned(),
            role: entry
                .get("role")
                .and_then(|v| v.as_str())
                .expect("fixture.role")
                .to_owned(),
            role_tag: entry
                .get("role_tag")
                .and_then(|v| v.as_str())
                .expect("fixture.role_tag")
                .to_owned(),
            sha256: entry
                .get("sha256")
                .and_then(|v| v.as_str())
                .expect("fixture.sha256")
                .to_owned(),
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn manifest_pins_match_on_disk_sha256() {
    let manifest = manifest_text();
    let entries = parse_fixture_entries(&manifest);
    assert!(
        entries.len() >= 8,
        "expected at least 4 positive + 4 negative fixtures, got {}",
        entries.len()
    );
    for entry in &entries {
        let on_disk = fs::read(fixtures_root().join(&entry.path))
            .expect("fixture file referenced by manifest is missing");
        let digest = Sha256::digest(&on_disk);
        let actual = hex_lower(&digest);
        assert_eq!(
            actual, entry.sha256,
            "fixture {} drifted from manifest digest; regenerate fixtures",
            entry.path
        );
    }
}

#[test]
fn positive_fixtures_verify_with_kernel_pk_and_receipt_root() {
    let manifest = manifest_text();
    let entries = parse_fixture_entries(&manifest);
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let n = now();
    let verifier = verifier_at(n);
    let positives: Vec<&ManifestEntry> = entries.iter().filter(|e| e.role == "positive").collect();
    assert!(positives.len() >= 4, "need >=4 positive fixtures");

    for entry in positives {
        let bytes = fs::read(fixtures_root().join(&entry.path)).unwrap();
        let verified = verifier
            .verify_quote(
                &bytes,
                &QuoteVerificationContext::new(&kernel, &receipt_root),
            )
            .unwrap_or_else(|e| panic!("positive fixture {} rejected: {e}", entry.path));
        assert_eq!(verified.tee_kind, TeeKind::AwsNitro);
        assert!(verified.tcb_acceptable());
    }
}

#[test]
fn negative_fixtures_reject_with_expected_reason() {
    let manifest = manifest_text();
    let entries = parse_fixture_entries(&manifest);
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let verifier = verifier_at(now());
    let negatives: Vec<&ManifestEntry> = entries.iter().filter(|e| e.role == "negative").collect();
    assert!(negatives.len() >= 4, "need >=4 negative fixtures");

    for entry in negatives {
        let bytes = fs::read(fixtures_root().join(&entry.path)).unwrap();
        let result = verifier.verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        );
        let error = match result {
            Ok(_) => panic!(
                "negative fixture {} (tag {}) MUST NOT verify",
                entry.path, entry.role_tag
            ),
            Err(e) => e,
        };
        match (entry.role_tag.as_str(), &error) {
            ("aws-nitro-user-data-mismatch", AttestError::ReportDataMismatch) => {}
            ("aws-nitro-pcr0-mismatch", AttestError::QuoteRejected(_)) => {}
            ("aws-nitro-document-leaf-mismatch", AttestError::TrustRoot) => {}
            ("aws-nitro-root-rotation-old-leaf", AttestError::TrustRoot) => {}
            (tag, err) => {
                panic!("negative fixture tag {tag} rejected with unexpected error {err:?}")
            }
        }
    }
}

#[test]
fn root_rotation_rejects_fixtures_anchored_at_old_root() {
    // Root-rotation regression: the verifier's embedded root has
    // rotated to G2 (different bytes), and the new chain vouches
    // for a leaf that is NOT what the old positive fixture
    // presented. A document that presents the old leaf MUST be
    // rejected by the rotated verifier.
    let manifest = manifest_text();
    let entries = parse_fixture_entries(&manifest);
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let verifier = rotated_verifier_at(now());

    let positives: Vec<&ManifestEntry> = entries.iter().filter(|e| e.role == "positive").collect();
    assert!(!positives.is_empty(), "need at least one positive fixture");

    for entry in positives {
        let bytes = fs::read(fixtures_root().join(&entry.path)).unwrap();
        let result = verifier.verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        );
        match result {
            Err(AttestError::TrustRoot) => {}
            Err(other) => panic!(
                "rotated-root verifier rejected positive fixture {} with unexpected error {other:?}",
                entry.path
            ),
            Ok(_) => panic!(
                "rotated-root verifier MUST NOT accept positive fixture {} signed under the old root",
                entry.path
            ),
        }
    }
}

#[test]
fn root_rotation_does_not_accept_old_root_for_new_chain() {
    // Symmetric guard: a verifier configured with the new root
    // MUST NOT accept a chain whose trailer bytes are the OLD root.
    // This pins the chain-trailer byte-match contract.
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let n = now();
    let mut bad = rotated_collateral_at(n);
    // Replace the trailer with the old root bytes; the chain now
    // does not terminate at the configured (rotated) root.
    bad.chain_der.pop();
    bad.chain_der.push(aws_nitro_root_bytes());
    let verifier = NitroVerifier::with_verification_time(bad, PINNED_PCR0, n);

    let bytes =
        fs::read(fixtures_root().join("positive/nitro_kernel_seed_09_root_08.bin")).unwrap();
    let result = verifier.verify_quote(
        &bytes,
        &QuoteVerificationContext::new(&kernel, &receipt_root),
    );
    assert!(
        matches!(result, Err(AttestError::TrustRoot)),
        "verifier with rotated root MUST reject a chain trailing at the old root"
    );
}
