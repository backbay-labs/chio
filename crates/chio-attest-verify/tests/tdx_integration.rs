//! Integration coverage for the Intel TDX backend.
//!
//! Consumes the pinned fixture corpus written by the
//! `generate_tdx_fixtures` example. Each fixture envelope mirrors the
//! shape produced by the chio-tee container: a TDX v4 quote header,
//! TD10 report body, and signature blob trailer. This test exercises
//! the consumer-side verifier.
//!
//! Positive coverage: every fixture under `fixtures/quotes/tdx/positive/`
//! verifies under the kernel signing key and receipt root pair the
//! generator pinned in MANIFEST.toml. The fixture's report_data is
//! re-derived through `expect_report_data` and the verifier's emitted
//! `VerifiedQuote::report_data` is byte-compared against it, locking
//! the binding rule.
//!
//! Negative coverage: every fixture under `fixtures/quotes/tdx/negative/`
//! is rejected by the verifier with the expected fail-closed reason.
//!
//! Manifest contract: every binary file referenced by MANIFEST.toml is
//! re-hashed at test time and compared to the manifest's pinned SHA256.
//! A drifted fixture (manifest vs disk) fails the test before any
//! verifier work runs, so future fixture regeneration cannot silently
//! land without updating the manifest.

#![cfg(feature = "tee-quotes")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chio_attest_verify::tdx::{TdxCollateral, TdxDcapVerifier};
use chio_attest_verify::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind,
};
use chio_core_types::crypto::Keypair;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use sha2::{Digest, Sha256};

const FIXTURES_DIR: &str = "fixtures/quotes/tdx";
const KERNEL_SEED: [u8; 32] = [9u8; 32];
const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
const P256_ATTESTATION_KEY_SEED: [u8; 32] = [0x25; 32];
const P384_ATTESTATION_KEY_SEED: [u8; 48] = [0x38; 48];

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_DIR)
}

fn manifest_text() -> String {
    fs::read_to_string(fixtures_root().join("MANIFEST.toml"))
        .expect("MANIFEST.toml must exist; run the generate_tdx_fixtures example to regenerate")
}

fn collateral_at(now: SystemTime, role_tag: &str) -> TdxCollateral {
    let root = b"intel-root-ca-fixture".to_vec();
    let leaf = if role_tag.contains("p384") {
        p384_attestation_public_key()
    } else {
        p256_attestation_public_key()
    };
    TdxCollateral::new(
        root.clone(),
        vec![leaf, root.clone()],
        vec![b"tcb-info-signing-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

fn p256_attestation_public_key() -> Vec<u8> {
    let signing_key = P256SigningKey::from_bytes((&P256_ATTESTATION_KEY_SEED).into()).unwrap();
    let verifying_key = P256VerifyingKey::from(&signing_key);
    verifying_key.to_encoded_point(false).as_bytes().to_vec()
}

fn p384_attestation_public_key() -> Vec<u8> {
    let signing_key = P384SigningKey::from_bytes((&P384_ATTESTATION_KEY_SEED).into()).unwrap();
    let verifying_key = P384VerifyingKey::from(&signing_key);
    verifying_key.to_encoded_point(false).as_bytes().to_vec()
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

#[derive(Debug)]
struct ManifestEntry {
    path: String,
    role: String,
    role_tag: String,
    sha256: String,
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
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
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expected = expect_report_data(&kernel, &receipt_root);

    let positives: Vec<&ManifestEntry> = entries.iter().filter(|e| e.role == "positive").collect();
    assert!(positives.len() >= 4, "need >=4 positive fixtures");

    for entry in positives {
        let verifier =
            TdxDcapVerifier::with_verification_time(collateral_at(now, &entry.role_tag), 7, now);
        let bytes = fs::read(fixtures_root().join(&entry.path)).unwrap();
        let verified = verifier
            .verify_quote(
                &bytes,
                &QuoteVerificationContext::new(&kernel, &receipt_root),
            )
            .unwrap_or_else(|e| panic!("positive fixture {} rejected: {e}", entry.path));
        assert_eq!(verified.tee_kind, TeeKind::IntelTdx);
        assert_eq!(
            verified.report_data, expected,
            "fixture {} report_data must byte-match expect_report_data binding",
            entry.path
        );
        assert!(
            verified.tcb_acceptable(),
            "fixture {} TCB status was not acceptable",
            entry.path
        );
        assert_eq!(verified.signed_at, now);
    }
}

#[test]
fn negative_fixtures_reject_with_expected_reason() {
    let manifest = manifest_text();
    let entries = parse_fixture_entries(&manifest);
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let negatives: Vec<&ManifestEntry> = entries.iter().filter(|e| e.role == "negative").collect();
    assert!(negatives.len() >= 5, "need >=5 negative fixtures");

    for entry in negatives {
        let verifier =
            TdxDcapVerifier::with_verification_time(collateral_at(now, &entry.role_tag), 7, now);
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
            ("intel-tdx-report-data-mismatch", AttestError::ReportDataMismatch) => {}
            ("intel-tdx-upper-half-tamper", AttestError::ReportDataMismatch) => {}
            ("intel-tdx-non-intel-vendor", AttestError::Malformed(_)) => {}
            ("intel-tdx-att-key-type-epid", AttestError::Malformed(_)) => {}
            ("intel-tdx-signature-mismatch", AttestError::SignatureMismatch) => {}
            (tag, err) => {
                panic!("negative fixture tag {tag} rejected with unexpected error {err:?}")
            }
        }
    }
}

#[test]
fn integration_binds_kernel_pk_and_receipt_root_into_report_data() {
    // The headline integration assertion. Mirrors the trust-boundary
    // contract: a positive fixture's verified report_data MUST equal
    // SHA256(kernel_pk_canonical_bytes || receipt_root) padded with 32
    // zero bytes. Anything else is a regression.
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let verifier = TdxDcapVerifier::with_verification_time(collateral_at(now, "p256"), 7, now);
    let bytes = fs::read(fixtures_root().join("positive/kernel_seed_09_root_08.bin")).unwrap();

    let verified = verifier
        .verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(kernel.to_hex().as_bytes());
    hasher.update(receipt_root);
    let digest = hasher.finalize();
    assert_eq!(&verified.report_data[..32], digest.as_slice());
    assert_eq!(&verified.report_data[32..], &[0u8; 32]);
}

#[test]
fn integration_rejects_when_kernel_pk_does_not_match_fixture_binding() {
    let wrong_kernel = Keypair::from_seed(&[0xFE; 32]).public_key();
    let receipt_root = RECEIPT_ROOT;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let verifier = TdxDcapVerifier::with_verification_time(collateral_at(now, "p256"), 7, now);
    let bytes = fs::read(fixtures_root().join("positive/kernel_seed_09_root_08.bin")).unwrap();

    let error = verifier
        .verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&wrong_kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::ReportDataMismatch)));
}

#[test]
fn integration_rejects_when_receipt_root_does_not_match_fixture_binding() {
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let wrong_root = [0xFE; 32];
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let verifier = TdxDcapVerifier::with_verification_time(collateral_at(now, "p256"), 7, now);
    let bytes = fs::read(fixtures_root().join("positive/kernel_seed_09_root_08.bin")).unwrap();

    let error = verifier
        .verify_quote(&bytes, &QuoteVerificationContext::new(&kernel, &wrong_root))
        .err();

    assert!(matches!(error, Some(AttestError::ReportDataMismatch)));
}
