//! Corpus-level integration coverage for the AMD SEV-SNP backend.
//!
//! Consumes the pinned fixture corpus written by the
//! `generate_sev_snp_fixtures` example. Each fixture envelope mirrors
//! the deterministic subset of the AMD SEV-SNP attestation report
//! shape exercised by `tests/sev_snp_unit.rs`. The corpus locks the
//! file path, role, role tag, and SHA256 contract reviewers diff
//! against.
//!
//! Positive coverage: every fixture under
//! `fixtures/quotes/sev_snp/positive/` verifies under the kernel
//! signing key, receipt root, and launch digest the generator pinned
//! in MANIFEST.toml.
//!
//! Negative coverage: every fixture under
//! `fixtures/quotes/sev_snp/negative/` is rejected by the verifier
//! with the expected fail-closed reason. The corpus pins both stale
//! TCB (`amd-sev-snp-stale-tcb-marker`) and mismatched launch digest
//! (`amd-sev-snp-launch-digest-mismatch`) cases; the gate check trips
//! when either rejection regresses.
//!
//! Manifest contract: every binary file referenced by MANIFEST.toml
//! is re-hashed at test time and compared to the manifest's pinned
//! SHA256. A drifted fixture (manifest vs disk) fails the test before
//! any verifier work runs.

#![cfg(feature = "tee-quotes")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chio_attest_verify::sev_snp::{SevSnpCollateral, SevSnpVerifier};
use chio_attest_verify::{
    AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier, TeeKind,
};
use chio_core_types::crypto::Keypair;
use p384::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const FIXTURES_DIR: &str = "fixtures/quotes/sev_snp";
const KERNEL_SEED: [u8; 32] = [9u8; 32];
const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
const PINNED_LAUNCH_DIGEST: [u8; 48] = [0x4Cu8; 48];
const VCEK_ATTESTATION_KEY_SEED: [u8; 48] = [0x43u8; 48];
const VLEK_ATTESTATION_KEY_SEED: [u8; 48] = [0x44u8; 48];

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_DIR)
}

fn manifest_text() -> String {
    fs::read_to_string(fixtures_root().join("MANIFEST.toml"))
        .expect("MANIFEST.toml must exist; run the generate_sev_snp_fixtures example to regenerate")
}

fn attestation_public_key(seed: &[u8; 48]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(seed.into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);
    verifying_key.to_encoded_point(false).as_bytes().to_vec()
}

fn collateral_at(now: SystemTime) -> SevSnpCollateral {
    let root = b"amd-kds-root-fixture".to_vec();
    SevSnpCollateral::new(
        root.clone(),
        vec![
            attestation_public_key(&VCEK_ATTESTATION_KEY_SEED),
            root.clone(),
        ],
        vec![attestation_public_key(&VLEK_ATTESTATION_KEY_SEED), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

fn verifier_at(now: SystemTime) -> SevSnpVerifier {
    SevSnpVerifier::with_verification_time(collateral_at(now), 7, PINNED_LAUNCH_DIGEST, now)
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
    let verifier = verifier_at(now);
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
        assert_eq!(verified.tee_kind, TeeKind::AmdSevSnp);
        assert!(verified.tcb_acceptable());
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
    let verifier = verifier_at(now);
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
            ("amd-sev-snp-report-data-mismatch", AttestError::ReportDataMismatch) => {}
            ("amd-sev-snp-launch-digest-mismatch", AttestError::QuoteRejected(_)) => {}
            ("amd-sev-snp-stale-tcb-marker", AttestError::Malformed(_)) => {}
            ("amd-sev-snp-sig-algo-key-select-mismatch", AttestError::Malformed(_)) => {}
            (tag, err) => {
                panic!("negative fixture tag {tag} rejected with unexpected error {err:?}")
            }
        }
    }
}
