#![cfg(feature = "tee-quotes")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Cross-backend conformance test.
//!
//! Each backend's verifier rejects fixtures meant for the other two
//! backends. Catches type-confusion bugs that an attacker could exploit
//! by mislabelling a quote (e.g. presenting a SEV-SNP envelope to a TDX
//! verifier).
//!
//! The contract is mechanical: each fixture's kind is determined
//! by which directory tree it lives in. Fixtures under
//! `fixtures/quotes/tdx/` are TDX. Fixtures under
//! `fixtures/quotes/sev_snp/` are SEV-SNP. Fixtures under
//! `fixtures/quotes/nitro/` are Nitro. Each backend MUST reject every
//! fixture not produced for its own kind. The corpus also follows a
//! filename prefix convention (`tdx_*.bin`, `sev_snp_*.bin`,
//! `nitro_*.bin`) so the gate-side
//! `grep -qE '/(tdx_|sev_snp_|nitro_)'` check passes.
//!
//! Backends are configured with the same collateral shapes their
//! own corpus integration tests use, so positive fixtures still
//! verify and only mislabelled / cross-backend fixtures are
//! rejected.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chio_attest_verify::nitro::{NitroCollateral, NitroVerifier};
use chio_attest_verify::sev_snp::{SevSnpCollateral, SevSnpVerifier};
use chio_attest_verify::tdx::{TdxCollateral, TdxDcapVerifier};
use chio_attest_verify::{AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier};
use chio_core_types::crypto::Keypair;

const KERNEL_SEED: [u8; 32] = [9u8; 32];
const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
const SEV_SNP_PINNED_LAUNCH_DIGEST: [u8; 48] = [0x4Cu8; 48];
const NITRO_PINNED_PCR0: [u8; 48] = [0x77u8; 48];

const NITRO_LEAF_FIXTURE: &[u8] = b"aws-nitro-leaf-fixture";
const NITRO_INTERMEDIATE_FIXTURE: &[u8] = b"aws-nitro-intermediate-fixture";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn fixtures_root_for(kind: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/quotes")
        .join(kind)
}

fn read_all_bins(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for sub in ["positive", "negative"] {
        let dir = root.join(sub);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) == Some("bin") {
                let bytes = fs::read(&path).unwrap();
                out.push((path, bytes));
            }
        }
    }
    out
}

fn aws_nitro_root_bytes() -> Vec<u8> {
    let pem = include_bytes!("../fixtures/nitro/aws-nitro-root.pem");
    pem.to_vec()
}

fn tdx_verifier(now: SystemTime) -> TdxDcapVerifier {
    let root = b"intel-root-ca-fixture".to_vec();
    let collateral = TdxCollateral::new(
        root.clone(),
        vec![b"pck-leaf-fixture".to_vec(), root.clone()],
        vec![b"tcb-info-signing-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    );
    TdxDcapVerifier::with_verification_time(collateral, 7, now)
}

fn sev_snp_verifier(now: SystemTime) -> SevSnpVerifier {
    let root = b"amd-kds-root-fixture".to_vec();
    let collateral = SevSnpCollateral::new(
        root.clone(),
        vec![b"amd-vcek-leaf-fixture".to_vec(), root.clone()],
        vec![b"amd-vlek-leaf-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    );
    SevSnpVerifier::with_verification_time(collateral, 7, SEV_SNP_PINNED_LAUNCH_DIGEST, now)
}

fn nitro_verifier(now: SystemTime) -> NitroVerifier {
    let collateral = NitroCollateral::new(
        aws_nitro_root_bytes(),
        vec![
            NITRO_LEAF_FIXTURE.to_vec(),
            NITRO_INTERMEDIATE_FIXTURE.to_vec(),
            aws_nitro_root_bytes(),
        ],
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    );
    NitroVerifier::with_verification_time(collateral, NITRO_PINNED_PCR0, now)
}

#[test]
fn tdx_backend_rejects_sev_snp_and_nitro_fixtures() {
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let v = tdx_verifier(now());

    let mut foreign: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    foreign.extend(read_all_bins(&fixtures_root_for("sev_snp")));
    foreign.extend(read_all_bins(&fixtures_root_for("nitro")));
    assert!(
        !foreign.is_empty(),
        "expected non-empty SEV-SNP and Nitro fixture corpora"
    );

    for (path, bytes) in foreign {
        let result = v.verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        );
        match result {
            Ok(_) => panic!(
                "TDX backend MUST NOT accept foreign fixture at {}",
                path.display()
            ),
            Err(AttestError::Malformed(_))
            | Err(AttestError::ReportDataMismatch)
            | Err(AttestError::TrustRoot)
            | Err(AttestError::QuoteRejected(_)) => {}
            Err(other) => panic!(
                "TDX backend rejected foreign fixture at {} with unexpected error {other:?}",
                path.display()
            ),
        }
    }
}

#[test]
fn sev_snp_backend_rejects_tdx_and_nitro_fixtures() {
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let v = sev_snp_verifier(now());

    let mut foreign: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    foreign.extend(read_all_bins(&fixtures_root_for("tdx")));
    foreign.extend(read_all_bins(&fixtures_root_for("nitro")));
    assert!(
        !foreign.is_empty(),
        "expected non-empty TDX and Nitro fixture corpora"
    );

    for (path, bytes) in foreign {
        let result = v.verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        );
        match result {
            Ok(_) => panic!(
                "SEV-SNP backend MUST NOT accept foreign fixture at {}",
                path.display()
            ),
            Err(AttestError::Malformed(_))
            | Err(AttestError::ReportDataMismatch)
            | Err(AttestError::TrustRoot)
            | Err(AttestError::QuoteRejected(_)) => {}
            Err(other) => panic!(
                "SEV-SNP backend rejected foreign fixture at {} with unexpected error {other:?}",
                path.display()
            ),
        }
    }
}

#[test]
fn nitro_backend_rejects_tdx_and_sev_snp_fixtures() {
    let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
    let receipt_root = RECEIPT_ROOT;
    let v = nitro_verifier(now());

    let mut foreign: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    foreign.extend(read_all_bins(&fixtures_root_for("tdx")));
    foreign.extend(read_all_bins(&fixtures_root_for("sev_snp")));
    assert!(
        !foreign.is_empty(),
        "expected non-empty TDX and SEV-SNP fixture corpora"
    );

    for (path, bytes) in foreign {
        let result = v.verify_quote(
            &bytes,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        );
        match result {
            Ok(_) => panic!(
                "Nitro backend MUST NOT accept foreign fixture at {}",
                path.display()
            ),
            Err(AttestError::Malformed(_))
            | Err(AttestError::ReportDataMismatch)
            | Err(AttestError::TrustRoot)
            | Err(AttestError::QuoteRejected(_)) => {}
            Err(other) => panic!(
                "Nitro backend rejected foreign fixture at {} with unexpected error {other:?}",
                path.display()
            ),
        }
    }
}

#[test]
fn corpus_filename_prefix_convention_is_present_for_forward_kinds() {
    // The SEV-SNP and Nitro corpora landing in P4 follow the
    // `<kind>_*.bin` convention. Pin that here so the gate-side
    // grep for /(tdx_|sev_snp_|nitro_)/ keeps passing.
    let sev_snp_root = fixtures_root_for("sev_snp");
    let mut sev_snp_count = 0usize;
    for (path, _) in read_all_bins(&sev_snp_root) {
        let stem = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        assert!(
            stem.starts_with("sev_snp_"),
            "SEV-SNP fixture must be named sev_snp_*.bin: {}",
            path.display()
        );
        sev_snp_count += 1;
    }
    assert!(sev_snp_count >= 8, "expected >=8 SEV-SNP fixtures total");

    let nitro_root = fixtures_root_for("nitro");
    let mut nitro_count = 0usize;
    for (path, _) in read_all_bins(&nitro_root) {
        let stem = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        assert!(
            stem.starts_with("nitro_"),
            "Nitro fixture must be named nitro_*.bin: {}",
            path.display()
        );
        nitro_count += 1;
    }
    assert!(nitro_count >= 8, "expected >=8 Nitro fixtures total");
}
