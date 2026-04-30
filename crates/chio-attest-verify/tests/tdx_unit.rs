#![cfg(feature = "tee-quotes")]

use std::time::{Duration, SystemTime};

use chio_attest_verify::tdx::{TdxCollateral, TdxDcapVerifier};
use chio_attest_verify::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind,
};
use chio_core_types::crypto::Keypair;

const QUOTE_HEADER_LEN: usize = 48;
const TD10_REPORT_LEN: usize = 584;
const TD10_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
const SIGNATURE_LEN_OFFSET: usize = QUOTE_HEADER_LEN + TD10_REPORT_LEN;
const SIGNATURE_BYTES_OFFSET: usize = SIGNATURE_LEN_OFFSET + 4;

#[test]
fn tdx_verifier_accepts_bound_quote_with_current_collateral() -> Result<(), String> {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 7, now);

    let verified = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .map_err(|error| format!("{error}"));

    let verified = verified?;
    assert_eq!(verified.tee_kind, TeeKind::IntelTdx);
    assert_eq!(
        verified.report_data,
        expect_report_data(&kernel, &receipt_root)
    );
    assert_eq!(verified.tcb_status, QuoteTcbStatus::UpToDate);
    assert_eq!(verified.signed_at, now);
    Ok(())
}

#[test]
fn tdx_verifier_rejects_mismatched_report_data() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote([0xAA; 64]);
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::ReportDataMismatch)));
}

#[test]
fn tdx_verifier_rejects_missing_collateral_root() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    let mut collateral = collateral(now);
    collateral.intel_root_ca_der.clear();
    let verifier = TdxDcapVerifier::with_verification_time(collateral, 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn tdx_verifier_rejects_stale_tcb_recovery_event_id() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 8, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::QuoteRejected(_))));
}

#[test]
fn tdx_verifier_rejects_non_intel_qe_vendor_id() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let mut quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    // Flip the vendor id to a non-Intel value.
    quote[12..28].copy_from_slice(&[0xDE; 16]);
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn tdx_verifier_rejects_unsupported_att_key_type() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let mut quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    // EPID-style (1) is invalid for TDX; backend MUST reject.
    quote[2..4].copy_from_slice(&1u16.to_le_bytes());
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn tdx_verifier_rejects_collateral_chain_consisting_only_of_root() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    let mut bad = collateral(now);
    let root = bad.intel_root_ca_der.clone();
    // Chain whose only link is the root: no real leaf, no real intermediate.
    bad.pck_certificate_chain_der = vec![root];
    let verifier = TdxDcapVerifier::with_verification_time(bad, 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn tdx_verifier_rejects_collateral_chain_with_empty_link() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let quote = fixture_quote(expect_report_data(&kernel, &receipt_root));
    let mut bad = collateral(now);
    let root = bad.intel_root_ca_der.clone();
    // Empty link forbidden: an attacker MUST NOT smuggle a "missing"
    // intermediate past the chain check.
    bad.tcb_info_issuer_chain_der = vec![Vec::new(), root];
    let verifier = TdxDcapVerifier::with_verification_time(bad, 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn tdx_verifier_rejects_malformed_or_wrong_tee_quote() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let verifier = TdxDcapVerifier::with_verification_time(collateral(now), 7, now);
    let mut wrong_tee = fixture_quote(expect_report_data(&kernel, &receipt_root));
    wrong_tee[4..8].copy_from_slice(&0u32.to_le_bytes());

    let short_error = verifier
        .verify_quote(
            &wrong_tee[..32],
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();
    let wrong_tee_error = verifier
        .verify_quote(
            &wrong_tee,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(short_error, Some(AttestError::Malformed(_))));
    assert!(matches!(wrong_tee_error, Some(AttestError::Malformed(_))));
}

fn collateral(now: SystemTime) -> TdxCollateral {
    let root = b"intel-root-ca-fixture".to_vec();
    TdxCollateral::new(
        root.clone(),
        vec![b"pck-leaf-fixture".to_vec(), root.clone()],
        vec![b"tcb-info-signing-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

const INTEL_SGX_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

fn fixture_quote(report_data: [u8; 64]) -> Vec<u8> {
    let signature_len = 1usize;
    let mut quote = vec![0u8; SIGNATURE_BYTES_OFFSET + signature_len];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[2..4].copy_from_slice(&2u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes());
    quote[12..28].copy_from_slice(&INTEL_SGX_QE_VENDOR_ID);
    quote[TD10_REPORT_DATA_OFFSET..TD10_REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
    quote[SIGNATURE_LEN_OFFSET..SIGNATURE_LEN_OFFSET + 4]
        .copy_from_slice(&(signature_len as u32).to_le_bytes());
    quote[SIGNATURE_BYTES_OFFSET] = 0xA5;
    quote
}
