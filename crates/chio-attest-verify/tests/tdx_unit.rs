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

fn fixture_quote(report_data: [u8; 64]) -> Vec<u8> {
    let signature_len = 1usize;
    let mut quote = vec![0u8; SIGNATURE_BYTES_OFFSET + signature_len];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[2..4].copy_from_slice(&2u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes());
    quote[TD10_REPORT_DATA_OFFSET..TD10_REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
    quote[SIGNATURE_LEN_OFFSET..SIGNATURE_LEN_OFFSET + 4]
        .copy_from_slice(&(signature_len as u32).to_le_bytes());
    quote[SIGNATURE_BYTES_OFFSET] = 0xA5;
    quote
}
