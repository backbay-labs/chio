#![cfg(feature = "tee-quotes")]

//! Unit coverage for the AMD SEV-SNP backend.
//!
//! Mirrors the shape of `tdx_unit.rs`: a deterministic envelope
//! builder, positive verification, and a battery of fail-closed
//! rejections that pin the trust-boundary contract.

use std::time::{Duration, SystemTime};

use chio_attest_verify::sev_snp::{
    SevSnpCollateral, SevSnpVerifier, SEV_SNP_MEASUREMENT_OFFSET, SEV_SNP_REPORT_DATA_OFFSET,
    SEV_SNP_REPORT_VERSION,
};
use chio_attest_verify::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind,
};
use chio_core_types::crypto::Keypair;

const SEV_SNP_HEADER_AND_BODY_LEN: usize = 0x300;
const SEV_SNP_VERSION_OFFSET: usize = 0;
const SEV_SNP_VMPL_OFFSET: usize = 12;
const SEV_SNP_SIG_ALGO_OFFSET: usize = 16;
const SEV_SNP_KEY_SELECT_OFFSET: usize = 20;
const SEV_SNP_REPORTED_TCB_OFFSET: usize = 24;
const SEV_SNP_SIGNATURE_LEN_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN - 4;
const SEV_SNP_SIGNATURE_BYTES_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN;

const SIG_ALGO_ECDSA_P384_VCEK: u32 = 0x01;
const SIG_ALGO_ECDSA_P384_VLEK: u32 = 0x02;
const KEY_SELECT_VCEK: u8 = 0x00;
const KEY_SELECT_VLEK: u8 = 0x01;

const PINNED_LAUNCH_DIGEST: [u8; 48] = [0x4Cu8; 48];

#[derive(Clone, Copy)]
struct EnvelopeOpts {
    version: u32,
    vmpl: u32,
    sig_algo: u32,
    key_select: u8,
    reported_tcb: u32,
    measurement: [u8; 48],
    report_data: [u8; 64],
    sig_byte: u8,
}

impl EnvelopeOpts {
    fn vcek_bound(report_data: [u8; 64], measurement: [u8; 48]) -> Self {
        Self {
            version: SEV_SNP_REPORT_VERSION,
            vmpl: 0,
            sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
            key_select: KEY_SELECT_VCEK,
            reported_tcb: 0x1234_5678,
            measurement,
            report_data,
            sig_byte: 0xA1,
        }
    }

    fn vlek_bound(report_data: [u8; 64], measurement: [u8; 48]) -> Self {
        Self {
            version: SEV_SNP_REPORT_VERSION,
            vmpl: 0,
            sig_algo: SIG_ALGO_ECDSA_P384_VLEK,
            key_select: KEY_SELECT_VLEK,
            reported_tcb: 0x1234_5678,
            measurement,
            report_data,
            sig_byte: 0xA2,
        }
    }
}

fn build_envelope(opts: EnvelopeOpts) -> Vec<u8> {
    let signature_len = 1usize;
    let mut quote = vec![0u8; SEV_SNP_SIGNATURE_BYTES_OFFSET + signature_len];
    quote[SEV_SNP_VERSION_OFFSET..SEV_SNP_VERSION_OFFSET + 4]
        .copy_from_slice(&opts.version.to_le_bytes());
    quote[SEV_SNP_VMPL_OFFSET..SEV_SNP_VMPL_OFFSET + 4].copy_from_slice(&opts.vmpl.to_le_bytes());
    quote[SEV_SNP_SIG_ALGO_OFFSET..SEV_SNP_SIG_ALGO_OFFSET + 4]
        .copy_from_slice(&opts.sig_algo.to_le_bytes());
    quote[SEV_SNP_KEY_SELECT_OFFSET] = opts.key_select;
    quote[SEV_SNP_REPORTED_TCB_OFFSET..SEV_SNP_REPORTED_TCB_OFFSET + 4]
        .copy_from_slice(&opts.reported_tcb.to_le_bytes());
    quote[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48]
        .copy_from_slice(&opts.measurement);
    quote[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
        .copy_from_slice(&opts.report_data);
    quote[SEV_SNP_SIGNATURE_LEN_OFFSET..SEV_SNP_SIGNATURE_LEN_OFFSET + 4]
        .copy_from_slice(&(signature_len as u32).to_le_bytes());
    quote[SEV_SNP_SIGNATURE_BYTES_OFFSET] = opts.sig_byte;
    quote
}

fn collateral(now: SystemTime) -> SevSnpCollateral {
    let root = b"amd-kds-root-fixture".to_vec();
    SevSnpCollateral::new(
        root.clone(),
        vec![b"amd-vcek-leaf-fixture".to_vec(), root.clone()],
        vec![b"amd-vlek-leaf-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    )
}

fn verifier(now: SystemTime) -> SevSnpVerifier {
    SevSnpVerifier::with_verification_time(collateral(now), 7, PINNED_LAUNCH_DIGEST, now)
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn kernel_and_root() -> (chio_core_types::crypto::PublicKey, [u8; 32]) {
    (Keypair::from_seed(&[9u8; 32]).public_key(), [8u8; 32])
}

#[test]
fn sev_snp_verifier_accepts_bound_vcek_quote() -> Result<(), String> {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    let v = verifier(now());

    let verified = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .map_err(|error| format!("{error}"))?;

    assert_eq!(verified.tee_kind, TeeKind::AmdSevSnp);
    assert_eq!(verified.report_data, bound);
    assert_eq!(verified.tcb_status, QuoteTcbStatus::UpToDate);
    assert_eq!(verified.signed_at, now());
    Ok(())
}

#[test]
fn sev_snp_verifier_accepts_bound_vlek_quote() -> Result<(), String> {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vlek_bound(bound, PINNED_LAUNCH_DIGEST));
    let v = verifier(now());

    let verified = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .map_err(|error| format!("{error}"))?;

    assert_eq!(verified.tee_kind, TeeKind::AmdSevSnp);
    assert_eq!(verified.report_data, bound);
    Ok(())
}

#[test]
fn sev_snp_verifier_rejects_mismatched_report_data() {
    let (kernel, receipt_root) = kernel_and_root();
    let envelope = build_envelope(EnvelopeOpts::vcek_bound([0xAA; 64], PINNED_LAUNCH_DIGEST));
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::ReportDataMismatch)));
}

#[test]
fn sev_snp_verifier_rejects_mismatched_launch_digest() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, [0x11; 48]));
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::QuoteRejected(_))));
}

#[test]
fn sev_snp_verifier_rejects_missing_amd_root() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    let mut bad = collateral(now());
    bad.amd_kds_root_der.clear();
    let v = SevSnpVerifier::with_verification_time(bad, 7, PINNED_LAUNCH_DIGEST, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn sev_snp_verifier_rejects_vcek_chain_consisting_only_of_root() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    let mut bad = collateral(now());
    let root = bad.amd_kds_root_der.clone();
    bad.vcek_chain_der = vec![root];
    let v = SevSnpVerifier::with_verification_time(bad, 7, PINNED_LAUNCH_DIGEST, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn sev_snp_verifier_rejects_vlek_chain_with_empty_link() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vlek_bound(bound, PINNED_LAUNCH_DIGEST));
    let mut bad = collateral(now());
    let root = bad.amd_kds_root_der.clone();
    bad.vlek_chain_der = vec![Vec::new(), root];
    let v = SevSnpVerifier::with_verification_time(bad, 7, PINNED_LAUNCH_DIGEST, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn sev_snp_verifier_rejects_stale_tcb_recovery_event_id() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    let v =
        SevSnpVerifier::with_verification_time(collateral(now()), 8, PINNED_LAUNCH_DIGEST, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::QuoteRejected(_))));
}

#[test]
fn sev_snp_verifier_rejects_unsupported_version() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.version = 99;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_out_of_range_vmpl() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.vmpl = 4;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_unknown_sig_algo() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.sig_algo = 0x09;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_unknown_key_select() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.key_select = 0x77;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_sig_algo_key_select_mismatch() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    // VCEK sig_algo with VLEK key_select: type-confusion bait.
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.key_select = KEY_SELECT_VLEK;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_zero_reported_tcb() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST);
    opts.reported_tcb = 0;
    let envelope = build_envelope(opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_short_envelope() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope[..32],
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn sev_snp_verifier_rejects_signature_length_mismatch() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut envelope = build_envelope(EnvelopeOpts::vcek_bound(bound, PINNED_LAUNCH_DIGEST));
    // Declare a longer signature than is actually present in the buffer.
    envelope[SEV_SNP_SIGNATURE_LEN_OFFSET..SEV_SNP_SIGNATURE_LEN_OFFSET + 4]
        .copy_from_slice(&64u32.to_le_bytes());
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}
