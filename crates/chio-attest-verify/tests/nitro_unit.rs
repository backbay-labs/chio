#![cfg(feature = "tee-quotes")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::vec_init_then_push)]

//! Unit coverage for the AWS Nitro NSM backend.
//!
//! Mirrors the shape of `tdx_unit.rs` and `sev_snp_unit.rs`: a
//! deterministic envelope builder, positive verification, and a
//! battery of fail-closed rejections that pin the trust-boundary
//! contract.

use std::time::{Duration, SystemTime};

use chio_attest_verify::nitro::{
    NitroCollateral, NitroVerifier, NITRO_PCR_LEN, NITRO_USER_DATA_LEN,
};
use chio_attest_verify::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind,
};
use chio_core_types::crypto::Keypair;
use coset::cbor::Value as CborValue;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::{signature::Signer as _, Signature as P384Signature, SigningKey, VerifyingKey};

const PINNED_PCR0: [u8; NITRO_PCR_LEN] = [0x77u8; NITRO_PCR_LEN];
const TIMESTAMP_MS: u64 = 1_700_000_000_000;

const NITRO_ATTESTATION_KEY_SEED: [u8; 48] = [0x42u8; 48];
const NITRO_INTERMEDIATE_FIXTURE: &[u8] = b"aws-nitro-intermediate-fixture";

fn aws_nitro_root_bytes() -> Vec<u8> {
    let pem = include_bytes!("../fixtures/nitro/aws-nitro-root.pem");
    pem.to_vec()
}

fn nitro_attestation_signing_key() -> SigningKey {
    SigningKey::from_bytes((&NITRO_ATTESTATION_KEY_SEED).into()).unwrap()
}

fn nitro_attestation_public_key() -> Vec<u8> {
    let signing_key = nitro_attestation_signing_key();
    let verifying_key = VerifyingKey::from(&signing_key);
    verifying_key.to_encoded_point(false).as_bytes().to_vec()
}

fn sign_nitro_message(message: &[u8]) -> Vec<u8> {
    let signature: P384Signature = nitro_attestation_signing_key().sign(message);
    signature.to_vec()
}

#[derive(Clone, Debug)]
struct DocOpts {
    module_id: String,
    timestamp: u64,
    pcr0: [u8; NITRO_PCR_LEN],
    certificate: Vec<u8>,
    user_data: [u8; NITRO_USER_DATA_LEN],
}

impl DocOpts {
    fn bound(user_data: [u8; NITRO_USER_DATA_LEN], pcr0: [u8; NITRO_PCR_LEN]) -> Self {
        Self {
            module_id: "i-0123456789abcdef0-enc01234567890abcd".to_string(),
            timestamp: TIMESTAMP_MS,
            pcr0,
            certificate: nitro_attestation_public_key(),
            user_data,
        }
    }
}

fn build_document(opts: &DocOpts) -> Vec<u8> {
    let mut entries: Vec<(CborValue, CborValue)> = Vec::new();
    entries.push((
        CborValue::Text("module_id".to_string()),
        CborValue::Text(opts.module_id.clone()),
    ));
    entries.push((
        CborValue::Text("timestamp".to_string()),
        CborValue::Integer(opts.timestamp.into()),
    ));
    let mut pcrs: Vec<(CborValue, CborValue)> = Vec::new();
    pcrs.push((
        CborValue::Integer(0_i64.into()),
        CborValue::Bytes(opts.pcr0.to_vec()),
    ));
    pcrs.push((
        CborValue::Integer(1_i64.into()),
        CborValue::Bytes(vec![0u8; NITRO_PCR_LEN]),
    ));
    entries.push((CborValue::Text("pcrs".to_string()), CborValue::Map(pcrs)));
    entries.push((
        CborValue::Text("certificate".to_string()),
        CborValue::Bytes(opts.certificate.clone()),
    ));
    entries.push((
        CborValue::Text("cabundle".to_string()),
        CborValue::Array(vec![
            CborValue::Bytes(NITRO_INTERMEDIATE_FIXTURE.to_vec()),
            CborValue::Bytes(aws_nitro_root_bytes()),
        ]),
    ));
    entries.push((
        CborValue::Text("user_data".to_string()),
        CborValue::Bytes(opts.user_data.to_vec()),
    ));
    let mut payload = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut payload).unwrap();
    payload
}

fn build_envelope(opts: &DocOpts) -> Vec<u8> {
    let payload = build_document(opts);
    signed_envelope(payload)
}

fn signed_envelope(payload: Vec<u8>) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES384)
                .build(),
        )
        .payload(payload)
        .create_signature(b"", sign_nitro_message)
        .build()
        .to_vec()
        .unwrap()
}

fn raw_envelope(payload: Vec<u8>, signature: Vec<u8>) -> Vec<u8> {
    let mut builder = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES384)
                .build(),
        )
        .payload(payload);
    if !signature.is_empty() {
        builder = builder.signature(signature);
    }
    builder.build().to_vec().unwrap()
}

fn raw_envelope_no_payload(signature: Vec<u8>) -> Vec<u8> {
    let mut builder = CoseSign1Builder::new().protected(
        HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES384)
            .build(),
    );
    if !signature.is_empty() {
        builder = builder.signature(signature);
    }
    builder.build().to_vec().unwrap()
}

fn collateral(now: SystemTime) -> NitroCollateral {
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

fn verifier(now: SystemTime) -> NitroVerifier {
    NitroVerifier::with_verification_time(collateral(now), PINNED_PCR0, now)
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn kernel_and_root() -> (chio_core_types::crypto::PublicKey, [u8; 32]) {
    (Keypair::from_seed(&[9u8; 32]).public_key(), [8u8; 32])
}

#[test]
fn nitro_verifier_accepts_bound_document() -> Result<(), String> {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(&DocOpts::bound(bound, PINNED_PCR0));
    let v = verifier(now());

    let verified = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .map_err(|error| format!("{error}"))?;

    assert_eq!(verified.tee_kind, TeeKind::AwsNitro);
    assert_eq!(verified.report_data, bound);
    assert_eq!(verified.tcb_status, QuoteTcbStatus::UpToDate);
    Ok(())
}

#[test]
fn nitro_verifier_rejects_mismatched_user_data() {
    let (kernel, receipt_root) = kernel_and_root();
    let envelope = build_envelope(&DocOpts::bound([0xAA; 64], PINNED_PCR0));
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
fn nitro_verifier_rejects_mismatched_pcr0() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(&DocOpts::bound(bound, [0x11; NITRO_PCR_LEN]));
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
fn nitro_verifier_rejects_missing_root() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(&DocOpts::bound(bound, PINNED_PCR0));
    let mut bad = collateral(now());
    bad.aws_nitro_root_der.clear();
    let v = NitroVerifier::with_verification_time(bad, PINNED_PCR0, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn nitro_verifier_rejects_chain_consisting_only_of_root() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(&DocOpts::bound(bound, PINNED_PCR0));
    let mut bad = collateral(now());
    bad.chain_der = vec![aws_nitro_root_bytes()];
    let v = NitroVerifier::with_verification_time(bad, PINNED_PCR0, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn nitro_verifier_rejects_chain_with_empty_link() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let envelope = build_envelope(&DocOpts::bound(bound, PINNED_PCR0));
    let mut bad = collateral(now());
    bad.chain_der = vec![
        nitro_attestation_public_key(),
        Vec::new(),
        aws_nitro_root_bytes(),
    ];
    let v = NitroVerifier::with_verification_time(bad, PINNED_PCR0, now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn nitro_verifier_rejects_document_certificate_not_matching_chain_leaf() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut opts = DocOpts::bound(bound, PINNED_PCR0);
    opts.certificate = b"adversary-leaf".to_vec();
    let envelope = build_envelope(&opts);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::TrustRoot)));
}

#[test]
fn nitro_verifier_rejects_signature_mismatch() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let payload = build_document(&DocOpts::bound(bound, PINNED_PCR0));
    let envelope = raw_envelope(payload, vec![0xAB; 96]);
    let v = verifier(now());

    let error = v
        .verify_quote(
            &envelope,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::SignatureMismatch)));
}

#[test]
fn nitro_verifier_rejects_empty_signature() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let payload = build_document(&DocOpts::bound(bound, PINNED_PCR0));
    let envelope = raw_envelope(payload, Vec::new());
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
fn nitro_verifier_rejects_user_data_wrong_length() {
    let (kernel, receipt_root) = kernel_and_root();
    let mut entries: Vec<(CborValue, CborValue)> = Vec::new();
    entries.push((
        CborValue::Text("module_id".to_string()),
        CborValue::Text("module".to_string()),
    ));
    entries.push((
        CborValue::Text("timestamp".to_string()),
        CborValue::Integer(TIMESTAMP_MS.into()),
    ));
    let pcrs = vec![(
        CborValue::Integer(0_i64.into()),
        CborValue::Bytes(PINNED_PCR0.to_vec()),
    )];
    entries.push((CborValue::Text("pcrs".to_string()), CborValue::Map(pcrs)));
    entries.push((
        CborValue::Text("certificate".to_string()),
        CborValue::Bytes(nitro_attestation_public_key()),
    ));
    entries.push((
        CborValue::Text("user_data".to_string()),
        CborValue::Bytes(vec![0u8; 32]),
    ));
    let mut payload = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut payload).unwrap();

    let envelope = raw_envelope(payload, vec![0xAB; 96]);
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
fn nitro_verifier_rejects_pcr0_wrong_length() {
    let (kernel, receipt_root) = kernel_and_root();
    let bound = expect_report_data(&kernel, &receipt_root);
    let mut entries: Vec<(CborValue, CborValue)> = Vec::new();
    entries.push((
        CborValue::Text("module_id".to_string()),
        CborValue::Text("module".to_string()),
    ));
    entries.push((
        CborValue::Text("timestamp".to_string()),
        CborValue::Integer(TIMESTAMP_MS.into()),
    ));
    let pcrs = vec![(
        CborValue::Integer(0_i64.into()),
        CborValue::Bytes(vec![0u8; 16]),
    )];
    entries.push((CborValue::Text("pcrs".to_string()), CborValue::Map(pcrs)));
    entries.push((
        CborValue::Text("certificate".to_string()),
        CborValue::Bytes(nitro_attestation_public_key()),
    ));
    entries.push((
        CborValue::Text("user_data".to_string()),
        CborValue::Bytes(bound.to_vec()),
    ));
    let mut payload = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut payload).unwrap();
    let envelope = raw_envelope(payload, vec![0xAB; 96]);
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
fn nitro_verifier_rejects_payload_not_cbor() {
    let (kernel, receipt_root) = kernel_and_root();
    let envelope = raw_envelope(b"not-a-cbor-document".to_vec(), vec![0xAB; 96]);
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
fn nitro_verifier_rejects_garbage_envelope() {
    let (kernel, receipt_root) = kernel_and_root();
    let v = verifier(now());

    let error = v
        .verify_quote(
            b"not-a-cose-sign1-envelope",
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    assert!(matches!(error, Some(AttestError::Malformed(_))));
}

#[test]
fn nitro_verifier_rejects_missing_payload() {
    let (kernel, receipt_root) = kernel_and_root();
    let envelope = raw_envelope_no_payload(vec![0xAB; 96]);
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
fn nitro_aws_root_pem_is_present_and_nonempty() {
    let pem = include_bytes!("../fixtures/nitro/aws-nitro-root.pem");
    assert!(!pem.is_empty());
    let header = b"-----BEGIN CERTIFICATE-----";
    assert!(pem.windows(header.len()).any(|w| w == header));
}
