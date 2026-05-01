//! Trust-boundary tests for the `expect_report_data` binding helper.
//!
//! Every TDX, SEV-SNP, or Nitro backend MUST byte-compare the full
//! 64-byte report_data slot returned by this helper. These tests
//! enforce the byte layout (digest in 0..32, zeros in 32..64), the
//! order-sensitivity of the binding, and that the helper never returns
//! an all-zero slot for any valid kernel key plus receipt root pair.

use chio_attest_verify::expect_report_data;
use chio_core_types::crypto::Keypair;
use sha2::{Digest, Sha256};

#[test]
fn report_data_uses_digest_then_zero_padding() {
    let kernel = Keypair::from_seed(&[7u8; 32]).public_key();
    let receipt_root = [3u8; 32];

    let report_data = expect_report_data(&kernel, &receipt_root);

    let mut hasher = Sha256::new();
    hasher.update(kernel.to_hex().as_bytes());
    hasher.update(receipt_root);
    let digest = hasher.finalize();

    assert_eq!(&report_data[..32], digest.as_slice());
    assert_eq!(&report_data[32..], &[0u8; 32]);
}

#[test]
fn report_data_changes_when_kernel_key_changes() {
    let first = Keypair::from_seed(&[1u8; 32]).public_key();
    let second = Keypair::from_seed(&[2u8; 32]).public_key();
    let receipt_root = [4u8; 32];

    assert_ne!(
        expect_report_data(&first, &receipt_root),
        expect_report_data(&second, &receipt_root)
    );
}

#[test]
fn report_data_changes_when_receipt_root_changes() {
    let kernel = Keypair::from_seed(&[5u8; 32]).public_key();

    assert_ne!(
        expect_report_data(&kernel, &[6u8; 32]),
        expect_report_data(&kernel, &[7u8; 32])
    );
}

#[test]
fn report_data_is_never_all_zero_for_valid_inputs() {
    // SHA-256 of any non-empty message has cryptographically negligible
    // chance of being the all-zero digest. The full report_data slot
    // therefore MUST NOT match an "uninitialized" 64-byte zero buffer
    // for any kernel signing key plus receipt root pair the kernel can
    // produce. A backend that accepts an all-zero report_data is buggy.
    let kernel = Keypair::from_seed(&[0u8; 32]).public_key();
    let report_data = expect_report_data(&kernel, &[0u8; 32]);
    assert_ne!(report_data, [0u8; 64]);
    // The all-zero kernel key plus all-zero receipt root MUST still
    // yield a non-zero digest in the lower 32 bytes.
    assert_ne!(&report_data[..32], &[0u8; 32]);
}

#[test]
fn report_data_upper_half_is_always_zero_padding() {
    // The byte layout contract is: digest in 0..32, zero padding in
    // 32..64. Verifiers MUST byte-compare the full 64-byte slot, so
    // the upper half is part of the binding and MUST be zero for every
    // input pair the helper sees.
    for seed in 0u8..8 {
        let kernel = Keypair::from_seed(&[seed; 32]).public_key();
        for root_byte in 0u8..8 {
            let report_data = expect_report_data(&kernel, &[root_byte; 32]);
            assert_eq!(
                &report_data[32..],
                &[0u8; 32],
                "upper half of report_data must always be zero padding"
            );
        }
    }
}

#[test]
fn report_data_inputs_are_order_sensitive() {
    // Concatenation order in the digest input MUST be (kernel_pk ||
    // receipt_root). Swapping the inputs produces a different output:
    // an attacker who controls one of the two cannot replay the other
    // by reinterpreting bytes.
    let kernel_a = Keypair::from_seed(&[0xAA; 32]).public_key();
    let kernel_b = Keypair::from_seed(&[0xBB; 32]).public_key();
    let root_a = [0xCC; 32];
    let root_b = [0xDD; 32];
    assert_ne!(
        expect_report_data(&kernel_a, &root_b),
        expect_report_data(&kernel_b, &root_a),
    );
}

/// Trust-boundary check: a TDX backend MUST byte-compare the full
/// 64-byte report_data slot. Mutating just one byte in the upper
/// (zero-padding) half MUST cause verification to fail closed.
#[cfg(feature = "tee-quotes")]
#[test]
fn tdx_verifier_rejects_when_only_upper_half_of_report_data_is_tampered() -> Result<(), &'static str>
{
    use chio_attest_verify::tdx::{TdxCollateral, TdxDcapVerifier};
    use chio_attest_verify::{
        AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    };
    use p256::ecdsa::{
        signature::Signer as _, Signature as P256Signature, SigningKey, VerifyingKey,
    };
    use std::time::{Duration, SystemTime};

    const QUOTE_HEADER_LEN: usize = 48;
    const TD10_REPORT_LEN: usize = 584;
    const TD10_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
    const SIGNATURE_LEN_OFFSET: usize = QUOTE_HEADER_LEN + TD10_REPORT_LEN;
    const SIGNATURE_BYTES_OFFSET: usize = SIGNATURE_LEN_OFFSET + 4;

    const INTEL_SGX_QE_VENDOR_ID: [u8; 16] = [
        0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06,
        0x07,
    ];
    const P256_ATTESTATION_KEY_SEED: [u8; 32] = [0x25; 32];

    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let kernel = Keypair::from_seed(&[0x42; 32]).public_key();
    let receipt_root = [0x99; 32];

    let mut report_data = expect_report_data(&kernel, &receipt_root);
    // Touch a single byte in the upper half (the zero padding region).
    // The verifier MUST reject because it byte-compares the full slot.
    report_data[40] = 0x01;

    // Build a minimal TDX v4 quote that embeds the tampered report_data.
    let signature_len = 64usize;
    let mut quote = vec![0u8; SIGNATURE_BYTES_OFFSET + signature_len];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[2..4].copy_from_slice(&2u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes());
    quote[12..28].copy_from_slice(&INTEL_SGX_QE_VENDOR_ID);
    quote[TD10_REPORT_DATA_OFFSET..TD10_REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
    quote[SIGNATURE_LEN_OFFSET..SIGNATURE_LEN_OFFSET + 4]
        .copy_from_slice(&(signature_len as u32).to_le_bytes());
    let signing_key = SigningKey::from_bytes((&P256_ATTESTATION_KEY_SEED).into())
        .map_err(|_| "fixture P-256 signing key seed is invalid")?;
    let signature: P256Signature = signing_key.sign(&quote[..SIGNATURE_LEN_OFFSET]);
    quote[SIGNATURE_BYTES_OFFSET..SIGNATURE_BYTES_OFFSET + signature_len]
        .copy_from_slice(&signature.to_vec());

    let root = b"intel-root-ca-fixture".to_vec();
    let verifying_key = VerifyingKey::from(&signing_key);
    let collateral = TdxCollateral::new(
        root.clone(),
        vec![
            verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            root.clone(),
        ],
        vec![b"tcb-info-signing-fixture".to_vec(), root],
        7,
        QuoteTcbStatus::UpToDate,
        now - Duration::from_secs(60),
        now + Duration::from_secs(60),
    );
    let verifier = TdxDcapVerifier::with_verification_time(collateral, 7, now);

    let error = verifier
        .verify_quote(
            &quote,
            &QuoteVerificationContext::new(&kernel, &receipt_root),
        )
        .err();

    match error {
        Some(AttestError::ReportDataMismatch) => Ok(()),
        Some(other) => Err({
            // Diagnostic: the verifier rejected, but for the wrong reason.
            let _ = other;
            "expected ReportDataMismatch from upper-half tamper, got a different error"
        }),
        None => Err("verifier accepted a quote with tampered upper-half report_data"),
    }
}
