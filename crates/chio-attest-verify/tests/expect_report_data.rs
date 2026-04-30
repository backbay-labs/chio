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
