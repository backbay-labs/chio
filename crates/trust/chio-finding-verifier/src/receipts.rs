//! Strict receipt verification for the finding evidence boundary.

use chio_core_types::crypto::SigningAlgorithm;
use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt};
use chio_core_types::receipt::signing::{validate_bbs_receipt_binding, ChioReceiptSigningBody};

/// Strict receipt verification failures. Every variant is a rejection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptStrictError {
    #[error("receipt kernel key must use Ed25519")]
    UnsupportedKeyAlgorithm,
    #[error("receipt kernel key is a weak Ed25519 key")]
    WeakKernelKey,
    #[error("receipt BBS binding invalid")]
    BbsBindingInvalid,
    #[error("receipt id does not match the canonical body")]
    ReceiptIdMismatch,
    #[error("receipt signature failed strict verification")]
    SignatureInvalid,
}

/// Verify one receipt strictly against its embedded kernel key: canonical
/// Ed25519 only, weak keys rejected, BBS binding validated, content
/// address recomputed, and the signature verified STRICTLY over the exact
/// signing body (`id` + body + BBS signature). Whether the kernel key is
/// TRUSTED (admitted, unrevoked, role-pinned) is a separate check at the
/// caller; this proves only that the bytes are internally authentic.
pub fn verify_receipt_strict(receipt: &ChioReceipt) -> Result<(), ReceiptStrictError> {
    if receipt.kernel_key.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(ReceiptStrictError::UnsupportedKeyAlgorithm);
    }
    if receipt.kernel_key.is_weak_ed25519() {
        return Err(ReceiptStrictError::WeakKernelKey);
    }
    let body = receipt.body();
    if validate_bbs_receipt_binding(&body, receipt.bbs_signature.as_ref()).is_err() {
        return Err(ReceiptStrictError::BbsBindingInvalid);
    }
    match chio_receipt_id(&body) {
        Ok(expected) if expected == receipt.id => {}
        _ => return Err(ReceiptStrictError::ReceiptIdMismatch),
    }
    let signing_body =
        ChioReceiptSigningBody::from_body_and_bbs(&body, receipt.bbs_signature.as_ref());
    match receipt
        .kernel_key
        .verify_canonical_strict(&signing_body, &receipt.signature)
    {
        Ok(true) => Ok(()),
        _ => Err(ReceiptStrictError::SignatureInvalid),
    }
}
