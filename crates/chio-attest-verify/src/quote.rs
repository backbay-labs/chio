use std::time::SystemTime;

use chio_core_types::crypto::PublicKey;
use sha2::{Digest, Sha256};

/// TEE family that produced a verified quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TeeKind {
    /// Intel Trust Domain Extensions quote verified through DCAP evidence.
    IntelTdx,
}

/// Normalized TCB status emitted by a quote backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuoteTcbStatus {
    UpToDate,
    ConfigurationNeeded,
    OutOfDate,
    Revoked,
    Unrecognized,
}

impl QuoteTcbStatus {
    /// Returns true only for TCB states a verifier may accept.
    #[must_use]
    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::UpToDate | Self::ConfigurationNeeded)
    }
}

/// Context all quote backends must bind into the quote report data.
#[derive(Debug, Clone, Copy)]
pub struct QuoteVerificationContext<'a> {
    pub kernel_pk: &'a PublicKey,
    pub receipt_root: &'a [u8; 32],
}

impl<'a> QuoteVerificationContext<'a> {
    #[must_use]
    pub fn new(kernel_pk: &'a PublicKey, receipt_root: &'a [u8; 32]) -> Self {
        Self {
            kernel_pk,
            receipt_root,
        }
    }

    /// Compute the full 64-byte report_data binding expected from the quote.
    #[must_use]
    pub fn expected_report_data(self) -> [u8; 64] {
        expect_report_data(self.kernel_pk, self.receipt_root)
    }
}

/// Result of a successful TEE quote verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    pub tee_kind: TeeKind,
    pub report_data: [u8; 64],
    pub tcb_status: QuoteTcbStatus,
    pub signed_at: SystemTime,
}

/// Bind a quote to the Chio kernel signing key and receipt root.
///
/// The first 32 bytes are SHA256(kernel public-key canonical bytes ||
/// receipt_root). The remaining 32 bytes are right-padded with zeroes.
#[must_use]
pub fn expect_report_data(kernel_pk: &PublicKey, receipt_root: &[u8; 32]) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(kernel_public_key_canonical_bytes(kernel_pk));
    hasher.update(receipt_root);

    let digest = hasher.finalize();
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&digest);
    report_data
}

fn kernel_public_key_canonical_bytes(kernel_pk: &PublicKey) -> Vec<u8> {
    kernel_pk.to_hex().into_bytes()
}
