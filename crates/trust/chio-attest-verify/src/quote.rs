//! `QuoteVerifier` shared shapes.
//!
//! This module defines the trait surface every TEE quote backend ships
//! against. It is the single import point for downstream consumers:
//!
//! - The revocation oracle (`crates/chio-revocation/`) consumes
//!   [`VerifiedQuote`] when a revocation root is signed by a kernel that
//!   ran inside an attested TEE.
//! - Hardware custody envelopes (`crates/chio-tee/`) consume
//!   [`expect_report_data`] before declaring a custody handoff valid.
//!
//! All shapes here are intentionally minimal: a TEE family discriminator,
//! a normalized TCB status, the verification context that every backend
//! must bind into the quote, and the verification result. Backend-specific
//! collateral types (TDX DCAP collateral, SEV-SNP VLEK / VCEK chains,
//! Nitro NSM root) live in their own modules and never leak into this
//! shape.

use std::fmt;
use std::time::SystemTime;

use chio_core_types::crypto::PublicKey;
use sha2::{Digest, Sha256};

/// TEE family that produced a verified quote.
///
/// The enum is `non_exhaustive` so adding a new TEE family in a future
/// release is not a breaking change for consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TeeKind {
    /// Intel Trust Domain Extensions quote verified through DCAP
    /// collateral. Backend module: `tdx`.
    IntelTdx,
    /// AMD SEV-SNP attestation verified against the AMD KDS root via
    /// VLEK or VCEK. Backend module: `sev_snp`.
    AmdSevSnp,
    /// AWS Nitro NSM attestation document verified against the embedded
    /// AWS Nitro root certificate. Backend module: `nitro`.
    AwsNitro,
}

impl fmt::Display for TeeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::IntelTdx => "intel-tdx",
            Self::AmdSevSnp => "amd-sev-snp",
            Self::AwsNitro => "aws-nitro",
        };
        f.write_str(label)
    }
}

/// Normalized TCB status emitted by a quote backend.
///
/// Backends translate vendor specific TCB strings into this enum so
/// downstream policy can apply a single freshness rule across families.
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
    ///
    /// `OutOfDate`, `Revoked`, and `Unrecognized` always fail closed.
    #[must_use]
    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::UpToDate | Self::ConfigurationNeeded)
    }
}

impl fmt::Display for QuoteTcbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UpToDate => "up-to-date",
            Self::ConfigurationNeeded => "configuration-needed",
            Self::OutOfDate => "out-of-date",
            Self::Revoked => "revoked",
            Self::Unrecognized => "unrecognized",
        };
        f.write_str(label)
    }
}

/// Context all quote backends must bind into the quote `report_data`.
///
/// Construct this once per verification call. Backends that succeed
/// without consulting [`Self::expected_report_data`] are buggy: every
/// quote MUST commit to both the kernel signing key and the receipt
/// root, otherwise the quote can be replayed under a different kernel
/// or against a different receipt history.
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

    /// Compute the full 64-byte `report_data` binding expected from the
    /// quote. Backends MUST byte-compare the observed `report_data`
    /// against this value over the entire 64-byte slot.
    #[must_use]
    pub fn expected_report_data(self) -> [u8; 64] {
        expect_report_data(self.kernel_pk, self.receipt_root)
    }
}

/// Result of a successful TEE quote verification.
///
/// Carries enough context for receipts and audit logs to record the
/// verification without re-parsing the quote. The `report_data` field
/// is the 64-byte slot exactly as observed in the quote, after the
/// backend has confirmed it matches the expected binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    pub tee_kind: TeeKind,
    pub report_data: [u8; 64],
    pub tcb_status: QuoteTcbStatus,
    pub signed_at: SystemTime,
}

impl VerifiedQuote {
    /// True when the verified TCB status is acceptable for production use.
    ///
    /// A `VerifiedQuote` with `tcb_status = OutOfDate` cannot exist: the
    /// backend would have failed closed before constructing this value.
    /// This helper is a defence-in-depth check for downstream consumers
    /// that re-evaluate freshness against their own policy.
    #[must_use]
    pub fn tcb_acceptable(&self) -> bool {
        self.tcb_status.is_acceptable()
    }
}

/// Bind a quote to the Chio kernel signing key and receipt root.
///
/// Layout: bytes `0..32` are `SHA256(kernel_signing_pk_canonical_bytes
/// || receipt_root)`; bytes `32..64` are right-padded with `0x00` to
/// fill the full 64-byte `report_data` slot. Verifiers MUST byte-compare
/// the entire 64-byte slot, including the zero padding, so a quote that
/// stuffs unrelated bytes into `32..64` is rejected.
///
/// `kernel_signing_pk_canonical_bytes` is the algorithm-prefixed hex
/// rendering of the kernel public key (`Ed25519` bare hex, `p256:<hex>`,
/// `p384:<hex>`, `hybrid:<...>`). That encoding is the canonical-JSON form
/// locked by the wire spec, so the binding is byte-stable across the wire.
#[must_use]
pub fn expect_report_data(kernel_pk: &PublicKey, receipt_root: &[u8; 32]) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(kernel_public_key_canonical_bytes(kernel_pk));
    hasher.update(receipt_root);

    let digest = hasher.finalize();
    // Right-pad with [0u8; 32] to fill the 64-byte report_data slot.
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&digest);
    report_data
}

fn kernel_public_key_canonical_bytes(kernel_pk: &PublicKey) -> Vec<u8> {
    kernel_pk.to_hex().into_bytes()
}
