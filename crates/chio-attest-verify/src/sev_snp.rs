//! AMD SEV-SNP backend.
//!
//! Parses an AMD SEV-SNP attestation envelope, walks the supplied
//! VLEK or VCEK chain to the configured AMD KDS root, enforces the
//! launch-digest expectation pinned by the verifier, and binds the
//! quote into the kernel signing key plus receipt root via
//! [`expect_report_data`].
//!
//! The envelope shape is a deterministic subset of the AMD SEV-SNP
//! attestation report layout (`AttestationReport` in the upstream
//! `sev` crate). The fields that matter for the trust boundary are:
//!
//! - `version` (`u32` LE at offset 0): MUST equal [`SEV_SNP_REPORT_VERSION`].
//! - `vmpl` (`u32` LE at offset 12): MUST be one of the documented
//!   privilege levels (0..=3 inclusive, AMD PPR Vol. 7 "VMPL").
//! - `sig_algo` (`u32` LE at offset 16): MUST be one of the
//!   ECDSA-P384 variants documented by AMD; we accept either the
//!   VLEK or VCEK key id and use that flag to pick which chain on
//!   the [`SevSnpCollateral`] is anchored against the AMD KDS root.
//! - `key_select` (`u8` at offset 20): `0x00` => VCEK (chip-bound),
//!   `0x01` => VLEK (versioned, machine-bound). Any other value is
//!   rejected before any cryptographic work runs.
//! - `measurement` (`[u8; 48]` at offset [`SEV_SNP_MEASUREMENT_OFFSET`]):
//!   the launch digest emitted by AMD-SP. The verifier byte-compares
//!   this against the configured [`SevSnpVerifier::expected_launch_digest`].
//! - `report_data` (`[u8; 64]` at offset
//!   [`SEV_SNP_REPORT_DATA_OFFSET`]): the kernel binding slot. MUST
//!   byte-match [`expect_report_data`] for the supplied kernel public
//!   key plus receipt root.
//! - A trailing signature blob whose length is declared by a
//!   little-endian `u32` at [`SEV_SNP_SIGNATURE_LEN_OFFSET`].
//!
//! VLEK vs VCEK splits the same way the AMD KDS endpoints do: the
//! VLEK chain is versioned and tied to a specific machine release,
//! while the VCEK chain is chip-bound. The backend handles both by
//! selecting the appropriate chain on [`SevSnpCollateral`] based on
//! the `key_select` flag in the envelope. Both chains anchor at the
//! same AMD KDS root configured on the verifier.
//!
//! The collateral chain check follows the same shape as the TDX
//! backend: chains are rejected when empty, when any link is empty,
//! when the leaf equals the anchor (no real intermediate / leaf
//! present), and when the configured root is empty.

use std::time::SystemTime;

use crate::tee_signature::verify_p384_signature_with_attestation_key;
use crate::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind, VerifiedQuote,
};

/// Wire-level version this backend accepts. Mirrors the v2 shape used
/// by AMD SEV-SNP attestation reports today.
pub const SEV_SNP_REPORT_VERSION: u32 = 2;

/// Total fixed-size envelope length before the trailing signature
/// blob. Mirrors the deterministic subset documented above.
const SEV_SNP_HEADER_AND_BODY_LEN: usize = 0x300;
const SEV_SNP_VERSION_OFFSET: usize = 0;
const SEV_SNP_VMPL_OFFSET: usize = 12;
const SEV_SNP_SIG_ALGO_OFFSET: usize = 16;
const SEV_SNP_KEY_SELECT_OFFSET: usize = 20;
const SEV_SNP_REPORTED_TCB_OFFSET: usize = 24;
/// Offset of the 48-byte `measurement` (launch digest) field inside
/// the envelope. Anchored well clear of the header and well clear of
/// `report_data` so a single-bit tamper in either field cannot
/// alias.
pub const SEV_SNP_MEASUREMENT_OFFSET: usize = 0x90;
/// Offset of the 64-byte `report_data` slot inside the envelope.
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0xC0;
const SEV_SNP_SIGNATURE_LEN_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN - 4;
const SEV_SNP_SIGNATURE_BYTES_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN;

/// AMD-documented sig_algo values for SEV-SNP attestation reports.
/// 0x01 (ECDSA-P384-SHA384 with VCEK) and 0x02 (ECDSA-P384-SHA384
/// with VLEK) are the only values this backend accepts.
const SIG_ALGO_ECDSA_P384_VCEK: u32 = 0x01;
const SIG_ALGO_ECDSA_P384_VLEK: u32 = 0x02;

/// AMD VMPL range. Values 0..=3 are documented by the AMD PPR; any
/// other value is rejected.
const SEV_SNP_VMPL_MAX: u32 = 3;

/// VCEK key_select flag: chip-bound endorsement key chain.
const KEY_SELECT_VCEK: u8 = 0x00;
/// VLEK key_select flag: versioned, machine-bound endorsement key
/// chain.
const KEY_SELECT_VLEK: u8 = 0x01;

/// AMD SEV-SNP key endorsement variant resolved from the envelope's
/// `key_select` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevSnpKeySelect {
    /// Chip-bound VCEK chain. Anchored against
    /// [`SevSnpCollateral::vcek_chain_der`].
    Vcek,
    /// Versioned, machine-bound VLEK chain. Anchored against
    /// [`SevSnpCollateral::vlek_chain_der`].
    Vlek,
}

impl SevSnpKeySelect {
    fn from_byte(byte: u8) -> Result<Self, AttestError> {
        match byte {
            KEY_SELECT_VCEK => Ok(Self::Vcek),
            KEY_SELECT_VLEK => Ok(Self::Vlek),
            other => Err(AttestError::Malformed(format!(
                "sev-snp key_select {other:#x} is neither VCEK nor VLEK"
            ))),
        }
    }
}

/// Minimal AMD KDS collateral bundle required by the SEV-SNP backend.
///
/// Holds the AMD KDS root bytes, the VCEK chain anchored at that root,
/// and the VLEK chain anchored at that root. The two chains share the
/// same root; the `key_select` byte in each envelope selects which
/// chain a given quote anchors against.
#[derive(Debug, Clone)]
pub struct SevSnpCollateral {
    /// AMD KDS root certificate bytes (DER). Both chains MUST
    /// terminate at these exact bytes.
    pub amd_kds_root_der: Vec<u8>,
    /// VCEK chain (chip-bound), terminating at `amd_kds_root_der`.
    pub vcek_chain_der: Vec<Vec<u8>>,
    /// VLEK chain (versioned, machine-bound), terminating at
    /// `amd_kds_root_der`.
    pub vlek_chain_der: Vec<Vec<u8>>,
    /// AMD-reported TCB recovery event id. The verifier rejects when
    /// this is below the configured `min_tcb_recovery_event_id`.
    pub tcb_recovery_event_id: u32,
    /// Normalized TCB status. Backends fail closed on
    /// non-acceptable values per [`QuoteTcbStatus::is_acceptable`].
    pub tcb_status: QuoteTcbStatus,
    /// Collateral validity window start.
    pub not_before: SystemTime,
    /// Collateral validity window end.
    pub not_after: SystemTime,
}

impl SevSnpCollateral {
    #[must_use]
    pub fn new(
        amd_kds_root_der: Vec<u8>,
        vcek_chain_der: Vec<Vec<u8>>,
        vlek_chain_der: Vec<Vec<u8>>,
        tcb_recovery_event_id: u32,
        tcb_status: QuoteTcbStatus,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Self {
        Self {
            amd_kds_root_der,
            vcek_chain_der,
            vlek_chain_der,
            tcb_recovery_event_id,
            tcb_status,
            not_before,
            not_after,
        }
    }
}

/// AMD SEV-SNP quote verifier.
#[derive(Debug, Clone)]
pub struct SevSnpVerifier {
    collateral: SevSnpCollateral,
    min_tcb_recovery_event_id: u32,
    expected_launch_digest: [u8; 48],
    verification_time: SystemTime,
}

impl SevSnpVerifier {
    #[must_use]
    pub fn new(
        collateral: SevSnpCollateral,
        min_tcb_recovery_event_id: u32,
        expected_launch_digest: [u8; 48],
    ) -> Self {
        Self {
            collateral,
            min_tcb_recovery_event_id,
            expected_launch_digest,
            verification_time: SystemTime::now(),
        }
    }

    #[must_use]
    pub fn with_verification_time(
        collateral: SevSnpCollateral,
        min_tcb_recovery_event_id: u32,
        expected_launch_digest: [u8; 48],
        verification_time: SystemTime,
    ) -> Self {
        Self {
            collateral,
            min_tcb_recovery_event_id,
            expected_launch_digest,
            verification_time,
        }
    }

    /// Pinned launch digest. Exposed for tests and audit consumers.
    #[must_use]
    pub fn expected_launch_digest(&self) -> [u8; 48] {
        self.expected_launch_digest
    }

    fn verify_collateral(
        &self,
        key_select: SevSnpKeySelect,
    ) -> Result<QuoteTcbStatus, AttestError> {
        if self.collateral.amd_kds_root_der.is_empty() {
            return Err(AttestError::TrustRoot);
        }
        let chain = match key_select {
            SevSnpKeySelect::Vcek => &self.collateral.vcek_chain_der,
            SevSnpKeySelect::Vlek => &self.collateral.vlek_chain_der,
        };
        if !chain_terminates_at_root(chain, &self.collateral.amd_kds_root_der) {
            return Err(AttestError::TrustRoot);
        }
        if self.verification_time < self.collateral.not_before
            || self.verification_time > self.collateral.not_after
        {
            return Err(AttestError::CertificateExpired);
        }
        if self.collateral.tcb_recovery_event_id < self.min_tcb_recovery_event_id {
            return Err(AttestError::QuoteRejected(
                "sev-snp tcb recovery event id is below minimum".to_string(),
            ));
        }
        if !self.collateral.tcb_status.is_acceptable() {
            return Err(AttestError::QuoteRejected(
                "sev-snp tcb status is not acceptable".to_string(),
            ));
        }
        Ok(self.collateral.tcb_status)
    }
}

impl QuoteVerifier for SevSnpVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        context: &QuoteVerificationContext<'_>,
    ) -> Result<VerifiedQuote, AttestError> {
        let parsed = ParsedSevSnpQuote::parse(quote)?;
        let tcb_status = self.verify_collateral(parsed.key_select)?;
        let attestation_key = self.attestation_key(parsed.key_select)?;
        verify_p384_signature_with_attestation_key(
            attestation_key,
            &parsed.signed_report,
            &parsed.signature,
        )?;

        if parsed.measurement != self.expected_launch_digest {
            return Err(AttestError::QuoteRejected(
                "sev-snp launch digest does not match expected kernel measurement".to_string(),
            ));
        }

        let expected_report_data = expect_report_data(context.kernel_pk, context.receipt_root);
        if parsed.report_data != expected_report_data {
            return Err(AttestError::ReportDataMismatch);
        }

        Ok(VerifiedQuote {
            tee_kind: TeeKind::AmdSevSnp,
            report_data: parsed.report_data,
            tcb_status,
            signed_at: self.verification_time,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSevSnpQuote {
    key_select: SevSnpKeySelect,
    measurement: [u8; 48],
    report_data: [u8; 64],
    signed_report: Vec<u8>,
    signature: Vec<u8>,
}

impl ParsedSevSnpQuote {
    fn parse(quote: &[u8]) -> Result<Self, AttestError> {
        if quote.len() < SEV_SNP_SIGNATURE_BYTES_OFFSET {
            return Err(AttestError::Malformed(
                "sev-snp envelope shorter than fixed header and body".to_string(),
            ));
        }

        let version = read_u32_le(quote, SEV_SNP_VERSION_OFFSET)?;
        if version != SEV_SNP_REPORT_VERSION {
            return Err(AttestError::Malformed(format!(
                "unsupported sev-snp report version {version}"
            )));
        }

        let vmpl = read_u32_le(quote, SEV_SNP_VMPL_OFFSET)?;
        if vmpl > SEV_SNP_VMPL_MAX {
            return Err(AttestError::Malformed(format!(
                "sev-snp vmpl {vmpl} is outside the documented 0..=3 range"
            )));
        }

        let sig_algo = read_u32_le(quote, SEV_SNP_SIG_ALGO_OFFSET)?;
        if sig_algo != SIG_ALGO_ECDSA_P384_VCEK && sig_algo != SIG_ALGO_ECDSA_P384_VLEK {
            return Err(AttestError::Malformed(format!(
                "sev-snp sig_algo {sig_algo:#x} is not an AMD ECDSA-P384 variant"
            )));
        }

        let key_select_byte = quote
            .get(SEV_SNP_KEY_SELECT_OFFSET)
            .copied()
            .ok_or_else(|| {
                AttestError::Malformed("sev-snp envelope missing key_select byte".to_string())
            })?;
        let key_select = SevSnpKeySelect::from_byte(key_select_byte)?;

        // sig_algo and key_select must agree on which endorsement key
        // produced the signature. Disagreement is type-confusion bait.
        let sig_algo_matches_key_select = matches!(
            (sig_algo, key_select),
            (SIG_ALGO_ECDSA_P384_VCEK, SevSnpKeySelect::Vcek)
                | (SIG_ALGO_ECDSA_P384_VLEK, SevSnpKeySelect::Vlek)
        );
        if !sig_algo_matches_key_select {
            return Err(AttestError::Malformed(
                "sev-snp sig_algo does not match key_select; type-confusion rejected".to_string(),
            ));
        }

        // reported_tcb is currently informational at the wire level;
        // the envelope is rejected when the value is 0 because real
        // AMD-SP firmware never emits an all-zero TCB version.
        let reported_tcb = read_u32_le(quote, SEV_SNP_REPORTED_TCB_OFFSET)?;
        if reported_tcb == 0 {
            return Err(AttestError::Malformed(
                "sev-snp reported_tcb must be non-zero".to_string(),
            ));
        }

        let mut measurement = [0u8; 48];
        let m_slice = quote
            .get(SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48)
            .ok_or_else(|| {
                AttestError::Malformed("sev-snp envelope missing measurement field".to_string())
            })?;
        measurement.copy_from_slice(m_slice);

        let mut report_data = [0u8; 64];
        let rd_slice = quote
            .get(SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64)
            .ok_or_else(|| {
                AttestError::Malformed("sev-snp envelope missing report_data slot".to_string())
            })?;
        report_data.copy_from_slice(rd_slice);

        let signature_len = read_u32_le(quote, SEV_SNP_SIGNATURE_LEN_OFFSET)? as usize;
        if signature_len == 0 {
            return Err(AttestError::Malformed(
                "sev-snp signature blob is empty".to_string(),
            ));
        }
        let expected_len = SEV_SNP_SIGNATURE_BYTES_OFFSET
            .checked_add(signature_len)
            .ok_or_else(|| {
                AttestError::Malformed("sev-snp envelope length overflow".to_string())
            })?;
        if quote.len() != expected_len {
            return Err(AttestError::Malformed(
                "sev-snp signature length does not match envelope".to_string(),
            ));
        }

        Ok(Self {
            key_select,
            measurement,
            report_data,
            signed_report: quote[..SEV_SNP_HEADER_AND_BODY_LEN].to_vec(),
            signature: quote[SEV_SNP_SIGNATURE_BYTES_OFFSET..expected_len].to_vec(),
        })
    }
}

impl SevSnpVerifier {
    fn attestation_key(&self, key_select: SevSnpKeySelect) -> Result<&[u8], AttestError> {
        let chain = match key_select {
            SevSnpKeySelect::Vcek => &self.collateral.vcek_chain_der,
            SevSnpKeySelect::Vlek => &self.collateral.vlek_chain_der,
        };
        let leaf = chain.first().ok_or(AttestError::TrustRoot)?;
        Ok(leaf.as_slice())
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, AttestError> {
    let field = bytes.get(offset..offset + 4).ok_or_else(|| {
        AttestError::Malformed("sev-snp envelope missing little-endian u32 field".to_string())
    })?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// True only when the chain terminates at the supplied root and the
/// chain has at least one non-empty link below the root, ensuring a
/// real leaf or intermediate is present and that no link is the
/// empty byte slice. A chain that consists solely of the root, or
/// one whose leaf is byte-equal to the root, is rejected.
fn chain_terminates_at_root(chain: &[Vec<u8>], root: &[u8]) -> bool {
    if chain.len() < 2 {
        return false;
    }
    if chain.iter().any(std::vec::Vec::is_empty) {
        return false;
    }
    let Some(last) = chain.last() else {
        return false;
    };
    if last.as_slice() != root {
        return false;
    }
    let Some(first) = chain.first() else {
        return false;
    };
    if first.as_slice() == root {
        return false;
    }
    true
}
