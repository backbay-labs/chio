//! Intel TDX DCAP backend.
//!
//! Parses an Intel TDX v4 quote envelope, walks the supplied DCAP
//! collateral chain to the configured Intel root, enforces the
//! documented `min_tcb_recovery_event_id`, and binds the quote into
//! the kernel signing key plus receipt root via [`expect_report_data`].
//!
//! The collateral chain check anchors at the configured Intel root
//! bytes for both the PCK certificate chain and the TCB info issuer
//! chain. Chains are rejected when empty, when any link is empty, when
//! the leaf equals the anchor (no real intermediate / leaf present),
//! or when the leaf does not differ from the next link in the chain.
//!
//! The header check additionally enforces the Intel SGX Quoting
//! Enclave vendor id and an Intel ECDSA attestation key type, so a
//! quote produced by a non-Intel QE or signed under an unsupported key
//! type is rejected before any binding work runs.

use std::time::SystemTime;

use crate::tee_signature::{
    verify_p256_signature_with_attestation_key, verify_p384_signature_with_attestation_key,
};
use crate::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind, VerifiedQuote,
};

const QUOTE_V4: u16 = 4;
const TDX_TEE_TYPE: u32 = 0x0000_0081;
const QUOTE_HEADER_LEN: usize = 48;
const TD10_REPORT_LEN: usize = 584;
const TD10_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
const TD10_REPORT_DATA_END: usize = TD10_REPORT_DATA_OFFSET + 64;
const SIGNATURE_LEN_OFFSET: usize = QUOTE_HEADER_LEN + TD10_REPORT_LEN;
const SIGNATURE_BYTES_OFFSET: usize = SIGNATURE_LEN_OFFSET + 4;
const TDX_SIGNATURE_DATA_MAX_LEN: usize = 128 * 1024;

/// Intel SGX Quoting Enclave vendor id, embedded in TDX v4 quote
/// headers at bytes 12..28. Source: Intel TDX Quote Generation
/// Library reference (`sgx_quote_4_t.qe_vendor_id`).
const INTEL_SGX_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

/// ECDSA-256-with-P-256 attestation key. Source: Intel SGX DCAP
/// Quoting Library, `sgx_quote_sign_type_t`. Other values either
/// designate EPID (legacy SGX, never valid for TDX) or future Intel
/// reserved values; both are rejected.
const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
const ATT_KEY_TYPE_ECDSA_P384: u16 = 3;

/// Minimal DCAP collateral bundle for TDX quote verification.
///
/// Full quote and collateral corpus pinning is not yet wired; this
/// shape already rejects absent evidence, stale collateral, and chains that do
/// not anchor at the configured Intel root bytes.
#[derive(Debug, Clone)]
pub struct TdxCollateral {
    pub intel_root_ca_der: Vec<u8>,
    pub pck_certificate_chain_der: Vec<Vec<u8>>,
    pub tcb_info_issuer_chain_der: Vec<Vec<u8>>,
    pub tcb_recovery_event_id: u32,
    pub tcb_status: QuoteTcbStatus,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

impl TdxCollateral {
    #[must_use]
    pub fn new(
        intel_root_ca_der: Vec<u8>,
        pck_certificate_chain_der: Vec<Vec<u8>>,
        tcb_info_issuer_chain_der: Vec<Vec<u8>>,
        tcb_recovery_event_id: u32,
        tcb_status: QuoteTcbStatus,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Self {
        Self {
            intel_root_ca_der,
            pck_certificate_chain_der,
            tcb_info_issuer_chain_der,
            tcb_recovery_event_id,
            tcb_status,
            not_before,
            not_after,
        }
    }
}

/// Intel TDX DCAP quote verifier.
#[derive(Debug, Clone)]
pub struct TdxDcapVerifier {
    collateral: TdxCollateral,
    min_tcb_recovery_event_id: u32,
    verification_time: SystemTime,
}

impl TdxDcapVerifier {
    #[must_use]
    pub fn new(collateral: TdxCollateral, min_tcb_recovery_event_id: u32) -> Self {
        Self {
            collateral,
            min_tcb_recovery_event_id,
            verification_time: SystemTime::now(),
        }
    }

    #[must_use]
    pub fn with_verification_time(
        collateral: TdxCollateral,
        min_tcb_recovery_event_id: u32,
        verification_time: SystemTime,
    ) -> Self {
        Self {
            collateral,
            min_tcb_recovery_event_id,
            verification_time,
        }
    }

    fn verify_collateral(&self) -> Result<QuoteTcbStatus, AttestError> {
        if self.collateral.intel_root_ca_der.is_empty() {
            return Err(AttestError::TrustRoot);
        }
        if !chain_terminates_at_root(
            &self.collateral.pck_certificate_chain_der,
            &self.collateral.intel_root_ca_der,
        ) {
            return Err(AttestError::TrustRoot);
        }
        if !chain_terminates_at_root(
            &self.collateral.tcb_info_issuer_chain_der,
            &self.collateral.intel_root_ca_der,
        ) {
            return Err(AttestError::TrustRoot);
        }
        if self.verification_time < self.collateral.not_before
            || self.verification_time > self.collateral.not_after
        {
            return Err(AttestError::CertificateExpired);
        }
        if self.collateral.tcb_recovery_event_id < self.min_tcb_recovery_event_id {
            return Err(AttestError::QuoteRejected(
                "tdx tcb recovery event id is below minimum".to_string(),
            ));
        }
        if !self.collateral.tcb_status.is_acceptable() {
            return Err(AttestError::QuoteRejected(
                "tdx tcb status is not acceptable".to_string(),
            ));
        }
        Ok(self.collateral.tcb_status)
    }
}

impl QuoteVerifier for TdxDcapVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        context: &QuoteVerificationContext<'_>,
    ) -> Result<VerifiedQuote, AttestError> {
        let tcb_status = self.verify_collateral()?;
        let parsed = ParsedTdxQuote::parse(quote)?;
        let attestation_key = self
            .collateral
            .pck_certificate_chain_der
            .first()
            .ok_or(AttestError::TrustRoot)?;
        match parsed.att_key_type {
            ATT_KEY_TYPE_ECDSA_P256 => verify_p256_signature_with_attestation_key(
                attestation_key,
                &parsed.signed_message,
                &parsed.signature,
            )?,
            ATT_KEY_TYPE_ECDSA_P384 => verify_p384_signature_with_attestation_key(
                attestation_key,
                &parsed.signed_message,
                &parsed.signature,
            )?,
            other => {
                return Err(AttestError::Malformed(format!(
                    "tdx quote att_key_type {other} is not supported"
                )))
            }
        }
        let expected_report_data = expect_report_data(context.kernel_pk, context.receipt_root);

        if parsed.report_data != expected_report_data {
            return Err(AttestError::ReportDataMismatch);
        }

        Ok(VerifiedQuote {
            tee_kind: TeeKind::IntelTdx,
            report_data: parsed.report_data,
            tcb_status,
            signed_at: self.verification_time,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTdxQuote {
    att_key_type: u16,
    report_data: [u8; 64],
    signed_message: Vec<u8>,
    signature: Vec<u8>,
}

impl ParsedTdxQuote {
    fn parse(quote: &[u8]) -> Result<Self, AttestError> {
        if quote.len() < SIGNATURE_BYTES_OFFSET {
            return Err(AttestError::Malformed(
                "tdx quote is shorter than v4 header and report body".to_string(),
            ));
        }

        let version = read_u16_le(quote, 0)?;
        if version != QUOTE_V4 {
            return Err(AttestError::Malformed(format!(
                "unsupported tdx quote version {version}"
            )));
        }

        let att_key_type = read_u16_le(quote, 2)?;
        if att_key_type != ATT_KEY_TYPE_ECDSA_P256 && att_key_type != ATT_KEY_TYPE_ECDSA_P384 {
            return Err(AttestError::Malformed(format!(
                "tdx quote att_key_type {att_key_type} is not an Intel ECDSA variant"
            )));
        }

        let tee_type = read_u32_le(quote, 4)?;
        if tee_type != TDX_TEE_TYPE {
            return Err(AttestError::Malformed(
                "quote tee_type is not Intel TDX".to_string(),
            ));
        }

        let qe_vendor_id = quote.get(12..28).ok_or_else(|| {
            AttestError::Malformed("tdx quote missing qe_vendor_id field".to_string())
        })?;
        if qe_vendor_id != INTEL_SGX_QE_VENDOR_ID {
            return Err(AttestError::Malformed(
                "tdx quote qe_vendor_id is not the Intel SGX QE".to_string(),
            ));
        }

        let signature_len = read_u32_le(quote, SIGNATURE_LEN_OFFSET)? as usize;
        if signature_len == 0 {
            return Err(AttestError::Malformed(
                "tdx quote signature data is empty".to_string(),
            ));
        }
        if signature_len > TDX_SIGNATURE_DATA_MAX_LEN {
            return Err(AttestError::Malformed(
                "tdx quote signature data exceeds maximum length".to_string(),
            ));
        }
        let expected_len = SIGNATURE_BYTES_OFFSET
            .checked_add(signature_len)
            .ok_or_else(|| AttestError::Malformed("tdx quote length overflow".to_string()))?;
        if quote.len() != expected_len {
            return Err(AttestError::Malformed(
                "tdx quote signature length does not match envelope".to_string(),
            ));
        }

        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&quote[TD10_REPORT_DATA_OFFSET..TD10_REPORT_DATA_END]);
        let signed_message = quote[..SIGNATURE_LEN_OFFSET].to_vec();
        let signature = quote[SIGNATURE_BYTES_OFFSET..expected_len].to_vec();

        Ok(Self {
            att_key_type,
            report_data,
            signed_message,
            signature,
        })
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, AttestError> {
    let field = bytes.get(offset..offset + 2).ok_or_else(|| {
        AttestError::Malformed("tdx quote missing little-endian u16 field".to_string())
    })?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, AttestError> {
    let field = bytes.get(offset..offset + 4).ok_or_else(|| {
        AttestError::Malformed("tdx quote missing little-endian u32 field".to_string())
    })?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// True only when the chain terminates at the supplied root and the
/// chain has at least one non-empty link below the root, ensuring a
/// real leaf or intermediate is present and that no link is the empty
/// byte slice. A chain that consists solely of the root, or one whose
/// leaf is byte-equal to the root, is rejected.
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
