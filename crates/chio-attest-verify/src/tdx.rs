use std::time::SystemTime;

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

/// Minimal DCAP collateral bundle required by the TDX scaffold.
///
/// Full quote and collateral corpus pinning lands in the next phase, but this
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

/// Intel TDX DCAP quote verifier scaffold.
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
        if !chain_anchors_at_root(
            &self.collateral.pck_certificate_chain_der,
            &self.collateral.intel_root_ca_der,
        ) {
            return Err(AttestError::TrustRoot);
        }
        if !chain_anchors_at_root(
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
    report_data: [u8; 64],
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

        let tee_type = read_u32_le(quote, 4)?;
        if tee_type != TDX_TEE_TYPE {
            return Err(AttestError::Malformed(
                "quote tee_type is not Intel TDX".to_string(),
            ));
        }

        let signature_len = read_u32_le(quote, SIGNATURE_LEN_OFFSET)? as usize;
        if signature_len == 0 {
            return Err(AttestError::Malformed(
                "tdx quote signature data is empty".to_string(),
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

        Ok(Self { report_data })
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

fn chain_anchors_at_root(chain: &[Vec<u8>], root: &[u8]) -> bool {
    chain
        .last()
        .is_some_and(|last| !last.is_empty() && last.as_slice() == root)
}
