//! AWS Nitro NSM backend.
//!
//! Parses an AWS Nitro NSM attestation document (a `COSE_Sign1`
//! envelope wrapping a CBOR attestation payload), walks the
//! supplied certificate bundle to the embedded AWS Nitro root,
//! enforces the documented PCR0 expectation pinned by the
//! verifier, and binds the quote into the kernel signing key plus
//! receipt root via [`expect_report_data`].
//!
//! Wire-level shape (subset of the AWS Nitro NSM specification):
//!
//! - Outer envelope is a `COSE_Sign1` parsed by [`coset::CoseSign1`].
//! - The payload is a CBOR map with at least the following keys:
//!     - `module_id` (text): identifier of the NSM module.
//!     - `pcrs` (map of integer to bytes): platform configuration
//!       registers measured at launch. PCR0 (key `0`) is the
//!       launch-image digest the verifier byte-compares against
//!       the configured [`NitroVerifier::expected_pcr0`].
//!     - `certificate` (bytes): the leaf attestation certificate
//!       presented by the NSM. The verifier requires
//!       byte-equality with the leaf of the configured
//!       collateral chain.
//!     - `cabundle` (array of bytes): the certificate chain the
//!       NSM presents, ending at the embedded AWS Nitro root.
//!     - `user_data` (bytes): the kernel binding slot. MUST be
//!       64 bytes, MUST byte-match [`expect_report_data`] for the
//!       supplied kernel public key plus receipt root.
//!     - `timestamp` (unsigned): NSM-emitted document time. Used
//!       to populate [`VerifiedQuote::signed_at`].
//!
//! Trust-boundary contract:
//!
//! - The verifier rejects when the embedded AWS Nitro root bytes
//!   are empty, when the configured chain is shorter than two
//!   links, when any link is empty, when the chain leaf does not
//!   byte-match the document's `certificate` field, when the
//!   chain root does not byte-match the configured AWS Nitro
//!   root, or when the chain leaf is the root itself.
//! - The verifier rejects when PCR0 in the document does not
//!   byte-match the configured launch digest. Mismatch returns
//!   [`AttestError::QuoteRejected`].
//! - The verifier rejects when `user_data` is missing, is not
//!   64 bytes, or does not byte-match the expected
//!   `report_data` binding. Mismatch returns
//!   [`AttestError::ReportDataMismatch`].
//! - The verifier rejects all malformed CBOR, missing required
//!   keys, and short or oversized fields with
//!   [`AttestError::Malformed`].

use std::time::{Duration, SystemTime};

use coset::cbor::Value as CborValue;
use coset::{Algorithm, CborSerializable, CoseSign1};

use crate::tee_signature::verify_p384_signature_with_attestation_key;
use crate::{
    expect_report_data, AttestError, QuoteTcbStatus, QuoteVerificationContext, QuoteVerifier,
    TeeKind, VerifiedQuote,
};

/// Required length of the `user_data` field carrying the kernel +
/// receipt-root binding.
pub const NITRO_USER_DATA_LEN: usize = 64;

/// Required length of the PCR0 (and other PCR) field.
pub const NITRO_PCR_LEN: usize = 48;

const NITRO_TIMESTAMP_MAX_SKEW: Duration = Duration::from_secs(300);
const NITRO_QUOTE_MAX_LEN: usize = 1024 * 1024;
const NITRO_PAYLOAD_MAX_LEN: usize = 512 * 1024;
const NITRO_MODULE_ID_MAX_LEN: usize = 256;
const NITRO_CERTIFICATE_MAX_LEN: usize = 64 * 1024;
const NITRO_CABUNDLE_MAX_ENTRIES: usize = 16;

/// AWS Nitro NSM collateral bundle.
///
/// Carries the embedded AWS Nitro root certificate bytes (DER) and
/// the chain expected to terminate at that root. The chain leaf
/// MUST byte-match the document's `certificate` field; the chain
/// trailer MUST byte-match the configured root.
#[derive(Debug, Clone)]
pub struct NitroCollateral {
    /// AWS Nitro root certificate (DER) embedded by the verifier.
    /// Source bytes are pinned in
    /// `crates/trust/chio-attest-verify/fixtures/nitro/aws-nitro-root.pem`
    /// in the same crate; integrators that consume this struct
    /// directly load that file or supply their own byte-equal
    /// snapshot.
    pub aws_nitro_root_der: Vec<u8>,
    /// Certificate chain (DER) terminating at `aws_nitro_root_der`.
    /// The first element is the NSM leaf; the last element is the
    /// AWS Nitro root. Reviewers diff this against the embedded
    /// root to confirm the chain anchors.
    pub chain_der: Vec<Vec<u8>>,
    /// Normalized TCB status for downstream policy. Backends fail
    /// closed when this value is not acceptable.
    pub tcb_status: QuoteTcbStatus,
    /// Collateral validity window start.
    pub not_before: SystemTime,
    /// Collateral validity window end.
    pub not_after: SystemTime,
}

impl NitroCollateral {
    #[must_use]
    pub fn new(
        aws_nitro_root_der: Vec<u8>,
        chain_der: Vec<Vec<u8>>,
        tcb_status: QuoteTcbStatus,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Self {
        Self {
            aws_nitro_root_der,
            chain_der,
            tcb_status,
            not_before,
            not_after,
        }
    }
}

/// AWS Nitro NSM quote verifier.
#[derive(Debug, Clone)]
pub struct NitroVerifier {
    collateral: NitroCollateral,
    expected_pcr0: [u8; NITRO_PCR_LEN],
    verification_time: SystemTime,
}

impl NitroVerifier {
    #[must_use]
    pub fn new(collateral: NitroCollateral, expected_pcr0: [u8; NITRO_PCR_LEN]) -> Self {
        Self {
            collateral,
            expected_pcr0,
            verification_time: SystemTime::now(),
        }
    }

    #[must_use]
    pub fn with_verification_time(
        collateral: NitroCollateral,
        expected_pcr0: [u8; NITRO_PCR_LEN],
        verification_time: SystemTime,
    ) -> Self {
        Self {
            collateral,
            expected_pcr0,
            verification_time,
        }
    }

    /// Pinned launch-image PCR0 digest. Exposed for tests and audit
    /// consumers.
    #[must_use]
    pub fn expected_pcr0(&self) -> [u8; NITRO_PCR_LEN] {
        self.expected_pcr0
    }

    fn verify_collateral(
        &self,
        document_certificate: &[u8],
    ) -> Result<QuoteTcbStatus, AttestError> {
        if self.collateral.aws_nitro_root_der.is_empty() {
            return Err(AttestError::TrustRoot);
        }
        if !chain_terminates_at_root(
            &self.collateral.chain_der,
            &self.collateral.aws_nitro_root_der,
        ) {
            return Err(AttestError::TrustRoot);
        }
        // The document's `certificate` must byte-match the leaf of
        // the chain we trust. An attacker who swaps the document's
        // leaf MUST NOT be able to ride a chain we vouched for.
        let leaf = self
            .collateral
            .chain_der
            .first()
            .ok_or(AttestError::TrustRoot)?;
        if leaf.as_slice() != document_certificate {
            return Err(AttestError::TrustRoot);
        }
        if self.verification_time < self.collateral.not_before
            || self.verification_time > self.collateral.not_after
        {
            return Err(AttestError::CertificateExpired);
        }
        if !self.collateral.tcb_status.is_acceptable() {
            return Err(AttestError::QuoteRejected(
                "nitro tcb status is not acceptable".to_string(),
            ));
        }
        Ok(self.collateral.tcb_status)
    }
}

impl QuoteVerifier for NitroVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        context: &QuoteVerificationContext<'_>,
    ) -> Result<VerifiedQuote, AttestError> {
        if quote.len() > NITRO_QUOTE_MAX_LEN {
            return Err(AttestError::Malformed(
                "nitro cose_sign1 envelope exceeds maximum length".to_string(),
            ));
        }
        let cose = CoseSign1::from_slice(quote)
            .map_err(|e| AttestError::Malformed(format!("nitro cose_sign1 parse failed: {e}")))?;

        let payload_bytes = cose
            .payload
            .as_ref()
            .ok_or_else(|| AttestError::Malformed("nitro cose_sign1 has no payload".to_string()))?;
        if payload_bytes.len() > NITRO_PAYLOAD_MAX_LEN {
            return Err(AttestError::Malformed(
                "nitro payload exceeds maximum length".to_string(),
            ));
        }

        // Reject empty signatures up front: a real NSM emits a
        // non-empty ECDSA P-384 signature blob.
        if cose.signature.is_empty() {
            return Err(AttestError::Malformed(
                "nitro cose_sign1 signature is empty".to_string(),
            ));
        }
        if cose.protected.header.alg != Some(Algorithm::Assigned(coset::iana::Algorithm::ES384)) {
            return Err(AttestError::Malformed(
                "nitro cose_sign1 algorithm is not ES384".to_string(),
            ));
        }

        let parsed = ParsedNitroDocument::parse(payload_bytes)?;
        let tcb_status = self.verify_collateral(&parsed.certificate)?;
        cose.verify_signature(b"", |signature, signed_message| {
            verify_p384_signature_with_attestation_key(
                &parsed.certificate,
                signed_message,
                signature,
            )
        })?;

        if parsed.pcr0 != self.expected_pcr0 {
            return Err(AttestError::QuoteRejected(
                "nitro PCR0 does not match expected launch image".to_string(),
            ));
        }

        let expected_report_data = expect_report_data(context.kernel_pk, context.receipt_root);
        if parsed.user_data != expected_report_data {
            return Err(AttestError::ReportDataMismatch);
        }

        let signed_at = nitro_timestamp_millis_to_system_time(parsed.timestamp_millis)?;
        self.verify_document_timestamp(signed_at)?;

        Ok(VerifiedQuote {
            tee_kind: TeeKind::AwsNitro,
            report_data: parsed.user_data,
            tcb_status,
            signed_at,
        })
    }
}

impl NitroVerifier {
    fn verify_document_timestamp(&self, signed_at: SystemTime) -> Result<(), AttestError> {
        let oldest_allowed = match self.verification_time.checked_sub(NITRO_TIMESTAMP_MAX_SKEW) {
            Some(bound) => bound,
            None => SystemTime::UNIX_EPOCH,
        };
        let newest_allowed = self
            .verification_time
            .checked_add(NITRO_TIMESTAMP_MAX_SKEW)
            .ok_or_else(|| {
                AttestError::Malformed("nitro timestamp freshness window overflows".to_string())
            })?;

        if signed_at < oldest_allowed || signed_at > newest_allowed {
            return Err(AttestError::QuoteRejected(
                "nitro timestamp is outside the freshness window".to_string(),
            ));
        }
        if signed_at < self.collateral.not_before || signed_at > self.collateral.not_after {
            return Err(AttestError::CertificateExpired);
        }
        Ok(())
    }
}

fn nitro_timestamp_millis_to_system_time(timestamp_millis: u64) -> Result<SystemTime, AttestError> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(timestamp_millis))
        .ok_or_else(|| AttestError::Malformed("nitro timestamp overflows SystemTime".to_string()))
}

/// Decoded fields of an AWS Nitro NSM attestation document. The
/// fields not consumed by the trust-boundary contract are dropped
/// after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedNitroDocument {
    pcr0: [u8; NITRO_PCR_LEN],
    certificate: Vec<u8>,
    user_data: [u8; NITRO_USER_DATA_LEN],
    timestamp_millis: u64,
}

impl ParsedNitroDocument {
    fn parse(payload: &[u8]) -> Result<Self, AttestError> {
        if payload.len() > NITRO_PAYLOAD_MAX_LEN {
            return Err(AttestError::Malformed(
                "nitro payload exceeds maximum length".to_string(),
            ));
        }
        let value: CborValue = coset::cbor::de::from_reader(payload)
            .map_err(|e| AttestError::Malformed(format!("nitro payload not CBOR: {e}")))?;
        let map = match value {
            CborValue::Map(m) => m,
            _ => {
                return Err(AttestError::Malformed(
                    "nitro payload is not a CBOR map".to_string(),
                ))
            }
        };

        let mut module_id: Option<String> = None;
        let mut timestamp_millis: Option<u64> = None;
        let mut pcr0: Option<[u8; NITRO_PCR_LEN]> = None;
        let mut certificate: Option<Vec<u8>> = None;
        let mut cabundle_seen = false;
        let mut user_data: Option<[u8; NITRO_USER_DATA_LEN]> = None;

        for (k, v) in map {
            let key = match k {
                CborValue::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "module_id" => {
                    if let CborValue::Text(s) = v {
                        if s.len() > NITRO_MODULE_ID_MAX_LEN {
                            return Err(AttestError::Malformed(
                                "nitro module_id exceeds maximum length".to_string(),
                            ));
                        }
                        module_id = Some(s);
                    }
                }
                "timestamp" => match v {
                    CborValue::Integer(i) => {
                        let raw: i128 = i.into();
                        if raw < 0 {
                            return Err(AttestError::Malformed(
                                "nitro timestamp is negative".to_string(),
                            ));
                        }
                        let raw_u: u128 = raw as u128;
                        let raw_u64: u64 = u64::try_from(raw_u).map_err(|_| {
                            AttestError::Malformed("nitro timestamp overflows u64".to_string())
                        })?;
                        timestamp_millis = Some(raw_u64);
                    }
                    _ => {
                        return Err(AttestError::Malformed(
                            "nitro timestamp is not an integer".to_string(),
                        ))
                    }
                },
                "pcrs" => {
                    let pcr_map = match v {
                        CborValue::Map(m) => m,
                        _ => {
                            return Err(AttestError::Malformed(
                                "nitro pcrs is not a CBOR map".to_string(),
                            ))
                        }
                    };
                    for (pk, pv) in pcr_map {
                        let pcr_index: i128 = match pk {
                            CborValue::Integer(i) => i.into(),
                            _ => continue,
                        };
                        if pcr_index == 0 {
                            let bytes = match pv {
                                CborValue::Bytes(b) => b,
                                _ => {
                                    return Err(AttestError::Malformed(
                                        "nitro PCR0 is not a CBOR byte string".to_string(),
                                    ))
                                }
                            };
                            if bytes.len() != NITRO_PCR_LEN {
                                return Err(AttestError::Malformed(format!(
                                    "nitro PCR0 length {} not {NITRO_PCR_LEN}",
                                    bytes.len()
                                )));
                            }
                            let mut arr = [0u8; NITRO_PCR_LEN];
                            arr.copy_from_slice(&bytes);
                            pcr0 = Some(arr);
                        }
                    }
                }
                "certificate" => match v {
                    CborValue::Bytes(b) => {
                        if b.is_empty() {
                            return Err(AttestError::Malformed(
                                "nitro certificate field is empty".to_string(),
                            ));
                        }
                        if b.len() > NITRO_CERTIFICATE_MAX_LEN {
                            return Err(AttestError::Malformed(
                                "nitro certificate field exceeds maximum length".to_string(),
                            ));
                        }
                        certificate = Some(b);
                    }
                    _ => {
                        return Err(AttestError::Malformed(
                            "nitro certificate field is not a CBOR byte string".to_string(),
                        ))
                    }
                },
                "cabundle" => {
                    let entries = match v {
                        CborValue::Array(entries) => entries,
                        _ => {
                            return Err(AttestError::Malformed(
                                "nitro cabundle is not a CBOR array".to_string(),
                            ))
                        }
                    };
                    if entries.is_empty() || entries.len() > NITRO_CABUNDLE_MAX_ENTRIES {
                        return Err(AttestError::Malformed(
                            "nitro cabundle length is outside bounds".to_string(),
                        ));
                    }
                    for entry in entries {
                        let bytes = match entry {
                            CborValue::Bytes(bytes) => bytes,
                            _ => {
                                return Err(AttestError::Malformed(
                                    "nitro cabundle entry is not a CBOR byte string".to_string(),
                                ))
                            }
                        };
                        if bytes.is_empty() || bytes.len() > NITRO_CERTIFICATE_MAX_LEN {
                            return Err(AttestError::Malformed(
                                "nitro cabundle entry length is outside bounds".to_string(),
                            ));
                        }
                    }
                    cabundle_seen = true;
                }
                "user_data" => match v {
                    CborValue::Bytes(b) => {
                        if b.len() != NITRO_USER_DATA_LEN {
                            return Err(AttestError::Malformed(format!(
                                "nitro user_data length {} not {NITRO_USER_DATA_LEN}",
                                b.len()
                            )));
                        }
                        let mut arr = [0u8; NITRO_USER_DATA_LEN];
                        arr.copy_from_slice(&b);
                        user_data = Some(arr);
                    }
                    _ => {
                        return Err(AttestError::Malformed(
                            "nitro user_data is not a CBOR byte string".to_string(),
                        ))
                    }
                },
                _ => {}
            }
        }

        let module_id = module_id
            .ok_or_else(|| AttestError::Malformed("nitro payload missing module_id".to_string()))?;
        if module_id.is_empty() {
            return Err(AttestError::Malformed(
                "nitro module_id is empty".to_string(),
            ));
        }
        let timestamp_millis = timestamp_millis
            .ok_or_else(|| AttestError::Malformed("nitro payload missing timestamp".to_string()))?;
        let pcr0 =
            pcr0.ok_or_else(|| AttestError::Malformed("nitro payload missing PCR0".to_string()))?;
        let certificate = certificate.ok_or_else(|| {
            AttestError::Malformed("nitro payload missing certificate".to_string())
        })?;
        if !cabundle_seen {
            return Err(AttestError::Malformed(
                "nitro payload missing cabundle".to_string(),
            ));
        }
        let user_data = user_data
            .ok_or_else(|| AttestError::Malformed("nitro payload missing user_data".to_string()))?;

        Ok(Self {
            pcr0,
            certificate,
            user_data,
            timestamp_millis,
        })
    }
}

/// True only when the chain terminates at the supplied root and has
/// at least one non-empty link below the root, ensuring a real leaf
/// or intermediate is present and that no link is the empty byte
/// slice.
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
