use std::time::{SystemTime, UNIX_EPOCH};

use pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sigstore::crypto::{CosignVerificationKey, Signature as SigstoreSignature};
use webpki::{EndEntityCert, KeyUsage};
use x509_cert::Certificate;

use crate::AttestError;

use super::ID_KP_CODE_SIGNING;

pub(super) fn validate_against_fulcio(
    leaf_der: &[u8],
    fulcio_root_ders: &[Vec<u8>],
) -> Result<(), AttestError> {
    let trust_anchors: Vec<TrustAnchor<'_>> = fulcio_root_ders
        .iter()
        .map(|bytes| {
            let der = CertificateDer::from(bytes.as_slice());
            webpki::anchor_from_trusted_cert(&der).map(|a| a.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AttestError::TrustRoot)?;

    let leaf_der_handle = CertificateDer::from(leaf_der);
    let end_entity = EndEntityCert::try_from(&leaf_der_handle)
        .map_err(|_| AttestError::Malformed("leaf cert is not a valid EE cert".into()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AttestError::CertificateExpired)?;
    let unix_now = UnixTime::since_unix_epoch(now);

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            unix_now,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None,
            None,
        )
        .map_err(map_webpki_error)?;

    Ok(())
}

pub(super) fn map_webpki_error(err: webpki::Error) -> AttestError {
    match err {
        webpki::Error::CertNotValidYet { .. } | webpki::Error::CertExpired { .. } => {
            AttestError::CertificateExpired
        }
        webpki::Error::UnknownIssuer => AttestError::TrustRoot,
        _ => AttestError::Malformed(format!("certificate chain validation: {err:?}")),
    }
}

pub(super) fn certificate_validity(
    cert: &Certificate,
) -> Result<(SystemTime, SystemTime), AttestError> {
    let validity = &cert.tbs_certificate.validity;
    let not_before = UNIX_EPOCH + validity.not_before.to_unix_duration();
    let not_after = UNIX_EPOCH + validity.not_after.to_unix_duration();
    Ok((not_before, not_after))
}

pub(super) fn is_within_validity_window(
    now: SystemTime,
    not_before: SystemTime,
    not_after: SystemTime,
) -> bool {
    !(now < not_before || now > not_after)
}

pub(super) fn verify_signature_bytes(
    key: &CosignVerificationKey,
    signature: &[u8],
    msg: &[u8],
) -> Result<(), AttestError> {
    let base64_attempt = key.verify_signature(SigstoreSignature::Base64Encoded(signature), msg);
    if base64_attempt.is_ok() {
        return Ok(());
    }
    key.verify_signature(SigstoreSignature::Raw(signature), msg)
        .map_err(|_| AttestError::SignatureMismatch)
}
