use x509_cert::der::Decode;

use crate::AttestError;

/// Accept either a PEM-armored or raw-DER certificate input. The cosign
/// CLI emits PEM by default; some pipelines double-base64-encode. We
/// strip one base64 layer if the bytes do not begin with the PEM header.
pub(super) fn parse_certificate_to_der(input: &[u8]) -> Result<Vec<u8>, AttestError> {
    if let Ok(parsed) = pem::parse(input) {
        if parsed.tag() == "CERTIFICATE" {
            return Ok(parsed.into_contents());
        }
    }

    if input.first() == Some(&0x30) {
        return Ok(input.to_vec());
    }

    Err(AttestError::Malformed(
        "certificate is neither PEM nor DER".into(),
    ))
}

/// Decode the bytes of the Fulcio OIDC issuer X.509 extension. Real-world
/// Fulcio leaves wrap the issuer as a DER UTF8String (tag 0x0C); some
/// older / hand-rolled emitters embed the raw UTF-8 directly.
pub(super) fn decode_oidc_issuer_value(bytes: &[u8]) -> Result<String, AttestError> {
    if let Ok(parsed) = x509_cert::der::asn1::Utf8StringRef::from_der(bytes) {
        return Ok(parsed.as_str().to_owned());
    }

    if let Ok(direct) = std::str::from_utf8(bytes) {
        if !direct.is_empty() && direct.chars().all(|c| !c.is_control()) {
            return Ok(direct.to_owned());
        }
    }

    Err(AttestError::Malformed(
        "OIDC issuer extension is neither DER UTF8String nor printable raw UTF-8".into(),
    ))
}
