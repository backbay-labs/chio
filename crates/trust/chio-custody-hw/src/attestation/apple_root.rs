//! Pinned Apple App Attestation root.

use sha2::{Digest, Sha256};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use super::errors::AttestationError;

pub const APPLE_APP_ATTEST_ROOT_SHA256: [u8; 32] = [
    0x1c, 0xb9, 0x82, 0x3b, 0xa2, 0x8b, 0xa6, 0xad, 0x2d, 0x33, 0xa0, 0x06, 0x94, 0x1d, 0xe2, 0xae,
    0x4f, 0x51, 0x3e, 0xf1, 0xd4, 0xe8, 0x31, 0xb9, 0xf7, 0xe0, 0xfa, 0x7b, 0x62, 0x42, 0xc9, 0x32,
];

pub const APPLE_APP_ATTEST_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n\
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n\
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n\
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n\
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n\
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n\
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n\
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n\
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n\
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n\
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n\
oyFraWVIyd/dganmrduC1bmTBGwD\n\
-----END CERTIFICATE-----\n";

pub fn validate_pinned_apple_root() -> Result<(), AttestationError> {
    let root_der = apple_app_attest_root_der()?;
    let (_, cert) = X509Certificate::from_der(&root_der)
        .map_err(|error| AttestationError::InvalidRoot(format!("DER parse failed: {error}")))?;
    let subject = cert.subject().to_string();
    if !subject.contains("Apple App Attestation Root CA") {
        return Err(AttestationError::InvalidRoot(format!(
            "unexpected subject {subject}"
        )));
    }
    let actual: [u8; 32] = Sha256::digest(&root_der).into();
    if actual != APPLE_APP_ATTEST_ROOT_SHA256 {
        return Err(AttestationError::InvalidRoot(
            "root SHA-256 fingerprint mismatch".to_string(),
        ));
    }
    Ok(())
}

pub fn apple_app_attest_root_der() -> Result<Vec<u8>, AttestationError> {
    let (_, pem) = parse_x509_pem(APPLE_APP_ATTEST_ROOT_PEM.as_bytes())
        .map_err(|error| AttestationError::InvalidRoot(format!("PEM parse failed: {error}")))?;
    Ok(pem.contents)
}
