use regex::Regex;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

use crate::{AttestError, ExpectedIdentity};

use super::parse::decode_oidc_issuer_value;
use super::{OIDC_ISSUER_OID, OTHERNAME_OID};

pub(super) fn match_identity(
    cert: &Certificate,
    expected: &ExpectedIdentity,
) -> Result<String, AttestError> {
    let issuer = read_oidc_issuer_extension(cert)?;
    if issuer != expected.certificate_oidc_issuer {
        return Err(AttestError::IssuerMismatch);
    }

    let anchored = format!("^(?:{})$", expected.certificate_identity_regexp);
    let regex = Regex::new(&anchored)
        .map_err(|e| AttestError::Malformed(format!("identity regex compile: {e}")))?;

    let san_match = cert
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|e| AttestError::Malformed(format!("SAN extension parse: {e}")))?;

    let Some((_critical, san)) = san_match else {
        return Err(AttestError::IdentityMismatch);
    };

    for name in san.0.iter() {
        let candidate: Option<String> = match name {
            GeneralName::Rfc822Name(s) => Some(s.as_str().to_owned()),
            GeneralName::UniformResourceIdentifier(s) => Some(s.as_str().to_owned()),
            GeneralName::OtherName(other) if other.type_id == OTHERNAME_OID => {
                std::str::from_utf8(other.value.value())
                    .ok()
                    .map(|s| s.to_owned())
            }
            _ => None,
        };

        if let Some(candidate) = candidate {
            if regex.is_match(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(AttestError::IdentityMismatch)
}

pub(super) fn read_oidc_issuer_extension(cert: &Certificate) -> Result<String, AttestError> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| AttestError::Malformed("certificate has no extensions".into()))?;

    for ext in extensions.iter() {
        if ext.extn_id == OIDC_ISSUER_OID {
            let bytes = ext.extn_value.as_bytes();
            return decode_oidc_issuer_value(bytes);
        }
    }

    Err(AttestError::IssuerMismatch)
}
