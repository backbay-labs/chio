use sigstore::bundle::verify::policy::VerificationPolicy;

use super::parse::decode_oidc_issuer_value;
use super::OIDC_ISSUER_OID;

/// Issuer-only verification policy: confirms that the certificate carries
/// an OIDC issuer extension matching the caller's expected issuer string,
/// and defers SAN matching to `match_identity` (which supports regex).
pub(super) struct IssuerOnlyPolicy {
    pub(super) expected_issuer: String,
}

impl VerificationPolicy for IssuerOnlyPolicy {
    fn verify(
        &self,
        cert: &x509_cert::Certificate,
    ) -> Result<(), sigstore::bundle::verify::PolicyError> {
        use sigstore::bundle::verify::PolicyError;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(PolicyError::ExtensionNotFound)?;

        for ext in extensions.iter() {
            if ext.extn_id == OIDC_ISSUER_OID {
                let bytes = ext.extn_value.as_bytes();
                let actual = match decode_oidc_issuer_value(bytes) {
                    Ok(s) => s,
                    Err(_) => return Err(PolicyError::ExtensionNotFound),
                };
                if actual == self.expected_issuer {
                    return Ok(());
                }
                return Err(PolicyError::ExtensionCheckFailed {
                    extension: "OIDCIssuer".to_owned(),
                    expected: self.expected_issuer.clone(),
                    actual,
                });
            }
        }
        Err(PolicyError::ExtensionNotFound)
    }
}
