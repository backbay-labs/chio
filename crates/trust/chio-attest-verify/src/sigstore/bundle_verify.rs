use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::Sha256;
use sigstore::bundle::verify::Verifier as AsyncBundleVerifier;
use sigstore::bundle::Bundle;

use crate::AttestError;

use super::compat;
use super::policy::IssuerOnlyPolicy;

/// Drive the async `sigstore-rs` bundle verifier from a synchronous
/// trait method without panicking when the caller is itself running
/// inside a tokio runtime.
pub(super) fn run_async_bundle_verify(
    fallback_runtime: &tokio::runtime::Runtime,
    verifier: AsyncBundleVerifier,
    hasher: Sha256,
    bundle: Bundle,
    issuer_policy: IssuerOnlyPolicy,
) -> sigstore::bundle::verify::VerificationResult {
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    return Err(sigstore::bundle::verify::VerificationError::Input(
                        io::Error::other(format!("spawn helper-runtime: {err}")),
                    ));
                }
            };
            rt.block_on(verifier.verify_digest(hasher, bundle, &issuer_policy, true))
        })
        .join()
        .unwrap_or_else(|_| {
            Err(sigstore::bundle::verify::VerificationError::Input(
                io::Error::other("verify helper thread panicked"),
            ))
        })
    } else {
        fallback_runtime.block_on(verifier.verify_digest(hasher, bundle, &issuer_policy, true))
    }
}

pub(super) fn bundle_leaf_certificate_der(bundle: &Bundle) -> Result<Vec<u8>, AttestError> {
    compat::leaf_der(bundle)
        .ok_or_else(|| AttestError::Malformed("bundle has no leaf certificate".into()))
}

pub(super) fn bundle_rekor_metadata(bundle: &Bundle) -> (u64, SystemTime) {
    let (index, integrated) = compat::rekor_metadata(bundle).unwrap_or((0, 0));
    let signed_at = if integrated > 0 {
        UNIX_EPOCH + Duration::from_secs(integrated as u64)
    } else {
        SystemTime::now()
    };
    (index, signed_at)
}

pub(super) fn bundle_rekor_inclusion_verified(_bundle: &Bundle) -> bool {
    false
}

pub(super) fn map_bundle_verification_error(
    err: sigstore::bundle::verify::VerificationError,
) -> AttestError {
    use sigstore::bundle::verify::VerificationError as VE;

    let rendered = err.to_string().to_ascii_lowercase();
    match err {
        VE::Input(e) => AttestError::Io(io::Error::other(e.to_string())),
        VE::Bundle(_) => AttestError::Malformed(format!("sigstore bundle: {rendered}")),
        VE::Certificate(_) => {
            if rendered.contains("expired") {
                AttestError::CertificateExpired
            } else {
                AttestError::TrustRoot
            }
        }
        VE::Signature(_) => {
            if rendered.contains("transparency") {
                AttestError::RekorInclusion
            } else {
                AttestError::SignatureMismatch
            }
        }
        VE::Policy(_) => AttestError::IssuerMismatch,
    }
}
