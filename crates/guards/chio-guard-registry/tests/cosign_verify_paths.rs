use std::path::Path;
use std::time::SystemTime;

use chio_guard_registry::{
    AttestError, AttestVerifier, ExpectedIdentity, GuardRegistryError, GuardSigstoreVerifier,
    SigstoreVerifier, VerifiedAttestation,
};

struct BundleErrorVerifier {
    error: AttestError,
}

impl AttestVerifier for BundleErrorVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_owned()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".to_owned()))
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        match &self.error {
            AttestError::IdentityMismatch => Err(AttestError::IdentityMismatch),
            AttestError::IssuerMismatch => Err(AttestError::IssuerMismatch),
            AttestError::RekorInclusion => Err(AttestError::RekorInclusion),
            AttestError::TrustRoot => Err(AttestError::TrustRoot),
            AttestError::SignatureMismatch => Err(AttestError::SignatureMismatch),
            AttestError::CertificateExpired => Err(AttestError::CertificateExpired),
            AttestError::Malformed(message) => Err(AttestError::Malformed(message.clone())),
            AttestError::Io(source) => Err(AttestError::Io(std::io::Error::new(
                source.kind(),
                source.to_string(),
            ))),
            _ => Err(AttestError::SignatureMismatch),
        }
    }
}

struct BundleSuccessVerifier {
    rekor_inclusion_verified: bool,
}

impl AttestVerifier for BundleSuccessVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_owned()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".to_owned()))
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Ok(VerifiedAttestation {
            subject_digest_sha256: [1u8; 32],
            certificate_identity: expected.certificate_identity_regexp.clone(),
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index: 42,
            rekor_inclusion_verified: self.rekor_inclusion_verified,
            signed_at: SystemTime::UNIX_EPOCH,
        })
    }
}

struct BytesErrorVerifier {
    error: AttestError,
}

impl AttestVerifier for BytesErrorVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_owned()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        match &self.error {
            AttestError::IdentityMismatch => Err(AttestError::IdentityMismatch),
            AttestError::IssuerMismatch => Err(AttestError::IssuerMismatch),
            AttestError::RekorInclusion => Err(AttestError::RekorInclusion),
            AttestError::TrustRoot => Err(AttestError::TrustRoot),
            AttestError::SignatureMismatch => Err(AttestError::SignatureMismatch),
            AttestError::CertificateExpired => Err(AttestError::CertificateExpired),
            AttestError::Malformed(message) => Err(AttestError::Malformed(message.clone())),
            AttestError::Io(source) => Err(AttestError::Io(std::io::Error::new(
                source.kind(),
                source.to_string(),
            ))),
            _ => Err(AttestError::SignatureMismatch),
        }
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bundle unused".to_owned()))
    }
}

#[test]
fn malformed_bundle_maps_to_guard_registry_error() {
    let verifier = match SigstoreVerifier::with_embedded_root() {
        Ok(verifier) => verifier,
        Err(error) => panic!("embedded Sigstore trust root should load: {error}"),
    };
    let expected = expected_identity();
    let guard_verifier = GuardSigstoreVerifier::new(&verifier, &expected);

    let result = guard_verifier.verify_bundle(b"hello world", b"this is not json");

    match result {
        Err(GuardRegistryError::VerifyMalformedBundle { message }) => {
            assert!(
                message.to_ascii_lowercase().contains("bundle"),
                "expected bundle parse context, got {message}"
            );
        }
        other => panic!("expected malformed bundle mapping, got {other:?}"),
    }
}

#[test]
fn bundle_wrong_subject_and_issuer_map_distinctly() {
    let expected = expected_identity();

    let subject_verifier = BundleErrorVerifier {
        error: AttestError::IdentityMismatch,
    };
    let subject_result =
        GuardSigstoreVerifier::new(&subject_verifier, &expected).verify_bundle(b"wasm", b"bundle");
    assert!(matches!(
        subject_result,
        Err(GuardRegistryError::VerifyWrongSubject)
    ));

    let issuer_verifier = BundleErrorVerifier {
        error: AttestError::IssuerMismatch,
    };
    let issuer_result =
        GuardSigstoreVerifier::new(&issuer_verifier, &expected).verify_bundle(b"wasm", b"bundle");
    assert!(matches!(
        issuer_result,
        Err(GuardRegistryError::VerifyWrongOidcIssuer)
    ));
}

#[test]
fn bundle_missing_rekor_and_trust_root_map_distinctly() {
    let expected = expected_identity();

    let rekor_verifier = BundleErrorVerifier {
        error: AttestError::RekorInclusion,
    };
    let rekor_result =
        GuardSigstoreVerifier::new(&rekor_verifier, &expected).verify_bundle(b"wasm", b"bundle");
    assert!(matches!(
        rekor_result,
        Err(GuardRegistryError::VerifyMissingRekorProof)
    ));

    let trust_root_verifier = BundleErrorVerifier {
        error: AttestError::TrustRoot,
    };
    let trust_root_result = GuardSigstoreVerifier::new(&trust_root_verifier, &expected)
        .verify_bundle(b"wasm", b"bundle");
    assert!(matches!(
        trust_root_result,
        Err(GuardRegistryError::VerifyTrustRoot)
    ));
}

#[test]
fn bundle_admission_denies_unverified_rekor_inclusion() {
    let expected = expected_identity();
    let verifier = BundleSuccessVerifier {
        rekor_inclusion_verified: false,
    };

    let result = GuardSigstoreVerifier::new(&verifier, &expected).verify_bundle(b"wasm", b"bundle");

    assert!(matches!(
        result,
        Err(GuardRegistryError::VerifyMissingRekorProof)
    ));
}

#[test]
fn bundle_report_only_preserves_unverified_rekor_inclusion_bit() {
    let expected = expected_identity();
    let verifier = BundleSuccessVerifier {
        rekor_inclusion_verified: false,
    };

    let attestation = match GuardSigstoreVerifier::new(&verifier, &expected)
        .verify_bundle_report_only(b"wasm", b"bundle")
    {
        Ok(attestation) => attestation,
        Err(error) => panic!("report-only Sigstore verification should preserve metadata: {error}"),
    };

    assert!(!attestation.rekor_inclusion_verified);
    assert_eq!(attestation.rekor_log_index, 42);
    assert_eq!(
        attestation.certificate_oidc_issuer,
        expected.certificate_oidc_issuer
    );
}

#[test]
fn streamed_loads_use_verify_bytes_error_mapping() {
    let expected = expected_identity();
    let verifier = BytesErrorVerifier {
        error: AttestError::IssuerMismatch,
    };
    let result =
        GuardSigstoreVerifier::new(&verifier, &expected).verify_bytes(b"wasm", b"sig", b"cert");

    assert!(matches!(
        result,
        Err(GuardRegistryError::VerifyWrongOidcIssuer)
    ));
}

fn expected_identity() -> ExpectedIdentity
where
    ExpectedIdentity: Sized,
{
    ExpectedIdentity::doc_hidden_inline(
        "https://github\\.com/backbay-labs/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v.*",
        "https://token.actions.githubusercontent.com",
    )
}
