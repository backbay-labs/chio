use std::path::Path;

use chio_guard_registry::{
    expected_identity_from_config, AttestError, AttestVerifier, ExpectedIdentity,
    GuardRegistryError, GuardSigstoreVerifier, SigstoreVerifier, VerifiedAttestation,
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

#[test]
fn guard_registry_source_has_no_raw_cosign_shellout_or_shadow_identity() {
    let source = [
        include_str!("../src/lib.rs"),
        include_str!("../src/verify.rs"),
        include_str!("../src/oci.rs"),
        include_str!("../src/pull.rs"),
    ]
    .join("\n");

    assert!(!source.contains(&["cosign", " verify-blob"].concat()));
    assert!(!source.contains(&["std::process", "::Command"].concat()));
    assert!(!source.contains("struct ExpectedIdentity"));
}

fn expected_identity() -> ExpectedIdentity
where
    ExpectedIdentity: Sized,
{
    expected_identity_from_config(
        "https://github\\.com/backbay/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v.*",
        "https://token.actions.githubusercontent.com",
    )
}
