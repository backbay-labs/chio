#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration coverage for [`SigstoreVerifier`]: fail-closed contract tests
//! for malformed inputs, signature mismatches, and chain-validation failures.

use std::io::Write;

use chio_attest_verify::{AttestError, AttestVerifier, ExpectedIdentity, SigstoreVerifier};

fn github_release_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            r"https://github\.com/backbay/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
                .to_owned(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
    }
}

#[test]
fn constructor_loads_embedded_trust_root() {
    let verifier = SigstoreVerifier::with_embedded_root()
        .expect("embedded TUF root must parse and yield a usable verifier");
    // Trait object coercion confirms the impl satisfies Send + Sync.
    let _trait_object: &dyn AttestVerifier = &verifier;
}

#[test]
fn verify_bundle_rejects_malformed_json() {
    let verifier = SigstoreVerifier::with_embedded_root().expect("embedded TUF root must parse");
    let expected = github_release_identity();

    let result = verifier.verify_bundle(b"hello world", b"this is not json", &expected);
    match result {
        Err(AttestError::Malformed(msg)) => {
            assert!(
                msg.to_ascii_lowercase().contains("bundle"),
                "expected bundle parse error, got: {msg}"
            );
        }
        // Test-only panic: surfaces a test failure with diagnostic
        // context. The trust-boundary `panic!()` ban applies under
        // `src/` only (per EXECUTION-BOARD "No verifier or trust-boundary
        // stubs"); this file lives under `tests/` and is compiled solely
        // by `cargo test`.
        other => panic!("expected Malformed bundle error, got {other:?}"),
    }
}

#[test]
fn verify_bundle_rejects_empty_bundle_object() {
    let verifier = SigstoreVerifier::with_embedded_root().expect("embedded TUF root must parse");
    let expected = github_release_identity();

    // A syntactically valid empty bundle object is missing every required
    // field; the verifier MUST reject it rather than treating "no
    // verification material" as a passing signal.
    let result = verifier.verify_bundle(b"hello world", b"{}", &expected);
    assert!(
        matches!(
            result,
            Err(AttestError::Malformed(_))
                | Err(AttestError::TrustRoot)
                | Err(AttestError::SignatureMismatch)
                | Err(AttestError::IssuerMismatch)
                | Err(AttestError::IdentityMismatch)
                | Err(AttestError::RekorInclusion)
                | Err(AttestError::CertificateExpired)
        ),
        "empty bundle must fail closed; got {result:?}"
    );
}

#[test]
fn verify_bytes_rejects_random_garbage() {
    let verifier = SigstoreVerifier::with_embedded_root().expect("embedded TUF root must parse");
    let expected = github_release_identity();

    let result = verifier.verify_bytes(
        b"some artifact bytes",
        b"definitely not a real signature",
        b"definitely not a certificate",
        &expected,
    );
    assert!(
        matches!(result, Err(AttestError::Malformed(_))),
        "garbage cert must surface a Malformed error; got {result:?}"
    );
}

#[test]
fn verify_bytes_rejects_self_signed_cert_against_fulcio_root() {
    // A non-Fulcio leaf certificate (here a real but unrelated PEM) must
    // be rejected by the chain-validation step before the signature is
    // ever inspected.
    let bogus_pem = b"-----BEGIN CERTIFICATE-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijkl\n\
mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=\n\
-----END CERTIFICATE-----\n";

    let verifier = SigstoreVerifier::with_embedded_root().expect("embedded TUF root must parse");
    let expected = github_release_identity();

    let result = verifier.verify_bytes(b"artifact", b"AAAA", bogus_pem, &expected);
    assert!(
        matches!(
            result,
            Err(AttestError::Malformed(_))
                | Err(AttestError::TrustRoot)
                | Err(AttestError::CertificateExpired)
        ),
        "non-Fulcio leaf must be rejected before signature check; got {result:?}"
    );
}

#[test]
fn verify_blob_returns_io_error_for_missing_artifact() {
    let verifier = SigstoreVerifier::with_embedded_root().expect("embedded TUF root must parse");
    let expected = github_release_identity();

    let dir = tempfile::tempdir().expect("tempdir");
    let nonexistent = dir.path().join("does-not-exist.bin");
    let mut sig = tempfile::NamedTempFile::new().expect("sig tempfile");
    let mut cert = tempfile::NamedTempFile::new().expect("cert tempfile");
    sig.write_all(b"placeholder").expect("write sig");
    cert.write_all(b"placeholder").expect("write cert");

    let result = verifier.verify_blob(&nonexistent, sig.path(), cert.path(), &expected);
    assert!(
        matches!(result, Err(AttestError::Io(_))),
        "missing artifact path must surface as Io error; got {result:?}"
    );
}
