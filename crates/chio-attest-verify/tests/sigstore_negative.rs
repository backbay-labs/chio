#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

#[path = "fixtures/cert_time.rs"]
mod cert_time;
#[path = "fixtures/malformed_chain.rs"]
mod malformed_chain;
#[path = "fixtures/oidc_mismatch.rs"]
mod oidc_mismatch;

use chio_attest_verify::{AttestError, AttestVerifier, SigstoreVerifier};

fn verifier() -> SigstoreVerifier {
    match SigstoreVerifier::with_embedded_root() {
        Ok(verifier) => verifier,
        Err(error) => panic!("embedded Sigstore root should load for negative tests: {error:?}"),
    }
}

fn assert_verify_bytes_rejects(certificate: &[u8], context: &str) -> AttestError {
    let verifier = verifier();
    match verifier.verify_bytes(
        b"artifact bytes",
        b"not-a-real-signature",
        certificate,
        &oidc_mismatch::github_actions_identity(),
    ) {
        Ok(attestation) => panic!("{context}: unexpected verified attestation {attestation:?}"),
        Err(error) => error,
    }
}

#[test]
fn cert_time_fixture_bytes_fail_closed_before_signature_acceptance() {
    for (name, certificate) in [
        (
            "not-yet-valid synthetic pem",
            cert_time::not_yet_valid_leaf_pem(),
        ),
        ("expired synthetic der", cert_time::expired_leaf_der()),
    ] {
        let error = assert_verify_bytes_rejects(certificate, name);
        assert!(
            matches!(
                error,
                AttestError::Malformed(_)
                    | AttestError::TrustRoot
                    | AttestError::CertificateExpired
            ),
            "{name} returned {error:?}"
        );
    }
}

#[test]
fn malformed_chain_fixtures_never_verify_as_fulcio_leaves() {
    for (name, certificate) in [
        ("truncated leaf der", malformed_chain::truncated_leaf_der()),
        ("wrong ca root pem", malformed_chain::wrong_ca_root_pem()),
    ] {
        let error = assert_verify_bytes_rejects(certificate, name);
        assert!(
            matches!(
                error,
                AttestError::Malformed(_)
                    | AttestError::TrustRoot
                    | AttestError::CertificateExpired
            ),
            "{name} returned {error:?}"
        );
    }
}

#[test]
fn oidc_mismatch_input_does_not_fall_back_to_identity_regex_only() {
    let verifier = verifier();
    let result = verifier.verify_bytes(
        b"artifact bytes",
        b"not-a-real-signature",
        malformed_chain::wrong_ca_root_pem(),
        &oidc_mismatch::wrong_issuer_identity(),
    );

    assert!(
        result.is_err(),
        "wrong issuer input must not verify even when identity regex is broad"
    );
}

#[test]
fn malformed_bundle_json_fails_closed() {
    let verifier = verifier();
    let result = verifier.verify_bundle(
        b"artifact bytes",
        br#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2"}"#,
        &oidc_mismatch::github_actions_identity(),
    );

    assert!(
        matches!(result, Err(AttestError::Malformed(_))),
        "malformed bundle JSON should reject before attestation acceptance: {result:?}"
    );
}
