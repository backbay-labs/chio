#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration coverage for [`TenantPolicyLoader`].
//!
//! The loader is verified against the same `AttestVerifier` trait every
//! other attestation flows through, so these tests substitute a mock
//! implementation that records the bytes it received. Real Sigstore
//! signing is exercised by `tests/integration.rs` against the embedded
//! TUF root and is not duplicated here.

use std::cell::RefCell;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use chio_attest_verify::policy::TenantPolicy;
use chio_attest_verify::policy_loader::{
    TenantPolicyLoader, DEFAULT_STALENESS_HORIZON, MAX_POLICY_CERTIFICATE_BYTES,
};
use chio_attest_verify::{AttestError, AttestVerifier, ExpectedIdentity, VerifiedAttestation};

const BOOTSTRAP_FIXTURE: &str = include_str!("fixtures/policies/bootstrap.toml");
const PLACEHOLDER_SIGNATURE: &[u8] = b"PLACEHOLDER-SIGNATURE-OVERRIDE-IN-PRODUCTION";
const STUB_CERTIFICATE_PEM: &[u8] =
    b"-----BEGIN CERTIFICATE-----\nstub-pem\n-----END CERTIFICATE-----\n";

/// Test verifier that succeeds iff the artifact bytes are exactly the
/// canonical signing bytes of the policy file we intend to load and the
/// signature matches a fixed placeholder. Records calls so individual
/// tests can assert the loader actually invoked the verifier rather than
/// short-circuiting.
struct RecordingVerifier {
    expected_artifact: Vec<u8>,
    expected_signature: Vec<u8>,
    call_seen: AtomicBool,
    forced_error: RefCell<Option<AttestError>>,
}

impl RecordingVerifier {
    fn new(expected_artifact: Vec<u8>, expected_signature: Vec<u8>) -> Self {
        Self {
            expected_artifact,
            expected_signature,
            call_seen: AtomicBool::new(false),
            forced_error: RefCell::new(None),
        }
    }

    fn force_next_error(&self, err: AttestError) {
        *self.forced_error.borrow_mut() = Some(err);
    }

    fn was_called(&self) -> bool {
        self.call_seen.load(Ordering::SeqCst)
    }
}

unsafe impl Sync for RecordingVerifier {}

impl AttestVerifier for RecordingVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::SignatureMismatch)
    }

    fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        self.call_seen.store(true, Ordering::SeqCst);
        if let Some(err) = self.forced_error.borrow_mut().take() {
            return Err(err);
        }
        assert_eq!(
            artifact, self.expected_artifact,
            "loader must hand the canonical signing bytes to the verifier"
        );
        assert_eq!(
            signature, self.expected_signature,
            "loader must hand the policy signature to the verifier"
        );
        assert_eq!(certificate_pem, STUB_CERTIFICATE_PEM);
        assert!(!expected.certificate_identity_regexp.is_empty());
        assert!(!expected.certificate_oidc_issuer.is_empty());
        Ok(VerifiedAttestation {
            subject_digest_sha256: [0u8; 32],
            certificate_identity: expected.certificate_identity_regexp.clone(),
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index: 0,
            rekor_inclusion_verified: false,
            signed_at: SystemTime::UNIX_EPOCH,
        })
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::SignatureMismatch)
    }
}

fn release_signer_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            r"https://github\.com/backbay-labs/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
                .to_owned(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
    }
}

fn fresh_now() -> SystemTime {
    // 2026-05-01T00:00:00Z = 1_777_593_600 unix seconds. One month after
    // the bootstrap fixture's signed_at, well within a 90-day horizon.
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_777_593_600)
}

fn canonical_bytes_for(toml_text: &str) -> Vec<u8> {
    let policy = TenantPolicy::from_toml_slice(toml_text.as_bytes()).expect("fixture must parse");
    policy.canonical_signing_bytes().expect("canonical encode")
}

#[test]
fn default_horizon_is_ninety_days() {
    assert_eq!(
        TenantPolicyLoader::with_default_horizon().horizon(),
        DEFAULT_STALENESS_HORIZON
    );
    assert_eq!(
        DEFAULT_STALENESS_HORIZON,
        Duration::from_secs(90 * 24 * 60 * 60)
    );
}

#[test]
fn loads_bootstrap_fixture_against_recording_verifier() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical.clone(), PLACEHOLDER_SIGNATURE.to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();

    let policy = loader
        .load_signed(
            &verifier,
            &release_signer_identity(),
            BOOTSTRAP_FIXTURE.as_bytes(),
            STUB_CERTIFICATE_PEM,
            fresh_now(),
        )
        .expect("bootstrap fixture must load against recording verifier");

    assert!(verifier.was_called(), "loader must invoke verifier");
    assert_eq!(policy.tenant_id, "bootstrap");
    assert_eq!(policy.version, 1);
    assert!(policy.pq_identity_regexps.is_empty());
}

#[test]
fn signature_failure_propagates_fail_closed() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    verifier.force_next_error(AttestError::SignatureMismatch);
    let loader = TenantPolicyLoader::with_default_horizon();

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        STUB_CERTIFICATE_PEM,
        fresh_now(),
    );

    match result {
        Err(AttestError::SignatureMismatch) => {}
        other => panic!("expected SignatureMismatch, got {other:?}"),
    }
}

#[test]
fn issuer_mismatch_propagates_fail_closed() {
    // The verifier surface returns IssuerMismatch when the policy
    // signing certificate carries an OIDC issuer that does not match
    // the operator-pinned signer identity. The loader MUST surface
    // that error verbatim rather than swallowing it as a generic
    // "policy invalid" outcome; auditors rely on the variant to know
    // that the cert chained but the issuer was wrong.
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    verifier.force_next_error(AttestError::IssuerMismatch);
    let loader = TenantPolicyLoader::with_default_horizon();

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        STUB_CERTIFICATE_PEM,
        fresh_now(),
    );

    match result {
        Err(AttestError::IssuerMismatch) => {}
        other => panic!("expected IssuerMismatch to propagate, got {other:?}"),
    }
    assert!(
        verifier.was_called(),
        "loader must invoke verifier before issuer rejection"
    );
}

#[test]
fn identity_mismatch_propagates_fail_closed() {
    // IdentityMismatch from the verifier MUST also fail-closed at the
    // loader. A tampered policy whose signing cert chains correctly
    // but whose SAN does not match the pinned identity regex is a
    // forged policy; the loader MUST refuse it.
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    verifier.force_next_error(AttestError::IdentityMismatch);
    let loader = TenantPolicyLoader::with_default_horizon();

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        STUB_CERTIFICATE_PEM,
        fresh_now(),
    );

    match result {
        Err(AttestError::IdentityMismatch) => {}
        other => panic!("expected IdentityMismatch to propagate, got {other:?}"),
    }
    assert!(
        verifier.was_called(),
        "loader must invoke verifier before identity rejection"
    );
}

#[test]
fn stale_policy_rejected_at_default_horizon() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();

    // signed_at is 2026-04-01T00:00:00Z. Anchor "now" 91 days later
    // (1_775_001_600 + 91*86400 = 1_782_864_000) so the loader trips
    // the staleness gate.
    let stale_now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_782_864_000);
    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        STUB_CERTIFICATE_PEM,
        stale_now,
    );

    match result {
        Err(AttestError::Malformed(msg)) => {
            assert!(
                msg.contains("signed_at"),
                "expected staleness msg, got: {msg}"
            );
            assert!(
                msg.contains("horizon"),
                "expected staleness msg, got: {msg}"
            );
        }
        other => panic!("expected Malformed staleness error, got {other:?}"),
    }
}

#[test]
fn fresh_policy_at_horizon_boundary_accepted() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();

    // signed_at + exactly 90 days. Boundary case: must be accepted.
    let boundary_now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_775_001_600 + 90 * 86_400);
    loader
        .load_signed(
            &verifier,
            &release_signer_identity(),
            BOOTSTRAP_FIXTURE.as_bytes(),
            STUB_CERTIFICATE_PEM,
            boundary_now,
        )
        .expect("policy at exactly 90 days old must still be accepted");
}

#[test]
fn shortened_horizon_rejects_otherwise_fresh_policy() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    // Aggressive 7-day horizon.
    let loader = TenantPolicyLoader::with_horizon(Duration::from_secs(7 * 86_400));

    let now = fresh_now(); // 30 days past signed_at
    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        STUB_CERTIFICATE_PEM,
        now,
    );

    match result {
        Err(AttestError::Malformed(msg)) => {
            assert!(msg.contains("horizon"), "got: {msg}");
        }
        other => panic!("expected Malformed staleness error, got {other:?}"),
    }
}

#[test]
fn malformed_toml_rejected_before_any_verifier_call() {
    let canonical = b"unused".to_vec();
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        b"this is not toml = =",
        STUB_CERTIFICATE_PEM,
        fresh_now(),
    );

    assert!(matches!(result, Err(AttestError::Malformed(_))));
    assert!(
        !verifier.was_called(),
        "verifier MUST NOT be invoked on structurally-invalid policies"
    );
}

#[test]
fn oversized_certificate_rejected_before_any_verifier_call() {
    let canonical = canonical_bytes_for(BOOTSTRAP_FIXTURE);
    let verifier = RecordingVerifier::new(canonical, PLACEHOLDER_SIGNATURE.to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();
    let certificate = vec![b'A'; MAX_POLICY_CERTIFICATE_BYTES + 1];

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        BOOTSTRAP_FIXTURE.as_bytes(),
        &certificate,
        fresh_now(),
    );

    match result {
        Err(AttestError::Malformed(msg)) => assert!(msg.contains("certificate"), "got: {msg}"),
        other => panic!("expected Malformed certificate-size error, got {other:?}"),
    }
    assert!(
        !verifier.was_called(),
        "verifier MUST NOT be invoked on oversized signer certificates"
    );
}

#[test]
fn future_dated_policy_rejected() {
    let toml = r#"
tenant_id = "future"
version = 1
identity_regexps = ["https://example.com/.*"]
oidc_issuers = ["https://token.example.com"]
signed_at = "2099-01-01T00:00:00Z"
signature = "AAAA"
"#;
    let canonical = canonical_bytes_for(toml);
    let verifier = RecordingVerifier::new(canonical, b"AAAA".to_vec());
    let loader = TenantPolicyLoader::with_default_horizon();

    let result = loader.load_signed(
        &verifier,
        &release_signer_identity(),
        toml.as_bytes(),
        STUB_CERTIFICATE_PEM,
        fresh_now(),
    );

    match result {
        Err(AttestError::Malformed(msg)) => {
            assert!(msg.contains("future"), "got: {msg}");
        }
        other => panic!("expected Malformed future error, got {other:?}"),
    }
}
