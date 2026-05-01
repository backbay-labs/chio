//! Integration coverage for the cosign bundle helper (P4.T3).
//!
//! These tests exercise [`chio_weights::bundle::verify_model_card_bundle`]
//! against a hand-rolled `AttestVerifier` test double. The real
//! `chio_attest_verify::SigstoreVerifier` requires the embedded TUF root
//! and a network-equivalent fixture; that path is exercised by
//! `chio-attest-verify`'s own integration suite, which M10 P4 consumes
//! verbatim.
//!
//! The contract these tests lock:
//!
//! 1. The helper passes the exact card bytes through to the underlying
//!    `verify_bundle` call (no re-encoding, no re-canonicalisation).
//! 2. A bundle the upstream verifier accepts plus a card whose
//!    canonical-JSON bytes decode cleanly plus a `now` strictly before
//!    `expires_at` produces `Ok(VerifiedModelCard)`.
//! 3. A rejected bundle, an expired card, or malformed bytes all surface
//!    as `WeightsError` with the matching `urn()`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use chio_attest_verify::{
    AttestError, AttestVerifier, ExpectedIdentity, VerifiedAttestation,
};
use chio_weights::bundle::verify_model_card_bundle;
use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;
use chrono::{DateTime, TimeZone, Utc};

struct FakeVerifier {
    outcome: Mutex<FakeOutcome>,
}

enum FakeOutcome {
    Ok,
    Reject(AttestError),
}

impl FakeVerifier {
    fn ok() -> Self {
        Self {
            outcome: Mutex::new(FakeOutcome::Ok),
        }
    }
    fn reject(err: AttestError) -> Self {
        Self {
            outcome: Mutex::new(FakeOutcome::Reject(err)),
        }
    }
}

impl AttestVerifier for FakeVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".into()))
    }
    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".into()))
    }
    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        let outcome = self.outcome.lock().unwrap();
        match &*outcome {
            FakeOutcome::Ok => Ok(VerifiedAttestation {
                subject_digest_sha256: [0u8; 32],
                certificate_identity: "https://example.com/issuer".into(),
                certificate_oidc_issuer: "https://token.example.com".into(),
                rekor_log_index: 7,
                rekor_inclusion_verified: true,
                signed_at: SystemTime::UNIX_EPOCH,
            }),
            FakeOutcome::Reject(err) => Err(match err {
                AttestError::SignatureMismatch => AttestError::SignatureMismatch,
                AttestError::IdentityMismatch => AttestError::IdentityMismatch,
                AttestError::IssuerMismatch => AttestError::IssuerMismatch,
                AttestError::RekorInclusion => AttestError::RekorInclusion,
                AttestError::CertificateExpired => AttestError::CertificateExpired,
                AttestError::TrustRoot => AttestError::TrustRoot,
                AttestError::Malformed(s) => AttestError::Malformed(s.clone()),
                _ => AttestError::SignatureMismatch,
            }),
        }
    }
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap()
}

fn good_card() -> ModelCard {
    let now = fixed_now();
    ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer",
        now,
        now + chrono::Duration::days(30),
    )
    .unwrap()
}

fn expected() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp: "https://example\\.com/.*".into(),
        certificate_oidc_issuer: "https://token.example.com".into(),
    }
}

#[test]
fn verify_returns_attestation_alongside_card() {
    let card = good_card();
    let bytes = card.to_canonical_json().unwrap();
    let verifier = FakeVerifier::ok();

    let res =
        verify_model_card_bundle(&verifier, &bytes, b"{}", &expected(), fixed_now()).unwrap();
    assert_eq!(res.card.weights_hash, card.weights_hash);
    assert_eq!(res.attestation.rekor_log_index, 7);
    assert!(res.attestation.rekor_inclusion_verified);
}

#[test]
fn verify_propagates_signature_mismatch() {
    let card = good_card();
    let bytes = card.to_canonical_json().unwrap();
    let verifier = FakeVerifier::reject(AttestError::SignatureMismatch);

    let err =
        verify_model_card_bundle(&verifier, &bytes, b"{}", &expected(), fixed_now()).unwrap_err();
    assert_eq!(err.urn(), "urn:chio:error:weights:bundle-rejected");
    assert!(matches!(err, WeightsError::BundleRejected(_)));
}

#[test]
fn verify_propagates_identity_mismatch() {
    let card = good_card();
    let bytes = card.to_canonical_json().unwrap();
    let verifier = FakeVerifier::reject(AttestError::IdentityMismatch);

    let err =
        verify_model_card_bundle(&verifier, &bytes, b"{}", &expected(), fixed_now()).unwrap_err();
    assert!(matches!(err, WeightsError::BundleRejected(_)));
}

#[test]
fn verify_rejects_expired_card_after_bundle_verifies() {
    let card = good_card();
    let bytes = card.to_canonical_json().unwrap();
    let verifier = FakeVerifier::ok();

    // now well past expires_at
    let later = fixed_now() + chrono::Duration::days(365);
    let err =
        verify_model_card_bundle(&verifier, &bytes, b"{}", &expected(), later).unwrap_err();
    assert_eq!(err.urn(), "urn:chio:error:weights:card-expired");
    assert!(matches!(err, WeightsError::Expired { .. }));
}

#[test]
fn verify_rejects_malformed_card_bytes() {
    let verifier = FakeVerifier::ok();
    // The fake bundle verifier accepts any byte slice; the helper still
    // rejects because the canonical-JSON decode fails.
    let err = verify_model_card_bundle(
        &verifier,
        b"this is definitely not a model card",
        b"{}",
        &expected(),
        fixed_now(),
    )
    .unwrap_err();
    assert!(matches!(err, WeightsError::Encoding(_)));
}

#[test]
fn verify_byte_pins_artifact_pass_through() {
    // The helper MUST forward the exact card bytes (not a re-encoded copy)
    // to verify_bundle. Otherwise a non-canonical encode upstream would
    // silently change the digest the cosign signature was taken over.
    let card = good_card();
    let bytes = card.to_canonical_json().unwrap();

    struct ArtifactProbe {
        seen: Mutex<Option<Vec<u8>>>,
    }
    impl AttestVerifier for ArtifactProbe {
        fn verify_blob(
            &self,
            _: &Path,
            _: &Path,
            _: &Path,
            _: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            Err(AttestError::Malformed("unused".into()))
        }
        fn verify_bytes(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            Err(AttestError::Malformed("unused".into()))
        }
        fn verify_bundle(
            &self,
            artifact: &[u8],
            _bundle_json: &[u8],
            _expected: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            *self.seen.lock().unwrap() = Some(artifact.to_vec());
            Ok(VerifiedAttestation {
                subject_digest_sha256: [0u8; 32],
                certificate_identity: "https://example.com/issuer".into(),
                certificate_oidc_issuer: "https://token.example.com".into(),
                rekor_log_index: 0,
                rekor_inclusion_verified: false,
                signed_at: SystemTime::UNIX_EPOCH,
            })
        }
    }

    let probe = ArtifactProbe {
        seen: Mutex::new(None),
    };
    let _ = verify_model_card_bundle(&probe, &bytes, b"{}", &expected(), fixed_now()).unwrap();

    let seen = probe.seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen, bytes, "helper must forward the exact canonical bytes");
}
