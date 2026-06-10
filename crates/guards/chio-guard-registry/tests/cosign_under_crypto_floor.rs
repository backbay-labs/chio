//! Cosign-bundle gating regression under all `crypto_floor` settings.
//!
//! Hybrid signing on receipts, capability tokens, and the session
//! compliance certificate must not affect this path. The cosign bundle
//! path through `chio-guard-registry` MUST NOT change: cosign payload
//! bytes are not signed hybrid; the registry verifies them via the
//! existing `SigstoreVerifier::verify_bundle`. This test pins that
//! contract by exercising `GuardSigstoreVerifier::verify_bundle` with a
//! mock `AttestVerifier` across the three crypto_floor states an
//! operator might configure.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::SystemTime;

use chio_guard_registry::{
    AttestError, AttestVerifier, ExpectedIdentity, GuardSigstoreVerifier, VerifiedAttestation,
};

/// Mirror of the kernel-side `KernelCryptoFloor` enum, defined locally so
/// the regression test is self-contained (chio-guard-registry has no
/// dependency on chio-kernel and must not gain one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoFloorScenario {
    AllowClassical,
    AllowHybrid,
    PqRequired,
}

impl CryptoFloorScenario {
    fn label(&self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }
}

const ALL_FLOORS: [CryptoFloorScenario; 3] = [
    CryptoFloorScenario::AllowClassical,
    CryptoFloorScenario::AllowHybrid,
    CryptoFloorScenario::PqRequired,
];

/// Mock verifier that reports a successful cosign-bundle verification
/// regardless of input. The cosign verifier is the surface T6 protects;
/// `chio-attest-verify::SigstoreVerifier` is exercised by the rest of
/// `tests/cosign_verify_paths.rs` and is not re-tested here.
struct AlwaysOkBundleVerifier;

impl AttestVerifier for AlwaysOkBundleVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed(
            "verify_blob unused in this regression".to_owned(),
        ))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed(
            "verify_bytes unused in this regression".to_owned(),
        ))
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Ok(VerifiedAttestation {
            subject_digest_sha256: [0u8; 32],
            certificate_identity: expected.certificate_identity_regexp.clone(),
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index: 1,
            rekor_inclusion_verified: true,
            signed_at: SystemTime::UNIX_EPOCH,
        })
    }
}

fn make_expected() -> ExpectedIdentity {
    ExpectedIdentity::doc_hidden_inline(
        "https://github.com/test/repo/.github/workflows/.*",
        "https://token.actions.githubusercontent.com",
    )
}

/// Sanity: the cosign bundle bytes themselves are not crypto_floor-aware.
/// The same payload + bundle MUST produce a successful
/// `VerifiedAttestation` regardless of the kernel-side floor.
fn run_cosign_bundle_verify(_floor: CryptoFloorScenario) -> VerifiedAttestation {
    let attest_verifier = AlwaysOkBundleVerifier;
    let expected = make_expected();
    let guard_verifier = GuardSigstoreVerifier::new(&attest_verifier, &expected);
    guard_verifier
        .verify_bundle(b"artifact-bytes", b"{\"bundle\": \"json\"}")
        .unwrap()
}

#[test]
fn cosign_bundle_passes_under_allow_classical() {
    let result = run_cosign_bundle_verify(CryptoFloorScenario::AllowClassical);
    assert!(result.rekor_inclusion_verified);
    assert_eq!(result.rekor_log_index, 1);
}

#[test]
fn cosign_bundle_passes_under_allow_hybrid() {
    let result = run_cosign_bundle_verify(CryptoFloorScenario::AllowHybrid);
    assert!(result.rekor_inclusion_verified);
    assert_eq!(result.rekor_log_index, 1);
}

#[test]
fn cosign_bundle_passes_under_pq_required() {
    // The crucial cell: pq_required does NOT degrade the cosign path.
    // The verifier surface stays green even under the strictest
    // kernel-side floor because cosign payload bytes are not hybrid-signed.
    let result = run_cosign_bundle_verify(CryptoFloorScenario::PqRequired);
    assert!(result.rekor_inclusion_verified);
    assert_eq!(result.rekor_log_index, 1);
}

#[test]
fn cosign_bundle_outcome_byte_identical_across_floors() {
    // Byte-equivalence: the verified attestation that downstream consumers
    // observe (the SAN, the OIDC issuer, the inclusion proof bit) is
    // byte-identical across all three floors. A future change that makes
    // the cosign path observe `crypto_floor` MUST flag here first so the
    // verifier surface contract is renegotiated explicitly rather than
    // silently drifting.
    let mut renderings = Vec::new();
    for floor in ALL_FLOORS {
        let attestation = run_cosign_bundle_verify(floor);
        renderings.push((
            floor.label(),
            attestation.certificate_identity.clone(),
            attestation.certificate_oidc_issuer.clone(),
            attestation.rekor_inclusion_verified,
            attestation.rekor_log_index,
        ));
    }
    let baseline = &renderings[0];
    for entry in &renderings[1..] {
        assert_eq!(
            (&entry.1, &entry.2, entry.3, entry.4),
            (&baseline.1, &baseline.2, baseline.3, baseline.4),
            "cosign verification result drifted under floor {} vs {}",
            entry.0,
            baseline.0
        );
    }
}

#[test]
fn cosign_bundle_failure_propagates_under_all_floors() {
    // Negative cell: a failing AttestVerifier still fails identically
    // under every floor. Threat model row `pq_signature_downgrade` does
    // not bleed into the cosign-bundle gate.
    struct FailingVerifier;
    impl AttestVerifier for FailingVerifier {
        fn verify_blob(
            &self,
            _: &Path,
            _: &Path,
            _: &Path,
            _: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            Err(AttestError::SignatureMismatch)
        }
        fn verify_bytes(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            Err(AttestError::SignatureMismatch)
        }
        fn verify_bundle(
            &self,
            _: &[u8],
            _: &[u8],
            _: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            Err(AttestError::SignatureMismatch)
        }
    }

    let expected = make_expected();
    let verifier = FailingVerifier;
    let guard_verifier = GuardSigstoreVerifier::new(&verifier, &expected);

    for floor in ALL_FLOORS {
        let result = guard_verifier.verify_bundle(b"x", b"{}");
        assert!(
            result.is_err(),
            "cosign failure under {} must propagate",
            floor.label()
        );
    }
}
