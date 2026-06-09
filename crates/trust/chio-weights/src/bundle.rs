//! Cosign bundle helper for model cards.
//!
//! Wraps [`chio_attest_verify::SigstoreVerifier::verify_bundle`] so that
//! callers presenting a `(card_bytes, bundle_json)` pair can verify the
//! bundle without reaching into `sigstore-rs` directly. The model-card
//! binding does not introduce a new trust root or a new signature path;
//! the existing cosign bundle verifier (and the PQ-hybrid surface) is
//! consumed verbatim.
//!
//! # Trust contract
//!
//! - `card_bytes` MUST be the RFC 8785 canonical-JSON encoding of the
//!   [`crate::card::ModelCard`]. The cosign bundle's signature is taken
//!   over those bytes, so re-encoding through any non-canonical serializer
//!   produces a different digest and the bundle rejects fail-closed.
//! - `expected` is an [`ExpectedIdentity`] supplied by the caller. The
//!   helper does not synthesise a default identity; deployments that flip
//!   `policy.weights_card_required = required_with_pin` provide the SAN
//!   regex from the provider matrix.
//! - `now` is the verifier-side current time used to enforce the card's
//!   `expires_at`. The cosign verifier's certificate-window check is
//!   independent of this and runs against the cert's `notBefore` /
//!   `notAfter`.
//!
//! # Trust boundary
//!
//! Every public method that returns `Ok(_)` MUST mean:
//!
//! 1. the cosign bundle verified against the supplied card bytes,
//! 2. the bundle's certificate identity matched [`ExpectedIdentity`] and
//!    its OIDC issuer matched [`ExpectedIdentity::certificate_oidc_issuer`],
//! 3. the card decoded cleanly from the canonical bytes, and
//! 4. the card's `expires_at` is strictly after `now`.
//!
//! Any failing precondition surfaces as a [`crate::error::WeightsError`].

use chio_attest_verify::{AttestVerifier, ExpectedIdentity, VerifiedAttestation};
use chrono::{DateTime, Utc};

use crate::card::ModelCard;
use crate::error::WeightsError;

/// Successful verification result. Pairs the parsed [`ModelCard`] with the
/// upstream [`VerifiedAttestation`] so receipt consumers can correlate the
/// Rekor log index, the Fulcio identity, and the model card's logical
/// fields without re-parsing the bundle.
#[derive(Debug, Clone)]
pub struct VerifiedModelCard {
    /// Parsed model card decoded from the canonical-JSON byte slice the
    /// cosign bundle was signed over.
    pub card: ModelCard,
    /// Upstream attestation metadata (cert identity, OIDC issuer, Rekor
    /// log index, signing time).
    pub attestation: VerifiedAttestation,
}

/// Verify a cosign-signed model card. Delegates the cryptographic verify
/// path to [`AttestVerifier::verify_bundle`]; this helper does not fork
/// it.
///
/// On success, returns the parsed [`ModelCard`] alongside the upstream
/// [`VerifiedAttestation`]. Fail-closed: any failing precondition returns
/// a [`WeightsError`] whose [`WeightsError::urn`] gives the stable
/// `urn:chio:error:weights:*` code.
///
/// # Liveness
///
/// The card's `expires_at` field is enforced against `now`. A card whose
/// cosign signature would otherwise verify but whose `expires_at` has
/// already passed surfaces as [`WeightsError::Expired`].
pub fn verify_model_card_bundle<V: AttestVerifier + ?Sized>(
    verifier: &V,
    card_bytes: &[u8],
    bundle_json: &[u8],
    expected: &ExpectedIdentity,
    now: DateTime<Utc>,
) -> Result<VerifiedModelCard, WeightsError> {
    let attestation = verifier
        .verify_bundle(card_bytes, bundle_json, expected)
        .map_err(|err| WeightsError::BundleRejected(format!("{err}")))?;

    let card = ModelCard::from_canonical_json(card_bytes)?;
    if card.issuer != attestation.certificate_identity {
        return Err(WeightsError::BundleRejected(format!(
            "model card issuer {:?} does not match verified certificate identity {:?}",
            card.issuer, attestation.certificate_identity
        )));
    }
    card.require_live(now)?;

    Ok(VerifiedModelCard { card, attestation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::SystemTime;

    use chio_attest_verify::AttestError;
    use chrono::TimeZone;

    use crate::card::StringSet;

    /// Fake verifier that records the inputs it was called with and emits
    /// a configurable response. Used in unit tests to lock the helper's
    /// behaviour without standing up the real Sigstore TUF root.
    #[derive(Default)]
    struct FakeVerifier {
        last_artifact: Mutex<Option<Vec<u8>>>,
        last_bundle: Mutex<Option<Vec<u8>>>,
        last_expected: Mutex<Option<ExpectedIdentity>>,
        outcome: Mutex<Outcome>,
    }

    enum Outcome {
        Ok(VerifiedAttestation),
        Reject(AttestError),
    }

    impl Default for Outcome {
        fn default() -> Self {
            Self::Reject(AttestError::SignatureMismatch)
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
            Err(AttestError::Malformed(
                "verify_blob not used in tests".into(),
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
                "verify_bytes not used in tests".into(),
            ))
        }
        fn verify_bundle(
            &self,
            artifact: &[u8],
            bundle_json: &[u8],
            expected: &ExpectedIdentity,
        ) -> Result<VerifiedAttestation, AttestError> {
            if let Ok(mut slot) = self.last_artifact.lock() {
                *slot = Some(artifact.to_vec());
            }
            if let Ok(mut slot) = self.last_bundle.lock() {
                *slot = Some(bundle_json.to_vec());
            }
            if let Ok(mut slot) = self.last_expected.lock() {
                *slot = Some(expected.clone());
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(_) => return Err(AttestError::SignatureMismatch),
            };
            match &*outcome {
                Outcome::Ok(att) => Ok(att.clone()),
                Outcome::Reject(err) => Err(match err {
                    AttestError::SignatureMismatch => AttestError::SignatureMismatch,
                    AttestError::IdentityMismatch => AttestError::IdentityMismatch,
                    AttestError::IssuerMismatch => AttestError::IssuerMismatch,
                    AttestError::RekorInclusion => AttestError::RekorInclusion,
                    AttestError::CertificateExpired => AttestError::CertificateExpired,
                    AttestError::TrustRoot => AttestError::TrustRoot,
                    AttestError::Malformed(s) => AttestError::Malformed(s.clone()),
                    AttestError::ReportDataMismatch => AttestError::ReportDataMismatch,
                    AttestError::QuoteRejected(s) => AttestError::QuoteRejected(s.clone()),
                    AttestError::Io(_) => AttestError::Malformed("io error stand-in".into()),
                    _ => AttestError::SignatureMismatch,
                }),
            }
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_now fixture must construct"),
        }
    }

    fn card_bytes_with_issuer(issuer: &str) -> Vec<u8> {
        let now = fixed_now();
        let card = match ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new(["tool:read"]),
            StringSet::default(),
            "public-internet",
            issuer,
            now,
            now + chrono::Duration::days(30),
        ) {
            Ok(c) => c,
            Err(e) => panic!("good card must construct: {e}"),
        };
        match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("canonical-json encode must succeed: {e}"),
        }
    }

    fn good_card_bytes() -> Vec<u8> {
        card_bytes_with_issuer("https://example.com/issuer")
    }

    fn ok_outcome() -> Outcome {
        Outcome::Ok(VerifiedAttestation {
            subject_digest_sha256: [0u8; 32],
            certificate_identity: "https://example.com/issuer".into(),
            certificate_oidc_issuer: "https://token.example.com".into(),
            rekor_log_index: 0,
            rekor_inclusion_verified: true,
            signed_at: SystemTime::UNIX_EPOCH,
        })
    }

    fn expected_identity() -> ExpectedIdentity {
        ExpectedIdentity {
            certificate_identity_regexp: "https://example\\.com/.*".into(),
            certificate_oidc_issuer: "https://token.example.com".into(),
        }
    }

    #[test]
    fn verify_passes_through_to_underlying_verifier() {
        let verifier = FakeVerifier::default();
        if let Ok(mut slot) = verifier.outcome.lock() {
            *slot = ok_outcome();
        }
        let bytes = good_card_bytes();
        let bundle = b"{\"fake-bundle\":true}";
        let expected = expected_identity();

        let res = match verify_model_card_bundle(&verifier, &bytes, bundle, &expected, fixed_now())
        {
            Ok(v) => v,
            Err(e) => panic!("ok outcome must verify: {e}"),
        };
        assert_eq!(
            res.card.weights_hash,
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let last_artifact = match verifier.last_artifact.lock() {
            Ok(g) => match g.clone() {
                Some(b) => b,
                None => panic!("artifact slot must be populated"),
            },
            Err(_) => panic!("artifact mutex must lock"),
        };
        assert_eq!(
            last_artifact, bytes,
            "helper must forward exact card bytes to verify_bundle"
        );
        let last_bundle = match verifier.last_bundle.lock() {
            Ok(g) => match g.clone() {
                Some(b) => b,
                None => panic!("bundle slot must be populated"),
            },
            Err(_) => panic!("bundle mutex must lock"),
        };
        assert_eq!(last_bundle, bundle);
    }

    #[test]
    fn verify_rejects_when_underlying_verifier_rejects() {
        let verifier = FakeVerifier::default();
        if let Ok(mut slot) = verifier.outcome.lock() {
            *slot = Outcome::Reject(AttestError::SignatureMismatch);
        }
        let bytes = good_card_bytes();
        let bundle = b"{\"fake-bundle\":true}";
        let expected = expected_identity();

        let res = verify_model_card_bundle(&verifier, &bytes, bundle, &expected, fixed_now());
        assert!(matches!(res, Err(WeightsError::BundleRejected(_))));
    }

    #[test]
    fn verify_rejects_expired_card_even_if_bundle_verifies() {
        let verifier = FakeVerifier::default();
        if let Ok(mut slot) = verifier.outcome.lock() {
            *slot = ok_outcome();
        }
        let bytes = good_card_bytes();
        let bundle = b"{\"fake-bundle\":true}";
        let expected = expected_identity();

        // Far past expiry.
        let later = fixed_now() + chrono::Duration::days(365);
        let res = verify_model_card_bundle(&verifier, &bytes, bundle, &expected, later);
        assert!(matches!(res, Err(WeightsError::Expired { .. })));
    }

    #[test]
    fn verify_rejects_card_issuer_mismatch() {
        let verifier = FakeVerifier::default();
        if let Ok(mut slot) = verifier.outcome.lock() {
            *slot = ok_outcome();
        }
        let bytes = card_bytes_with_issuer("https://example.com/other-issuer");
        let bundle = b"{\"fake-bundle\":true}";
        let expected = expected_identity();

        let res = verify_model_card_bundle(&verifier, &bytes, bundle, &expected, fixed_now());
        assert!(matches!(res, Err(WeightsError::BundleRejected(_))));
    }

    #[test]
    fn verify_rejects_malformed_card_bytes() {
        let verifier = FakeVerifier::default();
        if let Ok(mut slot) = verifier.outcome.lock() {
            *slot = ok_outcome();
        }
        let bundle = b"{\"fake-bundle\":true}";
        let expected = expected_identity();

        // Non-JSON byte slice. Bundle verifier fakes success, but the
        // helper still must reject because the canonical-JSON decoder
        // rejects malformed input.
        let res = verify_model_card_bundle(
            &verifier,
            b"not json at all",
            bundle,
            &expected,
            fixed_now(),
        );
        assert!(matches!(res, Err(WeightsError::Encoding(_))));
    }
}
