use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use chio_guard_registry::{
    expected_identity_from_config, load_guard_with_policy, verify_dual_mode, AttestError,
    AttestVerifier, ExpectedIdentity, GuardCache, GuardCacheArtifact, GuardLoadEvent,
    GuardLoadEventResult, GuardLoadSource, GuardNetworkState, GuardOfflineLoadError,
    GuardOfflineLoadRequest, GuardRegistryError, GuardSigstoreVerifier, GuardVerificationKind,
    GuardVerificationReport, GuardVerifiedSignature, Sha256Digest, VerifiedAttestation,
    CHIO_GUARD_VERIFY_EVENT,
};

const DIGEST: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const MODULE_BYTES: &[u8] = b"\0asm\x01\0\0\0";
const BUNDLE_BYTES: &[u8] = br#"{"bundle":"fixture"}"#;

enum BundleMode {
    Ok {
        digest: [u8; 32],
        identity: &'static str,
    },
    SignatureMismatch,
}

struct StaticBundleVerifier {
    mode: BundleMode,
    bundle_calls: AtomicUsize,
}

impl StaticBundleVerifier {
    fn ok(digest: [u8; 32], identity: &'static str) -> Self {
        Self {
            mode: BundleMode::Ok { digest, identity },
            bundle_calls: AtomicUsize::new(0),
        }
    }

    fn signature_mismatch() -> Self {
        Self {
            mode: BundleMode::SignatureMismatch,
            bundle_calls: AtomicUsize::new(0),
        }
    }

    fn bundle_call_count(&self) -> usize {
        self.bundle_calls.load(Ordering::SeqCst)
    }
}

impl AttestVerifier for StaticBundleVerifier {
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
        artifact: &[u8],
        bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        self.bundle_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(artifact, MODULE_BYTES);
        assert_eq!(bundle_json, BUNDLE_BYTES);

        match self.mode {
            BundleMode::Ok { digest, identity } => Ok(VerifiedAttestation {
                subject_digest_sha256: digest,
                certificate_identity: identity.to_owned(),
                certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
                rekor_log_index: 7,
                rekor_inclusion_verified: true,
                signed_at: SystemTime::UNIX_EPOCH,
            }),
            BundleMode::SignatureMismatch => Err(AttestError::SignatureMismatch),
        }
    }
}

#[test]
fn offline_cached_and_verified_allows_load() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    write_cache(&cache, &digest);

    let verifier = StaticBundleVerifier::ok(digest_bytes(7), "sigstore-subject");
    let expected = expected_identity();
    let sigstore = GuardSigstoreVerifier::new(&verifier, &expected);
    let request = GuardOfflineLoadRequest {
        cache: &cache,
        digest: &digest,
        network: GuardNetworkState::Offline,
        verification: GuardVerificationKind::SigstoreOnly,
    };

    let load = match load_guard_with_policy(request, |layout| {
        sigstore.verify_cached_layout_report(layout)
    }) {
        Ok(load) => load,
        Err(error) => panic!("offline cached verified load should allow: {error}"),
    };

    assert_eq!(load.digest, digest);
    assert_eq!(load.event.event, CHIO_GUARD_VERIFY_EVENT);
    assert_eq!(load.event.result, GuardLoadEventResult::Allow);
    assert_eq!(load.event.verification, GuardVerificationKind::SigstoreOnly);
    assert_eq!(load.event.verification.as_str(), "sigstore-only");
    assert_eq!(load.event.source, GuardLoadSource::OfflineCache);
    assert_eq!(load.event.source.as_str(), "offline-cache");
    assert_eq!(load.event.reason, None);
    assert_eq!(verifier.bundle_call_count(), 1);
}

#[test]
fn offline_uncached_denies_without_verifier_call() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    let calls = AtomicUsize::new(0);
    let request = GuardOfflineLoadRequest {
        cache: &cache,
        digest: &digest,
        network: GuardNetworkState::Offline,
        verification: GuardVerificationKind::SigstoreOnly,
    };

    let result = load_guard_with_policy(request, |_layout| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(sigstore_report(digest_bytes(1), "unused"))
    });

    match result {
        Err(GuardOfflineLoadError::OfflineCacheMiss {
            digest: denied_digest,
            missing,
            event,
        }) => {
            assert_eq!(denied_digest, DIGEST);
            assert_eq!(missing.len(), 5);
            assert_deny_event(
                &event,
                GuardVerificationKind::SigstoreOnly,
                GuardLoadSource::OfflineCache,
                "offline-cache-miss",
            );
        }
        other => panic!("expected offline cache miss denial, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn network_signature_failure_denies_load() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    write_cache(&cache, &digest);

    let verifier = StaticBundleVerifier::signature_mismatch();
    let expected = expected_identity();
    let sigstore = GuardSigstoreVerifier::new(&verifier, &expected);
    let request = GuardOfflineLoadRequest {
        cache: &cache,
        digest: &digest,
        network: GuardNetworkState::Online,
        verification: GuardVerificationKind::SigstoreOnly,
    };

    let result = load_guard_with_policy(request, |layout| {
        sigstore.verify_cached_layout_report(layout)
    });

    match result {
        Err(GuardOfflineLoadError::NetworkSignatureDenied { source, event }) => {
            assert!(matches!(
                *source,
                GuardRegistryError::VerifySignatureMismatch
            ));
            assert_deny_event(
                &event,
                GuardVerificationKind::SigstoreOnly,
                GuardLoadSource::Network,
                "signature-verification-failed",
            );
        }
        other => panic!("expected network signature denial, got {other:?}"),
    }
    assert_eq!(verifier.bundle_call_count(), 1);
}

#[test]
fn dual_mode_digest_mismatch_denies_load_after_both_verifiers_run() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    write_cache(&cache, &digest);

    let ed25519_calls = AtomicUsize::new(0);
    let verifier = StaticBundleVerifier::ok(digest_bytes(2), "shared-identity");
    let expected = expected_identity();
    let sigstore = GuardSigstoreVerifier::new(&verifier, &expected);
    let request = GuardOfflineLoadRequest {
        cache: &cache,
        digest: &digest,
        network: GuardNetworkState::Offline,
        verification: GuardVerificationKind::DualVerified,
    };

    let result = load_guard_with_policy(request, |layout| {
        verify_dual_mode(
            || {
                ed25519_calls.fetch_add(1, Ordering::SeqCst);
                Ok(GuardVerifiedSignature {
                    digest_sha256: digest_bytes(1),
                    identity: "shared-identity".to_owned(),
                })
            },
            || sigstore.verify_cached_layout(layout),
        )
    });

    match result {
        Err(GuardOfflineLoadError::CachedSignatureDenied { source, event }) => {
            match *source {
                GuardRegistryError::VerifyFailedClosed { message } => {
                    assert!(message.contains("digest mismatch"), "{message}");
                }
                other => panic!("expected dual-mode failed-closed error, got {other:?}"),
            }
            assert_deny_event(
                &event,
                GuardVerificationKind::DualVerified,
                GuardLoadSource::OfflineCache,
                "signature-verification-failed",
            );
        }
        other => panic!("expected dual-mode cached signature denial, got {other:?}"),
    }
    assert_eq!(ed25519_calls.load(Ordering::SeqCst), 1);
    assert_eq!(verifier.bundle_call_count(), 1);
}

#[test]
fn structured_event_labels_distinguish_all_verification_modes() {
    assert_eq!(GuardVerificationKind::Ed25519Only.as_str(), "ed25519-only");
    assert_eq!(
        GuardVerificationKind::SigstoreOnly.as_str(),
        "sigstore-only"
    );
    assert_eq!(
        GuardVerificationKind::DualVerified.as_str(),
        "dual-verified"
    );

    let event = GuardLoadEvent::allow(
        GuardVerificationKind::Ed25519Only,
        GuardLoadSource::OfflineCache,
        DIGEST,
        &GuardVerifiedSignature {
            digest_sha256: digest_bytes(9),
            identity: "ed25519-key".to_owned(),
        },
    );

    assert_eq!(event.result.as_str(), "allow");
    assert_eq!(event.verification.as_str(), "ed25519-only");
    assert_eq!(event.identity.as_deref(), Some("ed25519-key"));
}

fn sigstore_report(digest: [u8; 32], identity: &'static str) -> GuardVerificationReport {
    GuardVerificationReport::sigstore_only(&VerifiedAttestation {
        subject_digest_sha256: digest,
        certificate_identity: identity.to_owned(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        rekor_log_index: 7,
        rekor_inclusion_verified: true,
        signed_at: SystemTime::UNIX_EPOCH,
    })
}

fn assert_deny_event(
    event: &GuardLoadEvent,
    verification: GuardVerificationKind,
    source: GuardLoadSource,
    reason: &str,
) {
    assert_eq!(event.event, CHIO_GUARD_VERIFY_EVENT);
    assert_eq!(event.result, GuardLoadEventResult::Deny);
    assert_eq!(event.verification, verification);
    assert_eq!(event.source, source);
    assert_eq!(event.digest, DIGEST);
    assert_eq!(event.reason.as_deref(), Some(reason));
}

fn write_cache(cache: &GuardCache, digest: &Sha256Digest) {
    let result = cache.write_artifact(
        digest,
        GuardCacheArtifact {
            manifest_json: br#"{"schemaVersion":2}"#,
            config_json: br#"{"wit_world":"chio:guard/guard@0.2.0"}"#,
            wit: b"package chio:guard@0.2.0;",
            module: MODULE_BYTES,
            sigstore_bundle_json: BUNDLE_BYTES,
        },
    );
    if let Err(error) = result {
        panic!("cache write should succeed: {error}");
    }
}

fn digest() -> Sha256Digest {
    match DIGEST.parse::<Sha256Digest>() {
        Ok(digest) => digest,
        Err(error) => panic!("fixture digest should parse: {error}"),
    }
}

fn digest_bytes(value: u8) -> [u8; 32] {
    [value; 32]
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

fn tempdir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(temp) => temp,
        Err(error) => panic!("tempdir should be created: {error}"),
    }
}
