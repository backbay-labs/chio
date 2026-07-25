//! Kernel trust establishment / mTLS handshake tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::capability::features::{
    CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, CUMULATIVE_APPROVAL_BUDGET,
};
use chio_core_types::crypto::Keypair;
use chio_federation::{
    trust_establishment::ConformanceEvidence, trust_establishment::ConformanceTier,
    trust_establishment::KernelTrustExchange, trust_establishment::KernelTrustExchangeConfig,
    trust_establishment::LadderManifestRef, trust_establishment::PeerHandshakeEnvelope,
    trust_establishment::PeerHandshakeError, trust_establishment::QuorumPolicy,
    trust_establishment::DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
};

#[test]
fn handshake_succeeds_and_pins_both_sides() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;

    let exchange_a = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_trusted_peer("kernel.org-b", kp_b.public_key());
    let exchange_b = KernelTrustExchange::new("kernel.org-b", kp_b.clone())
        .with_trusted_peer("kernel.org-a", kp_a.public_key());

    // Each side builds its own signed envelope.
    let envelope_a = exchange_a
        .local_envelope("kernel.org-b", "nonce-a", now)
        .unwrap();
    let envelope_b = exchange_b
        .local_envelope("kernel.org-a", "nonce-b", now)
        .unwrap();

    // Each side verifies and pins the remote.
    let peer_b = exchange_a
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .unwrap();
    let peer_a = exchange_b
        .accept_envelope(&envelope_a, "kernel.org-a", now)
        .unwrap();

    assert_eq!(peer_b.kernel_id, "kernel.org-b");
    assert_eq!(peer_a.kernel_id, "kernel.org-a");
    assert_eq!(peer_b.conformance_tier, ConformanceTier::Bronze);
    assert_eq!(peer_a.conformance_tier, ConformanceTier::Bronze);
    assert!(peer_b.rotation_due > now);
    assert!(peer_a.rotation_due > now);

    // Resolve while fresh succeeds.
    let resolved = exchange_a.resolve("kernel.org-b", now + 60).unwrap();
    assert_eq!(resolved.public_key.to_hex(), kp_b.public_key().to_hex());
}

#[test]
fn default_handshake_omits_v1_compatibility_fields() {
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;

    let envelope =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-b", now, &kp_b).unwrap();
    let challenge = serde_json::to_value(&envelope.challenge).unwrap();

    assert!(challenge.get("capabilities").is_none());
    assert!(challenge.get("conformanceTier").is_none());
    assert!(challenge.get("ladderManifestRef").is_none());
    envelope.verify_signature().unwrap();
}

#[test]
fn ladder_manifest_ref_is_signed_and_pinned_when_requested() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let ladder_ref = LadderManifestRef {
        manifest_id: "ladder:payments:v1".to_string(),
        sha256: "a".repeat(64),
        issued_at_unix_ms: now * 1000,
        expires_at_unix_ms: (now + 3_600) * 1000,
    };

    let exchange_a = KernelTrustExchange::new("kernel.org-a", kp_a)
        .with_trusted_peer("kernel.org-b", kp_b.public_key());
    let exchange_b =
        KernelTrustExchange::new("kernel.org-b", kp_b).with_ladder_manifest_ref(ladder_ref.clone());

    let envelope_b = exchange_b
        .local_envelope("kernel.org-a", "nonce-ladder", now)
        .unwrap();
    assert_eq!(
        envelope_b.challenge.ladder_manifest_ref.as_ref(),
        Some(&ladder_ref)
    );
    envelope_b.verify_signature().unwrap();

    let peer_b = exchange_a
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .unwrap();
    assert_eq!(peer_b.ladder_manifest_ref.as_ref(), Some(&ladder_ref));
}

#[test]
fn explicit_t1_capabilities_are_signed_when_requested() {
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;

    let envelope = PeerHandshakeEnvelope::sign_with_capabilities(
        "kernel.org-b",
        "kernel.org-a",
        "nonce-b",
        now,
        &kp_b,
        CapabilityNegotiation::t1_default(),
    )
    .unwrap();
    let challenge = serde_json::to_value(&envelope.challenge).unwrap();

    assert!(challenge.get("capabilities").is_some());
    envelope.verify_signature().unwrap();
}

fn assert_feature_negotiation(
    feature: &str,
    nonce: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let mut enabled = CapabilityNegotiation::v1_default();
    enabled.features.insert(feature.to_string(), true);
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a)
        .with_trusted_peer("kernel.org-b", kp_b.public_key())
        .with_capabilities(enabled.clone());

    let enabled_envelope = PeerHandshakeEnvelope::sign_with_capabilities(
        "kernel.org-b",
        "kernel.org-a",
        &format!("nonce-{nonce}-enabled"),
        now,
        &kp_b,
        enabled,
    )?;
    let enabled_peer = exchange.accept_envelope(&enabled_envelope, "kernel.org-b", now)?;
    assert!(enabled_peer.capabilities.supports(feature));

    let missing_envelope = PeerHandshakeEnvelope::sign_with_capabilities(
        "kernel.org-b",
        "kernel.org-a",
        &format!("nonce-{nonce}-missing"),
        now,
        &kp_b,
        CapabilityNegotiation::v1_default(),
    )?;
    let missing_peer = exchange.accept_envelope(&missing_envelope, "kernel.org-b", now)?;
    assert!(!missing_peer.capabilities.supports(feature));

    let mut disabled = CapabilityNegotiation::v1_default();
    disabled.features.insert(feature.to_string(), false);
    let disabled_envelope = PeerHandshakeEnvelope::sign_with_capabilities(
        "kernel.org-b",
        "kernel.org-a",
        &format!("nonce-{nonce}-disabled"),
        now,
        &kp_b,
        disabled,
    )?;
    let disabled_peer = exchange.accept_envelope(&disabled_envelope, "kernel.org-b", now)?;
    assert!(!disabled_peer.capabilities.supports(feature));
    Ok(())
}

#[test]
fn aggregate_budget_negotiation_requires_both_peers() -> Result<(), Box<dyn std::error::Error>> {
    assert_feature_negotiation(AGGREGATE_INVOCATION_BUDGET, "aggregate")
}

#[test]
fn cumulative_approval_negotiation_requires_both_peers() -> Result<(), Box<dyn std::error::Error>> {
    assert_feature_negotiation(CUMULATIVE_APPROVAL_BUDGET, "cumulative")
}

#[test]
fn stale_peer_is_rejected_fail_closed() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;

    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_config(KernelTrustExchangeConfig {
            rotation_window_secs: 3_600,
            max_handshake_skew_secs: DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
        })
        .with_trusted_peer("kernel.org-b", kp_b.public_key());
    let envelope_b =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-b", now, &kp_b).unwrap();
    exchange
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .unwrap();

    // Just past the rotation window the peer is considered stale.
    let future = now + 3_600 + 1;
    let err = exchange
        .resolve("kernel.org-b", future)
        .expect_err("stale peer must be rejected");
    assert!(matches!(err, PeerHandshakeError::PeerStale(_)));
}

#[test]
fn freshness_rotation_reissues_pin() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;

    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_config(KernelTrustExchangeConfig {
            rotation_window_secs: 3_600,
            max_handshake_skew_secs: DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
        })
        .with_trusted_peer("kernel.org-b", kp_b.public_key());

    let envelope_b1 =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-1", now, &kp_b).unwrap();
    let peer1 = exchange
        .accept_envelope(&envelope_b1, "kernel.org-b", now)
        .unwrap();

    // After expiry, re-running the handshake re-pins the peer with a
    // later rotation_due.
    let later = now + 3_600 + 10;
    let envelope_b2 =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-2", later, &kp_b)
            .unwrap();
    let peer2 = exchange
        .accept_envelope(&envelope_b2, "kernel.org-b", later)
        .unwrap();

    assert!(peer2.rotation_due > peer1.rotation_due);
    assert!(peer2.is_fresh(later + 60));
    // Resolve at `later` succeeds again.
    exchange.resolve("kernel.org-b", later + 60).unwrap();
}

#[test]
fn accept_rejects_clock_skew() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_trusted_peer("kernel.org-b", kp_b.public_key());

    let skewed_ts = now + DEFAULT_HANDSHAKE_MAX_SKEW_SECS + 60;
    let envelope_b = PeerHandshakeEnvelope::sign(
        "kernel.org-b",
        "kernel.org-a",
        "nonce-skew",
        skewed_ts,
        &kp_b,
    )
    .unwrap();
    let err = exchange
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .expect_err("skewed envelope must be rejected");
    assert!(matches!(err, PeerHandshakeError::ClockSkewExceeded { .. }));
}

#[test]
fn accept_rejects_wrong_addressee() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_trusted_peer("kernel.org-b", kp_b.public_key());

    // Envelope addressed to someone else.
    let envelope_b =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-c", "nonce-x", now, &kp_b).unwrap();
    let err = exchange
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .expect_err("misaddressed envelope must be rejected");
    assert!(matches!(err, PeerHandshakeError::AddressMismatch { .. }));
}

#[test]
fn accept_rejects_tampered_signature() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_trusted_peer("kernel.org-b", kp_b.public_key());

    // Sign with kp_b but declare kp_c's public key.
    let mut envelope =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce", now, &kp_b).unwrap();
    envelope.declared_public_key = kp_c.public_key();

    let err = exchange
        .accept_envelope(&envelope, "kernel.org-b", now)
        .expect_err("mismatched public-key / signature must be rejected");
    assert!(matches!(err, PeerHandshakeError::InvalidSignature));
}

#[test]
fn resolve_unknown_peer_fails_closed() {
    let kp_a = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a);
    let err = exchange
        .resolve("kernel.org-b", now)
        .expect_err("unknown peer must be rejected");
    assert!(matches!(err, PeerHandshakeError::PeerNotPinned(_)));
}

#[test]
fn accept_rejects_untrusted_first_contact() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a);

    let envelope_b =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-b", now, &kp_b).unwrap();
    let err = exchange
        .accept_envelope(&envelope_b, "kernel.org-b", now)
        .expect_err("untrusted first contact must be rejected");
    assert!(matches!(err, PeerHandshakeError::MissingTrustAnchor(_)));
}

#[test]
fn conformance_tier_is_signed_and_pinned_at_handshake() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let policy = QuorumPolicy {
        min_tier: ConformanceTier::Silver,
    };

    let exchange_a = KernelTrustExchange::new("kernel.org-a", kp_a.clone())
        .with_trusted_peer("kernel.org-b", kp_b.public_key());
    let exchange_b = KernelTrustExchange::new("kernel.org-b", kp_b)
        .with_conformance_tier(ConformanceTier::Silver);

    let envelope_b = exchange_b
        .local_envelope("kernel.org-a", "nonce-tier", now)
        .unwrap();
    assert_eq!(
        envelope_b.challenge.conformance_tier,
        ConformanceTier::Silver
    );

    let peer_b = exchange_a
        .accept_envelope_with_policy(&envelope_b, "kernel.org-b", now, &policy)
        .unwrap();
    assert_eq!(peer_b.conformance_tier, ConformanceTier::Silver);
}

#[test]
fn quorum_policy_rejects_peer_below_min_tier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let policy = QuorumPolicy {
        min_tier: ConformanceTier::Silver,
    };

    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a)
        .with_trusted_peer("kernel.org-b", kp_b.public_key());
    let envelope_b =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-b", now, &kp_b).unwrap();

    let err = exchange
        .accept_envelope_with_policy(&envelope_b, "kernel.org-b", now, &policy)
        .expect_err("bronze peer must not satisfy silver policy");
    assert!(matches!(
        err,
        PeerHandshakeError::ConformanceTierBelowMinimum {
            actual: ConformanceTier::Bronze,
            minimum: ConformanceTier::Silver,
            ..
        }
    ));
}

#[test]
fn untrusted_peer_cannot_probe_quorum_tier_floor() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now: u64 = 1_800_000_000;
    let policy = QuorumPolicy {
        min_tier: ConformanceTier::Silver,
    };

    let exchange = KernelTrustExchange::new("kernel.org-a", kp_a);
    let envelope_b =
        PeerHandshakeEnvelope::sign("kernel.org-b", "kernel.org-a", "nonce-b", now, &kp_b).unwrap();

    let err = exchange
        .accept_envelope_with_policy(&envelope_b, "kernel.org-b", now, &policy)
        .expect_err("untrusted first contact must not reveal tier floor");
    assert!(matches!(err, PeerHandshakeError::MissingTrustAnchor(_)));
}

#[test]
fn conformance_evidence_derives_tiers_from_thresholds() {
    let bronze = ConformanceEvidence {
        threat_coverage_bps: 8_999,
        mutation_kill_bps: 10_000,
        kani_trust_boundary_crates: 8,
    };
    assert_eq!(bronze.derive_tier().unwrap(), ConformanceTier::Bronze);

    let silver = ConformanceEvidence {
        threat_coverage_bps: 9_000,
        mutation_kill_bps: 6_500,
        kani_trust_boundary_crates: 4,
    };
    assert_eq!(silver.derive_tier().unwrap(), ConformanceTier::Silver);

    let gold = ConformanceEvidence {
        threat_coverage_bps: 10_000,
        mutation_kill_bps: 8_000,
        kani_trust_boundary_crates: 8,
    };
    assert_eq!(gold.derive_tier().unwrap(), ConformanceTier::Gold);
}

#[test]
fn conformance_evidence_rejects_impossible_percentages() {
    let invalid = ConformanceEvidence {
        threat_coverage_bps: 10_001,
        mutation_kill_bps: 0,
        kani_trust_boundary_crates: 0,
    };
    assert!(matches!(
        invalid.derive_tier(),
        Err(PeerHandshakeError::InvalidConformanceEvidence(_))
    ));
}

#[cfg(feature = "pq")]
#[test]
fn handshake_accepts_hybrid_signing_backend() {
    use chio_core_types::crypto::{
        Ed25519Backend, HybridBackend, MlDsa65Backend, SigningAlgorithm,
    };

    let kp_a = Keypair::generate();
    let kp_b = Keypair::from_seed(&[9u8; 32]);
    let pq_b = MlDsa65Backend::from_seed(&[4u8; 32]);
    let hybrid_b = HybridBackend::new(Box::new(Ed25519Backend::new(kp_b)), pq_b).unwrap();
    let now: u64 = 1_800_000_000;

    let exchange_b = KernelTrustExchange::new_with_backend("kernel.org-b", Box::new(hybrid_b))
        .with_conformance_tier(ConformanceTier::Silver);
    let exchange_a = KernelTrustExchange::new("kernel.org-a", kp_a)
        .with_trusted_peer("kernel.org-b", exchange_b.local_public_key());

    let envelope_b = exchange_b
        .local_envelope("kernel.org-a", "nonce-hybrid", now)
        .unwrap();
    assert_eq!(
        envelope_b.declared_public_key.algorithm(),
        SigningAlgorithm::Hybrid
    );
    assert_eq!(envelope_b.signature.algorithm(), SigningAlgorithm::Hybrid);

    let peer_b = exchange_a
        .accept_envelope_with_policy(
            &envelope_b,
            "kernel.org-b",
            now,
            &QuorumPolicy {
                min_tier: ConformanceTier::Silver,
            },
        )
        .unwrap();
    assert_eq!(peer_b.public_key.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(peer_b.conformance_tier, ConformanceTier::Silver);
}
