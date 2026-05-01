//! Kernel trust establishment / mTLS handshake tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::Keypair;
use chio_federation::{
    KernelTrustExchange, KernelTrustExchangeConfig, PeerHandshakeEnvelope, PeerHandshakeError,
    DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
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
    assert!(peer_b.rotation_due > now);
    assert!(peer_a.rotation_due > now);

    // Resolve while fresh succeeds.
    let resolved = exchange_a.resolve("kernel.org-b", now + 60).unwrap();
    assert_eq!(resolved.public_key.to_hex(), kp_b.public_key().to_hex());
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
