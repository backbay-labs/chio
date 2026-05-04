//! Trust-boundary fuzz target for `chio-federation` kernel trust establishment.

#![no_main]

use chio_core_types::crypto::Keypair;
use chio_federation::{
    FederationPeer, HandshakeChallenge, KernelTrustExchange, KernelTrustExchangeConfig,
    PeerHandshakeEnvelope,
};
use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fn seed_at(data: &[u8], start: usize) -> Option<[u8; 32]> {
    if data.len() < start.saturating_add(32) {
        return None;
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&data[start..start + 32]);
    Some(seed)
}

fn u64_at(data: &[u8], start: usize, fallback: u64) -> u64 {
    if data.len() < start.saturating_add(8) {
        return fallback;
    }
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&data[start..start + 8]);
    u64::from_le_bytes(bytes)
}

fn nonce_from(data: &[u8]) -> &str {
    match core::str::from_utf8(data) {
        Ok(value) if !value.is_empty() => value,
        _ => "fuzz-nonce",
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(challenge) = serde_json::from_slice::<HandshakeChallenge>(data) {
        let _ = challenge.canonical_bytes();
        let _ = serde_json::to_vec(&challenge);
    }

    if let Ok(envelope) = serde_json::from_slice::<PeerHandshakeEnvelope>(data) {
        let _ = envelope.verify_signature();
        let _ = serde_json::to_vec(&envelope);
    }

    if let Ok(peer) = serde_json::from_slice::<FederationPeer>(data) {
        let now = u64_at(data, 0, 0);
        let _ = peer.is_fresh(now);
        let _ = serde_json::to_vec(&peer);
    }

    let Some(local_seed) = seed_at(data, 0) else {
        return;
    };
    let Some(remote_seed) = seed_at(data, 32) else {
        return;
    };

    let local_keypair = Keypair::from_seed(&local_seed);
    let remote_keypair = Keypair::from_seed(&remote_seed);
    let now = u64_at(data, 64, 1);
    let rotation_window_secs = u64_at(data, 72, 1);
    let max_handshake_skew_secs = u64_at(data, 80, 0);
    let nonce_tail = match data.get(88..) {
        Some(bytes) => bytes,
        None => &[],
    };
    let nonce = nonce_from(nonce_tail);

    let exchange = KernelTrustExchange::new("kernel.local", local_keypair)
        .with_config(KernelTrustExchangeConfig {
            rotation_window_secs,
            max_handshake_skew_secs,
        })
        .with_trusted_peer("kernel.remote", remote_keypair.public_key());

    let remote_envelope = match PeerHandshakeEnvelope::sign(
        "kernel.remote",
        "kernel.local",
        nonce,
        now,
        &remote_keypair,
    ) {
        Ok(envelope) => envelope,
        Err(_) => return,
    };

    let _ = remote_envelope.verify_signature();
    if exchange
        .accept_envelope(&remote_envelope, "kernel.remote", now)
        .is_ok()
    {
        let _ = exchange.resolve("kernel.remote", now);
        let _ = exchange.peers();
        let _ = exchange.forget("kernel.remote");
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
