//! In-process entry points shared by libFuzzer binaries and corpus smoke tests.

use chio_core_types::crypto::Keypair;
use chio_federation::trust_establishment::{
    FederationPeer, HandshakeChallenge, KernelTrustExchange, KernelTrustExchangeConfig,
    PeerHandshakeEnvelope,
};
use chio_underwriting::{
    build_underwriting_decision_artifact, compute_marketplace_credit_limit,
    evaluate_underwriting_policy_input, price_premium, LookbackWindow,
    MarketplaceCreditLimitRequest, PremiumInputs, UnderwritingAppealCreateRequest,
    UnderwritingAppealResolveRequest, UnderwritingDecisionArtifact, UnderwritingDecisionListReport,
    UnderwritingDecisionPolicy, UnderwritingDecisionQuery, UnderwritingPolicyInput,
    UnderwritingPolicyInputQuery, UnderwritingSimulationReport, UnderwritingSimulationRequest,
};

pub fn eval_receipt_bundle(data: &[u8]) {
    if let Ok(bundle_json) = core::str::from_utf8(data) {
        let _ = chio_eval_receipt::verify_bundle(bundle_json);
    }
}

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

pub fn federation_trust_establishment(data: &[u8]) {
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
}

pub fn underwriting_policy_input(data: &[u8]) {
    if let Ok(query) = serde_json::from_slice::<UnderwritingPolicyInputQuery>(data) {
        let normalized = query.normalized();
        let _ = normalized.validate();
    }

    if let Ok(query) = serde_json::from_slice::<UnderwritingDecisionQuery>(data) {
        let _ = query.normalized();
    }

    if let Ok(policy) = serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
        let _ = policy.validate();
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingSimulationRequest>(data) {
        let _ = request.query.normalized().validate();
        let _ = request.policy.validate();
    }

    if let Ok(input) = serde_json::from_slice::<UnderwritingPolicyInput>(data) {
        let policy = match serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
            Ok(policy) if policy.validate().is_ok() => policy,
            _ => UnderwritingDecisionPolicy::default(),
        };

        if let Ok(report) = evaluate_underwriting_policy_input(input, &policy) {
            let issued_at = report.generated_at;
            let _ = serde_json::to_vec(&report);
            let _ = build_underwriting_decision_artifact(report, issued_at, None, None);
        }
    }

    if let Ok(artifact) = serde_json::from_slice::<UnderwritingDecisionArtifact>(data) {
        let _ = serde_json::to_vec(&artifact);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingDecisionListReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingSimulationReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealCreateRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealResolveRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<MarketplaceCreditLimitRequest>(data) {
        let _ = compute_marketplace_credit_limit(&request);
    }

    if let Ok(inputs) = serde_json::from_slice::<PremiumInputs>(data) {
        let _ = inputs.validate();
        let window = LookbackWindow { since: 0, until: 0 };
        let _ = price_premium("fuzz-agent", "fuzz-scope", window, &inputs);
    }
}
