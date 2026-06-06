#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::Keypair;
use chio_federation::{
    pheromone_gossip::verify_pheromone_gossip_batch,
    pheromone_gossip::verify_pheromone_gossip_frame, pheromone_gossip::PheromoneDepositGossip,
    pheromone_gossip::PheromoneGossipBatchVerificationContext,
    pheromone_gossip::PheromoneGossipPushQueue, pheromone_gossip::PheromoneTransitChain,
    pheromone_gossip::PheromoneTransitHop, pheromone_gossip::PheromoneTransitLadderPin,
    pheromone_gossip::PheromoneTransitPolicy, pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA,
    pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA, pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA,
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, sign_deposit, PheromoneDepositBody,
    Severity, PHEROMONE_DEPOSIT_SCHEMA,
};
use serde_json::json;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn deposit() -> chio_pheromone::PheromoneDeposit {
    let passport_key = key(1);
    let public_key = passport_key.public_key();
    sign_deposit(
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
            kernel_id: "did:chio:llamaworks".to_string(),
            agent_passport_key_hash: agent_passport_key_hash(&public_key),
            agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            indicator: json!({"digest": "e".repeat(64)}),
            severity: Severity::High,
            confidence: 0.8,
            timestamp_unix_ms: 1_700_000_000_000,
            decay_half_life_secs: 3_600.0,
            evaporation_floor: Some(0.01),
            nonce: "nonce-001".to_string(),
            treaty_scope: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: None,
            workflow_context: None,
        },
        &passport_key,
    )
    .expect("sign")
}

fn policy() -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: vec!["did:chio:buyer-kernel".to_string()],
        allowed_ingress_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        allowed_egress_treaties: vec!["treaty:buyer-dataco:support-ops".to_string()],
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        valid_from_unix_ms: 1_699_999_000_000,
        valid_until_unix_ms: 1_800_000_000_000,
        max_hops: 2,
        required_action_class_id: "whisker.pheromone_deposit".to_string(),
        pinned_ladder_refs: vec![
            PheromoneTransitLadderPin {
                ladder_manifest_id: "ladder:llamaworks:support".to_string(),
                ladder_manifest_sha256: "a".repeat(64),
                ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                ladder_intersection_id: "intersection:buyer:llamaworks".to_string(),
                ladder_intersection_sha256: "c".repeat(64),
            },
            PheromoneTransitLadderPin {
                ladder_manifest_id: "ladder:buyer:support".to_string(),
                ladder_manifest_sha256: "b".repeat(64),
                ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                ladder_intersection_id: "intersection:buyer:dataco".to_string(),
                ladder_intersection_sha256: "d".repeat(64),
            },
        ],
    }
}

#[test]
fn pheromone_direct_gossip_requires_frame_treaty_in_deposit_scope() {
    let frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit: deposit(),
        origin_kernel_id: "did:chio:llamaworks".to_string(),
        gossiping_peer_kernel_id: "did:chio:llamaworks".to_string(),
        treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
        ts_unix_ms: 1_700_000_000_500,
        transit_chain: None,
    };

    let err = verify_pheromone_gossip_frame(&frame, &policy(), 1_700_000_000_500)
        .expect_err("downstream treaty smuggling fails");
    assert_eq!(err.code(), "treaty_scope_violation");
}

#[test]
fn pheromone_relayed_gossip_accepts_bounded_transit_chain() {
    let frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit: deposit(),
        origin_kernel_id: "did:chio:llamaworks".to_string(),
        gossiping_peer_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
        ts_unix_ms: 1_700_000_000_500,
        transit_chain: Some(PheromoneTransitChain {
            hops: vec![
                PheromoneTransitHop {
                    from_kernel_id: "did:chio:llamaworks".to_string(),
                    to_kernel_id: "did:chio:buyer-kernel".to_string(),
                    treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
                    ladder_manifest_id: "ladder:llamaworks:support".to_string(),
                    ladder_manifest_sha256: "a".repeat(64),
                    ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                    ladder_intersection_id: "intersection:buyer:llamaworks".to_string(),
                    ladder_intersection_sha256: "c".repeat(64),
                    action_class_id: "whisker.pheromone_deposit".to_string(),
                    emitted_at_unix_ms: 1_700_000_000_100,
                },
                PheromoneTransitHop {
                    from_kernel_id: "did:chio:buyer-kernel".to_string(),
                    to_kernel_id: "did:chio:dataco".to_string(),
                    treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
                    ladder_manifest_id: "ladder:buyer:support".to_string(),
                    ladder_manifest_sha256: "b".repeat(64),
                    ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                    ladder_intersection_id: "intersection:buyer:dataco".to_string(),
                    ladder_intersection_sha256: "d".repeat(64),
                    action_class_id: "whisker.pheromone_deposit".to_string(),
                    emitted_at_unix_ms: 1_700_000_000_200,
                },
            ],
        }),
    };

    verify_pheromone_gossip_frame(&frame, &policy(), 1_700_000_000_500)
        .expect("valid relay verifies");
}

#[test]
fn receiver_rejects_transit_hop_with_pinned_id_but_wrong_intersection_hash() {
    let frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit: deposit(),
        origin_kernel_id: "did:chio:llamaworks".to_string(),
        gossiping_peer_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
        ts_unix_ms: 1_700_000_000_500,
        transit_chain: Some(PheromoneTransitChain {
            hops: vec![
                PheromoneTransitHop {
                    from_kernel_id: "did:chio:llamaworks".to_string(),
                    to_kernel_id: "did:chio:buyer-kernel".to_string(),
                    treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
                    ladder_manifest_id: "ladder:llamaworks:support".to_string(),
                    ladder_manifest_sha256: "a".repeat(64),
                    ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                    ladder_intersection_id: "intersection:buyer:llamaworks".to_string(),
                    ladder_intersection_sha256: "e".repeat(64),
                    action_class_id: "whisker.pheromone_deposit".to_string(),
                    emitted_at_unix_ms: 1_700_000_000_100,
                },
                PheromoneTransitHop {
                    from_kernel_id: "did:chio:buyer-kernel".to_string(),
                    to_kernel_id: "did:chio:dataco".to_string(),
                    treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
                    ladder_manifest_id: "ladder:buyer:support".to_string(),
                    ladder_manifest_sha256: "b".repeat(64),
                    ladder_manifest_expires_at_unix_ms: 1_800_000_000_000,
                    ladder_intersection_id: "intersection:buyer:dataco".to_string(),
                    ladder_intersection_sha256: "d".repeat(64),
                    action_class_id: "whisker.pheromone_deposit".to_string(),
                    emitted_at_unix_ms: 1_700_000_000_200,
                },
            ],
        }),
    };

    let err = verify_pheromone_gossip_frame(&frame, &policy(), 1_700_000_000_500)
        .expect_err("intersection hash mismatch must reject");

    assert_eq!(err.code(), "transit_policy_violation");
}

#[test]
fn pheromone_push_queue_is_per_peer_per_treaty_fifo_without_coalescing() {
    let queue = PheromoneGossipPushQueue::new("did:chio:llamaworks", 4).expect("queue");
    queue
        .subscribe(
            "did:chio:buyer-kernel",
            "treaty:buyer-llamaworks:support-ops",
        )
        .expect("subscribe");
    queue.enqueue(deposit()).expect("enqueue first");
    let mut second = deposit();
    second.body.nonce = "nonce-002".to_string();
    queue.enqueue(second.clone()).expect("enqueue second");

    let batches = queue.flush_batches_at(1_700_000_000_500).expect("flush");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].schema, PHEROMONE_GOSSIP_BATCH_SCHEMA);
    assert_eq!(batches[0].recipient_kernel_id, "did:chio:buyer-kernel");
    assert_eq!(batches[0].frames.len(), 2);
    assert_eq!(
        batches[0].frames[0].gossiping_peer_kernel_id,
        "did:chio:llamaworks"
    );
    assert_eq!(batches[0].frames[0].deposit.body.nonce, "nonce-001");
    assert_eq!(batches[0].frames[1].deposit, second);
}

#[test]
fn pheromone_push_queue_only_routes_to_scoped_treaties() {
    let queue = PheromoneGossipPushQueue::new("did:chio:llamaworks", 4).expect("queue");
    queue
        .subscribe(
            "did:chio:buyer-kernel",
            "treaty:buyer-llamaworks:support-ops",
        )
        .expect("subscribe scoped");
    queue
        .subscribe("did:chio:dataco", "treaty:buyer-dataco:support-ops")
        .expect("subscribe unscoped");

    let delivered = queue.enqueue(deposit()).expect("enqueue");
    assert_eq!(delivered, 1);

    let batches = queue.flush_batches_at(1_700_000_000_500).expect("flush");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].treaty_id, "treaty:buyer-llamaworks:support-ops");
}

#[test]
fn pheromone_batch_verifier_accepts_scoped_direct_batch() {
    let queue = PheromoneGossipPushQueue::new("did:chio:llamaworks", 4).expect("queue");
    queue
        .subscribe(
            "did:chio:buyer-kernel",
            "treaty:buyer-llamaworks:support-ops",
        )
        .expect("subscribe");
    queue.enqueue(deposit()).expect("enqueue");
    let batches = queue.flush_batches_at(1_700_000_000_500).expect("flush");
    let batch = batches.first().expect("batch");

    verify_pheromone_gossip_batch(
        batch,
        &policy(),
        &PheromoneGossipBatchVerificationContext {
            now_unix_ms: 1_700_000_000_500,
            recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
            authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        },
    )
    .expect("batch verifies");
}

#[test]
fn pheromone_batch_verifier_rejects_empty_batch() {
    let batch = chio_federation::pheromone_gossip::PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        frames: Vec::new(),
        flushed_at_unix_ms: 1_700_000_000_500,
    };

    let err = verify_pheromone_gossip_batch(
        &batch,
        &policy(),
        &PheromoneGossipBatchVerificationContext {
            now_unix_ms: 1_700_000_000_500,
            recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
            authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        },
    )
    .expect_err("empty batch fails");
    assert_eq!(err.code(), "batch_empty");
}

#[test]
fn pheromone_batch_verifier_rejects_wrong_direct_sender() {
    let mut frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit: deposit(),
        origin_kernel_id: "did:chio:llamaworks".to_string(),
        gossiping_peer_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        ts_unix_ms: 1_700_000_000_500,
        transit_chain: None,
    };
    frame.deposit.body.treaty_scope = vec!["treaty:buyer-llamaworks:support-ops".to_string()];
    let batch = chio_federation::pheromone_gossip::PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        frames: vec![frame],
        flushed_at_unix_ms: 1_700_000_000_500,
    };

    let err = verify_pheromone_gossip_batch(
        &batch,
        &policy(),
        &PheromoneGossipBatchVerificationContext {
            now_unix_ms: 1_700_000_000_500,
            recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
            authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        },
    )
    .expect_err("wrong direct sender fails");
    assert_eq!(err.code(), "authenticated_sender_mismatch");
}
