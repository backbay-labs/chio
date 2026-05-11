#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::Keypair;
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, sign_deposit, CostCommitmentPolicy,
    DepositQuery, InMemoryPheromoneSubstrate, PassportAdmission, PheromoneCostCommitment,
    PheromoneDepositBody, PheromoneSubstrate, PheromoneValidationContext, PheromoneWorkflowContext,
    Severity, SubjectClassPolicy, PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_WORKFLOW_CONTEXT_SCHEMA,
};
use serde_json::json;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn workflow_context() -> PheromoneWorkflowContext {
    PheromoneWorkflowContext {
        schema: PHEROMONE_WORKFLOW_CONTEXT_SCHEMA.to_string(),
        workflow_id: "wf-chiodos-refund-001".to_string(),
        workflow_receipt_id: "wf-receipt-001".to_string(),
        workflow_receipt_sha256: "a".repeat(64),
        workflow_intersection_id: "workflow-intersection:buyer-refund:001".to_string(),
        workflow_intersection_sha256: "b".repeat(64),
        step_index: 0,
        tool_receipt_id: "tool-receipt-001".to_string(),
        bilateral_dsse_sha256: "c".repeat(64),
        consistency_anchor: "chiodos:consistency:wf-chiodos-refund-001:0".to_string(),
    }
}

fn cost_commitment() -> PheromoneCostCommitment {
    PheromoneCostCommitment {
        schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
        telemetry_chain_root: "d".repeat(64),
        chain_position: 7,
        chain_position_proof: json!({"proof": "fixture"}),
        observed_at_unix_ms: 1_700_000_000_000,
    }
}

fn body(passport_key: &Keypair) -> PheromoneDepositBody {
    let public_key = passport_key.public_key();
    PheromoneDepositBody {
        schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
        kernel_id: "did:chio:llamaworks".to_string(),
        agent_passport_key_hash: agent_passport_key_hash(&public_key),
        agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
        subject_class: "support.prompt_injection".to_string(),
        subject_class_namespace: "dev.chio.support".to_string(),
        indicator: json!({"kind": "prompt_injection", "digest": "e".repeat(64)}),
        severity: Severity::High,
        confidence: 0.82,
        timestamp_unix_ms: 1_700_000_000_000,
        decay_half_life_secs: 3_600.0,
        evaporation_floor: Some(0.01),
        nonce: "nonce-001".to_string(),
        treaty_scope: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        cost_commitment: Some(cost_commitment()),
        workflow_context: Some(workflow_context()),
    }
}

fn context(passport_key: &Keypair, kernel_key: &Keypair) -> PheromoneValidationContext {
    PheromoneValidationContext {
        now_unix_ms: 1_700_000_000_500,
        replay_window_ms: 86_400_000,
        active_peers_in_treaty: 9,
        known_reputation_epochs: vec![42],
        passports: vec![PassportAdmission {
            kernel_id: "did:chio:llamaworks".to_string(),
            public_key: passport_key.public_key(),
            valid_from_unix_ms: 1_699_999_000_000,
            valid_until_unix_ms: 1_800_000_000_000,
            first_seen_epoch: 37,
            revoked: false,
        }],
        kernel_public_keys: vec![kernel_key.public_key()],
        subject_classes: vec![SubjectClassPolicy {
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            allowed_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: CostCommitmentPolicy::Required,
            destructive: true,
        }],
        max_deposits_per_pair: 2,
    }
}

#[test]
fn signed_deposit_roundtrip_and_store_query() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();

    substrate
        .deposit(deposit.clone(), &context(&passport_key, &kernel_key))
        .expect("valid deposit stores");

    let stored = substrate
        .query_deposits(&DepositQuery {
            subject_class: Some("support.prompt_injection".to_string()),
            treaty_id: Some("treaty:buyer-llamaworks:support-ops".to_string()),
        })
        .expect("query succeeds");
    assert_eq!(stored, vec![deposit]);
}

#[test]
fn workflow_context_tamper_invalidates_signature() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    deposit
        .body
        .workflow_context
        .as_mut()
        .expect("workflow context")
        .workflow_receipt_sha256 = "f".repeat(64);

    let substrate = InMemoryPheromoneSubstrate::new();
    let err = substrate
        .deposit(deposit, &context(&passport_key, &kernel_key))
        .expect_err("tampered context fails");
    assert_eq!(err.code(), "signature_invalid");
}

#[test]
fn kernel_key_signing_is_rejected() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let public_key = kernel_key.public_key();
    let mut body = body(&passport_key);
    body.agent_passport_key_hash = agent_passport_key_hash(&public_key);
    body.agent_passport_jwk_thumbprint = agent_passport_jwk_thumbprint(&public_key);
    let deposit = sign_deposit(body, &kernel_key).expect("sign with kernel key");

    let substrate = InMemoryPheromoneSubstrate::new();
    let err = substrate
        .deposit(deposit, &context(&passport_key, &kernel_key))
        .expect_err("kernel-key deposit fails");
    assert_eq!(err.code(), "kernel_key_used_for_deposit");
}

#[test]
fn missing_cost_commitment_for_destructive_class_fails() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut body = body(&passport_key);
    body.cost_commitment = None;
    let deposit = sign_deposit(body, &passport_key).expect("sign deposit");

    let substrate = InMemoryPheromoneSubstrate::new();
    let err = substrate
        .deposit(deposit, &context(&passport_key, &kernel_key))
        .expect_err("missing cost commitment fails");
    assert_eq!(err.code(), "observation_cost_commitment_required");
}

#[test]
fn replay_nonce_and_diversity_limits_fail_closed() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();
    let context = context(&passport_key, &kernel_key);

    substrate
        .deposit(deposit.clone(), &context)
        .expect("first deposit stores");
    let replay = substrate
        .deposit(deposit, &context)
        .expect_err("replay fails");
    assert_eq!(replay.code(), "replay_window_exceeded");

    let mut second = body(&passport_key);
    second.nonce = "nonce-002".to_string();
    let second = sign_deposit(second, &passport_key).expect("sign second");
    substrate.deposit(second, &context).expect("second stores");
    let mut third = body(&passport_key);
    third.nonce = "nonce-003".to_string();
    let third = sign_deposit(third, &passport_key).expect("sign third");
    let capped = substrate
        .deposit(third, &context)
        .expect_err("pair cap fails");
    assert_eq!(capped.code(), "diversity_cap_exceeded");
}

#[test]
fn concentration_rejects_unknown_epoch_and_bad_weight() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();
    let context = context(&passport_key, &kernel_key);
    substrate
        .deposit(deposit, &context)
        .expect("deposit stores");

    let unknown = substrate
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            1_700_000_001_000,
            99,
            &context,
            &|_, _| 1.0,
        )
        .expect_err("unknown epoch fails");
    assert_eq!(unknown.code(), "unknown_reputation_epoch");

    let bad_weight = substrate
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            1_700_000_001_000,
            42,
            &context,
            &|_, _| f64::NAN,
        )
        .expect_err("bad weight fails");
    assert_eq!(bad_weight.code(), "weight_out_of_range");
}
