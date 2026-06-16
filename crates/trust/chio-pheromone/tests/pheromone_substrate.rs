#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::sha256_hex;
use chio_core_types::merkle::MerkleTree;
use chio_core_types::{Keypair, SigningAlgorithm};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, scarcity_policy_sha256,
    scarcity_window_id, sign_deposit, CostCommitmentPolicy, DepositQuery,
    InMemoryPheromoneSubstrate, ObservationCostVerificationMode, PassportAdmission,
    PheromoneCostCommitment, PheromoneDeposit, PheromoneDepositBody,
    PheromoneObservationCostAmount, PheromoneObservationCostLeaf,
    PheromoneObservationCostStatement, PheromoneObservationCostTelemetryRoot,
    PheromoneObservationCostVerifierRoot, PheromoneObservationCostVerifierRootBody,
    PheromoneRuntimeTrustFloorEntry, PheromoneRuntimeTrustFloorState, PheromoneScarcityPolicy,
    PheromoneSubstrate, PheromoneValidationContext, PheromoneWorkflowContext, Severity,
    SubjectClassPolicy, OBSERVATION_COST_TELEMETRY_ALGORITHM, OBSERVATION_COST_UNIT,
    PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA, PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA, PHEROMONE_SCARCITY_POLICY_SCHEMA,
    PHEROMONE_WORKFLOW_CONTEXT_SCHEMA,
};
use serde_json::json;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn workflow_context() -> PheromoneWorkflowContext {
    PheromoneWorkflowContext {
        schema: PHEROMONE_WORKFLOW_CONTEXT_SCHEMA.to_string(),
        workflow_id: "wf-chio-refund-001".to_string(),
        workflow_receipt_id: "wf-receipt-001".to_string(),
        workflow_receipt_sha256: "a".repeat(64),
        workflow_intersection_id: "workflow-intersection:buyer-refund:001".to_string(),
        workflow_intersection_sha256: "b".repeat(64),
        step_index: 0,
        tool_receipt_id: "tool-receipt-001".to_string(),
        bilateral_dsse_sha256: "c".repeat(64),
        consistency_anchor: "chio:consistency:wf-chio-refund-001:0".to_string(),
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
        cost_commitment: None,
        workflow_context: Some(workflow_context()),
    }
}

fn context(passport_key: &Keypair, kernel_key: &Keypair) -> PheromoneValidationContext {
    PheromoneValidationContext {
        now_unix_ms: 1_700_000_000_500,
        replay_window_ms: 86_400_000,
        active_peers_in_treaty: 9,
        active_reputation_epoch: 42,
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
            cost_commitment: CostCommitmentPolicy::NotRequired,
            destructive: false,
        }],
        max_deposits_per_pair: 2,
        scarcity_policies: Vec::new(),
        runtime_policy_sha256: None,
        runtime_policy_issuer_public_keys: Vec::new(),
        observation_cost_verifier_roots: Vec::new(),
        runtime_trust_floor_state: PheromoneRuntimeTrustFloorState::default(),
    }
}

fn scarcity_policy(
    reputation_epoch: u64,
    window_id: &str,
    treaty_scope: Vec<String>,
    subject_class_namespace: &str,
    subject_class: &str,
    token_capacity: u64,
    newcomer_horizon_epochs: u64,
) -> PheromoneScarcityPolicy {
    let mut policy = PheromoneScarcityPolicy {
        schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.to_string(),
        policy_id: format!("policy:{window_id}:{subject_class_namespace}:{subject_class}"),
        reputation_epoch,
        window_id: window_id.to_string(),
        window_start_unix_ms: 1_699_999_999_000,
        window_end_unix_ms: 1_700_000_010_000,
        token_capacity,
        newcomer_horizon_epochs,
        treaty_scope,
        subject_class_namespace: subject_class_namespace.to_string(),
        subject_class: subject_class.to_string(),
        observation_cost_verification: ObservationCostVerificationMode::NotRequired,
        verifier_id: "did:chio:cost-verifier".to_string(),
        runtime_policy_sha256: runtime_policy_sha256(),
        policy_sha256: String::new(),
        active_peers_epoch: reputation_epoch,
    };
    refresh_policy_window_id(&mut policy);
    policy
}

fn refresh_policy_window_id(policy: &mut PheromoneScarcityPolicy) {
    let treaty_id = policy
        .treaty_scope
        .first()
        .expect("test policy has treaty")
        .clone();
    policy.window_id = scarcity_window_id(policy, &treaty_id).expect("deterministic window id");
    policy.policy_sha256 = scarcity_policy_sha256(policy).expect("canonical policy hash");
}

fn context_with_scarcity_policy(
    passport_key: &Keypair,
    kernel_key: &Keypair,
    policy: PheromoneScarcityPolicy,
) -> PheromoneValidationContext {
    let mut context = context(passport_key, kernel_key);
    context.max_deposits_per_pair = 8;
    context.active_reputation_epoch = policy.reputation_epoch;
    context.known_reputation_epochs = vec![policy.reputation_epoch];
    if policy.active_peers_epoch != policy.reputation_epoch {
        context
            .known_reputation_epochs
            .push(policy.active_peers_epoch);
    }
    context.known_reputation_epochs.sort_unstable();
    context.known_reputation_epochs.dedup();
    context.runtime_policy_sha256 = Some(policy.runtime_policy_sha256.clone());
    context.scarcity_policies = vec![policy];
    context
}

fn live_context(passport_key: &Keypair, kernel_key: &Keypair) -> PheromoneValidationContext {
    let policy = scarcity_policy(
        42,
        "window-live",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        16,
        8,
    );
    let mut context = context_with_scarcity_policy(passport_key, kernel_key, policy);
    context.max_deposits_per_pair = 2;
    context
}

fn runtime_policy_sha256() -> String {
    "1".repeat(64)
}

fn deposit_body_sha256(deposit: &PheromoneDeposit) -> String {
    let mut signed_body = deposit.body.clone();
    signed_body.cost_commitment = None;
    sha256_hex(&chio_core_types::canonical::canonical_json_bytes(&signed_body).expect("canonical"))
}

fn deposit_signature_sha256(deposit: &PheromoneDeposit) -> String {
    sha256_hex(deposit.signature.to_hex().as_bytes())
}

fn verifier_root(
    verifier_key: &Keypair,
    issuer_key: &Keypair,
    runtime_policy_sha256: &str,
) -> PheromoneObservationCostVerifierRoot {
    let body = PheromoneObservationCostVerifierRootBody {
        schema: PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA.to_string(),
        verifier_id: "did:chio:cost-verifier".to_string(),
        verifier_key_id: "cost-root-key-1".to_string(),
        public_key: verifier_key.public_key(),
        signature_algorithm: SigningAlgorithm::Ed25519,
        valid_from_unix_ms: 1_699_999_000_000,
        valid_until_unix_ms: 1_800_000_000_000,
        allowed_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        allowed_subject_classes: vec!["support.prompt_injection".to_string()],
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
        issuer_kernel_id: "did:chio:receiver-runtime".to_string(),
    };
    let (issuer_signature, _) = issuer_key
        .sign_canonical(&body)
        .expect("sign verifier root");
    PheromoneObservationCostVerifierRoot {
        body,
        issuer_signature,
    }
}

fn trust_floor_entry_for_root(
    root: &PheromoneObservationCostVerifierRoot,
) -> PheromoneRuntimeTrustFloorEntry {
    PheromoneRuntimeTrustFloorEntry {
        verifier_id: root.body.verifier_id.clone(),
        key_id: root.body.verifier_key_id.clone(),
        highest_version: 1,
        latest_bundle_sha256: sha256_hex(b"cost-verifier-runtime-trust-bundle:v1"),
        latest_revocation_checkpoint_sha256: sha256_hex(b"cost-verifier-revocation-checkpoint:v1"),
    }
}

fn context_with_observation_cost_roots(
    passport_key: &Keypair,
    kernel_key: &Keypair,
    policy: PheromoneScarcityPolicy,
    verifier_key: &Keypair,
    issuer_key: &Keypair,
) -> PheromoneValidationContext {
    let runtime_policy_sha256 = runtime_policy_sha256();
    let mut context = context_with_scarcity_policy(passport_key, kernel_key, policy);
    context.runtime_policy_sha256 = Some(runtime_policy_sha256.clone());
    context.runtime_policy_issuer_public_keys = vec![issuer_key.public_key()];
    let root = verifier_root(verifier_key, issuer_key, &runtime_policy_sha256);
    context.runtime_trust_floor_state.entries = vec![trust_floor_entry_for_root(&root)];
    context.observation_cost_verifier_roots = vec![root];
    context
}

fn signed_cost_commitment(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    verifier_key: &Keypair,
    runtime_policy_sha256: &str,
) -> PheromoneCostCommitment {
    let cost = PheromoneObservationCostAmount {
        unit: OBSERVATION_COST_UNIT.to_string(),
        amount: 125,
    };
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256: deposit_body_sha256(deposit),
        deposit_signature_sha256: deposit_signature_sha256(deposit),
        kernel_id: deposit.body.kernel_id.clone(),
        agent_passport_key_hash: deposit.body.agent_passport_key_hash.clone(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        subject_class_namespace: deposit.body.subject_class_namespace.clone(),
        subject_class: deposit.body.subject_class.clone(),
        observed_at_unix_ms: 1_700_000_000_000,
        event_digest_sha256: "9".repeat(64),
        cost: cost.clone(),
        scarcity_policy_sha256: scarcity_policy_sha256(policy).expect("policy canonical"),
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
    };
    let leaf_bytes = chio_core_types::canonical::canonical_json_bytes(&leaf).expect("leaf");
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&leaf_bytes)).expect("tree");
    let statement = PheromoneObservationCostStatement {
        schema: PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA.to_string(),
        commitment_id: "cost-commitment-001".to_string(),
        verifier_id: "did:chio:cost-verifier".to_string(),
        verifier_key_id: "cost-root-key-1".to_string(),
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
        scarcity_policy_sha256: leaf.scarcity_policy_sha256.clone(),
        deposit_body_sha256: leaf.deposit_body_sha256.clone(),
        deposit_signature_sha256: leaf.deposit_signature_sha256.clone(),
        kernel_id: leaf.kernel_id.clone(),
        agent_passport_key_hash: leaf.agent_passport_key_hash.clone(),
        treaty_id: leaf.treaty_id.clone(),
        subject_class_namespace: leaf.subject_class_namespace.clone(),
        subject_class: leaf.subject_class.clone(),
        observation_window_start_unix_ms: policy.window_start_unix_ms,
        observation_window_end_unix_ms: policy.window_end_unix_ms,
        observed_at_unix_ms: leaf.observed_at_unix_ms,
        event_digest_sha256: leaf.event_digest_sha256.clone(),
        cost,
        telemetry: PheromoneObservationCostTelemetryRoot {
            schema: PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA.to_string(),
            algorithm: OBSERVATION_COST_TELEMETRY_ALGORITHM.to_string(),
            root_hash: tree.root(),
            tree_size: 1,
            verifier_id: "did:chio:cost-verifier".to_string(),
            verifier_key_id: "cost-root-key-1".to_string(),
            closed_at_unix_ms: 1_700_000_000_250,
        },
        inclusion_proof: tree.inclusion_proof(0).expect("proof"),
        leaf_preimage_sha256: sha256_hex(&leaf_bytes),
    };
    let (signature, _) = verifier_key
        .sign_canonical(&statement)
        .expect("sign cost statement");
    PheromoneCostCommitment {
        schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
        statement,
        signature,
    }
}

fn resign_cost_commitment(commitment: &mut PheromoneCostCommitment, verifier_key: &Keypair) {
    let (signature, _) = verifier_key
        .sign_canonical(&commitment.statement)
        .expect("resign cost statement");
    commitment.signature = signature;
}

fn invalid_cost_commitment_case(
    context: &PheromoneValidationContext,
    policy: &PheromoneScarcityPolicy,
    passport_key: &Keypair,
    verifier_key: &Keypair,
    nonce: &str,
    expected_code: &str,
    mutate: impl FnOnce(&mut PheromoneCostCommitment),
) {
    let mut unsigned_body = body(passport_key);
    unsigned_body.nonce = nonce.to_string();
    unsigned_body.cost_commitment = None;
    let mut deposit = sign_deposit(unsigned_body, passport_key).expect("sign invalid cost case");
    let mut commitment = signed_cost_commitment(
        &deposit,
        policy,
        verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    );
    mutate(&mut commitment);
    deposit.body.cost_commitment = Some(commitment);
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(deposit, context)
        .expect_err("invalid cost commitment rejects");
    assert_eq!(err.code(), expected_code, "{nonce}");
}

#[test]
fn signed_deposit_roundtrip_and_store_query() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();

    substrate
        .deposit(deposit.clone(), &live_context(&passport_key, &kernel_key))
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
fn live_deposit_without_scarcity_policy_is_rejected() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();

    let err = substrate
        .deposit(deposit, &context(&passport_key, &kernel_key))
        .expect_err("live deposit without scarcity policy must fail closed");

    assert_eq!(err.code(), "scarcity_policy_missing");
}

#[test]
fn deposit_nonce_must_be_non_empty_and_unpadded() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut body = body(&passport_key);
    body.nonce = " nonce-001".to_string();
    let deposit = sign_deposit(body, &passport_key).expect("sign padded nonce deposit");

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(deposit, &live_context(&passport_key, &kernel_key))
        .expect_err("padded nonce must fail closed");

    assert_eq!(err.code(), "invalid_field");
}

#[test]
fn deposit_treaty_scope_must_be_unique() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut body = body(&passport_key);
    body.treaty_scope
        .push("treaty:buyer-llamaworks:support-ops".to_string());
    let deposit = sign_deposit(body, &passport_key).expect("sign duplicate treaty deposit");

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(deposit, &live_context(&passport_key, &kernel_key))
        .expect_err("duplicate treaty scope must fail closed");

    assert_eq!(err.code(), "invalid_field");
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
        .deposit(deposit, &live_context(&passport_key, &kernel_key))
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
        .deposit(deposit, &live_context(&passport_key, &kernel_key))
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
    let mut context = live_context(&passport_key, &kernel_key);
    context.subject_classes[0].cost_commitment = CostCommitmentPolicy::Required;
    context.subject_classes[0].destructive = true;

    let substrate = InMemoryPheromoneSubstrate::new();
    let err = substrate
        .deposit(deposit, &context)
        .expect_err("missing cost commitment fails");
    assert_eq!(err.code(), "observation_cost_commitment_missing");
}

#[test]
fn replay_nonce_and_diversity_limits_fail_closed() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();
    let context = live_context(&passport_key, &kernel_key);

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
fn replay_window_expires_at_exact_boundary() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit_body = body(&passport_key);
    let deposit = sign_deposit(deposit_body.clone(), &passport_key).expect("sign deposit");
    let mut context = live_context(&passport_key, &kernel_key);
    context.now_unix_ms = deposit_body.timestamp_unix_ms + context.replay_window_ms;
    context.scarcity_policies[0].window_end_unix_ms = context.now_unix_ms + 1;
    refresh_policy_window_id(&mut context.scarcity_policies[0]);

    let substrate = InMemoryPheromoneSubstrate::new();
    let err = substrate
        .deposit(deposit, &context)
        .expect_err("exact replay-window boundary is expired");

    assert_eq!(err.code(), "replay_window_exceeded");
}

#[test]
fn diversity_limit_is_scoped_by_treaty() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let substrate = InMemoryPheromoneSubstrate::new();
    let mut context = live_context(&passport_key, &kernel_key);
    context.max_deposits_per_pair = 1;
    context.subject_classes[0]
        .allowed_treaties
        .push("treaty:buyer-llamaworks:security-ops".to_string());
    let mut security_policy = context.scarcity_policies[0].clone();
    security_policy.policy_id = "policy:security-treaty".to_string();
    security_policy.treaty_scope = vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    refresh_policy_window_id(&mut security_policy);
    context.scarcity_policies.push(security_policy);

    let first = sign_deposit(body(&passport_key), &passport_key).expect("sign first");
    substrate.deposit(first, &context).expect("first stores");

    let mut second = body(&passport_key);
    second.nonce = "nonce-other-treaty".to_string();
    second.treaty_scope = vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    let second = sign_deposit(second, &passport_key).expect("sign second");

    substrate
        .deposit(second, &context)
        .expect("different treaty has an independent diversity bucket");
}

#[test]
fn scarcity_bucket_exhaustion_fails_closed() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let policy = scarcity_policy(
        42,
        "window-a",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let context = context_with_scarcity_policy(&passport_key, &kernel_key, policy);
    let substrate = InMemoryPheromoneSubstrate::new();

    let first = sign_deposit(body(&passport_key), &passport_key).expect("sign first");
    substrate.deposit(first, &context).expect("first stores");
    let mut second = body(&passport_key);
    second.nonce = "nonce-exhausted".to_string();
    let second = sign_deposit(second, &passport_key).expect("sign second");

    let err = substrate
        .deposit(second, &context)
        .expect_err("scarcity bucket is exhausted");
    assert_eq!(err.code(), "rate_limit_exhausted");
}

#[test]
fn scarcity_buckets_are_scoped_by_window_treaty_namespace_and_class() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let substrate = InMemoryPheromoneSubstrate::new();
    let base_policy = scarcity_policy(
        42,
        "window-a",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let base_context = context_with_scarcity_policy(&passport_key, &kernel_key, base_policy);

    let first = sign_deposit(body(&passport_key), &passport_key).expect("sign first");
    substrate
        .deposit(first, &base_context)
        .expect("base bucket stores");

    let mut window_policy = base_context.scarcity_policies[0].clone();
    window_policy.policy_id = "policy:window-b".to_string();
    window_policy.window_start_unix_ms = 1_700_000_000_000;
    window_policy.window_end_unix_ms = 1_700_000_020_000;
    refresh_policy_window_id(&mut window_policy);
    let window_context = context_with_scarcity_policy(&passport_key, &kernel_key, window_policy);
    let mut window_body = body(&passport_key);
    window_body.nonce = "nonce-window-b".to_string();
    substrate
        .deposit(
            sign_deposit(window_body, &passport_key).expect("sign window"),
            &window_context,
        )
        .expect("different window has an independent bucket");

    let mut treaty_policy = base_context.scarcity_policies[0].clone();
    treaty_policy.policy_id = "policy:treaty-security".to_string();
    treaty_policy.treaty_scope = vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    refresh_policy_window_id(&mut treaty_policy);
    let mut treaty_context =
        context_with_scarcity_policy(&passport_key, &kernel_key, treaty_policy);
    treaty_context.subject_classes[0].allowed_treaties =
        vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    let mut treaty_body = body(&passport_key);
    treaty_body.nonce = "nonce-security-treaty".to_string();
    treaty_body.treaty_scope = vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    substrate
        .deposit(
            sign_deposit(treaty_body, &passport_key).expect("sign treaty"),
            &treaty_context,
        )
        .expect("different treaty has an independent bucket");

    let mut class_policy = base_context.scarcity_policies[0].clone();
    class_policy.policy_id = "policy:class-data-exfil".to_string();
    class_policy.subject_class = "support.data_exfiltration".to_string();
    refresh_policy_window_id(&mut class_policy);
    let mut class_context = context_with_scarcity_policy(&passport_key, &kernel_key, class_policy);
    class_context.subject_classes = vec![SubjectClassPolicy {
        subject_class: "support.data_exfiltration".to_string(),
        subject_class_namespace: "dev.chio.support".to_string(),
        allowed_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        cost_commitment: CostCommitmentPolicy::NotRequired,
        destructive: false,
    }];
    let mut class_body = body(&passport_key);
    class_body.nonce = "nonce-other-class".to_string();
    class_body.subject_class = "support.data_exfiltration".to_string();
    substrate
        .deposit(
            sign_deposit(class_body, &passport_key).expect("sign class"),
            &class_context,
        )
        .expect("different subject class has an independent bucket");

    let mut namespace_policy = base_context.scarcity_policies[0].clone();
    namespace_policy.policy_id = "policy:namespace-enterprise".to_string();
    namespace_policy.subject_class_namespace = "enterprise.chio.support".to_string();
    refresh_policy_window_id(&mut namespace_policy);
    let mut namespace_context =
        context_with_scarcity_policy(&passport_key, &kernel_key, namespace_policy);
    namespace_context.subject_classes = vec![SubjectClassPolicy {
        subject_class: "support.prompt_injection".to_string(),
        subject_class_namespace: "enterprise.chio.support".to_string(),
        allowed_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        cost_commitment: CostCommitmentPolicy::NotRequired,
        destructive: false,
    }];
    let mut namespace_body = body(&passport_key);
    namespace_body.nonce = "nonce-other-namespace".to_string();
    namespace_body.subject_class_namespace = "enterprise.chio.support".to_string();
    substrate
        .deposit(
            sign_deposit(namespace_body, &passport_key).expect("sign namespace"),
            &namespace_context,
        )
        .expect("different namespace has an independent bucket");
}

#[test]
fn scarcity_policy_rejects_stale_windows_unknown_epochs_and_invalid_horizon() {
    let passport_key = key(1);
    let kernel_key = key(2);

    let mut stale_policy = scarcity_policy(
        42,
        "window-stale",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    stale_policy.window_end_unix_ms = 1_699_999_999_999;
    refresh_policy_window_id(&mut stale_policy);
    let stale_context = context_with_scarcity_policy(&passport_key, &kernel_key, stale_policy);
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign stale"),
            &stale_context,
        )
        .expect_err("stale window rejected");
    assert_eq!(err.code(), "scarcity_window_stale");

    let unknown_policy = scarcity_policy(
        99,
        "window-unknown-epoch",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let mut unknown_context =
        context_with_scarcity_policy(&passport_key, &kernel_key, unknown_policy);
    unknown_context.known_reputation_epochs = vec![42];
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign unknown"),
            &unknown_context,
        )
        .expect_err("unknown policy epoch rejected");
    assert_eq!(err.code(), "unknown_reputation_epoch");

    let invalid_horizon_policy = scarcity_policy(
        42,
        "window-invalid-horizon",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        0,
    );
    let invalid_horizon_context =
        context_with_scarcity_policy(&passport_key, &kernel_key, invalid_horizon_policy);
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign horizon"),
            &invalid_horizon_context,
        )
        .expect_err("invalid newcomer horizon rejected");
    assert_eq!(err.code(), "invalid_newcomer_horizon");
}

#[test]
fn scarcity_policy_selection_uses_single_active_window_after_filtering() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let active_policy = scarcity_policy(
        42,
        "window-active",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let mut future_policy = active_policy.clone();
    future_policy.policy_id = "policy:window-future".to_string();
    future_policy.window_start_unix_ms = 1_700_000_010_000;
    future_policy.window_end_unix_ms = 1_700_000_020_000;
    refresh_policy_window_id(&mut future_policy);
    let mut context = context_with_scarcity_policy(&passport_key, &kernel_key, active_policy);
    context.scarcity_policies.push(future_policy);

    InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign active-window deposit"),
            &context,
        )
        .expect("exactly one active policy admits even when future rotation is staged");
}

#[test]
fn scarcity_policy_selection_ignores_known_but_inactive_reputation_epoch() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let inactive_epoch_policy = scarcity_policy(
        41,
        "window-inactive-epoch",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let mut context =
        context_with_scarcity_policy(&passport_key, &kernel_key, inactive_epoch_policy);
    context.active_reputation_epoch = 42;
    context.known_reputation_epochs = vec![41, 42];

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign inactive-epoch deposit"),
            &context,
        )
        .expect_err("known but inactive reputation epoch must not admit");

    assert_eq!(err.code(), "scarcity_window_stale");
}

#[test]
fn scarcity_policy_selection_rejects_ambiguous_active_windows() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let first_policy = scarcity_policy(
        42,
        "window-active-a",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    let mut second_policy = first_policy.clone();
    second_policy.policy_id = "policy:window-active-b".to_string();
    second_policy.window_id = "window-active-b".to_string();
    second_policy.window_start_unix_ms = 1_699_999_999_500;
    second_policy.window_end_unix_ms = 1_700_000_011_000;
    refresh_policy_window_id(&mut second_policy);
    let mut context = context_with_scarcity_policy(&passport_key, &kernel_key, first_policy);
    context.scarcity_policies.push(second_policy);

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign ambiguous deposit"),
            &context,
        )
        .expect_err("overlapping active policies are ambiguous");
    assert_eq!(err.code(), "scarcity_policy_ambiguous");
}

#[test]
fn scarcity_policy_selection_rejects_tampered_window_id() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut policy = scarcity_policy(
        42,
        "tampered-window-id",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        1,
        8,
    );
    policy.window_id = "tampered-window-id".to_string();
    let context = context_with_scarcity_policy(&passport_key, &kernel_key, policy);

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign tampered-window deposit"),
            &context,
        )
        .expect_err("window id must be recomputed from receiver-owned policy material");
    assert_eq!(err.code(), "scarcity_policy_invalid");
}

#[test]
fn scarcity_policy_selection_rejects_tampered_policy_hash_material() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut policy = scarcity_policy(
        42,
        "window-policy-hash",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    policy.policy_sha256 = "0".repeat(64);
    let context = context_with_scarcity_policy(&passport_key, &kernel_key, policy);

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(
            sign_deposit(body(&passport_key), &passport_key)
                .expect("sign tampered-policy-hash deposit"),
            &context,
        )
        .expect_err("policy hash must be recomputed from receiver-owned policy material");

    assert_eq!(err.code(), "scarcity_policy_invalid");
}

#[test]
fn observation_cost_commitment_requires_signed_statement_and_merkle_inclusion() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let verifier_key = key(8);
    let issuer_key = key(9);
    let mut policy = scarcity_policy(
        42,
        "window-cost-proof",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    policy.observation_cost_verification = ObservationCostVerificationMode::Required;
    refresh_policy_window_id(&mut policy);
    let context = context_with_observation_cost_roots(
        &passport_key,
        &kernel_key,
        policy.clone(),
        &verifier_key,
        &issuer_key,
    );
    let mut unsigned_body = body(&passport_key);
    unsigned_body.cost_commitment = None;
    let mut deposit = sign_deposit(unsigned_body, &passport_key).expect("sign deposit");
    deposit.body.cost_commitment = Some(signed_cost_commitment(
        &deposit,
        &policy,
        &verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    ));

    InMemoryPheromoneSubstrate::new()
        .deposit(deposit, &context)
        .expect("signed verifier statement with RFC 6962 inclusion admits");
}

#[test]
fn observation_cost_commitment_rejects_untrusted_invalid_and_revoked_roots() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let verifier_key = key(8);
    let issuer_key = key(9);
    let mut policy = scarcity_policy(
        42,
        "window-cost-negative",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    policy.observation_cost_verification = ObservationCostVerificationMode::Required;
    refresh_policy_window_id(&mut policy);
    let context = context_with_observation_cost_roots(
        &passport_key,
        &kernel_key,
        policy.clone(),
        &verifier_key,
        &issuer_key,
    );
    let mut unsigned_body = body(&passport_key);
    unsigned_body.cost_commitment = None;
    let deposit_without_cost =
        sign_deposit(unsigned_body.clone(), &passport_key).expect("sign missing");
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(deposit_without_cost, &context)
        .expect_err("missing commitment rejects distinctly");
    assert_eq!(err.code(), "observation_cost_commitment_missing");

    let mut untrusted_context = context.clone();
    untrusted_context.observation_cost_verifier_roots = Vec::new();
    let mut untrusted_deposit =
        sign_deposit(unsigned_body.clone(), &passport_key).expect("sign untrusted");
    untrusted_deposit.body.cost_commitment = Some(signed_cost_commitment(
        &untrusted_deposit,
        &policy,
        &verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    ));
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(untrusted_deposit, &untrusted_context)
        .expect_err("roots must come from receiver-owned runtime policy");
    assert_eq!(err.code(), "observation_cost_verifier_untrusted");

    let mut bad_signature_deposit =
        sign_deposit(unsigned_body.clone(), &passport_key).expect("sign bad signature");
    let mut commitment = signed_cost_commitment(
        &bad_signature_deposit,
        &policy,
        &verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    );
    commitment.statement.cost.amount += 1;
    bad_signature_deposit.body.cost_commitment = Some(commitment);
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(bad_signature_deposit, &context)
        .expect_err("statement mutation invalidates verifier signature");
    assert_eq!(err.code(), "observation_cost_signature_invalid");

    let mut bad_merkle_deposit =
        sign_deposit(unsigned_body.clone(), &passport_key).expect("sign bad merkle");
    let mut commitment = signed_cost_commitment(
        &bad_merkle_deposit,
        &policy,
        &verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    );
    commitment
        .statement
        .inclusion_proof
        .audit_path
        .push(chio_core_types::hashing::Hash::from_hex(&"a".repeat(64)).expect("hash"));
    let (signature, _) = verifier_key
        .sign_canonical(&commitment.statement)
        .expect("resign mutated proof");
    commitment.signature = signature;
    bad_merkle_deposit.body.cost_commitment = Some(commitment);
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(bad_merkle_deposit, &context)
        .expect_err("bad Merkle path rejects");
    assert_eq!(err.code(), "observation_cost_inclusion_invalid");

    let mut revoked_context = context.clone();
    revoked_context.runtime_trust_floor_state.entries.clear();
    let mut revoked_deposit = sign_deposit(unsigned_body, &passport_key).expect("sign revoked");
    revoked_deposit.body.cost_commitment = Some(signed_cost_commitment(
        &revoked_deposit,
        &policy,
        &verifier_key,
        context
            .runtime_policy_sha256
            .as_deref()
            .expect("runtime hash"),
    ));
    let err = InMemoryPheromoneSubstrate::new()
        .deposit(revoked_deposit, &revoked_context)
        .expect_err("revoked verifier root rejects");
    assert_eq!(err.code(), "observation_cost_revoked");
}

#[test]
fn verified_cost_commitment_must_bind_policy_subject_treaty_and_verifier() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let verifier_key = key(8);
    let issuer_key = key(9);
    let mut policy = scarcity_policy(
        42,
        "window-cost-binding",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    policy.observation_cost_verification = ObservationCostVerificationMode::Required;
    refresh_policy_window_id(&mut policy);
    let context = context_with_observation_cost_roots(
        &passport_key,
        &kernel_key,
        policy.clone(),
        &verifier_key,
        &issuer_key,
    );

    for (case, mutate) in [
        ("wrong verifier", "verifier"),
        ("wrong subject class", "subject"),
        ("wrong namespace", "namespace"),
        ("wrong treaty", "treaty"),
    ] {
        let mut body = body(&passport_key);
        body.nonce = format!("nonce-{case}");
        let mut deposit = sign_deposit(body, &passport_key).expect("sign invalid commitment");
        let mut commitment = signed_cost_commitment(
            &deposit,
            &policy,
            &verifier_key,
            context
                .runtime_policy_sha256
                .as_deref()
                .expect("runtime hash"),
        );
        match mutate {
            "verifier" => {
                commitment.statement.verifier_id = "did:chio:other-verifier".to_string();
                commitment.statement.telemetry.verifier_id = "did:chio:other-verifier".to_string();
            }
            "subject" => {
                commitment.statement.subject_class = "support.data_exfiltration".to_string();
            }
            "namespace" => {
                commitment.statement.subject_class_namespace =
                    "enterprise.chio.support".to_string();
            }
            "treaty" => {
                commitment.statement.treaty_id = "treaty:buyer-llamaworks:security-ops".to_string();
            }
            _ => unreachable!(),
        }
        deposit.body.cost_commitment = Some(commitment);
        let err = InMemoryPheromoneSubstrate::new()
            .deposit(deposit, &context)
            .expect_err("unverified commitment rejected");
        assert_eq!(err.code(), "observation_cost_policy_mismatch");
    }
}

#[test]
fn verified_cost_commitment_rejects_unit_window_runtime_leaf_and_deposit_hash_mismatches() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let verifier_key = key(8);
    let issuer_key = key(9);
    let mut policy = scarcity_policy(
        42,
        "window-cost-binding-extra",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    policy.observation_cost_verification = ObservationCostVerificationMode::Required;
    refresh_policy_window_id(&mut policy);
    let context = context_with_observation_cost_roots(
        &passport_key,
        &kernel_key,
        policy.clone(),
        &verifier_key,
        &issuer_key,
    );

    invalid_cost_commitment_case(
        &context,
        &policy,
        &passport_key,
        &verifier_key,
        "nonce-cost-wrong-unit",
        "observation_cost_unit_invalid",
        |commitment| {
            commitment.statement.cost.unit = "chio.observation.other-unit.v1".to_string();
        },
    );
    invalid_cost_commitment_case(
        &context,
        &policy,
        &passport_key,
        &verifier_key,
        "nonce-cost-stale-window",
        "observation_cost_window_mismatch",
        |commitment| {
            commitment.statement.observation_window_start_unix_ms = 1_699_999_000_000;
            commitment.statement.observation_window_end_unix_ms = 1_699_999_500_000;
            commitment.statement.observed_at_unix_ms = 1_699_999_250_000;
            commitment.statement.telemetry.closed_at_unix_ms = 1_699_999_250_000;
        },
    );
    invalid_cost_commitment_case(
        &context,
        &policy,
        &passport_key,
        &verifier_key,
        "nonce-cost-runtime-policy",
        "observation_cost_runtime_policy_mismatch",
        |commitment| {
            commitment.statement.runtime_policy_sha256 = "2".repeat(64);
        },
    );
    invalid_cost_commitment_case(
        &context,
        &policy,
        &passport_key,
        &verifier_key,
        "nonce-cost-leaf-preimage",
        "observation_cost_leaf_mismatch",
        |commitment| {
            commitment.statement.leaf_preimage_sha256 = "f".repeat(64);
            resign_cost_commitment(commitment, &verifier_key);
        },
    );
    invalid_cost_commitment_case(
        &context,
        &policy,
        &passport_key,
        &verifier_key,
        "nonce-cost-deposit-hash",
        "observation_cost_policy_mismatch",
        |commitment| {
            commitment.statement.deposit_body_sha256 = "d".repeat(64);
        },
    );
}

#[test]
fn newcomer_horizon_is_configurable_from_explicit_policy_material() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let horizon_eight_policy = scarcity_policy(
        42,
        "window-horizon-eight",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        8,
    );
    let horizon_eight_context =
        context_with_scarcity_policy(&passport_key, &kernel_key, horizon_eight_policy);
    let horizon_eight_substrate = InMemoryPheromoneSubstrate::new();
    horizon_eight_substrate
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign horizon eight"),
            &horizon_eight_context,
        )
        .expect("horizon eight deposit stores");
    let horizon_eight_concentration = horizon_eight_substrate
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            1_700_000_000_000,
            42,
            &horizon_eight_context,
            &|_, _| 1.0,
        )
        .expect("horizon eight query");
    assert!((horizon_eight_concentration.total_strength - 0.615).abs() < 0.000_001);

    let policy = scarcity_policy(
        42,
        "window-horizon-four",
        vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        "dev.chio.support",
        "support.prompt_injection",
        4,
        4,
    );
    let policy_context = context_with_scarcity_policy(&passport_key, &kernel_key, policy);
    let policy_substrate = InMemoryPheromoneSubstrate::new();
    policy_substrate
        .deposit(
            sign_deposit(body(&passport_key), &passport_key).expect("sign policy"),
            &policy_context,
        )
        .expect("policy deposit stores");
    let policy_concentration = policy_substrate
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            1_700_000_000_000,
            42,
            &policy_context,
            &|_, _| 1.0,
        )
        .expect("policy query");
    assert!((policy_concentration.total_strength - 0.82).abs() < 0.000_001);
}

#[test]
fn future_dated_deposit_is_rejected() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let mut body = body(&passport_key);
    body.timestamp_unix_ms = 1_700_000_001_000;
    let deposit = sign_deposit(body, &passport_key).expect("sign deposit");
    let mut context = live_context(&passport_key, &kernel_key);
    context.now_unix_ms = 1_700_000_000_500;

    let err = InMemoryPheromoneSubstrate::new()
        .deposit(deposit, &context)
        .expect_err("future deposit rejected");

    assert_eq!(err.code(), "deposit_from_future");
}

#[test]
fn concentration_rejects_unknown_epoch_and_bad_weight() {
    let passport_key = key(1);
    let kernel_key = key(2);
    let deposit = sign_deposit(body(&passport_key), &passport_key).expect("sign deposit");
    let substrate = InMemoryPheromoneSubstrate::new();
    let context = live_context(&passport_key, &kernel_key);
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
