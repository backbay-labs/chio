#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use chio_core_types::crypto::sha256_hex;
use chio_core_types::merkle::MerkleTree;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::Keypair;
use chio_federation::{
    pheromone_gossip::PheromoneDepositGossip, pheromone_gossip::PheromoneGossipBatch,
    pheromone_gossip::PheromoneTransitPolicy, pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA,
    pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA, pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA,
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, scarcity_policy_sha256,
    scarcity_window_id, sign_deposit, CostCommitmentPolicy, ObservationCostVerificationMode,
    PassportAdmission, PheromoneConcentration, PheromoneCostCommitment, PheromoneDeposit,
    PheromoneDepositBody, PheromoneObservationCostAmount, PheromoneObservationCostLeaf,
    PheromoneObservationCostStatement, PheromoneObservationCostTelemetryRoot,
    PheromoneRuntimeTrustFloorState, PheromoneScarcityPolicy, PheromoneValidationContext, Severity,
    SubjectClassPolicy, OBSERVATION_COST_TELEMETRY_ALGORITHM, OBSERVATION_COST_UNIT,
    PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA, PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA, PHEROMONE_SCARCITY_POLICY_SCHEMA,
};
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;
use chio_pheromone_runtime::{
    peer_weights_from_json, runtime_policy_document_sha256, runtime_policy_from_json,
    ChioWorkflowProofPackage, ChioWorkflowVerificationContext, ChioWorkflowVerifierTrustBundle,
    PeerWeightProvider, PheromoneBatchOutcome, PheromoneReceiveReport, PheromoneReceiver,
    PheromoneReceiverConfig, PheromoneRuntimeError, PheromoneRuntimeStore,
    StaticPeerWeightProvider, VerifiedChioWorkflowResolver,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("examples/chio-3vendor/fixtures")
        .join(path)
}

fn load_batch() -> PheromoneGossipBatch {
    serde_json::from_str(&fs::read_to_string(fixture("pheromone/gossip-batch.json")).unwrap())
        .unwrap()
}

fn load_runtime_policy() -> (PheromoneTransitPolicy, PheromoneReceiverConfig) {
    let trust_bundle = ChioWorkflowVerifierTrustBundle::from_json(
        &fs::read_to_string(fixture("verifier-trust-bundle.json")).unwrap(),
    )
    .unwrap();
    let (mut policy, config) = runtime_policy_from_json(
        &fs::read_to_string(fixture("pheromone/transit-policy.json")).unwrap(),
        1_766_000_000_500,
        trust_bundle.runtime_policy_issuer_public_keys(),
    )
    .unwrap();
    if let Some(treaty_id) = config.validation_context.scarcity_policies[0]
        .treaty_scope
        .first()
        .cloned()
    {
        if !policy.allowed_egress_treaties.contains(&treaty_id) {
            policy.allowed_egress_treaties.push(treaty_id);
        }
    }
    (policy, config)
}

fn resolver() -> VerifiedChioWorkflowResolver {
    let package = ChioWorkflowProofPackage::from_json(
        &fs::read_to_string(fixture("buyer-auditor-proof-package.json")).unwrap(),
    )
    .unwrap();
    let trust_bundle = ChioWorkflowVerifierTrustBundle::from_json(
        &fs::read_to_string(fixture("verifier-trust-bundle.json")).unwrap(),
    )
    .unwrap();
    let context = ChioWorkflowVerificationContext::from_json(
        &fs::read_to_string(fixture("verification-context.json")).unwrap(),
    )
    .unwrap();
    VerifiedChioWorkflowResolver::from_verified_package(&package, &trust_bundle, &context).unwrap()
}

fn runtime_policy_value() -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture("pheromone/transit-policy.json")).unwrap(),
    )
    .unwrap();
    value.get("body").cloned().unwrap_or(value)
}

fn runtime_policy_loader_error(value: &serde_json::Value) -> String {
    runtime_policy_from_json(
        &serde_json::to_string(value).unwrap(),
        1_700_000_000_500,
        &[key(42).public_key()],
    )
    .unwrap_err()
    .code()
    .to_string()
}

fn signed_runtime_policy_value(body: serde_json::Value) -> serde_json::Value {
    let envelope = SignedExportEnvelope::sign(body, &key(42)).unwrap();
    serde_json::to_value(envelope).unwrap()
}

fn signed_runtime_policy_loader_error(body: &serde_json::Value) -> String {
    runtime_policy_loader_error(&signed_runtime_policy_value(body.clone()))
}

#[test]
fn runtime_policy_loader_rejects_unsigned_policy_document() {
    let value = runtime_policy_value();

    assert_eq!(runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_boolean_trust_floor_entries() {
    let mut value = runtime_policy_value();
    value["admission"]["runtimeTrustFloorState"]["entries"] = serde_json::json!([
        {
            "verifierId": "did:chio:cost-verifier",
            "keyId": "cost-root-key-1",
            "revoked": false
        }
    ]);
    seal_runtime_policy_hashes(&mut value);

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_tampered_signed_policy_envelope() {
    let mut envelope = signed_runtime_policy_value(runtime_policy_value());
    envelope["body"]["valid_until_unix_ms"] = serde_json::json!(1_800_000_000_000_u64);

    assert_eq!(runtime_policy_loader_error(&envelope), "invalid_field");
}

#[test]
fn runtime_policy_loader_rejects_untrusted_policy_signer() {
    let envelope = SignedExportEnvelope::sign(runtime_policy_value(), &key(99)).unwrap();
    let value = serde_json::to_value(envelope).unwrap();

    assert_eq!(runtime_policy_loader_error(&value), "invalid_field");
}

#[test]
fn runtime_policy_loader_rejects_self_authorized_policy_signer() {
    let mut value = runtime_policy_value();
    value["admission"]["runtimePolicyIssuerPublicKeys"] = serde_json::json!([key(99).public_key()]);
    seal_runtime_policy_hashes(&mut value);
    let envelope = SignedExportEnvelope::sign(value, &key(99)).unwrap();
    let value = serde_json::to_value(envelope).unwrap();

    assert_eq!(runtime_policy_loader_error(&value), "invalid_field");
}

fn seal_runtime_policy_hashes(value: &mut serde_json::Value) {
    let policies = value["admission"]["scarcityPolicies"]
        .as_array_mut()
        .unwrap();
    for policy in policies.iter_mut() {
        let reputation_epoch = policy["reputationEpoch"].as_u64().unwrap();
        policy["activePeersEpoch"] = serde_json::json!(reputation_epoch);
        policy["runtimePolicySha256"] = serde_json::json!("0".repeat(64));
        policy["policySha256"] = serde_json::json!("0".repeat(64));
    }
    let runtime_policy_sha256 = runtime_policy_document_sha256(value).unwrap();
    for policy in value["admission"]["scarcityPolicies"]
        .as_array_mut()
        .unwrap()
    {
        policy["runtimePolicySha256"] = serde_json::json!(runtime_policy_sha256);
        let parsed: PheromoneScarcityPolicy = serde_json::from_value(policy.clone()).unwrap();
        policy["policySha256"] = serde_json::json!(scarcity_policy_sha256(&parsed).unwrap());
    }
}

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn runtime_policy_sha256() -> String {
    "1".repeat(64)
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
    let mut signed_body = deposit.body.clone();
    signed_body.cost_commitment = None;
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256: sha256_hex(
            &chio_core_types::canonical::canonical_json_bytes(&signed_body).unwrap(),
        ),
        deposit_signature_sha256: sha256_hex(deposit.signature.to_hex().as_bytes()),
        kernel_id: deposit.body.kernel_id.clone(),
        agent_passport_key_hash: deposit.body.agent_passport_key_hash.clone(),
        treaty_id: policy.treaty_scope.first().unwrap().clone(),
        subject_class_namespace: deposit.body.subject_class_namespace.clone(),
        subject_class: deposit.body.subject_class.clone(),
        observed_at_unix_ms: deposit.body.timestamp_unix_ms,
        event_digest_sha256: "9".repeat(64),
        cost: cost.clone(),
        scarcity_policy_sha256: scarcity_policy_sha256(policy).unwrap(),
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
    };
    let leaf_bytes = chio_core_types::canonical::canonical_json_bytes(&leaf).unwrap();
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&leaf_bytes)).unwrap();
    let statement = PheromoneObservationCostStatement {
        schema: PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA.to_string(),
        commitment_id: format!("cost-commitment-{}", deposit.body.nonce),
        verifier_id: policy.verifier_id.clone(),
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
            verifier_id: policy.verifier_id.clone(),
            verifier_key_id: "cost-root-key-1".to_string(),
            closed_at_unix_ms: deposit.body.timestamp_unix_ms.saturating_add(250),
        },
        inclusion_proof: tree.inclusion_proof(0).unwrap(),
        leaf_preimage_sha256: sha256_hex(&leaf_bytes),
    };
    let (signature, _) = verifier_key.sign_canonical(&statement).unwrap();
    PheromoneCostCommitment {
        schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
        statement,
        signature,
    }
}

fn runtime_body(
    passport_key: &Keypair,
    nonce: &str,
    treaty_scope: Vec<String>,
) -> PheromoneDepositBody {
    let public_key = passport_key.public_key();
    PheromoneDepositBody {
        schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
        kernel_id: "did:chio:llamaworks".to_string(),
        agent_passport_key_hash: agent_passport_key_hash(&public_key),
        agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
        subject_class: "support.prompt_injection".to_string(),
        subject_class_namespace: "dev.chio.support".to_string(),
        indicator: serde_json::json!({"kind": "prompt_injection", "digest": "e".repeat(64)}),
        severity: Severity::High,
        confidence: 0.82,
        timestamp_unix_ms: 1_700_000_000_000,
        decay_half_life_secs: 3_600.0,
        evaporation_floor: Some(0.01),
        nonce: nonce.to_string(),
        treaty_scope: treaty_scope.clone(),
        cost_commitment: None,
        workflow_context: None,
    }
}

fn scarcity_policy(
    window_id: &str,
    treaty_scope: Vec<String>,
    capacity: u64,
) -> PheromoneScarcityPolicy {
    let mut policy = PheromoneScarcityPolicy {
        schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.to_string(),
        policy_id: format!("policy:{window_id}"),
        reputation_epoch: 42,
        window_id: window_id.to_string(),
        window_start_unix_ms: 1_699_999_999_000,
        window_end_unix_ms: 1_700_000_010_000,
        token_capacity: capacity,
        newcomer_horizon_epochs: 8,
        treaty_scope,
        subject_class_namespace: "dev.chio.support".to_string(),
        subject_class: "support.prompt_injection".to_string(),
        observation_cost_verification: ObservationCostVerificationMode::NotRequired,
        verifier_id: "did:chio:cost-verifier".to_string(),
        runtime_policy_sha256: runtime_policy_sha256(),
        policy_sha256: String::new(),
        active_peers_epoch: 42,
    };
    let treaty_id = policy.treaty_scope.first().unwrap().clone();
    policy.window_id = scarcity_window_id(&policy, &treaty_id).unwrap();
    policy.policy_sha256 = scarcity_policy_sha256(&policy).unwrap();
    policy
}

fn runtime_context(
    passport_key: &Keypair,
    kernel_key: &Keypair,
    policy: PheromoneScarcityPolicy,
) -> PheromoneValidationContext {
    PheromoneValidationContext {
        now_unix_ms: 1_700_000_000_500,
        replay_window_ms: 86_400_000,
        active_peers_in_treaty: 9,
        active_reputation_epoch: policy.reputation_epoch,
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
            allowed_treaties: policy.treaty_scope.clone(),
            cost_commitment: CostCommitmentPolicy::NotRequired,
            destructive: false,
        }],
        max_deposits_per_pair: 8,
        runtime_policy_sha256: Some(policy.runtime_policy_sha256.clone()),
        scarcity_policies: vec![policy],
        runtime_policy_issuer_public_keys: Vec::new(),
        observation_cost_verifier_roots: Vec::new(),
        runtime_trust_floor_state: PheromoneRuntimeTrustFloorState::default(),
    }
}

fn direct_transit_policy(treaties: &[String]) -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: Vec::new(),
        allowed_ingress_treaties: treaties.to_vec(),
        allowed_egress_treaties: treaties.to_vec(),
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        valid_from_unix_ms: 1_699_999_999_000,
        valid_until_unix_ms: 1_700_000_010_000,
        max_hops: 4,
        required_action_class_id: "workflow.observation".to_string(),
        pinned_ladder_refs: Vec::new(),
    }
}

fn direct_batch(treaty_id: &str, deposit: PheromoneDeposit) -> PheromoneGossipBatch {
    PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:dataco".to_string(),
        treaty_id: treaty_id.to_string(),
        frames: vec![PheromoneDepositGossip {
            schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
            origin_kernel_id: deposit.body.kernel_id.clone(),
            gossiping_peer_kernel_id: deposit.body.kernel_id.clone(),
            treaty_id: treaty_id.to_string(),
            ts_unix_ms: 1_700_000_000_500,
            transit_chain: None,
            deposit,
        }],
        flushed_at_unix_ms: 1_700_000_000_500,
    }
}

struct FailingCommitStore;

impl PheromoneRuntimeStore for FailingCommitStore {
    fn receive_batch(
        &self,
        batch: &PheromoneGossipBatch,
        policy: &PheromoneTransitPolicy,
        config: &PheromoneReceiverConfig,
        resolver: &dyn chio_pheromone_runtime::WorkflowContextResolver,
    ) -> Result<PheromoneReceiveReport, PheromoneRuntimeError> {
        let store = SqlitePheromoneRuntimeStore::open_in_memory().unwrap();
        let report = store.receive_batch(batch, policy, config, resolver)?;
        let mut failed_report = report;
        failed_report.frames.iter_mut().for_each(|frame| {
            frame.accepted = false;
            frame.code = "storage_commit_failed".to_string();
            frame.detail = "simulated frame commit failure".to_string();
        });
        Ok(PheromoneReceiveReport {
            accepted: false,
            batch_outcome: PheromoneBatchOutcome::Rejected,
            accepted_frame_count: 0,
            rejected_frame_count: failed_report.frames.len() as u64,
            ..failed_report
        })
    }

    fn admit_deposit(
        &self,
        _deposit: PheromoneDeposit,
        _context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::Sqlite(
            "simulated frame commit failure".to_string(),
        ))
    }

    fn admit_deposit_for_treaty(
        &self,
        _deposit: PheromoneDeposit,
        _context: &PheromoneValidationContext,
        _treaty_id: &str,
    ) -> Result<(), PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::Sqlite(
            "simulated frame commit failure".to_string(),
        ))
    }

    fn query_deposits(
        &self,
        _subject_class: Option<&str>,
        _treaty_id: Option<&str>,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneRuntimeError> {
        Ok(Vec::new())
    }

    fn query_concentration(
        &self,
        _subject_class: &str,
        _subject_class_namespace: &str,
        _now_unix_ms: u64,
        _reputation_epoch: u64,
        _context: &PheromoneValidationContext,
        _peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneConcentration, PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::Sqlite(
            "not used by storage failure test".to_string(),
        ))
    }

    fn record_receive_report(
        &self,
        _report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError> {
        Ok(())
    }

    fn receive_reports(&self) -> Result<Vec<PheromoneReceiveReport>, PheromoneRuntimeError> {
        Ok(Vec::new())
    }
}

struct UnscopedOnlyStore;

impl PheromoneRuntimeStore for UnscopedOnlyStore {
    fn admit_deposit(
        &self,
        _deposit: PheromoneDeposit,
        _context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError> {
        Ok(())
    }

    fn query_deposits(
        &self,
        _subject_class: Option<&str>,
        _treaty_id: Option<&str>,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneRuntimeError> {
        Ok(Vec::new())
    }

    fn query_concentration(
        &self,
        _subject_class: &str,
        _subject_class_namespace: &str,
        _now_unix_ms: u64,
        _reputation_epoch: u64,
        _context: &PheromoneValidationContext,
        _peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneConcentration, PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::Sqlite(
            "not used by scoped trait invariant test".to_string(),
        ))
    }

    fn record_receive_report(
        &self,
        _report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError> {
        Ok(())
    }

    fn receive_reports(&self) -> Result<Vec<PheromoneReceiveReport>, PheromoneRuntimeError> {
        Ok(Vec::new())
    }
}

#[test]
fn receiver_accepts_fixture_and_persists_report() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);

    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(report.accepted, "{report:#?}");
    assert_eq!(report.batch_outcome, PheromoneBatchOutcome::Accepted);
    assert_eq!(report.accepted_frame_count, 1);
    assert_eq!(report.rejected_frame_count, 0);
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.frames[0].code, "accepted");
    assert_eq!(receiver.store().receive_reports().unwrap().len(), 1);
}

#[test]
fn receiver_rejects_relay_frame_without_receiver_pinned_ladder_refs() {
    let (mut policy, config) = load_runtime_policy();
    policy.pinned_ladder_refs.clear();
    let receiver = PheromoneReceiver::new(
        SqlitePheromoneRuntimeStore::open_in_memory().unwrap(),
        resolver(),
        config,
    );

    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.batch_outcome, PheromoneBatchOutcome::Rejected);
    assert_eq!(report.frames[0].code, "transit_policy_violation");
    assert!(
        report.frames[0].detail.contains("pinned"),
        "missing transit pins should fail closed, got: {}",
        report.frames[0].detail
    );
}

#[test]
fn unscoped_store_default_cannot_accept_live_receive() {
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(UnscopedOnlyStore, resolver(), config);

    let error = receiver.receive_batch(&load_batch(), &policy).unwrap_err();

    assert_eq!(error.code(), "invalid_field");
    assert!(
        error.to_string().contains("atomic"),
        "unscoped trait default must fail closed, got: {}",
        error
    );
}

#[test]
fn sqlite_receive_rolls_back_accepted_state_when_report_persistence_fails() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pheromone.sqlite3");
    let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("DROP TABLE chio_pheromone_receive_reports", [])
        .unwrap();
    drop(conn);
    let passport_key = key(61);
    let kernel_key = key(62);
    let treaty = "treaty:buyer-llamaworks:support-ops".to_string();
    let context = runtime_context(
        &passport_key,
        &kernel_key,
        scarcity_policy("window-report-rollback", vec![treaty.clone()], 8),
    );
    let config = PheromoneReceiverConfig {
        recipient_kernel_id: "did:chio:dataco".to_string(),
        authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        validation_context: context,
    };
    let policy = direct_transit_policy(std::slice::from_ref(&treaty));
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let deposit = sign_deposit(
        runtime_body(
            &passport_key,
            "runtime-nonce-report-rollback",
            vec![treaty.clone()],
        ),
        &passport_key,
    )
    .unwrap();

    let error = receiver
        .receive_batch(&direct_batch(&treaty, deposit), &policy)
        .unwrap_err();

    assert_eq!(error.code(), "sqlite");
    assert!(
        receiver
            .store()
            .query_deposits(None, None)
            .unwrap()
            .is_empty(),
        "accepted deposit state must roll back when receive report persistence fails"
    );
}

#[test]
fn storage_commit_failure_is_reported_without_accepting_frame() {
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(FailingCommitStore, resolver(), config);

    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.batch_outcome, PheromoneBatchOutcome::Rejected);
    assert_eq!(report.accepted_frame_count, 0);
    assert_eq!(report.rejected_frame_count, 1);
    assert_eq!(report.frames[0].code, "storage_commit_failed");
}

#[test]
fn runtime_policy_loader_reads_explicit_scarcity_policy() {
    let mut value = runtime_policy_value();
    let policy = serde_json::to_value(scarcity_policy(
        "window-loader",
        vec!["treaty:buyer-dataco:support-ops".to_string()],
        3,
    ))
    .unwrap();
    value["admission"]["scarcityPolicies"] = serde_json::json!([policy]);
    seal_runtime_policy_hashes(&mut value);

    let (_policy, config) = runtime_policy_from_json(
        &serde_json::to_string(&signed_runtime_policy_value(value)).unwrap(),
        1_700_000_000_500,
        &[key(42).public_key()],
    )
    .unwrap();

    assert_eq!(config.validation_context.scarcity_policies.len(), 1);
    assert_eq!(
        config.validation_context.scarcity_policies[0].schema,
        PHEROMONE_SCARCITY_POLICY_SCHEMA
    );
    assert_eq!(
        config.validation_context.scarcity_policies[0].policy_id,
        "policy:window-loader"
    );
    assert_eq!(
        config.validation_context.scarcity_policies[0].treaty_scope,
        vec!["treaty:buyer-dataco:support-ops".to_string()]
    );
}

#[test]
fn runtime_policy_loader_rejects_missing_scarcity_policy_before_serde_defaults() {
    let mut value = runtime_policy_value();
    value["admission"]
        .as_object_mut()
        .unwrap()
        .remove("scarcityPolicies");

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_empty_scarcity_policy_material() {
    let mut value = runtime_policy_value();
    value["admission"]["scarcityPolicies"] = serde_json::json!([]);

    assert_eq!(
        signed_runtime_policy_loader_error(&value),
        "scarcity_policy_missing"
    );
}

#[test]
fn runtime_policy_loader_rejects_missing_newcomer_horizon_before_serde_default() {
    let mut value = runtime_policy_value();
    value["admission"]["scarcityPolicies"][0]
        .as_object_mut()
        .unwrap()
        .remove("newcomerHorizonEpochs");

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_missing_scarcity_hash_material_before_serde() {
    let mut value = runtime_policy_value();
    seal_runtime_policy_hashes(&mut value);
    value["admission"]["scarcityPolicies"][0]
        .as_object_mut()
        .unwrap()
        .remove("policySha256");

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_tampered_runtime_policy_hash_binding() {
    let mut value = runtime_policy_value();
    seal_runtime_policy_hashes(&mut value);
    value["admission"]["scarcityPolicies"][0]["runtimePolicySha256"] =
        serde_json::json!("0".repeat(64));

    assert_eq!(
        signed_runtime_policy_loader_error(&value),
        "scarcity_policy_invalid"
    );
}

#[test]
fn runtime_policy_loader_rejects_unknown_admission_fields_before_serde() {
    let mut value = runtime_policy_value();
    value["admission"]["implicitCompatibilityDefault"] = serde_json::json!(true);

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn runtime_policy_loader_rejects_missing_active_reputation_epoch_before_serde() {
    let mut value = runtime_policy_value();
    value["admission"]
        .as_object_mut()
        .unwrap()
        .remove("activeReputationEpoch");

    assert_eq!(signed_runtime_policy_loader_error(&value), "schema_invalid");
}

#[test]
fn peer_weights_loader_rejects_unknown_fields_before_serde() {
    let value = serde_json::json!({
        "schema": "chio.pheromone.peer-weights.v1",
        "reputationEpoch": 42,
        "weights": [
            {
                "kernelId": "did:chio:llamaworks",
                "weight": 1.0
            }
        ],
        "implicitCompatibilityDefault": true
    });

    let err = peer_weights_from_json(&serde_json::to_string(&value).unwrap()).unwrap_err();

    assert_eq!(err.code(), "schema_invalid");
}

#[test]
fn peer_weights_loader_rejects_duplicate_kernel_ids() {
    let value = serde_json::json!({
        "schema": "chio.pheromone.peer-weights.v1",
        "reputationEpoch": 42,
        "weights": [
            {
                "kernelId": "did:chio:llamaworks",
                "weight": 1.0
            },
            {
                "kernelId": "did:chio:llamaworks",
                "weight": 0.5
            }
        ]
    });

    let err = peer_weights_from_json(&serde_json::to_string(&value).unwrap()).unwrap_err();

    assert_eq!(err.code(), "invalid_field");
}

#[test]
fn runtime_policy_loader_rejects_overlapping_scarcity_windows() {
    let mut value = runtime_policy_value();
    let mut overlapping = value["admission"]["scarcityPolicies"][0].clone();
    overlapping["policyId"] = serde_json::json!("scarcity:overlapping-window");
    overlapping["windowId"] = serde_json::json!("epoch42-window-overlap");
    overlapping["windowStartUnixMs"] = serde_json::json!(1_765_999_950_000_u64);
    overlapping["windowEndUnixMs"] = serde_json::json!(1_766_000_070_000_u64);
    value["admission"]["scarcityPolicies"]
        .as_array_mut()
        .unwrap()
        .push(overlapping);
    seal_runtime_policy_hashes(&mut value);

    assert_eq!(
        signed_runtime_policy_loader_error(&value),
        "scarcity_policy_ambiguous"
    );
}

#[test]
fn sqlite_scarcity_buckets_are_window_and_treaty_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let passport_key = key(1);
    let kernel_key = key(2);
    let support_treaty = vec!["treaty:buyer-llamaworks:support-ops".to_string()];
    let security_treaty = vec!["treaty:buyer-llamaworks:security-ops".to_string()];
    let context = runtime_context(
        &passport_key,
        &kernel_key,
        scarcity_policy("window-a", support_treaty.clone(), 1),
    );

    store
        .admit_deposit(
            sign_deposit(
                runtime_body(&passport_key, "runtime-nonce-1", support_treaty.clone()),
                &passport_key,
            )
            .unwrap(),
            &context,
        )
        .unwrap();
    let exhausted = store
        .admit_deposit(
            sign_deposit(
                runtime_body(&passport_key, "runtime-nonce-2", support_treaty.clone()),
                &passport_key,
            )
            .unwrap(),
            &context,
        )
        .unwrap_err();
    assert_eq!(exhausted.code(), "rate_limit_exhausted");

    let mut window_policy = scarcity_policy("window-b", support_treaty.clone(), 1);
    window_policy.window_start_unix_ms = 1_700_000_000_000;
    window_policy.window_end_unix_ms = 1_700_000_020_000;
    let treaty_id = window_policy.treaty_scope.first().unwrap().clone();
    window_policy.window_id = scarcity_window_id(&window_policy, &treaty_id).unwrap();
    window_policy.policy_sha256 = scarcity_policy_sha256(&window_policy).unwrap();
    let window_context = runtime_context(&passport_key, &kernel_key, window_policy);
    store
        .admit_deposit(
            sign_deposit(
                runtime_body(&passport_key, "runtime-nonce-window", support_treaty),
                &passport_key,
            )
            .unwrap(),
            &window_context,
        )
        .unwrap();

    let treaty_context = runtime_context(
        &passport_key,
        &kernel_key,
        scarcity_policy("window-a", security_treaty.clone(), 1),
    );
    store
        .admit_deposit(
            sign_deposit(
                runtime_body(&passport_key, "runtime-nonce-treaty", security_treaty),
                &passport_key,
            )
            .unwrap(),
            &treaty_context,
        )
        .unwrap();
}

#[test]
fn receiver_burns_only_the_frame_treaty_scarcity_bucket() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let passport_key = key(51);
    let kernel_key = key(52);
    let support_treaty = "treaty:buyer-llamaworks:support-ops".to_string();
    let security_treaty = "treaty:buyer-llamaworks:security-ops".to_string();
    let support_policy = scarcity_policy("window-frame-support", vec![support_treaty.clone()], 1);
    let security_policy =
        scarcity_policy("window-frame-security", vec![security_treaty.clone()], 1);
    let mut context = runtime_context(&passport_key, &kernel_key, support_policy);
    context.scarcity_policies.push(security_policy);
    context.subject_classes[0].allowed_treaties =
        vec![support_treaty.clone(), security_treaty.clone()];
    let config = PheromoneReceiverConfig {
        recipient_kernel_id: "did:chio:dataco".to_string(),
        authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        validation_context: context,
    };
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let policy = direct_transit_policy(&[support_treaty.clone(), security_treaty.clone()]);

    let multi_treaty_deposit = sign_deposit(
        runtime_body(
            &passport_key,
            "runtime-nonce-frame-support",
            vec![support_treaty.clone(), security_treaty.clone()],
        ),
        &passport_key,
    )
    .unwrap();
    let support_report = receiver
        .receive_batch(
            &direct_batch(&support_treaty, multi_treaty_deposit),
            &policy,
        )
        .unwrap();
    assert!(
        support_report.accepted,
        "support-frame admission must succeed"
    );

    let security_deposit = sign_deposit(
        runtime_body(
            &passport_key,
            "runtime-nonce-frame-security",
            vec![security_treaty.clone()],
        ),
        &passport_key,
    )
    .unwrap();
    let security_report = receiver
        .receive_batch(&direct_batch(&security_treaty, security_deposit), &policy)
        .unwrap();

    assert!(
        security_report.accepted,
        "support-frame admission must not burn security treaty scarcity"
    );
}

#[test]
fn replay_nonce_survives_store_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pheromone.sqlite3");
    {
        let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
        let (policy, config) = load_runtime_policy();
        let receiver = PheromoneReceiver::new(store, resolver(), config);
        assert!(
            receiver
                .receive_batch(&load_batch(), &policy)
                .unwrap()
                .accepted
        );
    }

    let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.frames[0].code, "replay_window_exceeded");
}

#[test]
fn workflow_context_mismatch_is_rejected_before_storage() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let mut batch = load_batch();
    batch.frames[0]
        .deposit
        .body
        .workflow_context
        .as_mut()
        .unwrap()
        .tool_receipt_id = "rcpt-wrong".to_string();

    let report = receiver.receive_batch(&batch, &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.frames[0].code, "workflow_context_mismatch");
    assert!(receiver
        .store()
        .query_deposits(None, None)
        .unwrap()
        .is_empty());
}

#[test]
fn mixed_batch_reports_partial_and_invalid_frame_consumes_no_admission_state() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let selected_policy = config.validation_context.scarcity_policies[0].clone();
    let runtime_policy_sha256 = config
        .validation_context
        .runtime_policy_sha256
        .clone()
        .unwrap();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let mut batch = load_batch();
    let mut malformed_frame = batch.frames[0].clone();
    malformed_frame.deposit.body.nonce = "pheromone-nonce-llamaworks-002".to_string();
    malformed_frame.deposit = sign_deposit(malformed_frame.deposit.body.clone(), &key(31)).unwrap();
    malformed_frame.deposit.body.cost_commitment = Some(signed_cost_commitment(
        &malformed_frame.deposit,
        &selected_policy,
        &key(41),
        &runtime_policy_sha256,
    ));
    malformed_frame
        .transit_chain
        .as_mut()
        .unwrap()
        .hops
        .last_mut()
        .unwrap()
        .to_kernel_id = "did:chio:wrong-recipient".to_string();
    batch.frames.push(malformed_frame.clone());

    let report = receiver.receive_batch(&batch, &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.batch_outcome, PheromoneBatchOutcome::Partial);
    assert_eq!(report.accepted_frame_count, 1);
    assert_eq!(report.rejected_frame_count, 1);
    assert_eq!(report.frames.len(), 2);
    assert_eq!(report.frames[0].code, "accepted");
    assert_eq!(report.frames[1].code, "batch_recipient_mismatch");
    assert_eq!(
        receiver.store().query_deposits(None, None).unwrap().len(),
        1
    );

    malformed_frame
        .transit_chain
        .as_mut()
        .unwrap()
        .hops
        .last_mut()
        .unwrap()
        .to_kernel_id = "did:chio:dataco".to_string();
    let retry_batch = PheromoneGossipBatch {
        frames: vec![malformed_frame],
        ..load_batch()
    };
    let retry_report = receiver.receive_batch(&retry_batch, &policy).unwrap();

    assert!(retry_report.accepted);
    assert_eq!(retry_report.batch_outcome, PheromoneBatchOutcome::Accepted);
    assert_eq!(
        receiver.store().query_deposits(None, None).unwrap().len(),
        2
    );
}

#[test]
fn concentration_query_rejects_bad_weights_and_unknown_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    assert!(
        receiver
            .receive_batch(&load_batch(), &policy)
            .unwrap()
            .accepted
    );

    let unknown_epoch = receiver
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            99,
            &StaticPeerWeightProvider::new(99, [("did:chio:llamaworks".to_string(), 1.0)]),
        )
        .unwrap_err();
    assert_eq!(unknown_epoch.code(), "unknown_reputation_epoch");

    let bad_weight = receiver
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            42,
            &StaticPeerWeightProvider::new(42, [("did:chio:llamaworks".to_string(), f64::NAN)]),
        )
        .unwrap_err();
    assert_eq!(bad_weight.code(), "weight_out_of_range");
}

#[test]
fn concentration_query_uses_persisted_passport_history_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pheromone.sqlite3");
    let (policy, config) = load_runtime_policy();
    let mut query_context = config.validation_context.clone();
    let expected_context = config.validation_context.clone();
    let weights = StaticPeerWeightProvider::new(42, [("did:chio:llamaworks".to_string(), 1.0)]);
    let expected_total = {
        let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
        let receiver = PheromoneReceiver::new(store, resolver(), config);
        assert!(
            receiver
                .receive_batch(&load_batch(), &policy)
                .unwrap()
                .accepted
        );
        receiver
            .store()
            .query_concentration(
                "support.prompt_injection",
                "dev.chio.support",
                expected_context.now_unix_ms,
                42,
                &expected_context,
                &weights,
            )
            .unwrap()
            .total_strength
    };

    query_context.passports.clear();
    let reopened = SqlitePheromoneRuntimeStore::open(&path).unwrap();
    let actual_total = reopened
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            query_context.now_unix_ms,
            42,
            &query_context,
            &weights,
        )
        .unwrap()
        .total_strength;

    assert!((actual_total - expected_total).abs() < f64::EPSILON);
}
