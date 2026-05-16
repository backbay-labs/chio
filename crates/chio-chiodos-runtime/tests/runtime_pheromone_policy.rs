use chio_chiodos_runtime::{
    evaluate_runtime_admission, runtime_peer_weights_sha256, InMemoryRuntimeAdmissionStore,
    RuntimeAdmissionBundle, RuntimeAdmissionInput, RuntimeAdmissionProfile, RuntimePeerWeight,
    RuntimePeerWeights, RuntimePheromoneAdvisory, RuntimePheromonePolicy,
    RuntimePheromonePolicyRule, RuntimeRequestBinding, RuntimeTrustedVerifierKey,
    RuntimeVerifierTrustBundleV4, SignedRuntimePheromoneQueryReport,
    CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::SignedExportEnvelope;
use std::io;

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-live-spine".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn binding() -> RuntimeRequestBinding {
    RuntimeRequestBinding {
        request_id: "req-live-destructive".to_string(),
        capability_id: "cap-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: Some("kernel.buyer".to_string()),
        host_kernel_id: "kernel.vendor-b".to_string(),
    }
}

fn bundle() -> RuntimeAdmissionBundle {
    RuntimeAdmissionBundle {
        schema: CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "adm-live-1".to_string(),
        binding: binding(),
        workflow_id: "wf-live-1".to_string(),
        workflow_grant_id: "grant-live-1".to_string(),
        step_index: 1,
        destructive: true,
        lease_id: Some("lease-live-1".to_string()),
        governance_receipt_id: Some("gov-live-1".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    }
}

fn trusted_keys(verifier: &Keypair) -> Vec<RuntimeTrustedVerifierKey> {
    vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }]
}

fn trust_body(version: u64, previous_hash_sha256: Option<String>) -> RuntimeVerifierTrustBundleV4 {
    RuntimeVerifierTrustBundleV4 {
        schema: CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        version,
        previous_hash_sha256,
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
        revocation_checkpoint_sha256: "d".repeat(64),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn advisory(strength: f64) -> RuntimePheromoneAdvisory {
    RuntimePheromoneAdvisory {
        source_report_sha256: "1".repeat(64),
        accepted: true,
        subject_class: "workflow.destructive_step".to_string(),
        subject_class_namespace: "chiodos.runtime".to_string(),
        total_strength: strength,
        distinct_origin_pairs: 1,
        reputation_epoch: 7,
        evaluated_at_unix_ms: 1_800_000_001_000,
        observe_only: true,
    }
}

fn policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
    RuntimePheromonePolicy {
        schema: CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: "policy-runtime-risk".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        allowed_reputation_epochs: vec![7],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: "b".repeat(64),
        peer_weights_sha256,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-runtime-risk".to_string(),
            subject_class: "workflow.destructive_step".to_string(),
            subject_class_namespace: "chiodos.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.75,
            effect: "deny".to_string(),
        }],
    }
}

fn peer_weights() -> RuntimePeerWeights {
    RuntimePeerWeights {
        schema: CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        reputation_epoch: 7,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: "kernel.vendor-b".to_string(),
            weight: 1.0,
        }],
    }
}

fn query_report_body(advisory: RuntimePheromoneAdvisory) -> serde_json::Value {
    serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": advisory.accepted,
        "concentration": {
            "subjectClass": advisory.subject_class,
            "subjectClassNamespace": advisory.subject_class_namespace,
            "totalStrength": advisory.total_strength,
            "distinctOriginPairs": advisory.distinct_origin_pairs,
            "reputationEpoch": advisory.reputation_epoch,
            "evaluatedAtUnixMs": advisory.evaluated_at_unix_ms
        }
    })
}

fn signed_query_report(
    advisory: RuntimePheromoneAdvisory,
    verifier: &Keypair,
) -> Result<SignedRuntimePheromoneQueryReport, Box<dyn std::error::Error>> {
    Ok(SignedExportEnvelope::sign(
        query_report_body(advisory),
        verifier,
    )?)
}

#[test]
fn destructive_admission_requires_signed_pheromone_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_query_report: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_pheromone_required_for_destructive")
    );
    Ok(())
}

#[test]
fn signed_runtime_pheromone_policy_can_deny_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut bundle = bundle();
    bundle.destructive = false;
    bundle.lease_id = None;
    bundle.governance_receipt_id = None;
    store.insert_bundle(bundle)?;
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;

    let high_risk_query_report = signed_query_report(advisory(0.91), &verifier)?;
    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&high_risk_query_report),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_pheromone_policy_deny")
    );
    let decision = rejected
        .pheromone_policy_decision
        .ok_or_else(|| io::Error::other("policy decision missing"))?;
    assert_eq!(decision.decision, "deny");
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-high-runtime-risk")
    );
    Ok(())
}

#[test]
fn runtime_pheromone_policy_rejects_query_report_signed_by_other_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    store.insert_bundle(admission_bundle)?;
    let verifier = Keypair::generate();
    let attacker = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let attacker_query_report = signed_query_report(advisory(0.10), &attacker)?;

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&attacker_query_report),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_pheromone_policy_query_report_signer_mismatch")
    );
    Ok(())
}

#[test]
fn runtime_pheromone_policy_enforces_distinct_origin_floor(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    store.insert_bundle(admission_bundle)?;
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let mut low_origin_advisory = advisory(0.10);
    low_origin_advisory.distinct_origin_pairs = 0;
    let low_origin_query_report = signed_query_report(low_origin_advisory, &verifier)?;

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&low_origin_query_report),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_pheromone_distinct_origin_floor")
    );
    Ok(())
}

#[test]
fn runtime_pheromone_policy_rejects_future_dated_advisory() -> Result<(), Box<dyn std::error::Error>>
{
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    store.insert_bundle(admission_bundle)?;
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let mut future_advisory = advisory(0.10);
    future_advisory.evaluated_at_unix_ms = 1_800_000_002_000;
    let future_query_report = signed_query_report(future_advisory, &verifier)?;

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&future_query_report),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_pheromone_advisory_future_dated")
    );
    Ok(())
}

#[test]
fn runtime_pheromone_query_report_parser_reads_snake_case_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let advisory = chio_chiodos_runtime::runtime_pheromone_advisory_from_query_report_json(
        &serde_json::json!({
            "schema": "chio.pheromone.query-report.v1",
            "accepted": true,
            "concentration": {
                "subject_class": "workflow.destructive_step",
                "subject_class_namespace": "chiodos.runtime",
                "total_strength": 0.42,
                "distinct_origin_pairs": 3,
                "reputation_epoch": 7,
                "evaluated_at_unix_ms": 1_800_000_001_000_i64
            }
        })
        .to_string(),
    )?;

    assert_eq!(advisory.subject_class, "workflow.destructive_step");
    assert_eq!(advisory.distinct_origin_pairs, 3);
    assert_eq!(advisory.reputation_epoch, 7);
    Ok(())
}
