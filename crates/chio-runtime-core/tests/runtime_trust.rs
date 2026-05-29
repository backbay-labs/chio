use chio_core_types::crypto::Keypair;
use chio_core_types::SignedExportEnvelope;
use chio_runtime_core::*;

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
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

#[test]
fn trusted_verifiers_parser_accepts_chio_native_schema() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Keypair::generate();
    let document = serde_json::json!({
        "schema": "chio.runtime.trusted-verifiers.v1",
        "verifierKeys": [
            {
                "verifierId": "did:chio:buyer-verifier",
                "keyId": "verifier-key-1",
                "publicKey": verifier.public_key(),
                "validFromUnixMs": 1_800_000_000_000u64,
                "validUntilUnixMs": 1_800_003_600_000u64,
                "status": "active"
            }
        ]
    });

    let parsed = runtime_trusted_verifier_keys_from_json(&serde_json::to_string(&document)?)?;

    assert_eq!(parsed.schema, "chio.runtime.trusted-verifiers.v1");
    assert_eq!(parsed.verifier_keys.len(), 1);
    assert_eq!(parsed.verifier_keys[0].public_key, verifier.public_key());
    Ok(())
}

#[derive(Debug, Default)]
struct TrustFloorFailingAdmissionStore {
    inner: InMemoryRuntimeAdmissionStore,
}

impl TrustFloorFailingAdmissionStore {
    fn new() -> Self {
        Self::default()
    }

    fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        self.inner.insert_bundle(bundle)
    }
}

impl RuntimeAdmissionStore for TrustFloorFailingAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.inner.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<chio_runtime_core::TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.inner
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<chio_runtime_core::RuntimeTrustFloorEntry>, ChioRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(&self.inner, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: chio_runtime_core::RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(&self.inner, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        _entry: chio_runtime_core::RuntimeTrustFloorEntry,
        _previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Store(
            "injected trust-floor persistence failure".to_string(),
        ))
    }
}

fn advisory(strength: f64) -> RuntimePheromoneAdvisory {
    RuntimePheromoneAdvisory {
        source_report_sha256: "1".repeat(64),
        accepted: true,
        subject_class: "workflow.destructive_step".to_string(),
        subject_class_namespace: "chio.runtime".to_string(),
        total_strength: strength,
        distinct_origin_pairs: 1,
        reputation_epoch: 7,
        evaluated_at_unix_ms: 1_800_000_001_000,
        observe_only: true,
    }
}

fn policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
    RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
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
            subject_class_namespace: "chio.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.75,
            effect: "deny".to_string(),
        }],
    }
}

fn peer_weights() -> RuntimePeerWeights {
    RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
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
fn strict_runtime_trust_input_binds_bundle_and_signer() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;

    let verifier = Keypair::generate();
    let trust_body = RuntimeVerifierTrustBundleV4 {
        schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        version: 1,
        previous_hash_sha256: None,
        trust_bundle_sha256: bundle.trust_bundle_sha256.clone(),
        verification_context_sha256: bundle.verification_context_sha256.clone(),
        revocation_checkpoint_sha256: "d".repeat(64),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let signed_trust = SignedExportEnvelope::sign(trust_body, &verifier)?;
    let trusted_keys = vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }];
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let advisory = signed_query_report(advisory(0.10), &verifier)?;

    let accepted = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(accepted.accepted);
    assert!(accepted
        .checks
        .iter()
        .any(|check| check.code == "runtime_trust.bundle_binding"));
    Ok(())
}

#[test]
fn strict_runtime_trust_input_binds_profile_verifier() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;

    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let mut mismatched_profile = profile();
    mismatched_profile.verifier_id = "did:chio:other-verifier".to_string();

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &mismatched_profile,
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_trust_input_verifier_mismatch")
    );
    assert!(!rejected
        .checks
        .iter()
        .any(|check| check.code == "runtime_trust.signature"));
    Ok(())
}

#[test]
fn runtime_trust_floor_rejects_rollback_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store_path = dir.path().join("runtime-store.json");
    let verifier = Keypair::generate();
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let runtime_advisory = signed_query_report(advisory(0.10), &verifier)?;

    {
        let store = chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path)?;
        let mut bundle_v2 = bundle();
        bundle_v2.admission_id = "adm-live-v2".to_string();
        store.insert_bundle(bundle_v2)?;
        let v1 = trust_body(1, None);
        let previous_hash = chio_runtime_core::runtime_verifier_trust_bundle_sha256(&v1)?;
        let signed_v2 = SignedExportEnvelope::sign(trust_body(2, Some(previous_hash)), &verifier)?;
        let accepted = evaluate_runtime_admission(RuntimeAdmissionInput {
            profile: &profile(),
            store: &store,
            admission_id: "adm-live-v2",
            request: &binding(),
            action_class_id: None,
            runtime_trust_input: Some(&signed_v2),
            trusted_verifier_keys: &trusted_keys(&verifier),
            pheromone_query_report: Some(&runtime_advisory),
            runtime_pheromone_policy: Some(&signed_policy),
            runtime_peer_weights: Some(&signed_weights),
            now_unix_ms: 1_800_000_001_000,
        })?;
        assert!(accepted.accepted);
    }

    let store = chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path)?;
    let mut bundle_v1 = bundle();
    bundle_v1.admission_id = "adm-live-v1".to_string();
    bundle_v1.lease_id = Some("lease-live-v1".to_string());
    store.insert_bundle(bundle_v1)?;
    let signed_v1 = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-v1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_v1),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_trust_rollback")
    );
    Ok(())
}

#[test]
fn runtime_trust_floor_rejects_same_version_conflict_without_burning_lease(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store_path = dir.path().join("runtime-store.json");
    let store = chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path)?;
    let verifier = Keypair::generate();
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let runtime_advisory = signed_query_report(advisory(0.10), &verifier)?;
    let signed_trust_v1 = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;

    store.insert_bundle(bundle())?;
    let accepted = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust_v1),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;
    assert!(accepted.accepted);

    let mut conflict_bundle = bundle();
    conflict_bundle.admission_id = "adm-live-conflict".to_string();
    conflict_bundle.lease_id = Some("lease-live-conflict".to_string());
    store.insert_bundle(conflict_bundle)?;
    let mut conflicting_trust = trust_body(1, None);
    conflicting_trust.revocation_checkpoint_sha256 = "e".repeat(64);
    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-conflict",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&SignedExportEnvelope::sign(conflicting_trust, &verifier)?),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_trust_same_version_mismatch")
    );

    let replay_after_rejection = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-conflict",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust_v1),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_003_000,
    })?;
    assert!(
        replay_after_rejection.accepted,
        "{replay_after_rejection:#?}"
    );
    Ok(())
}

#[test]
fn runtime_trust_floor_store_error_releases_reserved_destructive_lease(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = TrustFloorFailingAdmissionStore::new();
    let verifier = Keypair::generate();
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let runtime_advisory = signed_query_report(advisory(0.10), &verifier)?;
    store.insert_bundle(bundle())?;

    let failed = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&SignedExportEnvelope::sign(trust_body(1, None), &verifier)?),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    });
    match failed {
        Ok(report) => panic!("expected injected trust-floor store failure, got {report:#?}"),
        Err(error) => assert_eq!(error.code(), "runtime_admission_store"),
    }

    store.consume_destructive_lease("lease-live-1", "lease-probe-after-failure")?;
    Ok(())
}

#[test]
fn layered_store_keeps_trust_floor_separate_from_admission_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store_path = dir.path().join("runtime-store.json");
    let trust_floor_path = dir.path().join("runtime-trust-floor.json");
    let verifier = Keypair::generate();
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let runtime_advisory = signed_query_report(advisory(0.10), &verifier)?;

    {
        let admission_store = chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path)?;
        let trust_floor_store =
            chio_runtime_core::JsonRuntimeTrustFloorStateStore::open(&trust_floor_path)?;
        let layered_store = chio_runtime_core::LayeredRuntimeAdmissionStore::new(
            &admission_store,
            &trust_floor_store,
        );
        let mut bundle_v2 = bundle();
        bundle_v2.admission_id = "adm-live-v2".to_string();
        admission_store.insert_bundle(bundle_v2)?;

        let v1 = trust_body(1, None);
        let previous_hash = chio_runtime_core::runtime_verifier_trust_bundle_sha256(&v1)?;
        let signed_v2 = SignedExportEnvelope::sign(trust_body(2, Some(previous_hash)), &verifier)?;
        let accepted = evaluate_runtime_admission(RuntimeAdmissionInput {
            profile: &profile(),
            store: &layered_store,
            admission_id: "adm-live-v2",
            request: &binding(),
            action_class_id: None,
            runtime_trust_input: Some(&signed_v2),
            trusted_verifier_keys: &trusted_keys(&verifier),
            pheromone_query_report: Some(&runtime_advisory),
            runtime_pheromone_policy: Some(&signed_policy),
            runtime_peer_weights: Some(&signed_weights),
            now_unix_ms: 1_800_000_001_000,
        })?;
        assert!(accepted.accepted);
    }

    let admission_state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&store_path)?)?;
    assert_eq!(
        admission_state["schema"],
        serde_json::json!(CHIO_RUNTIME_ADMISSION_STORE_SCHEMA)
    );
    assert_eq!(admission_state["bundles"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        admission_state["consumedLeaseIds"].as_array().map(Vec::len),
        Some(1)
    );
    assert!(admission_state.get("trustFloors").is_none());

    let trust_floor_state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_floor_path)?)?;
    assert_eq!(
        trust_floor_state["schema"],
        serde_json::json!("chio.runtime.trust-floor-state.v1")
    );
    assert_eq!(
        trust_floor_state["entries"].as_array().map(Vec::len),
        Some(1)
    );

    let admission_store = chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path)?;
    let trust_floor_store =
        chio_runtime_core::JsonRuntimeTrustFloorStateStore::open(&trust_floor_path)?;
    let layered_store =
        chio_runtime_core::LayeredRuntimeAdmissionStore::new(&admission_store, &trust_floor_store);
    let mut bundle_v1 = bundle();
    bundle_v1.admission_id = "adm-live-v1".to_string();
    bundle_v1.lease_id = Some("lease-live-v1".to_string());
    admission_store.insert_bundle(bundle_v1)?;
    let signed_v1 = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &layered_store,
        admission_id: "adm-live-v1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_v1),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_query_report: Some(&runtime_advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_trust_rollback")
    );
    Ok(())
}

#[test]
fn runtime_trust_floor_store_reads_existing_json_and_normalizes_on_write(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let trust_floor_path = dir.path().join("runtime-trust-floor.json");
    std::fs::write(
        &trust_floor_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "chio.runtime.trust-floor-state.v1",
            "entries": [{
                "verifierId": "did:chio:buyer-verifier",
                "keyId": "verifier-key-1",
                "highestVersion": 1,
                "latestBundleSha256": "b".repeat(64),
                "latestRevocationCheckpointSha256": "d".repeat(64)
            }]
        }))? + "\n",
    )?;

    let store = chio_runtime_core::JsonRuntimeTrustFloorStateStore::open(&trust_floor_path)?;
    assert!(store
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .is_some());
    store.record_runtime_trust_floor(chio_runtime_core::RuntimeTrustFloorEntry {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        highest_version: 2,
        latest_bundle_sha256: "c".repeat(64),
        latest_revocation_checkpoint_sha256: "e".repeat(64),
    })?;

    let trust_floor_state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_floor_path)?)?;
    assert_eq!(
        trust_floor_state["schema"],
        serde_json::json!("chio.runtime.trust-floor-state.v1")
    );
    assert_eq!(
        trust_floor_state["entries"][0]["highestVersion"],
        serde_json::json!(2)
    );
    Ok(())
}

#[test]
fn strict_runtime_trust_input_rejects_bundle_hash_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;

    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(
        RuntimeVerifierTrustBundleV4 {
            schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
            verifier_id: "did:chio:buyer-verifier".to_string(),
            key_id: "verifier-key-1".to_string(),
            version: 1,
            previous_hash_sha256: None,
            trust_bundle_sha256: "e".repeat(64),
            verification_context_sha256: bundle.verification_context_sha256.clone(),
            revocation_checkpoint_sha256: "d".repeat(64),
            revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
        },
        &verifier,
    )?;
    let trusted_keys = vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }];

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys,
        pheromone_query_report: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!rejected.accepted);
    assert_eq!(
        rejected.failure_code.as_deref(),
        Some("runtime_trust_bundle_hash_mismatch")
    );
    Ok(())
}
