use chio_chiodos_runtime::{
    compute_ladder_intersection, evaluate_runtime_admission, runtime_admission_bundle_sha256,
    runtime_peer_weights_sha256, runtime_workflow_run_report_json, sign_runtime_admission_report,
    tool_args_sha256, validate_runtime_workflow_run_report, verify_signed_runtime_admission_report,
    BilateralInvocation, ChiodosRuntimeAdmissionHook, ChiodosRuntimeError, CrossKernelContinuation,
    InMemoryRuntimeAdmissionStore, ReceiptLineageBundle, ReceiptLineageStatement,
    RuntimeAdmissionBundle, RuntimeAdmissionInput, RuntimeAdmissionProfile, RuntimeAdmissionStore,
    RuntimeArtifactRetentionProfile, RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry,
    RuntimeOrchestrationProfile, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromoneAdvisory,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeProofParityReport,
    RuntimeProofRegenerationInput, RuntimeProofRegenerationReport, RuntimeProofSourceRecord,
    RuntimeProviderBinding, RuntimeProviderBindingsDocument, RuntimeRequestBinding,
    RuntimeStepEvidence, RuntimeSupervisorProfile, RuntimeTrustedVerifierKey,
    RuntimeVerifierTrustBundleV4, RuntimeWorkflowRunReport, SignedRuntimePheromoneQueryReport,
    SqliteRuntimeOrchestrationStore, TreatyScope, CHIODOS_BILATERAL_INVOCATION_SCHEMA,
    CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA,
    CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA, CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
    CHIODOS_RUNTIME_FAILURE_CODES, CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA, CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA,
    CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA, CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA,
    CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA, CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA,
    CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4, CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
};
use chio_core_types::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, GovernedTransactionIntent, Operation,
    ToolGrant,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
};
use chio_core_types::SignedExportEnvelope;
use chio_federation::{
    sign_chiodos_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use std::io;

mod support;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

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

fn supervisor_profile() -> RuntimeSupervisorProfile {
    RuntimeSupervisorProfile {
        schema: CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA.to_string(),
        profile_id: "runtime-supervisor-local".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_concurrent_runs: 2,
        run_lease_ttl_ms: 60_000,
        stale_run_after_ms: 300_000,
        evidence_required_roles: vec![
            "workflow_run_report".to_string(),
            "proof_regeneration_report".to_string(),
        ],
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    }
}

fn capability(capability_id: &str) -> Result<CapabilityToken, Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "vendor-ledger".to_string(),
                    tool_name: "close_account".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_800_000_000,
            expires_at: 1_800_003_600,
            delegation_chain: Vec::new(),
        },
        &issuer,
    )?)
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

#[derive(Debug, Default)]
struct TrustFloorFailingAdmissionStore {
    inner: InMemoryRuntimeAdmissionStore,
}

impl TrustFloorFailingAdmissionStore {
    fn new() -> Self {
        Self::default()
    }

    fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChiodosRuntimeError> {
        self.inner.insert_bundle(bundle)
    }
}

impl RuntimeAdmissionStore for TrustFloorFailingAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        self.inner.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<chio_chiodos_runtime::TreatyRuntimeArtifactRecord>, ChiodosRuntimeError>
    {
        self.inner
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.inner.consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.inner.release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.inner
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.inner
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<chio_chiodos_runtime::RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        self.inner.runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: chio_chiodos_runtime::RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        self.inner.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        _entry: chio_chiodos_runtime::RuntimeTrustFloorEntry,
        _previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        Err(ChiodosRuntimeError::Store(
            "injected trust-floor persistence failure".to_string(),
        ))
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

type SignedPolicyInputs = (
    SignedExportEnvelope<RuntimeVerifierTrustBundleV4>,
    Vec<RuntimeTrustedVerifierKey>,
    SignedRuntimePheromoneQueryReport,
    SignedExportEnvelope<RuntimePheromonePolicy>,
    SignedExportEnvelope<RuntimePeerWeights>,
);

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

fn signed_policy_inputs(strength: f64) -> Result<SignedPolicyInputs, Box<dyn std::error::Error>> {
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let signed_query_report = signed_query_report(advisory(strength), &verifier)?;
    Ok((
        signed_trust,
        trusted_keys(&verifier),
        signed_query_report,
        signed_policy,
        signed_weights,
    ))
}

fn allowing_policy_hook<S>(
    store: S,
) -> Result<ChiodosRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(ChiodosRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

#[test]
fn runtime_failure_code_registry_covers_hook_surface_codes() {
    let registry: std::collections::BTreeSet<_> =
        CHIODOS_RUNTIME_FAILURE_CODES.iter().copied().collect();
    assert_eq!(registry.len(), CHIODOS_RUNTIME_FAILURE_CODES.len());

    for code in [
        "missing_governed_intent",
        "missing_chiodos_admission_context",
        "invalid_chiodos_admission_context",
        "missing_admission_id",
        "missing_chiodos_treaty_context",
        "invalid_chiodos_treaty_context",
        "request_smuggled_trust_root",
        "request_smuggled_dynamic_trust",
        "missing_treaty_scope_id",
        "missing_treaty_scope_hash",
        "missing_ladder_intersection_id",
        "missing_ladder_intersection_hash",
        "missing_action_class_id",
        "invalid_chiodos_treaty_hash",
        "invalid_chiodos_treaty_evidence_ref",
        "missing_chiodos_treaty_evidence_ref",
        "chiodos_treaty_missing_scope",
        "chiodos_treaty_scope_hash_mismatch",
        "chiodos_treaty_missing_intersection",
        "unsupported_cross_kernel_continuation_schema",
        "continuation_invalid_window",
        "unsupported_receipt_lineage_statement_schema",
        "receipt_lineage_invalid_evidence_class",
        "chiodos_ladder_invalid_consistency_model",
        "chiodos_ladder_invalid_cosign_mode",
        "unsupported_runtime_step_evidence_schema",
        "runtime_step_evidence_missing_admission_id",
        "runtime_step_evidence_missing_consistency_anchor",
        "runtime_step_evidence_missing_governance",
    ] {
        assert!(
            registry.contains(code),
            "runtime failure code registry missing {code}"
        );
    }
}

#[test]
fn matching_destructive_admission_accepts_once_then_rejects_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;

    let first = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(first.accepted);
    assert_eq!(first.failure_code, None);
    assert_eq!(
        first.receipt_metadata["chiodos_runtime"]["admission_id"],
        "adm-live-1"
    );
    assert_eq!(
        first.receipt_metadata["chiodos_runtime"]["destructive"],
        true
    );

    let replay = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!replay.accepted);
    assert_eq!(
        replay.failure_code.as_deref(),
        Some("destructive_lease_replay")
    );
    Ok(())
}

#[test]
fn strict_runtime_trust_input_binds_bundle_and_signer() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;

    let verifier = Keypair::generate();
    let trust_body = RuntimeVerifierTrustBundleV4 {
        schema: CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4.to_string(),
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
        let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path)?;
        let mut bundle_v2 = bundle();
        bundle_v2.admission_id = "adm-live-v2".to_string();
        store.insert_bundle(bundle_v2)?;
        let v1 = trust_body(1, None);
        let previous_hash = chio_chiodos_runtime::runtime_verifier_trust_bundle_sha256(&v1)?;
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

    let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path)?;
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
    let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path)?;
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
        let admission_store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path)?;
        let trust_floor_store =
            chio_chiodos_runtime::JsonRuntimeTrustFloorStateStore::open(&trust_floor_path)?;
        let layered_store = chio_chiodos_runtime::LayeredRuntimeAdmissionStore::new(
            &admission_store,
            &trust_floor_store,
        );
        let mut bundle_v2 = bundle();
        bundle_v2.admission_id = "adm-live-v2".to_string();
        admission_store.insert_bundle(bundle_v2)?;

        let v1 = trust_body(1, None);
        let previous_hash = chio_chiodos_runtime::runtime_verifier_trust_bundle_sha256(&v1)?;
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
        serde_json::json!("chio.chiodos.runtime-admission-store.v1")
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
        serde_json::json!("chio.chiodos.runtime-trust-floor-state.v1")
    );
    assert_eq!(
        trust_floor_state["entries"].as_array().map(Vec::len),
        Some(1)
    );

    let admission_store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path)?;
    let trust_floor_store =
        chio_chiodos_runtime::JsonRuntimeTrustFloorStateStore::open(&trust_floor_path)?;
    let layered_store = chio_chiodos_runtime::LayeredRuntimeAdmissionStore::new(
        &admission_store,
        &trust_floor_store,
    );
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
fn signed_runtime_admission_report_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;
    let signer = Keypair::generate();
    let mut signed = sign_runtime_admission_report(report, &signer)?;
    assert!(verify_signed_runtime_admission_report(&signed)?);
    signed.body.accepted = false;
    assert!(!verify_signed_runtime_admission_report(&signed)?);
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
            schema: CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4.to_string(),
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

#[test]
fn treaty_runtime_hook_denies_missing_lineage_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("receiptLineageBundle");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_trust_root() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["trustRoot"] = serde_json::json!({"issuer": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "request_smuggled_trust_root"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_dynamic_trust(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["dynamicTrust"] = serde_json::json!({"discovery": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "request_smuggled_dynamic_trust"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_missing_bilateral_invocation_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralInvocation");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_requires_signed_bilateral_evidence_before_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralDsse");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_unverified_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_mismatched_continuation_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let mut context = treaty_runtime_context(&fixture);
    context["crossKernelContinuation"]["sha256"] = serde_json::Value::String("f".repeat(64));
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_hash_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_continuation_from_non_origin_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.source_kernel_id = "kernel.vendor-b".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_bare_tool_continuation_audience(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.audience_tool = "close_account".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.lineage_bundle.statements[0].evidence_class = "asserted".to_string();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_lineage_bundle_unverified_edge"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_stale_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_000_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.bilateral_invocation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_preserves_millisecond_time_for_continuation_staleness(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_001_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.bilateral_invocation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_600,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_replayed_continuation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let replay = hook.evaluate(&context)?;

    assert!(!replay.allowed);
    let metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_continuation_replay"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_releases_continuation_after_runtime_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let good_args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&good_args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let hook = allowing_policy_hook(store)?;
    let treaty_context = treaty_runtime_context(&fixture);

    let denied_request = treaty_runtime_request(
        serde_json::json!({"record": "vendor-ledger-7", "value": "wrong"}),
        bundle_hash.clone(),
        treaty_context.clone(),
    )?;
    let denied = hook.evaluate(&RuntimeAdmissionContext {
        request: &denied_request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;
    assert!(!denied.allowed);
    let metadata = denied
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "request_binding_mismatch"
    );

    let allowed_request = treaty_runtime_request(good_args, bundle_hash, treaty_context)?;
    let allowed = hook.evaluate(&RuntimeAdmissionContext {
        request: &allowed_request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;
    assert!(allowed.allowed, "{allowed:#?}");
    Ok(())
}

#[test]
fn treaty_runtime_hook_releases_reserved_state_after_kernel_abort(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let metadata = first
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    hook.release_reserved(&metadata)?;
    let second = hook.evaluate(&context)?;

    assert!(second.allowed, "{second:#?}");
    Ok(())
}

#[test]
fn kernel_hook_uses_configured_runtime_policy_to_deny() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let fixture = treaty_runtime_fixture()?;
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;

    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let mut policy_body = policy(runtime_peer_weights_sha256(&weights)?);
    policy_body.rules[0].action_class_id = fixture.bilateral_invocation.action_class_id.clone();
    let signed_policy = SignedExportEnvelope::sign(policy_body, &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let high_risk_query_report = signed_query_report(advisory(0.91), &verifier)?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted_keys(&verifier))
        .with_pheromone_query_report(high_risk_query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "runtime_pheromone_policy_deny"
    );
    Ok(())
}

#[test]
fn runtime_workflow_report_requires_structured_step_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeWorkflowRunReport {
        schema: CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-2".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        admission_report_sha256: "1".repeat(64),
        evidence_paths: vec!["runtime-admission-report-1.json".to_string()],
        step_evidence: vec![RuntimeStepEvidence {
            schema: CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
            step_index: 0,
            admission_id: "adm-live-1".to_string(),
            admission_report_sha256: "1".repeat(64),
            tool_receipt_id: "receipt-live-1".to_string(),
            tool_receipt_sha256: "2".repeat(64),
            output_sha256: "3".repeat(64),
            bilateral_dsse_sha256: "4".repeat(64),
            workflow_step_sha256: "5".repeat(64),
            parent_receipt_sha256: None,
            consistency_anchor: "chiodos:consistency:wf-live-1:0".to_string(),
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
        }],
        proof_regeneration_report_sha256: Some("6".repeat(64)),
    };

    validate_runtime_workflow_run_report(&report)?;
    let json = runtime_workflow_run_report_json(&report)?;
    assert!(json.contains("stepEvidence"));
    assert!(json.contains("proofRegenerationReportSha256"));
    Ok(())
}

#[test]
fn runtime_workflow_report_rejects_placeholder_success_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeWorkflowRunReport {
        schema: CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: "runtime-loopback-legacy".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        admission_report_sha256: "1".repeat(64),
        evidence_paths: vec!["regenerated-proof-package.json".to_string()],
        step_evidence: Vec::new(),
        proof_regeneration_report_sha256: None,
    };

    let error = match validate_runtime_workflow_run_report(&report) {
        Ok(()) => {
            return Err(io::Error::other(
                "placeholder runtime workflow report unexpectedly accepted",
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("runtime_workflow_missing_step_evidence"));
    Ok(())
}

#[test]
fn proof_regeneration_report_records_bound_runtime_artifacts(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeProofRegenerationReport {
        schema: CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-2".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        proof_package_sha256: Some("a".repeat(64)),
        verifier_report_sha256: Some("b".repeat(64)),
        workflow_receipt_sha256: Some("c".repeat(64)),
        source_records: vec![RuntimeProofSourceRecord {
            step_index: 0,
            admission_report_sha256: "1".repeat(64),
            tool_receipt_sha256: "2".repeat(64),
            bilateral_dsse_sha256: "3".repeat(64),
            workflow_step_sha256: "4".repeat(64),
        }],
        checks: vec!["runtime_source_records.bound".to_string()],
    };

    let json = serde_json::to_string(&report)?;
    assert!(json.contains(CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA));
    assert!(json.contains("sourceRecords"));
    chio_chiodos_runtime::validate_runtime_proof_regeneration_report(&report)?;
    Ok(())
}

#[test]
fn runtime_proof_regeneration_contracts_bind_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let source_record = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "1".repeat(64),
        tool_receipt_sha256: "2".repeat(64),
        bilateral_dsse_sha256: "3".repeat(64),
        workflow_step_sha256: "4".repeat(64),
    };
    let manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-3".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        workflow_run_report_sha256: "5".repeat(64),
        proof_regeneration_report_sha256: "6".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "proof_package".to_string(),
            path: "buyer-auditor-proof-package.json".to_string(),
            sha256: "7".repeat(64),
            byte_count: 4096,
        }],
    };
    let input = RuntimeProofRegenerationInput {
        schema: CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-3".to_string(),
        evidence_manifest_sha256: "8".repeat(64),
        workflow_run_report_sha256: "5".repeat(64),
        admission_report_sha256: "9".repeat(64),
        trust_bundle_sha256: "a".repeat(64),
        verification_context_sha256: "b".repeat(64),
        source_records: vec![source_record.clone()],
    };
    let parity = RuntimeProofParityReport {
        schema: CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-3".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        static_proof_package_sha256: "c".repeat(64),
        runtime_proof_package_sha256: "c".repeat(64),
        static_verifier_report_sha256: "d".repeat(64),
        runtime_verifier_report_sha256: "d".repeat(64),
        compared_fields: vec![
            "workflow_id".to_string(),
            "workflow_steps".to_string(),
            "workflow_intersection".to_string(),
        ],
        mismatches: Vec::new(),
    };

    let manifest_json = chio_chiodos_runtime::runtime_evidence_manifest_json(&manifest)?;
    let input_json = chio_chiodos_runtime::runtime_proof_regeneration_input_json(&input)?;
    let parity_json = chio_chiodos_runtime::runtime_proof_parity_report_json(&parity)?;
    assert!(manifest_json.contains("runtime-evidence-manifest"));
    assert!(input_json.contains("runtime-proof-regeneration-input"));
    assert!(parity_json.contains("runtime-proof-parity-report"));
    Ok(())
}

#[test]
fn runtime_orchestration_contracts_validate_status_and_run_report(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = chio_chiodos_runtime::RuntimeOrchestrationProfile {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-runtime-orchestration".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        mode: "local".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_concurrent_runs: 1,
        fail_closed_on: vec![
            "evidence_sink_unavailable".to_string(),
            "proof_regeneration_rejected".to_string(),
        ],
    };
    let profile_hash = chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile)?;
    let run_contract = chio_chiodos_runtime::RuntimeRunContract {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA.to_string(),
        run_id: "runtime-orchestration-1".to_string(),
        profile_sha256: profile_hash.clone(),
        workflow_id: "wf-chiodos-refund-001".to_string(),
        expected_step_count: 3,
        admission_ids: vec![
            "adm-loopback-1".to_string(),
            "adm-loopback-2".to_string(),
            "adm-loopback-3".to_string(),
        ],
        store_id: "runtime-store-local".to_string(),
        evidence_sink_id: "runtime-evidence-local".to_string(),
        proof_regeneration_required: true,
    };
    let run_contract_hash = chio_chiodos_runtime::runtime_run_contract_sha256(&run_contract)?;
    let run_report = chio_chiodos_runtime::RuntimeOrchestrationRunReport {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
        run_id: run_contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        status: "proof_accepted".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        profile_sha256: profile_hash.clone(),
        run_contract_sha256: run_contract_hash.clone(),
        workflow_run_report_sha256: Some("1".repeat(64)),
        evidence_manifest_sha256: Some("2".repeat(64)),
        proof_regeneration_report_sha256: Some("3".repeat(64)),
        verifier_report_sha256: Some("4".repeat(64)),
        step_states: vec![chio_chiodos_runtime::RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "adm-loopback-1".to_string(),
            state: "proof_accepted".to_string(),
            destructive: false,
            admission_report_sha256: Some("5".repeat(64)),
            tool_receipt_sha256: Some("6".repeat(64)),
            lease_id: None,
        }],
        checks: vec!["runtime_orchestration.proof_regeneration_verified".to_string()],
    };
    let status = chio_chiodos_runtime::RuntimeOrchestrationStatusReport {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA.to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        profile_sha256: profile_hash,
        store_backend: "sqlite".to_string(),
        store_path_sha256: "7".repeat(64),
        run_counts: std::collections::BTreeMap::from([("proof_accepted".to_string(), 1)]),
        consumed_lease_count: 1,
        trust_floor_count: 1,
        latest_failure_code: None,
        evidence_sink_healthy: true,
        ready: true,
        degraded: false,
    };

    chio_chiodos_runtime::validate_runtime_orchestration_profile(&profile)?;
    chio_chiodos_runtime::validate_runtime_run_contract(&run_contract)?;
    let stale_plan = chio_chiodos_runtime::build_runtime_orchestration_plan(
        &profile,
        &run_contract,
        profile.expires_at_unix_ms,
    )?;
    assert!(!stale_plan.accepted);
    assert_eq!(
        stale_plan.failure_code.as_deref(),
        Some("runtime_orchestration_profile_stale")
    );
    chio_chiodos_runtime::validate_runtime_orchestration_run_report(&run_report)?;
    chio_chiodos_runtime::validate_runtime_orchestration_status_report(&status)?;
    assert!(
        chio_chiodos_runtime::runtime_orchestration_run_report_json(&run_report)?
            .contains("proof_accepted")
    );
    Ok(())
}

#[test]
fn runtime_orchestration_status_rejects_stale_profile() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("runtime-status.sqlite3"))?;
    let profile = RuntimeOrchestrationProfile {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-runtime-orchestration".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_001_000,
        mode: "enforce".to_string(),
        max_concurrent_runs: 2,
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    };
    let profile_sha256 = chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile)?;

    let status = store.status_report(&profile, profile_sha256, 1_800_000_001_000, true)?;

    assert!(!status.accepted);
    assert!(!status.ready);
    assert_eq!(
        status.failure_code.as_deref(),
        Some("runtime_orchestration_profile_stale")
    );
    Ok(())
}

#[test]
fn runtime_proof_drift_report_rejects_manifest_hash_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "proof_package".to_string(),
            path: "buyer-auditor-proof-package.json".to_string(),
            sha256: "3".repeat(64),
            byte_count: 4096,
        }],
    };
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    candidate_manifest.entries[0].sha256 = "4".repeat(64);
    let source = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "5".repeat(64),
        tool_receipt_sha256: "6".repeat(64),
        bilateral_dsse_sha256: "7".repeat(64),
        workflow_step_sha256: "8".repeat(64),
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        proof_package_sha256: Some("9".repeat(64)),
        verifier_report_sha256: Some("a".repeat(64)),
        workflow_receipt_sha256: Some("b".repeat(64)),
        source_records: vec![source],
        checks: vec!["runtime_semantic_proof_regeneration.verified".to_string()],
    };
    let mut candidate_proof = proof.clone();
    candidate_proof.run_id = "runtime-candidate".to_string();

    let report = chio_chiodos_runtime::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_002_000,
    )?;
    assert_eq!(report.schema, CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA);
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_proof_drift_detected")
    );
    assert_eq!(report.artifact_drifts.len(), 1);
    Ok(())
}

#[test]
fn runtime_proof_drift_report_normalizes_timestamped_report_artifacts(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![
            RuntimeEvidenceManifestEntry {
                role: "proof_package".to_string(),
                path: "buyer-auditor-proof-package.json".to_string(),
                sha256: "3".repeat(64),
                byte_count: 4096,
            },
            RuntimeEvidenceManifestEntry {
                role: "runtime_run_report".to_string(),
                path: "runtime-run-report.json".to_string(),
                sha256: "4".repeat(64),
                byte_count: 2048,
            },
            RuntimeEvidenceManifestEntry {
                role: "workflow_run_report".to_string(),
                path: "workflow-run-report.json".to_string(),
                sha256: "5".repeat(64),
                byte_count: 2048,
            },
            RuntimeEvidenceManifestEntry {
                role: "proof_regeneration_report".to_string(),
                path: "proof-regeneration-report.json".to_string(),
                sha256: "6".repeat(64),
                byte_count: 2048,
            },
        ],
    };
    baseline_manifest.workflow_run_report_sha256 = baseline_manifest.entries[1].sha256.clone();
    baseline_manifest.proof_regeneration_report_sha256 =
        baseline_manifest.entries[3].sha256.clone();
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    candidate_manifest.generated_at_unix_ms = 1_800_000_002_000;
    candidate_manifest.entries[1].sha256 = "7".repeat(64);
    candidate_manifest.entries[2].sha256 = "8".repeat(64);
    candidate_manifest.entries[3].sha256 = "9".repeat(64);
    candidate_manifest.workflow_run_report_sha256 = candidate_manifest.entries[1].sha256.clone();
    candidate_manifest.proof_regeneration_report_sha256 =
        candidate_manifest.entries[3].sha256.clone();
    let source = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "a".repeat(64),
        tool_receipt_sha256: "b".repeat(64),
        bilateral_dsse_sha256: "c".repeat(64),
        workflow_step_sha256: "d".repeat(64),
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        proof_package_sha256: Some("e".repeat(64)),
        verifier_report_sha256: Some("f".repeat(64)),
        workflow_receipt_sha256: Some("0".repeat(64)),
        source_records: vec![source],
        checks: vec!["runtime_semantic_proof_regeneration.verified".to_string()],
    };
    let mut candidate_proof = proof.clone();
    candidate_proof.run_id = "runtime-candidate".to_string();
    candidate_proof.generated_at_unix_ms = 1_800_000_002_000;

    let report = chio_chiodos_runtime::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_003_000,
    )?;

    assert!(report.accepted, "{report:#?}");
    assert!(report.artifact_drifts.is_empty(), "{report:#?}");
    assert_eq!(
        report.normalized_fields,
        vec![
            "generatedAtUnixMs".to_string(),
            "timestampedReportArtifacts".to_string()
        ]
    );
    Ok(())
}

#[test]
fn runtime_proof_drift_report_rejects_manifest_proof_run_id_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "proof_package".to_string(),
            path: "buyer-auditor-proof-package.json".to_string(),
            sha256: "3".repeat(64),
            byte_count: 4096,
        }],
    };
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    let source = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "5".repeat(64),
        tool_receipt_sha256: "6".repeat(64),
        bilateral_dsse_sha256: "7".repeat(64),
        workflow_step_sha256: "8".repeat(64),
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: "runtime-other".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        proof_package_sha256: Some("9".repeat(64)),
        verifier_report_sha256: Some("a".repeat(64)),
        workflow_receipt_sha256: Some("b".repeat(64)),
        source_records: vec![source],
        checks: vec!["runtime_semantic_proof_regeneration.verified".to_string()],
    };
    let mut candidate_proof = proof.clone();
    candidate_proof.run_id = candidate_manifest.run_id.clone();

    let report = chio_chiodos_runtime::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_002_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_proof_drift_detected")
    );
    assert!(report
        .semantic_drifts
        .iter()
        .any(|drift| drift.field == "baseline_manifest_proof_run_id"));
    Ok(())
}

#[test]
fn runtime_ops_run_lease_blocks_competing_owner_and_allows_stale_takeover(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-1", "pending", None, 1_800_000_000_000)?;

    let first = store.acquire_run_lease("runtime-run-1", "owner-a", 1_800_000_000_000, 60_000)?;
    assert_eq!(first.fencing_token, 1);

    let conflict = store.acquire_run_lease("runtime-run-1", "owner-b", 1_800_000_010_000, 60_000);
    match conflict {
        Ok(_) => panic!("expected competing run lease to be rejected"),
        Err(error) => assert_eq!(error.code(), "runtime_run_lease_conflict"),
    }

    let same_owner = store.acquire_run_lease("runtime-run-1", "owner-a", 1_800_000_020_000, 60_000);
    match same_owner {
        Ok(_) => panic!("expected same-owner active lease takeover to be rejected"),
        Err(error) => assert_eq!(error.code(), "runtime_run_lease_conflict"),
    }

    let takeover =
        store.acquire_run_lease("runtime-run-1", "owner-b", 1_800_000_061_000, 60_000)?;
    assert_eq!(takeover.owner_id, "owner-b");
    assert_eq!(takeover.fencing_token, 2);

    let stale = store.heartbeat_run_lease(
        "runtime-run-1",
        "owner-a",
        first.fencing_token,
        1_800_000_062_000,
        60_000,
    );
    match stale {
        Ok(_) => panic!("expected stale fencing token rejection"),
        Err(error) => assert_eq!(error.code(), "runtime_run_stale_fencing_token"),
    }

    store.record_run_state(
        "runtime-run-expired-heartbeat",
        "pending",
        None,
        1_800_000_000_000,
    )?;
    let expiring = store.acquire_run_lease(
        "runtime-run-expired-heartbeat",
        "owner-a",
        1_800_000_000_000,
        1_000,
    )?;
    let expired_heartbeat = store.heartbeat_run_lease(
        "runtime-run-expired-heartbeat",
        "owner-a",
        expiring.fencing_token,
        1_800_000_002_000,
        60_000,
    );
    match expired_heartbeat {
        Ok(_) => panic!("expected expired heartbeat to be rejected"),
        Err(error) => assert_eq!(error.code(), "runtime_run_lease_expired"),
    }
    let recovered = store.acquire_run_lease(
        "runtime-run-expired-heartbeat",
        "owner-b",
        1_800_000_002_001,
        60_000,
    )?;
    assert_eq!(recovered.owner_id, "owner-b");
    assert_eq!(recovered.fencing_token, 2);
    Ok(())
}

#[test]
fn runtime_ops_scheduler_tick_claims_pending_runs_and_expires_stale_leases(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-tick.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-a", "pending", None, 1_800_000_000_000)?;
    store.record_run_state("runtime-run-b", "pending", None, 1_800_000_000_000)?;
    store.record_run_state("runtime-run-c", "pending", None, 1_800_000_000_000)?;
    store.acquire_run_lease("runtime-run-expired", "owner-old", 1_800_000_000_000, 1_000)?;

    let report =
        store.scheduler_tick_report(&supervisor_profile(), "operator-a", 1_800_000_002_000, 2)?;

    assert!(report.accepted, "{report:#?}");
    assert_eq!(report.claimed_run_ids.len(), 2);
    assert!(report
        .claimed_run_ids
        .contains(&"runtime-run-a".to_string()));
    assert!(report
        .claimed_run_ids
        .contains(&"runtime-run-b".to_string()));
    assert_eq!(report.skipped_run_count, 1);
    assert_eq!(report.expired_run_ids, vec!["runtime-run-expired"]);
    Ok(())
}

#[test]
fn runtime_ops_scheduler_tick_limits_claims_by_active_leases(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-active-capacity.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-a", "pending", None, 1_800_000_000_000)?;
    store.record_run_state("runtime-run-b", "pending", None, 1_800_000_000_000)?;
    store.acquire_run_lease(
        "runtime-run-active",
        "operator-old",
        1_800_000_001_000,
        60_000,
    )?;

    let report =
        store.scheduler_tick_report(&supervisor_profile(), "operator-a", 1_800_000_002_000, 2)?;

    assert!(report.accepted, "{report:#?}");
    assert_eq!(report.claimed_run_ids.len(), 1, "{report:#?}");
    assert_eq!(report.skipped_run_count, 1, "{report:#?}");
    assert!(report.expired_run_ids.is_empty(), "{report:#?}");
    Ok(())
}

#[test]
fn runtime_ops_scheduler_tick_excludes_active_leased_runs_before_claim_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-active-filter.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-active", "pending", None, 1_800_000_000_000)?;
    store.record_run_state("runtime-run-a", "pending", None, 1_800_000_000_001)?;
    store.record_run_state("runtime-run-b", "pending", None, 1_800_000_000_002)?;
    store.acquire_run_lease(
        "runtime-run-active",
        "operator-old",
        1_800_000_001_000,
        60_000,
    )?;

    let report =
        store.scheduler_tick_report(&supervisor_profile(), "operator-a", 1_800_000_002_000, 2)?;

    assert!(report.accepted, "{report:#?}");
    assert_eq!(report.claimed_run_ids, vec!["runtime-run-a"], "{report:#?}");
    assert_eq!(report.skipped_run_count, 1, "{report:#?}");
    assert!(report.expired_run_ids.is_empty(), "{report:#?}");
    Ok(())
}

#[test]
fn runtime_ops_scheduler_tick_rejects_profile_at_exact_expiry(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-expiry.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-a", "pending", None, 1_800_000_000_000)?;

    let profile = supervisor_profile();
    let report = store.scheduler_tick_report(
        &profile,
        "operator-a",
        profile.expires_at_unix_ms,
        profile.max_concurrent_runs,
    )?;

    assert!(!report.accepted, "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_scheduler_profile_stale")
    );
    assert!(report.claimed_run_ids.is_empty(), "{report:#?}");
    Ok(())
}

#[test]
fn runtime_ops_status_rejects_stale_supervisor_profile() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-status-stale-profile.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let profile = supervisor_profile();

    let report = store.ops_status_report(&profile, profile.expires_at_unix_ms, true, true)?;

    assert!(!report.accepted, "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_ops_supervisor_profile_stale")
    );
    assert!(report.degraded, "{report:#?}");
    assert!(!report.ready, "{report:#?}");
    Ok(())
}

#[test]
fn runtime_ops_recovery_drill_rejects_stale_supervisor_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir
        .path()
        .join("runtime-ops-recovery-stale-profile.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let profile = supervisor_profile();

    let report = store.recovery_drill_report_for_profile(
        &profile,
        "runtime-run-a",
        profile.expires_at_unix_ms,
    )?;

    assert!(!report.accepted, "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_recovery_supervisor_profile_stale")
    );
    assert!(report.blocked, "{report:#?}");
    assert!(!report.resumable, "{report:#?}");
    Ok(())
}

#[test]
fn runtime_ops_evidence_health_detects_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("workflow-run-report.json"),
        b"{\"ok\":true}",
    )?;
    let manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-run-health".to_string(),
        generated_at_unix_ms: 1_800_000_000_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "workflow_run_report".to_string(),
            path: "workflow-run-report.json".to_string(),
            sha256: "3".repeat(64),
            byte_count: 11,
        }],
    };

    let report = chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
        "runtime-run-health",
        dir.path(),
        &manifest,
        &["workflow_run_report".to_string()],
        1_800_000_000_000,
        false,
    )?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_evidence_artifact_hash_mismatch")
    );
    assert_eq!(
        report.artifact_hash_mismatches,
        vec!["workflow-run-report.json"]
    );
    Ok(())
}

#[test]
fn runtime_ops_evidence_health_rejects_manifest_run_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("workflow-run-report.json"),
        b"{\"ok\":true}",
    )?;
    let manifest = RuntimeEvidenceManifest {
        schema: CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-run-other".to_string(),
        generated_at_unix_ms: 1_800_000_000_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "workflow_run_report".to_string(),
            path: "workflow-run-report.json".to_string(),
            sha256: chio_core_types::crypto::sha256_hex(b"{\"ok\":true}"),
            byte_count: 11,
        }],
    };

    let report = chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
        "runtime-run-health",
        dir.path(),
        &manifest,
        &[],
        1_800_000_000_000,
        false,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_evidence_manifest_run_mismatch")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_discovery_attempts() -> Result<(), Box<dyn std::error::Error>>
{
    let bindings = RuntimeProviderBindingsDocument {
        schema: CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: true,
        }],
    };
    let report = chio_chiodos_runtime::generate_runtime_provider_health_report(
        &supervisor_profile(),
        &bindings,
        1_800_000_000_000,
    )?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_discovery_not_allowed")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_stale_supervisor_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let bindings = RuntimeProviderBindingsDocument {
        schema: CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: false,
        }],
    };
    let mut profile = supervisor_profile();
    profile.expires_at_unix_ms = 1_800_000_001_000;

    let report = chio_chiodos_runtime::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        1_800_000_001_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_supervisor_profile_stale")
    );
    Ok(())
}

#[test]
fn runtime_ops_retention_plan_rejects_stale_profile() -> Result<(), Box<dyn std::error::Error>> {
    let profile = RuntimeArtifactRetentionProfile {
        schema: CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA.to_string(),
        profile_id: "retention-runtime-local".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_001_000,
        min_retain_ms: 86_400_000,
        destructive_hold_ms: 604_800_000,
        legal_hold: false,
        dry_run_only: true,
    };

    let report = chio_chiodos_runtime::generate_runtime_artifact_retention_plan(
        &profile,
        &["runtime-run-1".to_string()],
        1_800_000_001_000,
    )?;

    assert_eq!(
        report.schema,
        CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA
    );
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_retention_profile_stale")
    );
    assert!(report.candidate_actions.is_empty());
    Ok(())
}

#[derive(Clone)]
struct TreatyRuntimeFixture {
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    ladder_intersection: chio_chiodos_runtime::LadderIntersection,
    ladder_intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage_bundle: ReceiptLineageBundle,
    lineage_bundle_sha256: String,
    bilateral_invocation: BilateralInvocation,
    bilateral_invocation_sha256: String,
    bilateral_dsse_id: String,
    bilateral_dsse: chio_federation::DsseEnvelope,
    bilateral_dsse_sha256: String,
}

fn treaty_runtime_fixture() -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_invocation", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_invocation", "receipt_lineage"],
        ),
    );
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
    let mut treaty_scope = treaty_scope();
    treaty_scope.participant_public_keys = vec![signer_a.public_key(), signer_b.public_key()];
    treaty_scope.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let treaty_scope_sha256 = chio_chiodos_runtime::treaty_scope_sha256(&treaty_scope)?;
    let ladder_intersection =
        compute_ladder_intersection(&treaty_scope, &[buyer, vendor], 1_800_000_001_000)?;
    let ladder_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&ladder_intersection)?;
    let continuation = CrossKernelContinuation {
        schema: CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-runtime-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-runtime-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    let mut bilateral_invocation = BilateralInvocation {
        schema: CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-runtime-1".to_string(),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: tool_args_sha256(&serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        }))?,
        outcome_sha256: "5".repeat(64),
        local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        remote_receipt_sha256: String::new(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: bilateral_invocation.invocation_id.clone(),
            timestamp: 1_800_000_001,
            capability_id: bilateral_invocation.capability_id.clone(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "record": "vendor-ledger-7",
                "value": "closed"
            }))?,
            decision: Decision::Allow,
            content_hash: bilateral_invocation.outcome_sha256.clone(),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: signer_b.public_key(),
        },
        &signer_b,
    )?;
    bilateral_invocation.remote_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&receipt)?,
    );
    let bilateral_invocation_binding_sha256 =
        chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    let lineage = ReceiptLineageStatement {
        schema: CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-runtime-1".to_string(),
        parent_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256,
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-runtime-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    };
    let lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage_bundle)?,
    );
    let bilateral_invocation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_invocation)?,
    );
    let bilateral_dsse = sign_chiodos_dsse_envelope(
        &receipt,
        &signer_a,
        &signer_b,
        &bilateral_invocation.signer_kernel_ids[0],
        &bilateral_invocation.signer_kernel_ids[1],
        "close_account",
        1_800_000_001_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-live-1".to_string(),
                issuer: bilateral_invocation.signer_kernel_ids[0].clone(),
                expires_at_unix_ms: 1_800_003_600_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-buyer".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-vendor".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-live-1".to_string(),
                kernel_id: bilateral_invocation.signer_kernel_ids[1].clone(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some(bilateral_invocation.consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: bilateral_invocation.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256.clone(),
                ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                admission_report_sha256: "6".repeat(64),
                continuation_sha256: continuation_sha256.clone(),
                lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                action_class_id: bilateral_invocation.action_class_id.clone(),
                consistency_model: bilateral_invocation.consistency_model.clone(),
                request_sha256: bilateral_invocation.request_sha256.clone(),
                outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                lease_refs: vec!["lease-live-1".to_string()],
                governance_refs: vec!["gov-live-1".to_string()],
                signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
            }),
        },
    )?;
    let bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_dsse)?,
    );
    Ok(TreatyRuntimeFixture {
        treaty_scope,
        treaty_scope_sha256,
        ladder_intersection,
        ladder_intersection_sha256,
        continuation,
        continuation_sha256,
        lineage_bundle,
        lineage_bundle_sha256,
        bilateral_invocation,
        bilateral_invocation_sha256,
        bilateral_dsse_id: "bilateral-dsse-runtime-1".to_string(),
        bilateral_dsse,
        bilateral_dsse_sha256,
    })
}

fn insert_treaty_runtime_fixture(
    store: &SqliteRuntimeOrchestrationStore,
    fixture: &TreatyRuntimeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    Ok(())
}

fn treaty_runtime_context(fixture: &TreatyRuntimeFixture) -> serde_json::Value {
    serde_json::json!({
        "treatyScopeId": fixture.treaty_scope.treaty_id,
        "treatyScopeSha256": fixture.treaty_scope_sha256,
        "ladderIntersectionId": fixture.ladder_intersection.intersection_id,
        "ladderIntersectionSha256": fixture.ladder_intersection_sha256,
        "actionClassId": "workflow.destructive.vendor_call",
        "crossKernelContinuation": {
            "id": fixture.continuation.continuation_id,
            "sha256": fixture.continuation_sha256
        },
        "receiptLineageBundle": {
            "id": fixture.lineage_bundle.bundle_id,
            "sha256": fixture.lineage_bundle_sha256
        },
        "bilateralInvocation": {
            "id": fixture.bilateral_invocation.invocation_id,
            "sha256": fixture.bilateral_invocation_sha256
        },
        "bilateralDsse": {
            "id": fixture.bilateral_dsse_id,
            "sha256": fixture.bilateral_dsse_sha256
        }
    })
}

fn treaty_runtime_request(
    args: serde_json::Value,
    bundle_hash: String,
    treaty_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let cap = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
    };
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        purpose: "close governed vendor account".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chiodosAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            },
            "chiodosTreaty": treaty_context
        })),
    });
    Ok(request)
}
