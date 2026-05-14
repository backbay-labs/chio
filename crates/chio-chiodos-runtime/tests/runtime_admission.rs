use chio_chiodos_runtime::{
    compute_ladder_intersection, evaluate_cross_boundary_admission, evaluate_runtime_admission,
    runtime_admission_bundle_sha256, runtime_peer_weights_sha256, runtime_workflow_run_report_json,
    sign_runtime_admission_report, tool_args_sha256, validate_governance_ladder_manifest,
    validate_runtime_workflow_run_report, verify_buyer_attestation_packet,
    verify_buyer_attestation_review_package, verify_receipt_lineage_bundle,
    verify_signed_runtime_admission_report, BilateralInvocation, BuyerAttestationPacket,
    BuyerAttestationReviewArtifactRef, BuyerAttestationReviewPackage, ChiodosRuntimeAdmissionHook,
    CrossBoundaryAdmissionInput, CrossBoundaryAdmissionReport, CrossBoundaryEvidenceRef,
    CrossKernelContinuation, GovernanceLadderActionClass, GovernanceLadderManifest,
    InMemoryRuntimeAdmissionStore, ReceiptLineageBundle, ReceiptLineageStatement,
    RuntimeAdmissionBundle, RuntimeAdmissionInput, RuntimeAdmissionProfile, RuntimeAdmissionStore,
    RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry, RuntimePeerWeight, RuntimePeerWeights,
    RuntimePheromoneAdvisory, RuntimePheromonePolicy, RuntimePheromonePolicyRule,
    RuntimeProofParityReport, RuntimeProofRegenerationInput, RuntimeProofRegenerationReport,
    RuntimeProofSourceRecord, RuntimeProviderBinding, RuntimeProviderBindingsDocument,
    RuntimeRequestBinding, RuntimeStepEvidence, RuntimeSupervisorProfile,
    RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundleV4, RuntimeWorkflowRunReport,
    SqliteRuntimeOrchestrationStore, TreatyScope, CHIODOS_BILATERAL_INVOCATION_SCHEMA,
    CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA, CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
    CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA, CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA, CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA, CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA,
    CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA, CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA,
    CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA, CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA,
    CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4, CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
    CHIODOS_TREATY_SCOPE_SCHEMA,
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
    PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use std::collections::BTreeMap;
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

fn advisory(strength: f64) -> RuntimePheromoneAdvisory {
    RuntimePheromoneAdvisory {
        source_report_sha256: "1".repeat(64),
        accepted: true,
        subject_class: "workflow.destructive_step".to_string(),
        subject_class_namespace: "chiodos.runtime".to_string(),
        total_strength: strength,
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

#[test]
fn matching_destructive_admission_accepts_once_then_rejects_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;

    let first = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_advisory: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
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
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_advisory: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
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

    let accepted = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys,
        pheromone_advisory: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
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
            runtime_trust_input: Some(&signed_v2),
            trusted_verifier_keys: &trusted_keys(&verifier),
            pheromone_advisory: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
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
        runtime_trust_input: Some(&signed_v1),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_advisory: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
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

    let rejected = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys(&verifier),
        pheromone_advisory: Some(&advisory(0.91)),
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
fn signed_runtime_admission_report_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;
    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_advisory: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
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
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted_keys,
        pheromone_advisory: None,
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
fn kernel_hook_accepts_governed_context_reference_and_returns_receipt_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

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
        federated_origin_kernel_id: None,
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
            }
        })),
    });

    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chiodos_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chiodos_runtime"]["accepted"], true);
    Ok(())
}

#[test]
fn kernel_hook_denies_federated_runtime_request_without_treaty_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

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
            }
        })),
    });

    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chiodos_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chiodos_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "missing_chiodos_treaty_context"
    );
    Ok(())
}

#[test]
fn kernel_hook_denies_cross_boundary_request_when_treaty_store_evidence_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

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
            "chiodosTreaty": {
                "treatyScopeId": "treaty-buyer-vendor",
                "treatyScopeSha256": "5".repeat(64),
                "ladderIntersectionId": "treaty-buyer-vendor:1800000010000",
                "ladderIntersectionSha256": "6".repeat(64),
                "actionClassId": "workflow.destructive.vendor_call"
            }
        })),
    });

    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "chiodos_treaty_missing_scope"
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
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
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
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["trustRoot"] = serde_json::json!({"issuer": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["dynamicTrust"] = serde_json::json!({"discovery": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
fn treaty_runtime_hook_denies_missing_bilateral_dsse_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
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
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
fn treaty_runtime_hook_denies_mismatched_continuation_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let mut context = treaty_runtime_context(&fixture);
    context["crossKernelContinuation"]["sha256"] = serde_json::Value::String("f".repeat(64));
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
fn treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
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
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
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
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store);
    let context = RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };

    assert!(hook.evaluate(&context)?.allowed);
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
fn kernel_hook_uses_configured_runtime_policy_to_deny() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.destructive = false;
    bundle.lease_id = None;
    bundle.governance_receipt_id = None;
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

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
            }
        })),
    });

    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let hook = ChiodosRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted_keys(&verifier))
        .with_pheromone_advisory(advisory(0.91))
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        now_unix_secs: 1_800_000_001,
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
    chio_chiodos_runtime::validate_runtime_orchestration_run_report(&run_report)?;
    chio_chiodos_runtime::validate_runtime_orchestration_status_report(&status)?;
    assert!(
        chio_chiodos_runtime::runtime_orchestration_run_report_json(&run_report)?
            .contains("proof_accepted")
    );
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_persists_replay_fence_and_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-orchestration.sqlite3");
    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_bundle(bundle())?;
        store.record_run_state(
            "runtime-orchestration-1",
            "proof_accepted",
            None,
            1_800_000_001_000,
        )?;
        store.record_step_state(chio_chiodos_runtime::RuntimeOrchestrationStepState {
            step_index: 1,
            admission_id: "adm-live-1".to_string(),
            state: "proof_accepted".to_string(),
            destructive: true,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: Some("2".repeat(64)),
            lease_id: Some("lease-live-1".to_string()),
        })?;
        store.consume_destructive_lease("lease-live-1", "adm-live-1")?;
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let replay = reopened.consume_destructive_lease("lease-live-1", "adm-live-1");
    match replay {
        Ok(()) => panic!("expected destructive lease replay rejection"),
        Err(error) => assert_eq!(error.code(), "destructive_lease_replay"),
    }
    let status = reopened.status_report(
        "profile-runtime-orchestration",
        "7".repeat(64),
        1_800_000_002_000,
        true,
    )?;
    assert_eq!(status.store_backend, "sqlite");
    assert_eq!(status.consumed_lease_count, 1);
    assert_eq!(status.run_counts.get("proof_accepted"), Some(&1));
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_persists_treaty_evidence_idempotently(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty.sqlite3");
    let treaty = treaty_scope();
    let treaty_sha256 = chio_chiodos_runtime::treaty_scope_sha256(&treaty)?;

    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;

        let mut mismatched = treaty.clone();
        mismatched.expires_at_unix_ms += 1;
        let duplicate =
            store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &mismatched);
        match duplicate {
            Ok(()) => panic!("expected treaty evidence id mismatch rejection"),
            Err(error) => assert_eq!(error.code(), "duplicate_treaty_runtime_artifact_mismatch"),
        }
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let record = reopened
        .treaty_runtime_artifact("treaty_scope", &treaty.treaty_id)?
        .ok_or_else(|| io::Error::other("treaty evidence missing after restart"))?;
    assert_eq!(record.evidence_kind, "treaty_scope");
    assert_eq!(record.evidence_id, treaty.treaty_id);
    assert_eq!(record.artifact_sha256, treaty_sha256);
    assert_eq!(
        serde_json::from_value::<TreatyScope>(record.raw_json)?,
        treaty
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

    assert!(report.accepted);
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

fn treaty_action_class(
    mode: &str,
    destructive: bool,
    consistency_model: &str,
    evidence_required: Vec<&str>,
) -> GovernanceLadderActionClass {
    GovernanceLadderActionClass {
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        mode: mode.to_string(),
        destructive,
        consistency_model: consistency_model.to_string(),
        co_sign: "bilateral_required".to_string(),
        evidence_required: evidence_required
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect(),
        aliases: Vec::new(),
    }
}

fn treaty_manifest(
    kernel_id: &str,
    action: GovernanceLadderActionClass,
) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: format!("did:chio:{kernel_id}"),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![action],
    }
}

fn treaty_scope() -> TreatyScope {
    TreatyScope {
        schema: CHIODOS_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
        ladder_manifest_sha256s: vec!["a".repeat(64), "b".repeat(64)],
        allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "d".repeat(64),
    }
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
            vec!["bilateral_dsse", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "receipt_lineage"],
        ),
    );
    let mut treaty_scope = treaty_scope();
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
    let lineage = ReceiptLineageStatement {
        schema: CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-runtime-1".to_string(),
        parent_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        child_receipt_sha256: "3".repeat(64),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: "4".repeat(64),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
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
    let bilateral_invocation = BilateralInvocation {
        schema: CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-runtime-1".to_string(),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256,
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: tool_args_sha256(&serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        }))?,
        outcome_sha256: "5".repeat(64),
        local_receipt_sha256: lineage_bundle.root_receipt_sha256.clone(),
        remote_receipt_sha256: lineage_bundle.leaf_receipt_sha256.clone(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    let bilateral_invocation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_invocation)?,
    );
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
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
            governance_receipt_ref: None,
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
                governance_refs: vec!["gov-receipt-1".to_string()],
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

#[test]
fn treaty_ladder_intersection_rejects_destructive_observation(
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = treaty_manifest(
        "kernel.buyer",
        treaty_action_class("observation", true, "totally_ordered", vec!["tool_receipt"]),
    );

    let err = match validate_governance_ladder_manifest(&manifest) {
        Ok(()) => {
            return Err(Box::new(io::Error::other(
                "destructive observation manifest unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chiodos_ladder_destructive_below_floor");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_requires_intersection_and_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;

    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256.clone()),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec!["governance_receipt".to_string()],
        verified_evidence: Vec::new(),
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chiodos_treaty_missing_required_evidence")
    );

    let accepted = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(accepted.accepted);
    assert_eq!(accepted.mode, "receipt_backed");
    assert_eq!(accepted.consistency_model, "totally_ordered");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_unverified_or_forged_intersection(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;
    intersection.action_classes[0]
        .evidence_required
        .retain(|evidence| evidence != "receipt_lineage");

    let forged = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!forged.accepted);
    assert_eq!(
        forged.failure_code.as_deref(),
        Some("chiodos_treaty_intersection_mismatch")
    );

    let intersection = compute_ladder_intersection(
        &treaty,
        &[
            treaty_manifest(
                "kernel.buyer",
                treaty_action_class(
                    "receipt_backed",
                    true,
                    "totally_ordered",
                    vec!["governance_receipt", "bilateral_dsse", "receipt_lineage"],
                ),
            ),
            treaty_manifest(
                "kernel.vendor-b",
                treaty_action_class(
                    "receipt_backed",
                    true,
                    "totally_ordered",
                    vec!["governance_receipt", "bilateral_dsse"],
                ),
            ),
        ],
        1_800_000_010_000,
    )?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;
    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: false,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chiodos_treaty_unverified_required_evidence")
    );
    Ok(())
}

#[test]
fn treaty_intersection_rejects_manifest_hash_mismatch_and_unknown_class(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_dsse"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec!["0".repeat(64), "1".repeat(64)];
    let err = match compute_ladder_intersection(
        &treaty,
        &[buyer.clone(), vendor.clone()],
        1_800_000_010_000,
    ) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "manifest hash mismatch unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chiodos_ladder_manifest_hash_mismatch");

    treaty.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    treaty.allowed_action_classes = vec!["workflow.unknown".to_string()];
    let err = match compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "unknown action class unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chiodos_treaty_action_class_not_allowed");
    Ok(())
}

#[test]
fn buyer_attestation_packet_preserves_verified_lineage_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let continuation = CrossKernelContinuation {
        schema: CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let lineage = ReceiptLineageStatement {
        schema: CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-1".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        child_receipt_sha256: "3".repeat(64),
        continuation_sha256: chio_core_types::crypto::sha256_hex(
            &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
        ),
        bilateral_invocation_sha256: "4".repeat(64),
        evidence_class: "verified".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
    };
    let lineage_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    let admission = chio_chiodos_runtime::CrossBoundaryAdmissionReport {
        schema: chio_chiodos_runtime::CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        required_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "4".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_hash.clone(),
                verified: true,
            },
        ],
        treaty_scope_sha256: "5".repeat(64),
        ladder_intersection_sha256: "6".repeat(64),
        expected_ladder_intersection_sha256: Some("6".repeat(64)),
        checks: vec!["chiodos_treaty.required_evidence_present".to_string()],
    };
    let admission_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&admission)?,
    );
    let packet = BuyerAttestationPacket {
        schema: CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA.to_string(),
        packet_id: "buyer-packet-1".to_string(),
        buyer_id: "buyer.acme".to_string(),
        capability_id: "cap-live-1".to_string(),
        treaty_scope_sha256: admission.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: admission_hash,
        continuation_sha256: lineage.continuation_sha256.clone(),
        receipt_lineage_statement_sha256: lineage_hash,
        bilateral_invocation_sha256: "4".repeat(64),
        workflow_receipt_sha256: "8".repeat(64),
        proof_package_sha256: "9".repeat(64),
        verifier_report_sha256: "a".repeat(64),
        budget_refs: vec!["budget.reserve:local-demo".to_string()],
        settlement_claimed: false,
    };
    let bilateral = BilateralInvocation {
        schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-1".to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
        continuation_sha256: packet.continuation_sha256.clone(),
        lineage_statement_sha256: packet.receipt_lineage_statement_sha256.clone(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: packet.capability_id.clone(),
        request_sha256: "b".repeat(64),
        outcome_sha256: "c".repeat(64),
        local_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        remote_receipt_sha256: lineage.child_receipt_sha256.clone(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };

    let accepted =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    assert!(accepted.accepted);
    assert_eq!(accepted.failure_code, None);

    let mut asserted = lineage.clone();
    asserted.evidence_class = "asserted".to_string();
    let denied =
        verify_buyer_attestation_packet(&packet, &asserted, &continuation, &admission, &bilateral)?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chiodos_buyer_packet_lineage_not_verified")
    );

    let mut mismatched = packet.clone();
    mismatched.bilateral_invocation_sha256 = "b".repeat(64);
    let denied = verify_buyer_attestation_packet(
        &mismatched,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chiodos_buyer_packet_hash_mismatch")
    );
    Ok(())
}

fn insert_review_source<T: serde::Serialize>(
    sources: &mut BTreeMap<String, Vec<u8>>,
    role: &str,
    artifact: &T,
) -> Result<BuyerAttestationReviewArtifactRef, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(artifact)?;
    let artifact_sha256 = chio_core_types::crypto::sha256_hex(&bytes);
    sources.insert(role.to_string(), bytes.clone());
    Ok(BuyerAttestationReviewArtifactRef {
        role: role.to_string(),
        relative_path: format!("{role}.json"),
        artifact_sha256,
        byte_count: bytes.len() as u64,
    })
}

type BuyerFixture = (
    BuyerAttestationPacket,
    ReceiptLineageStatement,
    CrossKernelContinuation,
    CrossBoundaryAdmissionReport,
    BilateralInvocation,
);

fn buyer_fixture() -> Result<BuyerFixture, Box<dyn std::error::Error>> {
    let continuation = CrossKernelContinuation {
        schema: CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    let lineage = ReceiptLineageStatement {
        schema: CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-1".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        child_receipt_sha256: "3".repeat(64),
        continuation_sha256,
        bilateral_invocation_sha256: "4".repeat(64),
        evidence_class: "verified".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
    };
    let lineage_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    let admission = CrossBoundaryAdmissionReport {
        schema: CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        required_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_dsse".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "4".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_hash.clone(),
                verified: true,
            },
        ],
        treaty_scope_sha256: "5".repeat(64),
        ladder_intersection_sha256: "6".repeat(64),
        expected_ladder_intersection_sha256: Some("6".repeat(64)),
        checks: vec!["chiodos_treaty.required_evidence_present".to_string()],
    };
    let admission_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&admission)?,
    );
    let packet = BuyerAttestationPacket {
        schema: CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA.to_string(),
        packet_id: "buyer-packet-1".to_string(),
        buyer_id: "buyer.acme".to_string(),
        capability_id: "cap-live-1".to_string(),
        treaty_scope_sha256: admission.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: admission_hash,
        continuation_sha256: lineage.continuation_sha256.clone(),
        receipt_lineage_statement_sha256: lineage_hash,
        bilateral_invocation_sha256: "4".repeat(64),
        workflow_receipt_sha256: "8".repeat(64),
        proof_package_sha256: "9".repeat(64),
        verifier_report_sha256: "a".repeat(64),
        budget_refs: vec!["budget.reserve:local-demo".to_string()],
        settlement_claimed: false,
    };
    let bilateral = BilateralInvocation {
        schema: CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-1".to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
        continuation_sha256: packet.continuation_sha256.clone(),
        lineage_statement_sha256: packet.receipt_lineage_statement_sha256.clone(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: packet.capability_id.clone(),
        request_sha256: "b".repeat(64),
        outcome_sha256: "c".repeat(64),
        local_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        remote_receipt_sha256: lineage.child_receipt_sha256.clone(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    Ok((packet, lineage, continuation, admission, bilateral))
}

struct StrictDsseFixture {
    envelope: chio_federation::DsseEnvelope,
    signer_a_public_key: chio_core_types::crypto::PublicKey,
    signer_b_public_key: chio_core_types::crypto::PublicKey,
}

fn strict_dsse_fixture_with_keys(
    packet: &BuyerAttestationPacket,
    lineage_bundle: &ReceiptLineageBundle,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<StrictDsseFixture, Box<dyn std::error::Error>> {
    strict_dsse_fixture_with_kernel_ids(packet, lineage_bundle, admission, bilateral, None)
}

fn strict_dsse_fixture_with_kernel_ids(
    packet: &BuyerAttestationPacket,
    lineage_bundle: &ReceiptLineageBundle,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
    signer_kernel_ids: Option<(&str, &str)>,
) -> Result<StrictDsseFixture, Box<dyn std::error::Error>> {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let (signer_a_kernel_id, signer_b_kernel_id) = signer_kernel_ids.unwrap_or((
        bilateral.signer_kernel_ids[0].as_str(),
        bilateral.signer_kernel_ids[1].as_str(),
    ));
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-treaty-dsse".to_string(),
            timestamp: 1_800_000_010,
            capability_id: packet.capability_id.clone(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "record": "vendor-ledger-7",
                "value": "closed"
            }))?,
            decision: Decision::Allow,
            content_hash: "c".repeat(64),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp_b.public_key(),
        },
        &kp_b,
    )?;
    let envelope = sign_chiodos_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        signer_a_kernel_id,
        signer_b_kernel_id,
        "close_account",
        1_800_000_010_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-live-1".to_string(),
                issuer: bilateral.signer_kernel_ids[0].clone(),
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
            governance_receipt_ref: None,
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some(admission.consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: admission.treaty_id.clone(),
                treaty_scope_sha256: packet.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
                admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
                continuation_sha256: packet.continuation_sha256.clone(),
                lineage_bundle_sha256: chio_core_types::crypto::sha256_hex(
                    &chio_core_types::crypto::canonical_json_bytes(lineage_bundle)?,
                ),
                action_class_id: admission.action_class_id.clone(),
                consistency_model: admission.consistency_model.clone(),
                request_sha256: bilateral.request_sha256.clone(),
                outcome_sha256: bilateral.outcome_sha256.clone(),
                local_receipt_sha256: bilateral.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral.remote_receipt_sha256.clone(),
                lease_refs: vec!["lease-live-1".to_string()],
                governance_refs: vec!["gov-receipt-1".to_string()],
                signer_kernel_ids: bilateral.signer_kernel_ids.clone(),
            }),
        },
    )?;
    Ok(StrictDsseFixture {
        envelope,
        signer_a_public_key: kp_a.public_key(),
        signer_b_public_key: kp_b.public_key(),
    })
}

fn proof_package_with_peer_keys(
    bilateral: &BilateralInvocation,
    dsse: &StrictDsseFixture,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "chio.chiodos.proof-package.v1",
        "proofPackageId": "proof-from-live-run",
        "peerLadderBindings": [
            {
                "kernelId": bilateral.signer_kernel_ids[0],
                "publicKey": dsse.signer_a_public_key.to_hex(),
                "ladderManifestRef": {
                    "manifestId": "ladder-buyer-live",
                    "issuedAtUnixMs": 1_800_000_000_000_i64,
                    "expiresAtUnixMs": 1_800_003_600_000_i64
                }
            },
            {
                "kernelId": bilateral.signer_kernel_ids[1],
                "publicKey": dsse.signer_b_public_key.to_hex(),
                "ladderManifestRef": {
                    "manifestId": "ladder-vendor-live",
                    "issuedAtUnixMs": 1_800_000_000_000_i64,
                    "expiresAtUnixMs": 1_800_003_600_000_i64
                }
            }
        ]
    })
}

type ReviewSourceBytes = BTreeMap<String, Vec<u8>>;
type ReviewPackageSources = (BuyerAttestationReviewPackage, ReviewSourceBytes);

struct BuyerReviewStrictDsseSources<'a> {
    packet: &'a mut BuyerAttestationPacket,
    lineage: &'a ReceiptLineageStatement,
    continuation: &'a CrossKernelContinuation,
    admission: &'a CrossBoundaryAdmissionReport,
    bilateral: &'a BilateralInvocation,
    lineage_bundle: &'a ReceiptLineageBundle,
    bilateral_dsse_envelope: &'a serde_json::Value,
    proof_package: &'a serde_json::Value,
}

fn buyer_review_sources_with_strict_dsse(
    sources: BuyerReviewStrictDsseSources<'_>,
) -> Result<ReviewPackageSources, Box<dyn std::error::Error>> {
    let BuyerReviewStrictDsseSources {
        packet,
        lineage,
        continuation,
        admission,
        bilateral,
        lineage_bundle,
        bilateral_dsse_envelope,
        proof_package,
    } = sources;
    let verifier_report = serde_json::json!({
        "schema": "chio.chiodos.verifier-report.v2",
        "accepted": true,
        "failure": null
    });
    let workflow_receipt = serde_json::json!({
        "schema": "chio.workflow-receipt.v2",
        "workflowId": "workflow-live-1"
    });
    let runtime_run_report = serde_json::json!({
        "schema": CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
        "runId": "run-live-1"
    });
    packet.workflow_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&workflow_receipt)?,
    );
    packet.proof_package_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(proof_package)?,
    );
    packet.verifier_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&verifier_report)?,
    );
    let mut sources = BTreeMap::new();
    let artifacts = vec![
        insert_review_source(&mut sources, "buyer_attestation_packet", packet)?,
        insert_review_source(&mut sources, "receipt_lineage_statement", lineage)?,
        insert_review_source(&mut sources, "receipt_lineage_bundle", lineage_bundle)?,
        insert_review_source(&mut sources, "cross_kernel_continuation", continuation)?,
        insert_review_source(&mut sources, "cross_boundary_admission_report", admission)?,
        insert_review_source(&mut sources, "bilateral_invocation", bilateral)?,
        insert_review_source(
            &mut sources,
            "bilateral_dsse_envelope",
            bilateral_dsse_envelope,
        )?,
        insert_review_source(&mut sources, "workflow_receipt", &workflow_receipt)?,
        insert_review_source(&mut sources, "proof_package", proof_package)?,
        insert_review_source(&mut sources, "verifier_report", &verifier_report)?,
        insert_review_source(&mut sources, "runtime_run_report", &runtime_run_report)?,
    ];
    let package = BuyerAttestationReviewPackage {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: "review-package-1".to_string(),
        packet_id: packet.packet_id.clone(),
        buyer_id: packet.buyer_id.clone(),
        generated_at_unix_ms: 1_800_000_010_000,
        artifacts,
    };
    Ok((package, sources))
}

#[test]
fn buyer_review_package_hydrates_required_artifacts_by_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources) = buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
        packet: &mut packet,
        lineage: &lineage,
        continuation: &continuation,
        admission: &admission,
        bilateral: &bilateral,
        lineage_bundle: &lineage_bundle,
        bilateral_dsse_envelope: &bilateral_dsse_envelope,
        proof_package: &proof_package,
    })?;

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(report.accepted);
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "chiodos_buyer_review.proof_verifier_accepted"));

    let mut tampered_sources = sources.clone();
    tampered_sources.insert(
        "verifier_report".to_string(),
        serde_json::to_vec(&serde_json::json!({
            "schema": "chio.chiodos.verifier-report.v2",
            "accepted": false
        }))?,
    );
    let denied = verify_buyer_attestation_review_package(&package, &tampered_sources)?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chiodos_buyer_review_artifact_hash_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_missing_strict_dsse_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let verifier_report = serde_json::json!({"accepted": true});
    let workflow_receipt = serde_json::json!({"schema": "chio.workflow-receipt.v2"});
    let runtime_run_report =
        serde_json::json!({"schema": CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA});
    packet.workflow_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&workflow_receipt)?,
    );
    packet.proof_package_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&proof_package)?,
    );
    packet.verifier_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&verifier_report)?,
    );
    let mut sources = BTreeMap::new();
    let artifacts = vec![
        insert_review_source(&mut sources, "buyer_attestation_packet", &packet)?,
        insert_review_source(&mut sources, "receipt_lineage_statement", &lineage)?,
        insert_review_source(&mut sources, "receipt_lineage_bundle", &lineage_bundle)?,
        insert_review_source(&mut sources, "cross_kernel_continuation", &continuation)?,
        insert_review_source(&mut sources, "cross_boundary_admission_report", &admission)?,
        insert_review_source(&mut sources, "bilateral_invocation", &bilateral)?,
        insert_review_source(&mut sources, "workflow_receipt", &workflow_receipt)?,
        insert_review_source(&mut sources, "proof_package", &proof_package)?,
        insert_review_source(&mut sources, "verifier_report", &verifier_report)?,
        insert_review_source(&mut sources, "runtime_run_report", &runtime_run_report)?,
    ];
    let package = BuyerAttestationReviewPackage {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: "review-package-1".to_string(),
        packet_id: packet.packet_id.clone(),
        buyer_id: packet.buyer_id.clone(),
        generated_at_unix_ms: 1_800_000_010_000,
        artifacts,
    };

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_missing_artifact_role")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_non_strict_dsse_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let verifier_report = serde_json::json!({"accepted": true});
    let workflow_receipt = serde_json::json!({"schema": "chio.workflow-receipt.v2"});
    let runtime_run_report =
        serde_json::json!({"schema": CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA});
    let compatibility_dsse = serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": "not-a-strict-chiodos-payload",
        "signatures": []
    });
    packet.workflow_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&workflow_receipt)?,
    );
    packet.proof_package_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&proof_package)?,
    );
    packet.verifier_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&verifier_report)?,
    );
    let mut sources = BTreeMap::new();
    let artifacts = vec![
        insert_review_source(&mut sources, "buyer_attestation_packet", &packet)?,
        insert_review_source(&mut sources, "receipt_lineage_statement", &lineage)?,
        insert_review_source(&mut sources, "receipt_lineage_bundle", &lineage_bundle)?,
        insert_review_source(&mut sources, "cross_kernel_continuation", &continuation)?,
        insert_review_source(&mut sources, "cross_boundary_admission_report", &admission)?,
        insert_review_source(&mut sources, "bilateral_invocation", &bilateral)?,
        insert_review_source(&mut sources, "bilateral_dsse_envelope", &compatibility_dsse)?,
        insert_review_source(&mut sources, "workflow_receipt", &workflow_receipt)?,
        insert_review_source(&mut sources, "proof_package", &proof_package)?,
        insert_review_source(&mut sources, "verifier_report", &verifier_report)?,
        insert_review_source(&mut sources, "runtime_run_report", &runtime_run_report)?,
    ];
    let package = BuyerAttestationReviewPackage {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: "review-package-1".to_string(),
        packet_id: packet.packet_id.clone(),
        buyer_id: packet.buyer_id.clone(),
        generated_at_unix_ms: 1_800_000_010_000,
        artifacts,
    };

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_non_strict_dsse")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[0].sig = dsse.envelope.signatures[1].sig.clone();
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources) = buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
        packet: &mut packet,
        lineage: &lineage,
        continuation: &continuation,
        admission: &admission,
        bilateral: &bilateral,
        lineage_bundle: &lineage_bundle,
        bilateral_dsse_envelope: &bilateral_dsse_envelope,
        proof_package: &proof_package,
    })?;

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_strict_dsse_signer_kernel_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_kernel_ids(
        &packet,
        &lineage_bundle,
        &admission,
        &bilateral,
        Some(("kernel.attacker", bilateral.signer_kernel_ids[1].as_str())),
    )?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources) = buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
        packet: &mut packet,
        lineage: &lineage,
        continuation: &continuation,
        admission: &admission,
        bilateral: &bilateral,
        lineage_bundle: &lineage_bundle,
        bilateral_dsse_envelope: &bilateral_dsse_envelope,
        proof_package: &proof_package,
    })?;

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_strict_dsse_signer_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_duplicate_strict_dsse_signature_keyids(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[1].keyid = dsse.envelope.signatures[0].keyid.clone();
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources) = buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
        packet: &mut packet,
        lineage: &lineage,
        continuation: &continuation,
        admission: &admission,
        bilateral: &bilateral,
        lineage_bundle: &lineage_bundle,
        bilateral_dsse_envelope: &bilateral_dsse_envelope,
        proof_package: &proof_package,
    })?;

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_same_key_strict_dsse_trust_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let Some(bindings) = proof_package
        .get_mut("peerLadderBindings")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Err(Box::new(io::Error::other(
            "proof package did not contain peer ladder bindings",
        )));
    };
    bindings[1]["publicKey"] = serde_json::json!(dsse.signer_a_public_key.to_hex());
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources) = buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
        packet: &mut packet,
        lineage: &lineage,
        continuation: &continuation,
        admission: &admission,
        bilateral: &bilateral,
        lineage_bundle: &lineage_bundle,
        bilateral_dsse_envelope: &bilateral_dsse_envelope,
        proof_package: &proof_package,
    })?;

    let report = verify_buyer_attestation_review_package(&package, &sources)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chiodos_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn receipt_lineage_bundle_rejects_asserted_required_edge() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, mut lineage, _, _, _) = buyer_fixture()?;
    let accepted = verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    })?;
    assert!(accepted);

    lineage.evidence_class = "asserted".to_string();
    let err = match verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-2".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    }) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "asserted lineage bundle unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chiodos_lineage_bundle_unverified_edge");
    Ok(())
}
