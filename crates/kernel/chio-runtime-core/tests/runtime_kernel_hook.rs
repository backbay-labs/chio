use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use chio_runtime_core::{
    runtime_admission_bundle_sha256, runtime_peer_weights_sha256, tool_args_sha256,
    ChioRuntimeAdmissionHook, InMemoryRuntimeAdmissionStore, RuntimeAdmissionBundle,
    RuntimeAdmissionProfile, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromoneAdvisory,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeRequestBinding,
    RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundleV4, SignedRuntimePheromoneQueryReport,
    SqliteRuntimeOrchestrationStore, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA,
    CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
use std::io;

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
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(ChioRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
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
        execution_nonce: None,
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
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            }
        })),
    });

    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    Ok(())
}

#[test]
fn kernel_hook_preserves_millisecond_admission_time() -> Result<(), Box<dyn std::error::Error>> {
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
        execution_nonce: None,
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
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            }
        })),
    });

    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    let mut expiring_profile = profile();
    expiring_profile.expires_at_unix_ms = 1_800_000_001_500;
    let hook = ChioRuntimeAdmissionHook::new(expiring_profile, store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_600,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["failure_code"], "stale_profile");
    Ok(())
}

#[test]
fn kernel_hook_bypasses_non_chio_request() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let cap = capability("cap-legacy-1")?;
    let request = ToolCallRequest {
        request_id: "req-legacy-tool".to_string(),
        capability: cap.clone(),
        tool_name: "read_status".to_string(),
        server_id: "legacy-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"record": "vendor-ledger-7"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-legacy-1".to_string(),
            server_id: "legacy-ledger".to_string(),
            tool_name: "read_status".to_string(),
            purpose: "ordinary non-Chio status read".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({"legacyTraceId": "trace-1"})),
        }),
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let hook = ChioRuntimeAdmissionHook::new(profile(), store);

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(decision.allowed, "{decision:#?}");
    assert!(decision.metadata.is_none(), "{decision:#?}");
    Ok(())
}

#[test]
fn kernel_hook_denies_federated_origin_without_any_runtime_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-federated-no-context".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
    };

    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed, "{decision:#?}");
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
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
        execution_nonce: None,
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
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            }
        })),
    });

    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
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
        execution_nonce: None,
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
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            },
            "chioTreaty": {
                "treatyScopeId": "treaty-buyer-vendor",
                "treatyScopeSha256": "5".repeat(64),
                "ladderIntersectionId": "treaty-buyer-vendor:1800000010000",
                "ladderIntersectionSha256": "6".repeat(64),
                "actionClassId": "workflow.destructive.vendor_call"
            }
        })),
    });

    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_scope"
    );
    Ok(())
}
