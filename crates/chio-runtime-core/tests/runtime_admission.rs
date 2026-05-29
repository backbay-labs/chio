use chio_core_types::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, GovernedTransactionIntent, Operation,
    ToolGrant,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    ActorRef, BoundaryClass, ChioReceipt, ChioReceiptBody, Decision, ReceiptKind, RedactionMode,
    ToolCallAction, ToolOrigin, TrustLevel,
};
use chio_core_types::SignedExportEnvelope;
use chio_federation::{
    sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    DsseEnvelope, GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict,
    TreatyBindingRef, PAYLOAD_TYPE_IN_TOTO,
};
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use chio_runtime_core::{
    compute_ladder_intersection, evaluate_runtime_admission, runtime_admission_bundle_sha256,
    runtime_peer_weights_sha256, sign_runtime_admission_report, tool_args_sha256,
    verify_signed_runtime_admission_report, BilateralInvocation, ChioRuntimeAdmissionHook,
    CrossKernelContinuation, InMemoryRuntimeAdmissionStore, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionInput,
    RuntimeAdmissionProfile, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromoneAdvisory,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeRequestBinding,
    RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundleV4, SignedRuntimePheromoneQueryReport,
    SqliteRuntimeOrchestrationStore, TreatyScope, CHIO_BILATERAL_INVOCATION_SCHEMA,
    CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIO_RUNTIME_FAILURE_CODES,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
use std::io;

mod support;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

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

#[test]
fn chio_native_runtime_admission_schema_emits_chio_report() -> Result<(), Box<dyn std::error::Error>>
{
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let mut bundle = bundle();
    bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    bundle.destructive = false;
    bundle.lease_id = None;
    bundle.governance_receipt_id = None;

    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone())?;
    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile,
        store: &store,
        admission_id: &bundle.admission_id,
        request: &bundle.binding,
        action_class_id: None,
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_query_report: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
        now_unix_ms: 1_800_000_000_001,
    })?;

    assert!(report.accepted);
    assert_eq!(report.schema, "chio.runtime.admission-report.v1");
    let metadata = report
        .receipt_metadata
        .get("chio_runtime")
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["admission_id"], bundle.admission_id);
    assert_eq!(metadata["accepted"], true);
    Ok(())
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

fn allowing_chio_policy_hook<S>(
    store: S,
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(ChioRuntimeAdmissionHook::new(profile, store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

#[test]
fn runtime_failure_code_registry_covers_hook_surface_codes() {
    let registry: std::collections::BTreeSet<_> =
        CHIO_RUNTIME_FAILURE_CODES.iter().copied().collect();
    assert_eq!(registry.len(), CHIO_RUNTIME_FAILURE_CODES.len());

    for code in [
        "missing_governed_intent",
        "missing_chio_admission_context",
        "invalid_chio_admission_context",
        "missing_admission_id",
        "missing_chio_treaty_context",
        "invalid_chio_treaty_context",
        "request_smuggled_trust_root",
        "request_smuggled_dynamic_trust",
        "missing_treaty_scope_id",
        "missing_treaty_scope_hash",
        "missing_ladder_intersection_id",
        "missing_ladder_intersection_hash",
        "missing_action_class_id",
        "invalid_chio_treaty_hash",
        "invalid_chio_treaty_evidence_ref",
        "missing_chio_treaty_evidence_ref",
        "chio_treaty_missing_scope",
        "chio_treaty_scope_hash_mismatch",
        "chio_treaty_missing_intersection",
        "unsupported_cross_kernel_continuation_schema",
        "continuation_invalid_window",
        "unsupported_receipt_lineage_statement_schema",
        "receipt_lineage_invalid_evidence_class",
        "chio_ladder_invalid_consistency_model",
        "chio_ladder_invalid_cosign_mode",
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
        first.receipt_metadata["chio_runtime"]["admission_id"],
        "adm-live-1"
    );
    assert_eq!(first.receipt_metadata["chio_runtime"]["destructive"], true);

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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
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
        metadata["chio_runtime"]["failure_code"],
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
        metadata["chio_runtime"]["failure_code"],
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_hash_mismatch"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_mismatch"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_mismatch"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_lineage_bundle_unverified_edge"
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
    fixture.bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store);
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_stale"
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
    fixture.bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store);
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_stale"
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_replay"
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
        metadata["chio_runtime"]["failure_code"],
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
fn chio_runtime_hook_releases_chio_native_reserved_state_after_kernel_abort(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        governed_intent: Some(GovernedTransactionIntent {
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
        }),
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
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
    let runtime_metadata = metadata
        .get("chio_runtime")
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(runtime_metadata["admission_id"], "adm-live-1");
    assert_eq!(runtime_metadata["accepted"], true);
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
    let hook = ChioRuntimeAdmissionHook::new(profile(), store)
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
        metadata["chio_runtime"]["failure_code"],
        "runtime_pheromone_policy_deny"
    );
    Ok(())
}

#[test]
fn kernel_hook_rejects_treaty_dsse_unanimous_deny() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let fixture = treaty_runtime_fixture_with_policy(unanimous_deny_policy_evaluation_summary())?;
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
    let hook = allowing_chio_policy_hook(store)?;
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_policy_denied"
    );
    Ok(())
}

#[test]
fn kernel_hook_rejects_treaty_dsse_policy_verdict_disagreement(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut fixture = treaty_runtime_fixture()?;
    fixture.bilateral_dsse = deny_policy_bilateral_dsse(&fixture.bilateral_dsse)?;
    fixture.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.bilateral_dsse)?,
    );
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
    let hook = allowing_chio_policy_hook(store)?;
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
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_unverified_required_evidence"
    );
    Ok(())
}

#[derive(Clone)]
struct TreatyRuntimeFixture {
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    ladder_intersection: chio_runtime_core::LadderIntersection,
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

fn allow_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
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
    }
}

fn unanimous_deny_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        joint_disposition: Some("deny".to_string()),
    }
}

fn treaty_runtime_fixture() -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_policy(allow_policy_evaluation_summary())
}

fn treaty_runtime_fixture_with_policy(
    policy_evaluation_summary: PolicyEvaluationSummary,
) -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
    let mut treaty_scope = treaty_scope();
    treaty_scope.participant_public_keys = vec![signer_a.public_key(), signer_b.public_key()];
    treaty_scope.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let treaty_scope_sha256 = chio_runtime_core::treaty_scope_sha256(&treaty_scope)?;
    let ladder_intersection =
        compute_ladder_intersection(&treaty_scope, &[buyer, vendor], 1_800_000_001_000)?;
    let ladder_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&ladder_intersection)?;
    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
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
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
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
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:chio-runtime/admission".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
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
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    let lineage = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-runtime-1".to_string(),
        parent_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-runtime-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    };
    let lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage_bundle)?,
    );
    let rebound_bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    assert_eq!(
        rebound_bilateral_invocation_sha256,
        bilateral_invocation_binding_sha256
    );
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256;
    let bilateral_dsse = sign_chio_bilateral_dsse_envelope(
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
            policy_evaluation_summary: Some(policy_evaluation_summary),
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

fn deny_policy_bilateral_dsse(
    envelope: &DsseEnvelope,
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = envelope.decode_statement()?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture DSSE missing policy summary"))?;
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            statement.canonical_bytes()?,
        ),
        signatures: envelope.signatures.clone(),
    })
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
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            },
            "chioTreaty": treaty_context
        })),
    });
    Ok(request)
}
