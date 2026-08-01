use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::{
    bilateral_dsse::sign_chio_bilateral_dsse_envelope,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_dsse::TreatyBindingRef, bilateral_dsse::PAYLOAD_TYPE_IN_TOTO,
};
use chio_kernel::{
    RuntimeAdmissionContext, RuntimeAdmissionHook, RuntimeAdmissionRevalidationContext,
    ToolCallRequest,
};
use chio_runtime_core::{
    compute_ladder_intersection, evaluate_runtime_admission, runtime_admission_bundle_sha256,
    runtime_peer_weights_sha256, sign_runtime_admission_report, tool_args_sha256,
    verify_signed_runtime_admission_report, BilateralInvocation, ChioRuntimeAdmissionHook,
    CrossKernelContinuation, InMemoryRuntimeAdmissionStore, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionInput,
    RuntimeAdmissionProfile, RuntimeAdmissionStore, RuntimePeerWeight, RuntimePeerWeights,
    RuntimePheromoneAdvisory, RuntimePheromonePolicy, RuntimePheromonePolicyRule,
    RuntimeRequestBinding, RuntimeTrustFloorEntry, RuntimeTrustedVerifierKey,
    RuntimeVerifierTrustBundleV4, SignedRuntimePheromoneQueryReport,
    SqliteRuntimeOrchestrationStore, TreatyRuntimeArtifactRecord, TreatyScope,
    CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_RUNTIME_FAILURE_CODES, CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA,
    CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
use chio_swarm_authority::{
    sign_swarm_continuation_token, sign_swarm_delegation_witness_hop, sign_swarm_join_receipt,
    sign_swarm_revocation_epoch, sign_swarm_route_plan_receipt, sign_swarm_task_graph,
    sign_swarm_terminal_graph_receipt, verify_swarm_authority_bundle, SwarmAuthorityBundle,
    SwarmBudgetAllocation, SwarmBudgetAllocationState, SwarmBudgetPool, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphEdge,
    SwarmGraphJoin, SwarmGraphNode, SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_BUDGET_POOL_SCHEMA, CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
};
use std::io;

use chio_runtime_core::ChioRuntimeError;

mod support;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

#[path = "runtime_admission/swarm_request_support.rs"]
mod swarm_request_support;
use swarm_request_support::{chio_swarm_runtime_request, swarm_runtime_context};

fn emit_threat_matrix_code(code: &str) {
    if std::env::var_os("CHIO_THREAT_MATRIX_EMIT_CODE").is_some() {
        println!("CHIO_THREAT_MATRIX_CODE={code}");
    }
}

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
            aggregate_invocation_budget: None,
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

include!("runtime_admission/fault_cases.rs");

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
        "invalid_chio_swarm_context",
        "invalid_chio_swarm_evidence_ref",
        "missing_chio_swarm_evidence_ref",
        "missing_chio_swarm_authority_bundle",
        "chio_swarm_authority_ref_mismatch",
        "chio_swarm_authority_rejected",
        "chio_swarm_continuation_replay",
        "chio_swarm_continuation_store_unsupported",
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
        "runtime_swarm_authority_empty_graph_id",
        "duplicate_swarm_authority_bundle_mismatch",
        "duplicate_consumed_swarm_continuation",
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
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
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    assert!(first.has_verified_treaty_material(), "{first:#?}");
    assert!(first
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_runtime"))
        .and_then(|runtime| runtime.get("federation_treaty_dsse"))
        .is_none());
    let replay = hook.evaluate(&context)?;

    assert!(!replay.allowed);
    let metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
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

    let mut denied_request = treaty_runtime_request(
        good_args.clone(),
        bundle_hash.clone(),
        treaty_context.clone(),
    )?;
    denied_request.request_id = "req-runtime-binding-mismatch".to_string();
    let denied = hook.evaluate(&RuntimeAdmissionContext {
        request: &denied_request,
        extra_metadata: None,
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
        extra_metadata: None,
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
        extra_metadata: None,
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
        execution_nonce: None,
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
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
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
fn chio_runtime_hook_denies_swarm_context_without_required_evidence_refs(
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
        execution_nonce: None,
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
                },
                "chioSwarm": {
                    "taskGraph": {
                        "id": "swarm-task-graph-runtime",
                        "sha256": "a".repeat(64)
                    },
                    "continuationToken": {
                        "id": "swarm-continuation-runtime",
                        "sha256": "b".repeat(64)
                    }
                }
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
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
        "missing_chio_swarm_evidence_ref"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_stale_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(true)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
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
                },
                "chioSwarm": swarm_runtime_context(&swarm_bundle)?
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_continuation_expired_since_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let mut swarm_bundle = runtime_swarm_bundle(false)?;
    swarm_bundle.continuation_tokens[0].expires_at_unix_ms = 1_800_000_001_500;
    swarm_bundle.continuation_tokens[0].signature = sign_swarm_continuation_token(
        &swarm_bundle.continuation_tokens[0],
        &swarm_witness_keypair(),
    )?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_metadata_mismatch_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "a2a",
            "protocolTarget": "a2a://provider-b"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_selection_id_mismatch_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route_selection": {
            "selectedRouteId": "a2a:task-child-b",
            "selectedTargetProtocol": "mcp"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_incomplete_swarm_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "mcp"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_plan_not_bound_to_continuation(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;
    let mut swarm_context = swarm_runtime_context(&swarm_bundle)?;
    swarm_context["routePlanReceipt"] = serde_json::json!({
        "id": &swarm_bundle.route_plan_receipts[1].route_plan_id,
        "sha256": canonical_test_hash(&swarm_bundle.route_plan_receipts[1])?
    });

    let request = chio_swarm_runtime_request(args, bundle_hash, swarm_context)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "a2a",
            "protocolTarget": "a2a://provider-runtime",
            "selectedRoute": "a2a:task-child-b"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_ref_mismatch"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_missing_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn sqlite_runtime_hook_denies_stale_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("swarm-hook.sqlite3"))?;
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(true)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_revalidates_reserved_swarm_continuation_then_denies_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let continuation_id = swarm_bundle.continuation_tokens[0].token_id.clone();
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };
    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let first_metadata = first
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        first_metadata["chio_runtime"]["reserved_swarm_continuation_id"],
        continuation_id
    );
    hook.revalidate_before_dispatch(&RuntimeAdmissionRevalidationContext {
        request: &request,
        admission_metadata: Some(&first_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    let replay = hook.evaluate(&context)?;
    assert!(!replay.allowed);
    let replay_metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        replay_metadata["chio_runtime"]["failure_code"],
        "chio_swarm_continuation_replay"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_revalidates_resumable_swarm_continuation_without_replay_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let mut swarm_bundle = runtime_swarm_bundle(false)?;
    swarm_bundle.continuation_tokens[0].mode = SwarmContinuationMode::Resumable;
    swarm_bundle.continuation_tokens[0].signature = sign_swarm_continuation_token(
        &swarm_bundle.continuation_tokens[0],
        &swarm_witness_keypair(),
    )?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };

    let first = hook.evaluate(&context)?;
    let second = hook.evaluate(&context)?;

    assert!(first.allowed, "{first:#?}");
    assert!(second.allowed, "{second:#?}");
    assert!(first
        .metadata
        .as_ref()
        .and_then(|metadata| metadata["chio_runtime"].get("reserved_swarm_continuation_id"))
        .is_none());
    Ok(())
}

#[test]
fn sqlite_runtime_hook_denies_replayed_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("swarm-replay.sqlite3"))?;
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };
    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");

    let replay = hook.evaluate(&context)?;
    assert!(!replay.allowed);
    let replay_metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        replay_metadata["chio_runtime"]["failure_code"],
        "chio_swarm_continuation_replay"
    );
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
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
    bilateral_dsse: chio_federation::bilateral_dsse::DsseEnvelope,
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
            bbs_projection_version: None,
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
    let dsse_consistency_model = chio_runtime_core::bilateral_dsse_consistency_model(
        &bilateral_invocation.consistency_model,
    )?
    .to_string();
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
            consistency_model: Some(dsse_consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: bilateral_invocation.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256.clone(),
                ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                admission_report_sha256: "6".repeat(64),
                continuation_sha256: continuation_sha256.clone(),
                lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                action_class_id: bilateral_invocation.action_class_id.clone(),
                consistency_model: dsse_consistency_model,
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

fn insert_in_memory_treaty_runtime_fixture(
    store: &InMemoryRuntimeAdmissionStore,
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
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
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
        body: Default::default(),
    });
    Ok(request)
}

fn swarm_route_metadata() -> serde_json::Value {
    serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-runtime",
            "selectedRoute": "mcp:task-child-a"
        }
    })
}

fn runtime_swarm_bundle(
    stale_continuation: bool,
) -> Result<SwarmAuthorityBundle, Box<dyn std::error::Error>> {
    let parent_scope = runtime_swarm_scope(3);
    let child_scope = runtime_swarm_scope(1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let scope_subset_proof = compute_attenuation_witness(&parent_scope, &child_scope)?;
    let revocation_root = runtime_swarm_revocation_root(&[], &[])?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        root_transaction_ref: "passport-runtime".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_depth: 1,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            SwarmGraphNode {
                task_id: "task-root".to_string(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: parent_scope_hash.clone(),
                depth: 0,
            },
            SwarmGraphNode {
                task_id: "task-child-a".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-a".to_string()),
                continuation_token_ref: Some("continuation-child-a".to_string()),
                budget_allocation_ref: Some("budget-child-a".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
            SwarmGraphNode {
                task_id: "task-child-b".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-b".to_string()),
                continuation_token_ref: Some("continuation-child-b".to_string()),
                budget_allocation_ref: Some("budget-child-b".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
        ],
        edges: vec![
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-a".to_string(),
                edge_type: "delegates".to_string(),
            },
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-b".to_string(),
                edge_type: "delegates".to_string(),
            },
        ],
        joins: vec![SwarmGraphJoin {
            join_id: "join-child-results".to_string(),
            parent_task_ids: vec!["task-child-a".to_string(), "task-child-b".to_string()],
            next_task_id: "task-root".to_string(),
        }],
        budget_pool_ref: "budget-pool-runtime".to_string(),
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        route_plan_refs: vec!["route-child-a".to_string(), "route-child-b".to_string()],
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    let graph_sha256 = canonical_test_hash(&task_graph)?;
    let mut continuation_a = runtime_swarm_continuation(
        "continuation-child-a",
        "task-child-a",
        "route-child-a",
        "budget-child-a",
        &graph_sha256,
        &revocation_root,
        stale_continuation,
    )?;
    let mut continuation_b = runtime_swarm_continuation(
        "continuation-child-b",
        "task-child-b",
        "route-child-b",
        "budget-child-b",
        &graph_sha256,
        &revocation_root,
        false,
    )?;
    task_graph.nodes[1].continuation_token_ref = Some(continuation_a.token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_b.token_id.clone());
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    continuation_a.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let witness_chain_a = runtime_swarm_witness_chain(
        "witness-child-a",
        "task-child-a",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof.clone(),
    )?;
    let witness_chain_b = runtime_swarm_witness_chain(
        "witness-child-b",
        "task-child-b",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof,
    )?;
    continuation_a.witness_chain_ref = Some(witness_chain_a.chain_id.clone());
    continuation_a.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_a)?);
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.witness_chain_ref = Some(witness_chain_b.chain_id.clone());
    continuation_b.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_b)?);
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let mut join_receipt = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-child-results".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        parent_set_hash: runtime_swarm_join_parent_set_hash(
            "swarm-chain-swarm-graph-runtime",
            &["receipt-child-a", "receipt-child-b"],
        )?,
        dag_ordinal: 2,
        hlc_unix_ms: 1_800_000_000_500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: "task-child-a".to_string(),
                receipt_id: "receipt-child-a".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: "task-child-b".to_string(),
                receipt_id: "receipt-child-b".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        next_task_id: "task-root".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    join_receipt.signature = sign_swarm_join_receipt(&join_receipt, &swarm_witness_keypair())?;

    let mut revocation_epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: "revocation-epoch-runtime".to_string(),
        root_hash: revocation_root,
        issued_at_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    revocation_epoch.signature =
        sign_swarm_revocation_epoch(&revocation_epoch, &swarm_witness_keypair())?;

    let bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens: vec![continuation_a, continuation_b],
        witness_chains: vec![witness_chain_a, witness_chain_b],
        join_receipts: vec![join_receipt],
        route_plan_receipts: vec![
            runtime_swarm_route_plan_receipt(
                "route-child-a",
                "task-child-a",
                "mcp",
                "mcp://provider-runtime",
                b"runtime-swarm-candidates",
            )?,
            runtime_swarm_route_plan_receipt(
                "route-child-b",
                "task-child-b",
                "a2a",
                "a2a://provider-runtime",
                b"runtime-swarm-candidates-b",
            )?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-runtime".to_string(),
            graph_id: "swarm-graph-runtime".to_string(),
            currency: "USD".to_string(),
            total_units: 10_000,
            allocations: vec![
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-a".to_string(),
                    task_id: "task-child-a".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
            ],
        },
        revocation_epoch,
        terminal_receipts: vec![runtime_swarm_terminal_graph_receipt()?],
        now_unix_ms: 1_800_000_001_000,
    };

    if !stale_continuation {
        verify_swarm_authority_bundle(&bundle, &trusted_swarm_witness_keys()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("runtime swarm fixture invalid: {}", error.runtime_detail()),
            )
        })?;
    }

    Ok(bundle)
}

fn runtime_swarm_continuation(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    budget_allocation_id: &str,
    graph_sha256: &str,
    revocation_epoch_root_hash: &str,
    stale: bool,
) -> Result<SwarmContinuationToken, Box<dyn std::error::Error>> {
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some("task-root".to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-root".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: budget_allocation_id.to_string(),
        witness_chain_ref: None,
        witness_chain_sha256: None,
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        revocation_epoch_root_hash: revocation_epoch_root_hash.to_string(),
        session_anchor_ref: "session-anchor-runtime".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: if stale {
            1_800_000_000_999
        } else {
            1_800_003_600_000
        },
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    token.signature = sign_swarm_continuation_token(&token, &swarm_witness_keypair())?;
    Ok(token)
}

fn runtime_swarm_witness_chain(
    chain_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core_types::capability::attenuation::AttenuationWitness,
) -> Result<SwarmDelegationWitnessChain, Box<dyn std::error::Error>> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        parent_task_id: "task-root".to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(child_task_id.as_bytes()),
            parent_scope_hash: parent_scope_hash.to_string(),
            child_scope_hash: child_scope_hash.to_string(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof,
            expires_at_unix_ms: 1_800_003_600_000,
            issuer: swarm_witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        }],
    };
    chain.hops[0].witness_signature =
        sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], &swarm_witness_keypair())?;
    Ok(chain)
}

fn runtime_swarm_scope(max_invocations: u32) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn swarm_witness_keypair() -> Keypair {
    Keypair::from_seed(&[31u8; 32])
}

fn trusted_swarm_witness_keys() -> Vec<PublicKey> {
    vec![swarm_witness_keypair().public_key()]
}

fn swarm_witness_issuer() -> String {
    format!("did:chio:{}", swarm_witness_keypair().public_key().to_hex())
}

fn runtime_swarm_join_parent_set_hash(
    chain_id: &str,
    receipt_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut sorted_receipt_ids = receipt_ids.to_vec();
    sorted_receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": sorted_receipt_ids,
    });
    Ok(sha256_hex(&canonical_json_bytes(&body)?))
}

fn runtime_swarm_route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
    candidate_seed: &[u8],
) -> Result<SwarmRoutePlanReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(candidate_seed),
        registry_snapshot_hash: sha256_hex(b"runtime-swarm-registry"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_contract_id: format!("{bridge_id}:egress-contract-{task_id}"),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: 1_800_003_600_000,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_route_plan_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

fn runtime_swarm_terminal_graph_receipt(
) -> Result<SwarmTerminalGraphReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-swarm-runtime".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        terminal_task_ids: vec!["task-root".to_string()],
        completed_task_ids: vec![
            "task-root".to_string(),
            "task-child-a".to_string(),
            "task-child-b".to_string(),
        ],
        join_receipt_ids: vec!["join-child-results".to_string()],
        route_plan_receipt_ids: vec!["route-child-a".to_string(), "route-child-b".to_string()],
        budget_pool_id: "budget-pool-runtime".to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: 2_000,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 2_000,
        }],
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        completed_at_unix_ms: 1_800_000_000_500,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_terminal_graph_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

fn canonical_test_hash<T: serde::Serialize>(
    value: &T,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn runtime_swarm_revocation_root(
    revoked_subjects: &[&str],
    revoked_task_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut revoked_subjects = revoked_subjects.to_vec();
    let mut revoked_task_ids = revoked_task_ids.to_vec();
    revoked_subjects.sort_unstable();
    revoked_task_ids.sort_unstable();
    canonical_test_hash(&serde_json::json!({
        "revokedSubjects": revoked_subjects,
        "revokedTaskIds": revoked_task_ids,
    }))
}
