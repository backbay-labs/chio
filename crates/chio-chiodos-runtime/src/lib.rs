//! Live Chiodos runtime admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::ChioReceipt;
use chio_core_types::{PublicKey, SignedExportEnvelope};
use chio_kernel::{
    KernelError, RuntimeAdmissionContext as KernelRuntimeAdmissionContext,
    RuntimeAdmissionDecision as KernelRuntimeAdmissionDecision, RuntimeAdmissionHook,
    ToolCallRequest,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

mod admission_hook;
mod buyer;
mod error;
mod orchestration;
mod schema;
mod store;
pub(crate) mod treaty;
mod types;

pub use admission_hook::*;
pub use buyer::*;
pub use error::ChiodosRuntimeError;
pub use orchestration::*;
pub use schema::*;
pub use store::*;
pub use treaty::{
    bilateral_invocation_binding_sha256, compute_ladder_intersection,
    cross_boundary_admission_report_json, evaluate_cross_boundary_admission,
    governance_ladder_manifest_from_json, governance_ladder_manifest_sha256,
    ladder_intersection_from_json, ladder_intersection_json, ladder_intersection_semantic_sha256,
    ladder_intersection_sha256, receipt_lineage_bundle_from_json,
    receipt_lineage_statement_from_json, receipt_lineage_statement_sha256, treaty_scope_from_json,
    treaty_scope_semantic_intersection_sha256, treaty_scope_sha256,
    validate_cross_boundary_admission_report, validate_governance_ladder_manifest,
    validate_ladder_intersection, validate_treaty_scope,
};
pub use types::*;

pub struct RuntimeAdmissionInput<'a> {
    pub profile: &'a RuntimeAdmissionProfile,
    pub store: &'a dyn RuntimeAdmissionStore,
    pub admission_id: &'a str,
    pub request: &'a RuntimeRequestBinding,
    pub action_class_id: Option<&'a str>,
    pub runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    pub trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    pub pheromone_query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    pub runtime_pheromone_policy: Option<&'a SignedRuntimePheromonePolicy>,
    pub runtime_peer_weights: Option<&'a SignedRuntimePeerWeights>,
    pub now_unix_ms: u64,
}

pub fn runtime_admission_profile_from_json(
    json: &str,
) -> Result<RuntimeAdmissionProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_bundle_from_json(
    json: &str,
) -> Result<RuntimeAdmissionBundle, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_request_binding_from_json(
    json: &str,
) -> Result<RuntimeRequestBinding, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_packet_from_json(
    json: &str,
) -> Result<BuyerAttestationPacket, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_package_from_json(
    json: &str,
) -> Result<BuyerAttestationReviewPackage, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_verifier_trust_bundle_from_json(
    json: &str,
) -> Result<SignedRuntimeVerifierTrustBundle, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_trusted_verifier_keys_from_json(
    json: &str,
) -> Result<RuntimeTrustedVerifierKeysDocument, ChiodosRuntimeError> {
    let document: RuntimeTrustedVerifierKeysDocument =
        serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    if document.schema != CHIODOS_RUNTIME_TRUSTED_VERIFIERS_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_trusted_verifiers_schema",
            detail: format!(
                "runtime trusted verifiers document declared unsupported schema {}",
                document.schema
            ),
        });
    }
    let mut keys = BTreeSet::new();
    for key in &document.verifier_keys {
        let identity = format!("{}:{}", key.verifier_id, key.key_id);
        if !keys.insert(identity.clone()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_trusted_verifier_key",
                detail: format!("runtime trusted verifier key {identity} is duplicated"),
            });
        }
    }
    Ok(document)
}

pub fn signed_runtime_pheromone_policy_from_json(
    json: &str,
) -> Result<SignedRuntimePheromonePolicy, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_peer_weights_from_json(
    json: &str,
) -> Result<SignedRuntimePeerWeights, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_report_json(
    report: &RuntimeAdmissionReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn sign_runtime_admission_report(
    report: RuntimeAdmissionReport,
    keypair: &Keypair,
) -> Result<SignedRuntimeAdmissionReport, ChiodosRuntimeError> {
    SignedExportEnvelope::sign(report, keypair)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))
}

pub fn signed_runtime_admission_report_from_json(
    json: &str,
) -> Result<SignedRuntimeAdmissionReport, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_admission_report_json(
    report: &SignedRuntimeAdmissionReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn verify_signed_runtime_admission_report(
    report: &SignedRuntimeAdmissionReport,
) -> Result<bool, ChiodosRuntimeError> {
    report
        .verify_signature()
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))
}

pub fn runtime_pheromone_advisory_from_query_report_json(
    json: &str,
) -> Result<RuntimePheromoneAdvisory, ChiodosRuntimeError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    runtime_pheromone_advisory_from_query_report_value(&value)
}

pub fn signed_runtime_pheromone_query_report_from_json(
    json: &str,
) -> Result<SignedRuntimePheromoneQueryReport, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_pheromone_query_report_json(
    report: &SignedRuntimePheromoneQueryReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

fn runtime_pheromone_advisory_from_query_report_value(
    value: &serde_json::Value,
) -> Result<RuntimePheromoneAdvisory, ChiodosRuntimeError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    let schema = value.get("schema").and_then(|item| item.as_str());
    if schema != Some("chio.pheromone.query-report.v1") {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_pheromone_query_report_schema",
            detail: "runtime pheromone advisory requires chio.pheromone.query-report.v1"
                .to_string(),
        });
    }
    let concentration =
        value
            .get("concentration")
            .ok_or_else(|| ChiodosRuntimeError::Rejected {
                code: "missing_pheromone_concentration",
                detail: "runtime pheromone advisory query report is missing concentration"
                    .to_string(),
            })?;
    Ok(RuntimePheromoneAdvisory {
        source_report_sha256: sha256_hex(&canonical),
        accepted: value
            .get("accepted")
            .and_then(|item| item.as_bool())
            .unwrap_or(false),
        subject_class: required_string_any(concentration, &["subject_class", "subjectClass"])?,
        subject_class_namespace: required_string_any(
            concentration,
            &["subject_class_namespace", "subjectClassNamespace"],
        )?,
        total_strength: required_f64_any(concentration, &["total_strength", "totalStrength"])?,
        distinct_origin_pairs: required_u64_any(
            concentration,
            &["distinct_origin_pairs", "distinctOriginPairs"],
        )?,
        reputation_epoch: required_u64_any(
            concentration,
            &["reputation_epoch", "reputationEpoch"],
        )?,
        evaluated_at_unix_ms: required_u64_any(
            concentration,
            &["evaluated_at_unix_ms", "evaluatedAtUnixMs"],
        )?,
        observe_only: true,
    })
}

pub fn runtime_workflow_run_report_json(
    report: &RuntimeWorkflowRunReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_workflow_run_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_verification_report_json(
    report: &BuyerAttestationVerificationReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_buyer_attestation_verification_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_report_json(
    report: &BuyerAttestationReviewReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_buyer_attestation_review_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_report_json(
    report: &RuntimeProofRegenerationReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_regeneration_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_manifest_json(
    manifest: &RuntimeEvidenceManifest,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_evidence_manifest(manifest)?;
    serde_json::to_string_pretty(manifest)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_input_json(
    input: &RuntimeProofRegenerationInput,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_regeneration_input(input)?;
    serde_json::to_string_pretty(input)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_parity_report_json(
    report: &RuntimeProofParityReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_parity_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_profile_from_json(
    json: &str,
) -> Result<RuntimeOrchestrationProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_run_contract_from_json(
    json: &str,
) -> Result<RuntimeRunContract, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_supervisor_profile_from_json(
    json: &str,
) -> Result<RuntimeSupervisorProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_profile_from_json(
    json: &str,
) -> Result<RuntimeArtifactRetentionProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_bindings_from_json(
    json: &str,
) -> Result<RuntimeProviderBindingsDocument, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_profile_sha256(
    profile: &RuntimeOrchestrationProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_run_contract_sha256(
    contract: &RuntimeRunContract,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(contract)
}

pub fn runtime_supervisor_profile_sha256(
    profile: &RuntimeSupervisorProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_artifact_retention_profile_sha256(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_orchestration_plan_json(
    plan: &RuntimeOrchestrationPlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_run_report_json(
    report: &RuntimeOrchestrationRunReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_run_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_resume_plan_json(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_resume_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_status_report_json(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_status_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_drift_report_json(
    report: &RuntimeProofDriftReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_drift_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_scheduler_tick_report_json(
    report: &RuntimeSchedulerTickReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_scheduler_tick_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_sink_health_report_json(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_evidence_sink_health_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_recovery_drill_report_json(
    report: &RuntimeRecoveryDrillReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_recovery_drill_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_plan_json(
    report: &RuntimeArtifactRetentionPlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_artifact_retention_plan(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_health_report_json(
    report: &RuntimeProviderHealthReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_provider_health_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_ops_status_report_json(
    report: &RuntimeOpsStatusReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_ops_status_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_packet_sha256(
    packet: &BuyerAttestationPacket,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(packet)
}

pub fn build_runtime_orchestration_plan(
    profile: &RuntimeOrchestrationProfile,
    contract: &RuntimeRunContract,
    now_unix_ms: u64,
) -> Result<RuntimeOrchestrationPlan, ChiodosRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    validate_runtime_run_contract(contract)?;
    let profile_sha256 = runtime_orchestration_profile_sha256(profile)?;
    if contract.profile_sha256 != profile_sha256 {
        return Ok(RuntimeOrchestrationPlan {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
            run_id: contract.run_id.clone(),
            accepted: false,
            failure_code: Some("runtime_orchestration_profile_hash_mismatch".to_string()),
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            run_contract_sha256: runtime_run_contract_sha256(contract)?,
            planned_steps: Vec::new(),
            checks: vec!["runtime_orchestration.profile_hash".to_string()],
        });
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Ok(RuntimeOrchestrationPlan {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
            run_id: contract.run_id.clone(),
            accepted: false,
            failure_code: Some("runtime_orchestration_profile_stale".to_string()),
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            run_contract_sha256: runtime_run_contract_sha256(contract)?,
            planned_steps: Vec::new(),
            checks: vec![
                "runtime_orchestration.profile_hash".to_string(),
                "runtime_orchestration.profile_freshness".to_string(),
            ],
        });
    }
    let planned_steps = contract
        .admission_ids
        .iter()
        .enumerate()
        .map(|(index, admission_id)| RuntimeOrchestrationPlannedStep {
            step_index: u64::try_from(index).unwrap_or(u64::MAX),
            admission_id: admission_id.clone(),
            state: "pending".to_string(),
        })
        .collect();
    Ok(RuntimeOrchestrationPlan {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: now_unix_ms,
        profile_sha256,
        run_contract_sha256: runtime_run_contract_sha256(contract)?,
        planned_steps,
        checks: vec![
            "runtime_orchestration.profile_valid".to_string(),
            "runtime_orchestration.run_contract_valid".to_string(),
        ],
    })
}

pub fn generate_runtime_proof_drift_report(
    baseline_manifest: &RuntimeEvidenceManifest,
    candidate_manifest: &RuntimeEvidenceManifest,
    baseline_proof: &RuntimeProofRegenerationReport,
    candidate_proof: &RuntimeProofRegenerationReport,
    now_unix_ms: u64,
) -> Result<RuntimeProofDriftReport, ChiodosRuntimeError> {
    validate_runtime_evidence_manifest(baseline_manifest)?;
    validate_runtime_evidence_manifest(candidate_manifest)?;
    validate_runtime_proof_regeneration_report(baseline_proof)?;
    validate_runtime_proof_regeneration_report(candidate_proof)?;
    let mut semantic_drifts = Vec::new();
    let mut artifact_drifts = Vec::new();
    let mut verifier_drifts = Vec::new();

    compare_semantic_field(
        "baseline_manifest_proof_run_id",
        &baseline_manifest.run_id,
        &baseline_proof.run_id,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "candidate_manifest_proof_run_id",
        &candidate_manifest.run_id,
        &candidate_proof.run_id,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "proof_package_sha256",
        &baseline_proof.proof_package_sha256,
        &candidate_proof.proof_package_sha256,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "workflow_receipt_sha256",
        &baseline_proof.workflow_receipt_sha256,
        &candidate_proof.workflow_receipt_sha256,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "source_records",
        &baseline_proof.source_records,
        &candidate_proof.source_records,
        &mut semantic_drifts,
    )?;
    compare_verifier_field(
        "verifier_report_sha256",
        &baseline_proof.verifier_report_sha256,
        &candidate_proof.verifier_report_sha256,
        &mut verifier_drifts,
    )?;
    let baseline_entries: BTreeMap<(&str, &str), &RuntimeEvidenceManifestEntry> = baseline_manifest
        .entries
        .iter()
        .map(|entry| ((entry.role.as_str(), entry.path.as_str()), entry))
        .collect();
    let candidate_entries: BTreeMap<(&str, &str), &RuntimeEvidenceManifestEntry> =
        candidate_manifest
            .entries
            .iter()
            .map(|entry| ((entry.role.as_str(), entry.path.as_str()), entry))
            .collect();
    for (key, baseline_entry) in &baseline_entries {
        if let Some(candidate_entry) = candidate_entries.get(key) {
            if baseline_entry.sha256 != candidate_entry.sha256
                && !is_timestamped_runtime_report_artifact(baseline_entry)
            {
                artifact_drifts.push(RuntimeProofArtifactDrift {
                    role: baseline_entry.role.clone(),
                    path: baseline_entry.path.clone(),
                    baseline_sha256: baseline_entry.sha256.clone(),
                    candidate_sha256: candidate_entry.sha256.clone(),
                });
            }
        } else {
            artifact_drifts.push(RuntimeProofArtifactDrift {
                role: baseline_entry.role.clone(),
                path: baseline_entry.path.clone(),
                baseline_sha256: baseline_entry.sha256.clone(),
                candidate_sha256: "0".repeat(64),
            });
        }
    }
    for (key, candidate_entry) in &candidate_entries {
        if !baseline_entries.contains_key(key) {
            artifact_drifts.push(RuntimeProofArtifactDrift {
                role: candidate_entry.role.clone(),
                path: candidate_entry.path.clone(),
                baseline_sha256: "0".repeat(64),
                candidate_sha256: candidate_entry.sha256.clone(),
            });
        }
    }
    let accepted =
        semantic_drifts.is_empty() && artifact_drifts.is_empty() && verifier_drifts.is_empty();
    let report = RuntimeProofDriftReport {
        schema: CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA.to_string(),
        baseline_run_id: baseline_manifest.run_id.clone(),
        candidate_run_id: candidate_manifest.run_id.clone(),
        accepted,
        failure_code: if accepted {
            None
        } else {
            Some("runtime_proof_drift_detected".to_string())
        },
        generated_at_unix_ms: now_unix_ms,
        baseline_manifest_sha256: canonical_sha256(baseline_manifest)?,
        candidate_manifest_sha256: canonical_sha256(candidate_manifest)?,
        baseline_proof_regeneration_report_sha256: canonical_sha256(baseline_proof)?,
        candidate_proof_regeneration_report_sha256: canonical_sha256(candidate_proof)?,
        comparison_profile: "local-repeat-deterministic-v1".to_string(),
        normalized_fields: vec![
            "generatedAtUnixMs".to_string(),
            "timestampedReportArtifacts".to_string(),
        ],
        semantic_drifts,
        artifact_drifts,
        verifier_drifts,
    };
    validate_runtime_proof_drift_report(&report)?;
    Ok(report)
}

fn is_timestamped_runtime_report_artifact(entry: &RuntimeEvidenceManifestEntry) -> bool {
    matches!(
        (entry.role.as_str(), entry.path.as_str()),
        (
            "proof_regeneration_report",
            "proof-regeneration-report.json"
        ) | ("runtime_run_report", "runtime-run-report.json")
            | ("workflow_run_report", "workflow-run-report.json")
    )
}

pub fn generate_runtime_evidence_sink_health_report(
    run_id: &str,
    evidence_root: &Path,
    manifest: &RuntimeEvidenceManifest,
    required_roles: &[String],
    now_unix_ms: u64,
    perform_write_probe: bool,
) -> Result<RuntimeEvidenceSinkHealthReport, ChiodosRuntimeError> {
    validate_non_empty(run_id, "runtime_evidence_health_empty_run_id")?;
    validate_runtime_evidence_manifest(manifest)?;
    let manifest_run_mismatch = manifest.run_id != run_id;
    let mut missing_roles = Vec::new();
    for role in required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
        if !manifest.entries.iter().any(|entry| entry.role == *role) {
            missing_roles.push(role.clone());
        }
    }
    let mut missing_artifacts = Vec::new();
    let mut artifact_hash_mismatches = Vec::new();
    let mut artifact_byte_count_mismatches = Vec::new();
    for entry in &manifest.entries {
        let path = evidence_root.join(&entry.path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                missing_artifacts.push(entry.path.clone());
                continue;
            }
        };
        if sha256_hex(&bytes) != entry.sha256 {
            artifact_hash_mismatches.push(entry.path.clone());
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.byte_count {
            artifact_byte_count_mismatches.push(entry.path.clone());
        }
    }
    let (temp_write_ok, atomic_rename_ok) = if perform_write_probe {
        evidence_sink_write_probe(evidence_root)
    } else {
        (true, true)
    };
    let failure_code = if manifest_run_mismatch {
        Some("runtime_evidence_manifest_run_mismatch".to_string())
    } else if !missing_roles.is_empty() {
        Some("runtime_evidence_missing_required_role".to_string())
    } else if !missing_artifacts.is_empty() || !temp_write_ok || !atomic_rename_ok {
        Some("runtime_evidence_sink_unavailable".to_string())
    } else if !artifact_hash_mismatches.is_empty() {
        Some("runtime_evidence_artifact_hash_mismatch".to_string())
    } else if !artifact_byte_count_mismatches.is_empty() {
        Some("runtime_evidence_artifact_byte_count_mismatch".to_string())
    } else {
        None
    };
    let report = RuntimeEvidenceSinkHealthReport {
        schema: CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        accepted: failure_code.is_none(),
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        evidence_root_sha256: sha256_hex(evidence_root.to_string_lossy().as_bytes()),
        required_roles: required_roles.to_vec(),
        missing_roles,
        missing_artifacts,
        artifact_hash_mismatches,
        artifact_byte_count_mismatches,
        unexpected_paths: Vec::new(),
        temp_write_ok,
        atomic_rename_ok,
        checks: vec!["runtime_ops.evidence_sink_health".to_string()],
    };
    validate_runtime_evidence_sink_health_report(&report)?;
    Ok(report)
}

pub fn generate_runtime_provider_health_report(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChiodosRuntimeError> {
    validate_runtime_supervisor_profile(profile)?;
    validate_runtime_provider_bindings(bindings)?;
    let profile_stale =
        now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
    let mut degraded_provider_ids = Vec::new();
    for binding in &bindings.bindings {
        if binding.discovery_allowed {
            degraded_provider_ids.push(binding.provider_id.clone());
        }
        if binding.local_kernel_id != profile.local_kernel_id {
            degraded_provider_ids.push(binding.provider_id.clone());
        }
    }
    degraded_provider_ids.sort();
    degraded_provider_ids.dedup();
    let failure_code = if profile_stale {
        Some("runtime_provider_supervisor_profile_stale".to_string())
    } else if bindings
        .bindings
        .iter()
        .any(|binding| binding.discovery_allowed)
    {
        Some("runtime_provider_discovery_not_allowed".to_string())
    } else if !degraded_provider_ids.is_empty() {
        Some("runtime_provider_health_degraded".to_string())
    } else {
        None
    };
    let checked_provider_count = u64::try_from(bindings.bindings.len()).unwrap_or(u64::MAX);
    let degraded_count = u64::try_from(degraded_provider_ids.len()).unwrap_or(u64::MAX);
    let report = RuntimeProviderHealthReport {
        schema: CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: failure_code.is_none(),
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        provider_bindings_sha256: canonical_sha256(bindings)?,
        checked_provider_count,
        healthy_provider_count: checked_provider_count.saturating_sub(degraded_count),
        degraded_provider_ids,
        checks: vec!["runtime_ops.provider_bindings_static".to_string()],
    };
    validate_runtime_provider_health_report(&report)?;
    Ok(report)
}

pub fn generate_runtime_artifact_retention_plan(
    profile: &RuntimeArtifactRetentionProfile,
    run_ids: &[String],
    now_unix_ms: u64,
) -> Result<RuntimeArtifactRetentionPlan, ChiodosRuntimeError> {
    validate_runtime_artifact_retention_profile(profile)?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        let report = RuntimeArtifactRetentionPlan {
            schema: CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA.to_string(),
            accepted: false,
            failure_code: Some("runtime_retention_profile_stale".to_string()),
            generated_at_unix_ms: now_unix_ms,
            retention_profile_sha256: canonical_sha256(profile)?,
            retain_count: 0,
            blocked_count: 0,
            quarantine_count: 0,
            expiring_soon_count: 0,
            eligible_for_operator_review_count: 0,
            candidate_actions: Vec::new(),
            checks: vec!["runtime_ops.retention_profile_window".to_string()],
        };
        validate_runtime_artifact_retention_plan(&report)?;
        return Ok(report);
    }
    let mut candidate_actions = Vec::new();
    for run_id in run_ids {
        validate_non_empty(run_id, "runtime_retention_empty_run_id")?;
        let action = if profile.legal_hold {
            "blocked"
        } else {
            "retain"
        };
        let reason_code = if profile.legal_hold {
            "runtime_retention_legal_hold"
        } else {
            "runtime_retention_dry_run_only"
        };
        candidate_actions.push(RuntimeArtifactRetentionAction {
            run_id: run_id.clone(),
            action: action.to_string(),
            reason_code: reason_code.to_string(),
        });
    }
    let blocked_count = candidate_actions
        .iter()
        .filter(|action| action.action == "blocked")
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let retain_count = candidate_actions
        .iter()
        .filter(|action| action.action == "retain")
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let report = RuntimeArtifactRetentionPlan {
        schema: CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA.to_string(),
        accepted: profile.dry_run_only,
        failure_code: if profile.dry_run_only {
            None
        } else {
            Some("runtime_retention_mutation_not_allowed".to_string())
        },
        generated_at_unix_ms: now_unix_ms,
        retention_profile_sha256: canonical_sha256(profile)?,
        retain_count,
        blocked_count,
        quarantine_count: 0,
        expiring_soon_count: 0,
        eligible_for_operator_review_count: 0,
        candidate_actions,
        checks: vec!["runtime_ops.retention_dry_run".to_string()],
    };
    validate_runtime_artifact_retention_plan(&report)?;
    Ok(report)
}

pub fn validate_runtime_orchestration_profile(
    profile: &RuntimeOrchestrationProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_profile_schema",
            detail: format!(
                "runtime orchestration profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(
        &profile.profile_id,
        "runtime_orchestration_profile_empty_id",
    )?;
    validate_non_empty(
        &profile.local_kernel_id,
        "runtime_orchestration_profile_empty_kernel",
    )?;
    validate_non_empty(
        &profile.verifier_id,
        "runtime_orchestration_profile_empty_verifier",
    )?;
    validate_state_label(&profile.mode, "runtime_orchestration_profile_invalid_mode")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_invalid_window",
            detail: "runtime orchestration profile issued time must precede expiry".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_zero_concurrency",
            detail: "runtime orchestration profile must allow at least one local run".to_string(),
        });
    }
    let mut codes = BTreeSet::new();
    for code in &profile.fail_closed_on {
        validate_state_label(
            code,
            "runtime_orchestration_profile_invalid_fail_closed_code",
        )?;
        if !codes.insert(code.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_profile_duplicate_fail_closed_code",
                detail: format!("runtime orchestration fail-closed code {code} is duplicated"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_profile_fresh(
    profile: &RuntimeOrchestrationProfile,
    now_unix_ms: u64,
) -> Result<(), ChiodosRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_stale",
            detail: "runtime orchestration profile is not fresh".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_run_contract(
    contract: &RuntimeRunContract,
) -> Result<(), ChiodosRuntimeError> {
    if contract.schema != CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_contract_schema",
            detail: format!(
                "runtime run contract declared unsupported schema {}",
                contract.schema
            ),
        });
    }
    validate_non_empty(&contract.run_id, "runtime_run_contract_empty_run_id")?;
    ensure_sha256_hash(
        &contract.profile_sha256,
        "runtime_run_contract_invalid_profile_hash",
    )?;
    validate_non_empty(&contract.workflow_id, "runtime_run_contract_empty_workflow")?;
    validate_non_empty(&contract.store_id, "runtime_run_contract_empty_store")?;
    validate_non_empty(
        &contract.evidence_sink_id,
        "runtime_run_contract_empty_evidence_sink",
    )?;
    if contract.expected_step_count == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_zero_steps",
            detail: "runtime run contract must expect at least one step".to_string(),
        });
    }
    if contract.admission_ids.len() != usize::try_from(contract.expected_step_count).unwrap_or(0) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_step_count_mismatch",
            detail: "runtime run contract admission ids must match expected step count".to_string(),
        });
    }
    let mut ids = BTreeSet::new();
    for id in &contract.admission_ids {
        validate_non_empty(id, "runtime_run_contract_empty_admission_id")?;
        if !ids.insert(id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_contract_duplicate_admission_id",
                detail: format!("runtime run contract repeats admission id {id}"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_plan(
    plan: &RuntimeOrchestrationPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_plan_schema",
            detail: format!(
                "runtime orchestration plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_plan_missing_failure_code",
        "runtime_orchestration_plan_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_plan_empty_run_id")?;
    ensure_sha256_hash(
        &plan.profile_sha256,
        "runtime_orchestration_plan_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &plan.run_contract_sha256,
        "runtime_orchestration_plan_invalid_contract_hash",
    )?;
    if plan.accepted && plan.planned_steps.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_plan_missing_steps",
            detail: "accepted runtime orchestration plan must carry planned steps".to_string(),
        });
    }
    validate_planned_steps(&plan.planned_steps)
}

pub fn validate_runtime_orchestration_run_report(
    report: &RuntimeOrchestrationRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_run_report_schema",
            detail: format!(
                "runtime orchestration run report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_orchestration_run_empty_id")?;
    validate_state_label(&report.status, "runtime_orchestration_run_invalid_status")?;
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_run_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.run_contract_sha256,
        "runtime_orchestration_run_invalid_contract_hash",
    )?;
    ensure_optional_sha256(
        report.workflow_run_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_workflow_hash",
    )?;
    ensure_optional_sha256(
        report.evidence_manifest_sha256.as_deref(),
        "runtime_orchestration_run_invalid_manifest_hash",
    )?;
    ensure_optional_sha256(
        report.proof_regeneration_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_proof_hash",
    )?;
    ensure_optional_sha256(
        report.verifier_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_verifier_hash",
    )?;
    if report.accepted && report.status != "proof_accepted" {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_accepted_without_proof",
            detail: "accepted runtime orchestration run must be proof_accepted".to_string(),
        });
    }
    if report.accepted
        && (report.workflow_run_report_sha256.is_none()
            || report.evidence_manifest_sha256.is_none()
            || report.proof_regeneration_report_sha256.is_none()
            || report.verifier_report_sha256.is_none())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_accepted_hash",
            detail: "accepted runtime orchestration run must bind proof artifacts".to_string(),
        });
    }
    if report.accepted && report.step_states.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_steps",
            detail: "accepted runtime orchestration run must carry step states".to_string(),
        });
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_states {
        validate_runtime_orchestration_step_state(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_run_duplicate_step",
                detail: format!("runtime orchestration run repeats step {}", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_resume_plan(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_resume_plan_schema",
            detail: format!(
                "runtime orchestration resume plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_resume_missing_failure_code",
        "runtime_orchestration_resume_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_resume_empty_run_id")?;
    if plan.accepted && plan.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_resume_accepted_blocked",
            detail: "accepted runtime orchestration resume plan cannot be blocked".to_string(),
        });
    }
    Ok(())
}

fn validate_acceptance_failure_code(
    accepted: bool,
    failure_code: Option<&str>,
    missing_code: &'static str,
    unexpected_code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if accepted && failure_code.is_some() {
        return Err(ChiodosRuntimeError::Rejected {
            code: unexpected_code,
            detail: "accepted runtime report cannot carry a failure code".to_string(),
        });
    }
    if !accepted && failure_code.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: missing_code,
            detail: "rejected runtime report must carry a failure code".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_orchestration_status_report(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_status_report_schema",
            detail: format!(
                "runtime orchestration status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_status_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.store_path_sha256,
        "runtime_orchestration_status_invalid_store_hash",
    )?;
    validate_state_label(
        &report.store_backend,
        "runtime_orchestration_status_invalid_store_backend",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_orchestration_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_orchestration_status_missing_failure_code",
        "runtime_orchestration_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_status_accepted_degraded",
            detail: "accepted runtime orchestration status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_drift_report_schema",
            detail: format!(
                "runtime proof drift report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(
        &report.baseline_run_id,
        "runtime_proof_drift_empty_baseline",
    )?;
    validate_non_empty(
        &report.candidate_run_id,
        "runtime_proof_drift_empty_candidate",
    )?;
    ensure_sha256_hash(
        &report.baseline_manifest_sha256,
        "runtime_proof_drift_invalid_baseline_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_manifest_sha256,
        "runtime_proof_drift_invalid_candidate_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.baseline_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_baseline_proof_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_candidate_proof_hash",
    )?;
    for drift in &report.semantic_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.verifier_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.artifact_drifts {
        validate_non_empty(&drift.role, "runtime_proof_drift_empty_artifact_role")?;
        validate_relative_evidence_path(&drift.path, "runtime_proof_drift_invalid_artifact_path")?;
        ensure_sha256_hash(
            &drift.baseline_sha256,
            "runtime_proof_drift_invalid_baseline_artifact_hash",
        )?;
        ensure_sha256_hash(
            &drift.candidate_sha256,
            "runtime_proof_drift_invalid_candidate_artifact_hash",
        )?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_drift_missing_failure_code",
        "runtime_proof_drift_unexpected_failure_code",
    )?;
    if report.accepted
        && (!report.semantic_drifts.is_empty()
            || !report.artifact_drifts.is_empty()
            || !report.verifier_drifts.is_empty())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_drift_accepted_with_drifts",
            detail: "accepted runtime proof drift report cannot carry drift rows".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_supervisor_profile(
    profile: &RuntimeSupervisorProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_supervisor_profile_schema",
            detail: format!(
                "runtime supervisor profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_supervisor_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_supervisor_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_window",
            detail: "runtime supervisor profile validity window is invalid".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0
        || profile.run_lease_ttl_ms == 0
        || profile.stale_run_after_ms == 0
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_limits",
            detail: "runtime supervisor profile limits must be positive".to_string(),
        });
    }
    for role in &profile.evidence_required_roles {
        validate_state_label(role, "runtime_supervisor_invalid_required_role")?;
    }
    for code in &profile.fail_closed_on {
        validate_state_label(code, "runtime_supervisor_invalid_fail_closed_code")?;
    }
    Ok(())
}

pub fn validate_runtime_run_lease(lease: &RuntimeRunLease) -> Result<(), ChiodosRuntimeError> {
    if lease.schema != CHIODOS_RUNTIME_RUN_LEASE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_lease_schema",
            detail: format!(
                "runtime run lease declared unsupported schema {}",
                lease.schema
            ),
        });
    }
    validate_non_empty(&lease.run_id, "runtime_run_lease_empty_run_id")?;
    validate_non_empty(&lease.lease_id, "runtime_run_lease_empty_lease_id")?;
    validate_non_empty(&lease.owner_id, "runtime_run_lease_empty_owner")?;
    validate_state_label(&lease.state, "runtime_run_lease_invalid_state")?;
    if lease.acquired_at_unix_ms > lease.heartbeat_at_unix_ms
        || lease.heartbeat_at_unix_ms > lease.expires_at_unix_ms
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_lease_invalid_time_order",
            detail: "runtime run lease timestamps are not ordered".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_scheduler_tick_report(
    report: &RuntimeSchedulerTickReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_scheduler_tick_report_schema",
            detail: format!(
                "runtime scheduler tick report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.tick_id, "runtime_scheduler_empty_tick_id")?;
    validate_non_empty(&report.owner_id, "runtime_scheduler_empty_owner")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_scheduler_missing_failure_code",
        "runtime_scheduler_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_evidence_sink_health_report(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_sink_health_report_schema",
            detail: format!(
                "runtime evidence sink health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_evidence_health_empty_run_id")?;
    ensure_sha256_hash(
        &report.evidence_root_sha256,
        "runtime_evidence_health_invalid_root_hash",
    )?;
    for role in &report.required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
    }
    for path in report
        .missing_artifacts
        .iter()
        .chain(report.artifact_hash_mismatches.iter())
        .chain(report.artifact_byte_count_mismatches.iter())
        .chain(report.unexpected_paths.iter())
    {
        validate_relative_evidence_path(path, "runtime_evidence_health_invalid_path")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_evidence_health_missing_failure_code",
        "runtime_evidence_health_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_recovery_drill_report(
    report: &RuntimeRecoveryDrillReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_recovery_drill_report_schema",
            detail: format!(
                "runtime recovery drill report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_recovery_empty_run_id")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_recovery_missing_failure_code",
        "runtime_recovery_unexpected_failure_code",
    )?;
    if report.accepted && report.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_recovery_accepted_blocked",
            detail: "accepted runtime recovery drill cannot be blocked".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_profile(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_profile_schema",
            detail: format!(
                "runtime retention profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_retention_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_retention_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_invalid_window",
            detail: "runtime retention profile validity window is invalid".to_string(),
        });
    }
    if !profile.dry_run_only {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_mutation_not_allowed",
            detail: "runtime retention planning must be dry-run only".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_plan(
    plan: &RuntimeArtifactRetentionPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_plan_schema",
            detail: format!(
                "runtime retention plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_retention_plan_missing_failure_code",
        "runtime_retention_plan_unexpected_failure_code",
    )?;
    ensure_sha256_hash(
        &plan.retention_profile_sha256,
        "runtime_retention_invalid_profile_hash",
    )?;
    for action in &plan.candidate_actions {
        validate_non_empty(&action.run_id, "runtime_retention_empty_run_id")?;
        validate_state_label(&action.action, "runtime_retention_invalid_action")?;
        validate_state_label(&action.reason_code, "runtime_retention_invalid_reason")?;
    }
    Ok(())
}

pub fn validate_runtime_provider_bindings(
    document: &RuntimeProviderBindingsDocument,
) -> Result<(), ChiodosRuntimeError> {
    if document.schema != CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_bindings_schema",
            detail: format!(
                "runtime provider bindings declared unsupported schema {}",
                document.schema
            ),
        });
    }
    let mut provider_ids = BTreeSet::new();
    for binding in &document.bindings {
        validate_non_empty(&binding.provider_id, "runtime_provider_empty_id")?;
        validate_non_empty(&binding.local_kernel_id, "runtime_provider_empty_kernel")?;
        validate_non_empty(&binding.server_id, "runtime_provider_empty_server")?;
        validate_non_empty(&binding.tool_name, "runtime_provider_empty_tool")?;
        if !provider_ids.insert(binding.provider_id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_provider_duplicate_id",
                detail: format!("runtime provider binding repeats {}", binding.provider_id),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_provider_health_report(
    report: &RuntimeProviderHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_health_report_schema",
            detail: format!(
                "runtime provider health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.provider_bindings_sha256,
        "runtime_provider_health_invalid_bindings_hash",
    )?;
    for provider_id in &report.degraded_provider_ids {
        validate_non_empty(provider_id, "runtime_provider_health_empty_degraded_id")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_provider_health_missing_failure_code",
        "runtime_provider_health_unexpected_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_ops_status_report(
    report: &RuntimeOpsStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_ops_status_report_schema",
            detail: format!(
                "runtime ops status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.supervisor_profile_sha256,
        "runtime_ops_status_invalid_profile_hash",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_ops_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_ops_status_missing_failure_code",
        "runtime_ops_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_ops_status_accepted_degraded",
            detail: "accepted runtime ops status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_workflow_run_report(
    report: &RuntimeWorkflowRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_workflow_report_schema",
            detail: format!(
                "runtime workflow report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    if !is_sha256_hex(&report.admission_report_sha256) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_invalid_admission_report_hash",
            detail: "runtime workflow report admission report hash is not sha256 hex".to_string(),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_workflow_missing_failure_code",
        "runtime_workflow_unexpected_failure_code",
    )?;
    if report.accepted && report.step_evidence.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_step_evidence",
            detail: "accepted runtime workflow report must carry step evidence".to_string(),
        });
    }
    if report.accepted && report.proof_regeneration_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_proof_regeneration_report",
            detail: "accepted runtime workflow report must bind proof regeneration report"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_regeneration_report_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_workflow_invalid_proof_regeneration_hash")?;
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_evidence {
        validate_runtime_step_evidence(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_workflow_duplicate_step_evidence",
                detail: format!("runtime workflow step {} is duplicated", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_evidence_manifest(
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChiodosRuntimeError> {
    if manifest.schema != CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_manifest_schema",
            detail: format!(
                "runtime evidence manifest declared unsupported schema {}",
                manifest.schema
            ),
        });
    }
    ensure_sha256_hash(
        &manifest.workflow_run_report_sha256,
        "runtime_evidence_manifest_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &manifest.proof_regeneration_report_sha256,
        "runtime_evidence_manifest_invalid_proof_report_hash",
    )?;
    if manifest.entries.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_evidence_manifest_missing_entries",
            detail: "runtime evidence manifest must bind at least one artifact".to_string(),
        });
    }
    let mut paths = BTreeSet::new();
    for entry in &manifest.entries {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        if entry.role.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_empty_role",
                detail: "runtime evidence manifest entry role is empty".to_string(),
            });
        }
        if !paths.insert(entry.path.clone()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_duplicate_path",
                detail: format!(
                    "runtime evidence manifest carries duplicate path {}",
                    entry.path
                ),
            });
        }
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
    }
    Ok(())
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChiodosRuntimeError> {
    if input.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_input_schema",
            detail: format!(
                "runtime proof regeneration input declared unsupported schema {}",
                input.schema
            ),
        });
    }
    ensure_sha256_hash(
        &input.evidence_manifest_sha256,
        "runtime_proof_regeneration_input_invalid_manifest_hash",
    )?;
    ensure_sha256_hash(
        &input.workflow_run_report_sha256,
        "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &input.admission_report_sha256,
        "runtime_proof_regeneration_input_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &input.trust_bundle_sha256,
        "runtime_proof_regeneration_input_invalid_trust_bundle_hash",
    )?;
    ensure_sha256_hash(
        &input.verification_context_sha256,
        "runtime_proof_regeneration_input_invalid_context_hash",
    )?;
    if input.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_input_missing_source_records",
            detail: "runtime proof regeneration input must carry source records".to_string(),
        });
    }
    validate_runtime_proof_source_records(&input.source_records)
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_report_schema",
            detail: format!(
                "runtime proof regeneration report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_regeneration_missing_failure_code",
        "runtime_proof_regeneration_unexpected_failure_code",
    )?;
    if report.accepted && report.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_source_records",
            detail: "accepted runtime proof regeneration report must carry source records"
                .to_string(),
        });
    }
    if report.accepted && report.proof_package_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_package_hash",
            detail: "accepted runtime proof regeneration report must bind proof package hash"
                .to_string(),
        });
    }
    if report.accepted && report.verifier_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_verifier_report_hash",
            detail: "accepted runtime proof regeneration report must bind verifier report hash"
                .to_string(),
        });
    }
    if report.accepted && report.workflow_receipt_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_workflow_receipt_hash",
            detail: "accepted runtime proof regeneration report must bind workflow receipt hash"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_package_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_proof_regeneration_invalid_package_hash")?;
    }
    if let Some(hash) = report.verifier_report_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_verifier_report_hash",
        )?;
    }
    if let Some(hash) = report.workflow_receipt_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_workflow_receipt_hash",
        )?;
    }
    validate_runtime_proof_source_records(&report.source_records)?;
    Ok(())
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_parity_report_schema",
            detail: format!(
                "runtime proof parity report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.static_proof_package_sha256,
        "runtime_proof_parity_invalid_static_package_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_proof_package_sha256,
        "runtime_proof_parity_invalid_runtime_package_hash",
    )?;
    ensure_sha256_hash(
        &report.static_verifier_report_sha256,
        "runtime_proof_parity_invalid_static_report_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_verifier_report_sha256,
        "runtime_proof_parity_invalid_runtime_report_hash",
    )?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_parity_missing_failure_code",
        "runtime_proof_parity_unexpected_failure_code",
    )?;
    if report.compared_fields.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_missing_compared_fields",
            detail: "runtime proof parity report must name compared fields".to_string(),
        });
    }
    if report.accepted && !report.mismatches.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_accepted_with_mismatches",
            detail: "accepted runtime proof parity report cannot carry mismatches".to_string(),
        });
    }
    for mismatch in &report.mismatches {
        if mismatch.field.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_parity_empty_mismatch_field",
                detail: "runtime proof parity mismatch field is empty".to_string(),
            });
        }
        ensure_sha256_hash(
            &mismatch.static_value_sha256,
            "runtime_proof_parity_invalid_static_value_hash",
        )?;
        ensure_sha256_hash(
            &mismatch.runtime_value_sha256,
            "runtime_proof_parity_invalid_runtime_value_hash",
        )?;
    }
    Ok(())
}

fn validate_runtime_proof_source_records(
    source_records: &[RuntimeProofSourceRecord],
) -> Result<(), ChiodosRuntimeError> {
    let mut step_indices = BTreeSet::new();
    for record in source_records {
        if !step_indices.insert(record.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_regeneration_duplicate_source_record",
                detail: format!(
                    "runtime proof source record step {} is duplicated",
                    record.step_index
                ),
            });
        }
        ensure_sha256_hash(
            &record.admission_report_sha256,
            "runtime_proof_regeneration_invalid_admission_hash",
        )?;
        ensure_sha256_hash(
            &record.tool_receipt_sha256,
            "runtime_proof_regeneration_invalid_tool_receipt_hash",
        )?;
        ensure_sha256_hash(
            &record.bilateral_dsse_sha256,
            "runtime_proof_regeneration_invalid_dsse_hash",
        )?;
        ensure_sha256_hash(
            &record.workflow_step_sha256,
            "runtime_proof_regeneration_invalid_workflow_step_hash",
        )?;
    }
    Ok(())
}

pub(crate) fn validate_relative_evidence_path(
    path: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains("//")
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime evidence path {path:?} is not a safe relative path"),
        });
    }
    Ok(())
}

pub fn evaluate_runtime_admission(
    input: RuntimeAdmissionInput<'_>,
) -> Result<RuntimeAdmissionReport, ChiodosRuntimeError> {
    let mut checks = Vec::new();
    if input.profile.schema != CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA {
        return Ok(rejected_report(
            input.admission_id,
            "unsupported_profile_schema",
            checks,
        ));
    }
    checks.push(passed("profile.schema"));
    if input.now_unix_ms < input.profile.issued_at_unix_ms
        || input.now_unix_ms >= input.profile.expires_at_unix_ms
    {
        return Ok(rejected_report(input.admission_id, "stale_profile", checks));
    }
    checks.push(passed("profile.freshness"));

    let Some(bundle) = input.store.bundle(input.admission_id)? else {
        return Ok(rejected_report(
            input.admission_id,
            "missing_admission_bundle",
            checks,
        ));
    };
    if bundle.schema != CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA {
        return Ok(rejected_report(
            input.admission_id,
            "unsupported_bundle_schema",
            checks,
        ));
    }
    checks.push(passed("bundle.schema"));

    let mut trust_floor_update = None;
    if let Some(runtime_trust_input) = input.runtime_trust_input {
        match validate_runtime_trust_input(
            runtime_trust_input,
            input.trusted_verifier_keys,
            &bundle,
            input.now_unix_ms,
            &mut checks,
        ) {
            Ok(entry) => {
                trust_floor_update = Some((
                    entry,
                    runtime_trust_input.body.previous_hash_sha256.as_deref(),
                ));
            }
            Err(code) => return Ok(rejected_report(input.admission_id, code, checks)),
        }
    } else if !input.trusted_verifier_keys.is_empty() {
        return Ok(rejected_report(
            input.admission_id,
            "missing_runtime_trust_input",
            checks,
        ));
    }

    if bundle.binding.host_kernel_id != input.profile.local_kernel_id {
        return Ok(rejected_report(
            input.admission_id,
            "host_kernel_mismatch",
            checks,
        ));
    }
    checks.push(passed("bundle.host_kernel"));

    if &bundle.binding != input.request {
        return Ok(rejected_report(
            input.admission_id,
            "request_binding_mismatch",
            checks,
        ));
    }
    checks.push(passed("request.binding"));

    if input.pheromone_query_report.is_some() {
        checks.push(passed("pheromone.query_report_signed"));
    }
    let (policy_decision, pheromone_advisory) =
        match evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
            policy: input.runtime_pheromone_policy,
            peer_weights: input.runtime_peer_weights,
            query_report: input.pheromone_query_report,
            runtime_trust_input: input.runtime_trust_input,
            trusted_verifier_keys: input.trusted_verifier_keys,
            bundle: &bundle,
            action_class_id: input.action_class_id,
            now_unix_ms: input.now_unix_ms,
            checks: &mut checks,
        }) {
            Ok(result) => result,
            Err(code) => {
                return Ok(rejected_report_with_policy(
                    input.admission_id,
                    code,
                    checks,
                    None,
                ));
            }
        };
    if pheromone_advisory.is_some() {
        checks.push(passed("pheromone.observe_only"));
    }
    if let Some(decision) = policy_decision.as_ref() {
        if decision.decision == "deny" {
            return Ok(rejected_report_with_policy(
                input.admission_id,
                "runtime_pheromone_policy_deny",
                checks,
                Some(decision.clone()),
            ));
        }
        if decision.decision == "escalate" {
            return Ok(rejected_report_with_policy(
                input.admission_id,
                "runtime_pheromone_policy_escalate",
                checks,
                Some(decision.clone()),
            ));
        }
    }

    let mut consumed_destructive_lease_id = None;
    if bundle.destructive {
        let Some(lease_id) = bundle.lease_id.as_deref() else {
            return Ok(rejected_report(
                input.admission_id,
                "missing_destructive_lease",
                checks,
            ));
        };
        if bundle.governance_receipt_id.is_none() {
            return Ok(rejected_report(
                input.admission_id,
                "missing_governance_receipt",
                checks,
            ));
        }
        match input
            .store
            .consume_destructive_lease(lease_id, input.admission_id)
        {
            Ok(()) => {
                consumed_destructive_lease_id = Some(lease_id.to_string());
                checks.push(passed("destructive.lease_reserved"));
            }
            Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                return Ok(rejected_report(input.admission_id, code, checks));
            }
            Err(error) => return Err(error),
        }
    }
    if let Some((entry, previous_hash_sha256)) = trust_floor_update {
        match input
            .store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
        {
            Ok(()) => checks.push(passed("runtime_trust.floor")),
            Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    input
                        .store
                        .release_destructive_lease(lease_id, input.admission_id)?;
                }
                return Ok(rejected_report(input.admission_id, code, checks));
            }
            Err(error) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    input
                        .store
                        .release_destructive_lease(lease_id, input.admission_id)?;
                }
                return Err(error);
            }
        }
    }

    Ok(RuntimeAdmissionReport {
        schema: CHIODOS_RUNTIME_ADMISSION_REPORT_SCHEMA.to_string(),
        admission_id: input.admission_id.to_string(),
        accepted: true,
        failure_code: None,
        checks,
        pheromone_advisory: pheromone_advisory.clone(),
        pheromone_policy_decision: policy_decision.clone(),
        receipt_metadata: receipt_metadata(
            &bundle,
            true,
            None,
            consumed_destructive_lease_id.as_deref(),
            pheromone_advisory.as_ref(),
            policy_decision.as_ref(),
        ),
    })
}

pub fn runtime_admission_bundle_sha256(
    bundle: &RuntimeAdmissionBundle,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_verifier_trust_bundle_sha256(
    bundle: &RuntimeVerifierTrustBundleV4,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_pheromone_policy_sha256(
    policy: &RuntimePheromonePolicy,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(policy)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_peer_weights_sha256(
    weights: &RuntimePeerWeights,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(weights)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn tool_args_sha256(arguments: &serde_json::Value) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(arguments)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn passed(code: &str) -> RuntimeAdmissionCheck {
    RuntimeAdmissionCheck {
        code: code.to_string(),
        passed: true,
    }
}

fn validate_runtime_step_evidence(step: &RuntimeStepEvidence) -> Result<(), ChiodosRuntimeError> {
    if step.schema != CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_step_evidence_schema",
            detail: format!(
                "runtime step evidence declared unsupported schema {}",
                step.schema
            ),
        });
    }
    if step.admission_id.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_admission_id",
            detail: "runtime step evidence must bind admission id".to_string(),
        });
    }
    ensure_sha256_hash(
        &step.admission_report_sha256,
        "runtime_step_evidence_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &step.tool_receipt_sha256,
        "runtime_step_evidence_invalid_tool_receipt_hash",
    )?;
    ensure_sha256_hash(
        &step.output_sha256,
        "runtime_step_evidence_invalid_output_hash",
    )?;
    ensure_sha256_hash(
        &step.bilateral_dsse_sha256,
        "runtime_step_evidence_invalid_dsse_hash",
    )?;
    ensure_sha256_hash(
        &step.workflow_step_sha256,
        "runtime_step_evidence_invalid_workflow_step_hash",
    )?;
    if let Some(parent) = step.parent_receipt_sha256.as_deref() {
        ensure_sha256_hash(parent, "runtime_step_evidence_invalid_parent_hash")?;
    }
    if step.consistency_anchor.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_consistency_anchor",
            detail: "runtime step evidence must bind consistency anchor".to_string(),
        });
    }
    if step.destructive && step.governance_receipt_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_governance",
            detail: "destructive runtime step evidence must bind governance receipt".to_string(),
        });
    }
    Ok(())
}

fn rejected<T>(code: &'static str, detail: &str) -> Result<T, ChiodosRuntimeError> {
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: detail.to_string(),
    })
}

fn ensure_sha256_hash(hash: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if is_sha256_hex(hash) {
        return Ok(());
    }
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: format!("runtime evidence hash {hash} is not sha256 hex"),
    })
}

fn ensure_optional_sha256(
    hash: Option<&str>,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(hash) = hash {
        ensure_sha256_hash(hash, code)?;
    }
    Ok(())
}

fn validate_non_empty(value: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: "runtime orchestration field must not be empty".to_string(),
        });
    }
    Ok(())
}

fn validate_state_label(value: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime orchestration label {value:?} is invalid"),
        });
    }
    Ok(())
}

fn validate_planned_steps(
    steps: &[RuntimeOrchestrationPlannedStep],
) -> Result<(), ChiodosRuntimeError> {
    let mut indices = BTreeSet::new();
    for step in steps {
        if !indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_plan_duplicate_step",
                detail: format!(
                    "runtime orchestration plan repeats step {}",
                    step.step_index
                ),
            });
        }
        validate_non_empty(
            &step.admission_id,
            "runtime_orchestration_plan_empty_admission_id",
        )?;
        validate_state_label(&step.state, "runtime_orchestration_plan_invalid_step_state")?;
    }
    Ok(())
}

fn validate_runtime_orchestration_step_state(
    state: &RuntimeOrchestrationStepState,
) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(
        &state.admission_id,
        "runtime_orchestration_step_empty_admission_id",
    )?;
    validate_state_label(&state.state, "runtime_orchestration_step_invalid_state")?;
    ensure_optional_sha256(
        state.admission_report_sha256.as_deref(),
        "runtime_orchestration_step_invalid_admission_hash",
    )?;
    ensure_optional_sha256(
        state.tool_receipt_sha256.as_deref(),
        "runtime_orchestration_step_invalid_receipt_hash",
    )?;
    if state.destructive && state.lease_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_step_missing_destructive_lease",
            detail: "destructive runtime orchestration step must bind lease id".to_string(),
        });
    }
    Ok(())
}

fn validate_runtime_proof_drift(drift: &RuntimeProofDrift) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(&drift.field, "runtime_proof_drift_empty_field")?;
    ensure_sha256_hash(
        &drift.baseline_value_sha256,
        "runtime_proof_drift_invalid_baseline_value_hash",
    )?;
    ensure_sha256_hash(
        &drift.candidate_value_sha256,
        "runtime_proof_drift_invalid_candidate_value_hash",
    )?;
    validate_state_label(&drift.severity, "runtime_proof_drift_invalid_severity")
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn compare_semantic_field<T: Serialize + PartialEq>(
    field: &str,
    baseline: &T,
    candidate: &T,
    drifts: &mut Vec<RuntimeProofDrift>,
) -> Result<(), ChiodosRuntimeError> {
    if baseline != candidate {
        drifts.push(RuntimeProofDrift {
            field: field.to_string(),
            baseline_value_sha256: canonical_sha256(baseline)?,
            candidate_value_sha256: canonical_sha256(candidate)?,
            severity: "error".to_string(),
        });
    }
    Ok(())
}

fn compare_verifier_field<T: Serialize + PartialEq>(
    field: &str,
    baseline: &T,
    candidate: &T,
    drifts: &mut Vec<RuntimeProofDrift>,
) -> Result<(), ChiodosRuntimeError> {
    compare_semantic_field(field, baseline, candidate, drifts)
}

fn evidence_sink_write_probe(evidence_root: &Path) -> (bool, bool) {
    let probe = evidence_root.join(".chiodos-runtime-health-probe.tmp");
    let committed = evidence_root.join(".chiodos-runtime-health-probe.done");
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    let write_ok = fs::write(&probe, b"runtime-evidence-health").is_ok();
    let rename_ok = write_ok && fs::rename(&probe, &committed).is_ok();
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    (write_ok, rename_ok)
}

fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn required_string_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<String, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value
            .get(*field)
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
        {
            return Ok(item.to_string());
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn required_u64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<u64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_u64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn required_f64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<f64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_f64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn validate_runtime_trust_input(
    envelope: &SignedRuntimeVerifierTrustBundle,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    bundle: &RuntimeAdmissionBundle,
    now_unix_ms: u64,
    checks: &mut Vec<RuntimeAdmissionCheck>,
) -> Result<RuntimeTrustFloorEntry, &'static str> {
    let body = &envelope.body;
    if body.schema != CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4 {
        return Err("unsupported_runtime_trust_schema");
    }
    checks.push(passed("runtime_trust.schema"));

    let signature_valid = envelope
        .verify_signature()
        .map_err(|_| "runtime_trust_signature_invalid")?;
    if !signature_valid {
        return Err("runtime_trust_signature_invalid");
    }
    checks.push(passed("runtime_trust.signature"));

    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == body.verifier_id
            && trusted.key_id == body.key_id
            && trusted.public_key == envelope.signer_key
    }) else {
        return Err("runtime_trust_signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("runtime_trust_signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("runtime_trust_signer_stale");
    }
    checks.push(passed("runtime_trust.signer"));

    if now_unix_ms < body.issued_at_unix_ms || now_unix_ms >= body.expires_at_unix_ms {
        return Err("runtime_trust_stale");
    }
    checks.push(passed("runtime_trust.freshness"));

    if body.version == 0 {
        return Err("runtime_trust_version_zero");
    }
    if body.version > 1 && body.previous_hash_sha256.is_none() {
        return Err("runtime_trust_previous_hash_missing");
    }
    checks.push(passed("runtime_trust.version"));

    let body_hash =
        runtime_verifier_trust_bundle_sha256(body).map_err(|_| "runtime_trust_hash_failed")?;

    if body.revocation_authority_roots.is_empty() {
        return Err("runtime_trust_revocation_roots_missing");
    }
    checks.push(passed("runtime_trust.revocation_roots"));

    if body.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return Err("runtime_trust_bundle_hash_mismatch");
    }
    if body.verification_context_sha256 != bundle.verification_context_sha256 {
        return Err("runtime_trust_context_hash_mismatch");
    }
    checks.push(passed("runtime_trust.bundle_binding"));
    Ok(RuntimeTrustFloorEntry {
        verifier_id: body.verifier_id.clone(),
        key_id: body.key_id.clone(),
        highest_version: body.version,
        latest_bundle_sha256: body_hash,
        latest_revocation_checkpoint_sha256: body.revocation_checkpoint_sha256.clone(),
    })
}

fn validate_runtime_trust_floor_transition(
    existing: Option<RuntimeTrustFloorEntry>,
    next: &RuntimeTrustFloorEntry,
    previous_hash_sha256: Option<&str>,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(floor) = existing {
        if next.highest_version < floor.highest_version {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_rollback",
                detail: "runtime trust input version is below persisted floor".to_string(),
            });
        }
        if next.highest_version == floor.highest_version
            && next.latest_bundle_sha256 != floor.latest_bundle_sha256
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_same_version_mismatch",
                detail: "runtime trust input reused a floor version with different content"
                    .to_string(),
            });
        }
        if next.highest_version > floor.highest_version
            && previous_hash_sha256 != Some(floor.latest_bundle_sha256.as_str())
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_previous_hash_mismatch",
                detail: "runtime trust input does not extend the persisted floor".to_string(),
            });
        }
    } else if next.highest_version > 1 && previous_hash_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_trust_previous_hash_missing",
            detail: "runtime trust input above version one must carry a previous hash".to_string(),
        });
    }
    Ok(())
}

struct RuntimePolicyEvaluationInput<'a, 'b> {
    policy: Option<&'a SignedRuntimePheromonePolicy>,
    peer_weights: Option<&'a SignedRuntimePeerWeights>,
    query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    bundle: &'a RuntimeAdmissionBundle,
    action_class_id: Option<&'a str>,
    now_unix_ms: u64,
    checks: &'b mut Vec<RuntimeAdmissionCheck>,
}

fn evaluate_runtime_pheromone_policy(
    input: RuntimePolicyEvaluationInput<'_, '_>,
) -> Result<
    (
        Option<RuntimePheromonePolicyDecision>,
        Option<RuntimePheromoneAdvisory>,
    ),
    &'static str,
> {
    if input.bundle.destructive
        && (input.policy.is_none() || input.peer_weights.is_none() || input.query_report.is_none())
    {
        return Err("runtime_pheromone_required_for_destructive");
    }
    match (input.policy, input.peer_weights) {
        (None, None) => return Ok((None, None)),
        (Some(_), None) => return Err("missing_runtime_peer_weights"),
        (None, Some(_)) => return Err("missing_runtime_pheromone_policy"),
        (Some(_), Some(_)) => {}
    }
    let Some(runtime_trust_input) = input.runtime_trust_input else {
        return Err("missing_runtime_trust_input");
    };
    let Some(query_report) = input.query_report else {
        return Err("missing_runtime_pheromone_advisory");
    };

    let policy = input.policy.ok_or("missing_runtime_pheromone_policy")?;
    let peer_weights = input.peer_weights.ok_or("missing_runtime_peer_weights")?;
    validate_signed_verifier_material(
        &policy.body.verifier_id,
        &policy.body.key_id,
        &policy.signer_key,
        || policy.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_pheromone_policy_untrusted")?;
    input.checks.push(passed("runtime_policy.signature"));
    if query_report.signer_key != policy.signer_key {
        return Err("runtime_pheromone_policy_query_report_signer_mismatch");
    }
    if !query_report
        .verify_signature()
        .map_err(|_| "runtime_pheromone_query_report_signature_invalid")?
    {
        return Err("runtime_pheromone_query_report_signature_invalid");
    }
    input
        .checks
        .push(passed("runtime_pheromone_query_report.signature"));
    let advisory = runtime_pheromone_advisory_from_query_report_value(&query_report.body)
        .map_err(|_| "invalid_pheromone_query_report")?;
    if !advisory.observe_only {
        return Err("runtime_pheromone_advisory_not_observe_only");
    }
    if !advisory.accepted {
        return Err("runtime_pheromone_advisory_rejected");
    }
    if advisory.evaluated_at_unix_ms > input.now_unix_ms {
        return Err("runtime_pheromone_advisory_future_dated");
    }
    validate_signed_verifier_material(
        &peer_weights.body.verifier_id,
        &peer_weights.body.key_id,
        &peer_weights.signer_key,
        || peer_weights.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_peer_weights_untrusted")?;
    input.checks.push(passed("runtime_peer_weights.signature"));

    let policy_body = &policy.body;
    let weights_body = &peer_weights.body;
    if policy_body.schema != CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA {
        return Err("unsupported_runtime_pheromone_policy_schema");
    }
    if weights_body.schema != CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA {
        return Err("unsupported_runtime_peer_weights_schema");
    }
    if policy_body.mode != "observe" && policy_body.mode != "enforce" {
        return Err("runtime_pheromone_policy_mode_unsupported");
    }
    if input.now_unix_ms < policy_body.issued_at_unix_ms
        || input.now_unix_ms >= policy_body.expires_at_unix_ms
    {
        return Err("runtime_pheromone_policy_stale");
    }
    if input.now_unix_ms < weights_body.issued_at_unix_ms
        || input.now_unix_ms >= weights_body.expires_at_unix_ms
    {
        return Err("runtime_peer_weights_stale");
    }
    if policy_body.verifier_id != runtime_trust_input.body.verifier_id {
        return Err("runtime_pheromone_policy_verifier_mismatch");
    }
    if policy_body.runtime_trust_bundle_sha256 != runtime_trust_input.body.trust_bundle_sha256 {
        return Err("runtime_pheromone_policy_trust_mismatch");
    }
    let weights_hash = runtime_peer_weights_sha256(weights_body)
        .map_err(|_| "runtime_peer_weights_hash_failed")?;
    if policy_body.peer_weights_sha256 != weights_hash {
        return Err("runtime_peer_weights_hash_mismatch");
    }
    if weights_body.reputation_epoch != advisory.reputation_epoch
        || !policy_body
            .allowed_reputation_epochs
            .contains(&advisory.reputation_epoch)
    {
        return Err("runtime_reputation_epoch_mismatch");
    }
    if input
        .now_unix_ms
        .saturating_sub(advisory.evaluated_at_unix_ms)
        > policy_body.max_query_report_age_ms
    {
        return Err("runtime_pheromone_advisory_stale");
    }
    if advisory.distinct_origin_pairs < policy_body.min_distinct_origin_pairs {
        return Err("runtime_pheromone_distinct_origin_floor");
    }
    validate_peer_weights(weights_body)?;
    input.checks.push(passed("runtime_policy.bindings"));

    let policy_hash =
        runtime_pheromone_policy_sha256(policy_body).map_err(|_| "runtime_policy_hash_failed")?;
    let mut decision = RuntimePheromonePolicyDecision {
        schema: CHIODOS_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA.to_string(),
        enforced: policy_body.mode == "enforce",
        decision: "allow".to_string(),
        policy_id: policy_body.policy_id.clone(),
        policy_sha256: policy_hash,
        query_report_sha256: advisory.source_report_sha256.clone(),
        peer_weights_sha256: weights_hash,
        reputation_epoch: advisory.reputation_epoch,
        matched_rule_id: None,
        reason_code: "runtime_pheromone_policy_allow".to_string(),
    };

    let action_class_id = input
        .action_class_id
        .unwrap_or(&input.bundle.binding.tool_name);
    for rule in &policy_body.rules {
        if rule.subject_class != advisory.subject_class
            || rule.subject_class_namespace != advisory.subject_class_namespace
        {
            continue;
        }
        if rule.action_class_id != action_class_id && rule.action_class_id != "*" {
            continue;
        }
        let matched = match rule.direction.as_str() {
            "deny_if_at_or_above" => advisory.total_strength >= rule.threshold_total_strength,
            "require_at_or_above" => advisory.total_strength < rule.threshold_total_strength,
            _ => return Err("runtime_pheromone_policy_direction_unsupported"),
        };
        if !matched {
            continue;
        }
        decision.matched_rule_id = Some(rule.rule_id.clone());
        decision.reason_code = format!("runtime_pheromone_policy_{}", rule.effect);
        if policy_body.mode == "enforce" {
            decision.decision = match rule.effect.as_str() {
                "deny" => "deny".to_string(),
                "require_review" => "escalate".to_string(),
                "receipt_tag" => "allow".to_string(),
                _ => return Err("runtime_pheromone_policy_effect_unsupported"),
            };
        }
        break;
    }
    Ok((Some(decision), Some(advisory)))
}

fn validate_peer_weights(weights: &RuntimePeerWeights) -> Result<(), &'static str> {
    let mut peers = BTreeSet::new();
    for weight in &weights.weights {
        if weight.peer_kernel_id.trim().is_empty() {
            return Err("runtime_peer_weights_invalid");
        }
        if !peers.insert(weight.peer_kernel_id.as_str()) {
            return Err("runtime_peer_weights_duplicate_peer");
        }
        if !weight.weight.is_finite() || weight.weight < 0.0 {
            return Err("runtime_peer_weights_invalid");
        }
    }
    Ok(())
}

fn validate_signed_verifier_material<F>(
    verifier_id: &str,
    key_id: &str,
    signer_key: &PublicKey,
    verify_signature: F,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    now_unix_ms: u64,
) -> Result<(), &'static str>
where
    F: FnOnce() -> Result<bool, chio_core_types::Error>,
{
    if !verify_signature().map_err(|_| "signature_invalid")? {
        return Err("signature_invalid");
    }
    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == verifier_id
            && trusted.key_id == key_id
            && trusted.public_key == *signer_key
    }) else {
        return Err("signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("signer_stale");
    }
    Ok(())
}

fn rejected_report(
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
) -> RuntimeAdmissionReport {
    rejected_report_with_policy(admission_id, failure_code, checks, None)
}

fn rejected_report_with_policy(
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
    pheromone_policy_decision: Option<RuntimePheromonePolicyDecision>,
) -> RuntimeAdmissionReport {
    RuntimeAdmissionReport {
        schema: CHIODOS_RUNTIME_ADMISSION_REPORT_SCHEMA.to_string(),
        admission_id: admission_id.to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
        pheromone_advisory: None,
        pheromone_policy_decision: pheromone_policy_decision.clone(),
        receipt_metadata: serde_json::json!({
            "chiodos_runtime": {
                "admission_id": admission_id,
                "accepted": false,
                "failure_code": failure_code,
                "pheromone_policy_decision": pheromone_policy_decision
            }
        }),
    }
}

fn receipt_metadata(
    bundle: &RuntimeAdmissionBundle,
    accepted: bool,
    failure_code: Option<&str>,
    reserved_destructive_lease_id: Option<&str>,
    pheromone_advisory: Option<&RuntimePheromoneAdvisory>,
    pheromone_policy_decision: Option<&RuntimePheromonePolicyDecision>,
) -> serde_json::Value {
    serde_json::json!({
        "chiodos_runtime": {
            "admission_id": bundle.admission_id,
            "accepted": accepted,
            "failure_code": failure_code,
            "workflow_id": bundle.workflow_id,
            "workflow_grant_id": bundle.workflow_grant_id,
            "step_index": bundle.step_index,
            "destructive": bundle.destructive,
            "lease_id": bundle.lease_id,
            "reserved_destructive_lease_id": reserved_destructive_lease_id,
            "governance_receipt_id": bundle.governance_receipt_id,
            "trust_bundle_sha256": bundle.trust_bundle_sha256,
            "verification_context_sha256": bundle.verification_context_sha256,
            "pheromone_advisory": pheromone_advisory,
            "pheromone_policy_decision": pheromone_policy_decision
        }
    })
}

fn trust_floor_identity(verifier_id: &str, key_id: &str) -> String {
    format!("{verifier_id}:{key_id}")
}
