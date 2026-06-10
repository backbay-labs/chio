use crate::buyer::{
    validate_buyer_attestation_review_report, validate_buyer_attestation_verification_report,
};
use crate::types::RuntimeRecoveryDrillReport;
use crate::validation::{required_f64_any, required_string_any, required_u64_any};
use crate::*;

pub fn runtime_admission_profile_from_json(
    json: &str,
) -> Result<RuntimeAdmissionProfile, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_bundle_from_json(
    json: &str,
) -> Result<RuntimeAdmissionBundle, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_request_binding_from_json(
    json: &str,
) -> Result<RuntimeRequestBinding, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_packet_from_json(
    json: &str,
) -> Result<BuyerAttestationPacket, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_package_from_json(
    json: &str,
) -> Result<BuyerAttestationReviewPackage, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_verifier_trust_bundle_from_json(
    json: &str,
) -> Result<SignedRuntimeVerifierTrustBundle, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_trusted_verifier_keys_from_json(
    json: &str,
) -> Result<RuntimeTrustedVerifierKeysDocument, ChioRuntimeError> {
    let document: RuntimeTrustedVerifierKeysDocument =
        serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    if !is_runtime_trusted_verifiers_schema(&document.schema) {
        return Err(ChioRuntimeError::Rejected {
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
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_trusted_verifier_key",
                detail: format!("runtime trusted verifier key {identity} is duplicated"),
            });
        }
    }
    Ok(document)
}

fn is_runtime_trusted_verifiers_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_TRUSTED_VERIFIERS_SCHEMA)
}

pub fn signed_runtime_pheromone_policy_from_json(
    json: &str,
) -> Result<SignedRuntimePheromonePolicy, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_peer_weights_from_json(
    json: &str,
) -> Result<SignedRuntimePeerWeights, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_report_json(
    report: &RuntimeAdmissionReport,
) -> Result<String, ChioRuntimeError> {
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn sign_runtime_admission_report(
    report: RuntimeAdmissionReport,
    keypair: &Keypair,
) -> Result<SignedRuntimeAdmissionReport, ChioRuntimeError> {
    SignedExportEnvelope::sign(report, keypair)
        .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))
}

pub fn signed_runtime_admission_report_from_json(
    json: &str,
) -> Result<SignedRuntimeAdmissionReport, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_admission_report_json(
    report: &SignedRuntimeAdmissionReport,
) -> Result<String, ChioRuntimeError> {
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn verify_signed_runtime_admission_report(
    report: &SignedRuntimeAdmissionReport,
) -> Result<bool, ChioRuntimeError> {
    report
        .verify_signature()
        .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))
}

pub fn runtime_pheromone_advisory_from_query_report_json(
    json: &str,
) -> Result<RuntimePheromoneAdvisory, ChioRuntimeError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    runtime_pheromone_advisory_from_query_report_value(&value)
}

pub fn signed_runtime_pheromone_query_report_from_json(
    json: &str,
) -> Result<SignedRuntimePheromoneQueryReport, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_pheromone_query_report_json(
    report: &SignedRuntimePheromoneQueryReport,
) -> Result<String, ChioRuntimeError> {
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub(crate) fn runtime_pheromone_advisory_from_query_report_value(
    value: &serde_json::Value,
) -> Result<RuntimePheromoneAdvisory, ChioRuntimeError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))?;
    let schema = value.get("schema").and_then(|item| item.as_str());
    if schema != Some("chio.pheromone.query-report.v1") {
        return Err(ChioRuntimeError::Rejected {
            code: "unsupported_pheromone_query_report_schema",
            detail: "runtime pheromone advisory requires chio.pheromone.query-report.v1"
                .to_string(),
        });
    }
    let concentration = value
        .get("concentration")
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "missing_pheromone_concentration",
            detail: "runtime pheromone advisory query report is missing concentration".to_string(),
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
) -> Result<String, ChioRuntimeError> {
    validate_runtime_workflow_run_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_verification_report_json(
    report: &BuyerAttestationVerificationReport,
) -> Result<String, ChioRuntimeError> {
    validate_buyer_attestation_verification_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_report_json(
    report: &BuyerAttestationReviewReport,
) -> Result<String, ChioRuntimeError> {
    validate_buyer_attestation_review_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_report_json(
    report: &RuntimeProofRegenerationReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_proof_regeneration_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_manifest_json(
    manifest: &RuntimeEvidenceManifest,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_evidence_manifest(manifest)?;
    serde_json::to_string_pretty(manifest)
        .map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_input_json(
    input: &RuntimeProofRegenerationInput,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_proof_regeneration_input(input)?;
    serde_json::to_string_pretty(input).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_parity_report_json(
    report: &RuntimeProofParityReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_proof_parity_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_profile_from_json(
    json: &str,
) -> Result<RuntimeOrchestrationProfile, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_run_contract_from_json(json: &str) -> Result<RuntimeRunContract, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_supervisor_profile_from_json(
    json: &str,
) -> Result<RuntimeSupervisorProfile, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_profile_from_json(
    json: &str,
) -> Result<RuntimeArtifactRetentionProfile, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_bindings_from_json(
    json: &str,
) -> Result<RuntimeProviderBindingsDocument, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_plan_json(
    plan: &RuntimeOrchestrationPlan,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_orchestration_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_run_report_json(
    report: &RuntimeOrchestrationRunReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_orchestration_run_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_resume_plan_json(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_orchestration_resume_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_status_report_json(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_orchestration_status_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_drift_report_json(
    report: &RuntimeProofDriftReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_proof_drift_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_scheduler_tick_report_json(
    report: &RuntimeSchedulerTickReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_scheduler_tick_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_sink_health_report_json(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_evidence_sink_health_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_recovery_drill_report_json(
    report: &RuntimeRecoveryDrillReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_recovery_drill_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_plan_json(
    report: &RuntimeArtifactRetentionPlan,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_artifact_retention_plan(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_health_report_json(
    report: &RuntimeProviderHealthReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_provider_health_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

pub fn runtime_ops_status_report_json(
    report: &RuntimeOpsStatusReport,
) -> Result<String, ChioRuntimeError> {
    validate_runtime_ops_status_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
