use crate::validation::{validate_non_empty, validate_state_label};
use crate::*;

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
        "accepted",
        &baseline_proof.accepted,
        &candidate_proof.accepted,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "failure_code",
        &baseline_proof.failure_code,
        &candidate_proof.failure_code,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "checks",
        &baseline_proof.checks,
        &candidate_proof.checks,
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
