use std::collections::BTreeMap;

use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;

use crate::validation::{validate_non_empty, validate_state_label};
use crate::*;

pub fn build_runtime_orchestration_plan(
    profile: &RuntimeOrchestrationProfile,
    contract: &RuntimeRunContract,
    now_unix_ms: u64,
) -> Result<RuntimeOrchestrationPlan, ChioRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    validate_runtime_run_contract(contract)?;
    let profile_sha256 = runtime_orchestration_profile_sha256(profile)?;
    if contract.profile_sha256 != profile_sha256 {
        return Ok(RuntimeOrchestrationPlan {
            schema: CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
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
            schema: CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
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
) -> Result<RuntimeProofDriftReport, ChioRuntimeError> {
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
        schema: crate::CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA.to_string(),
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
) -> Result<RuntimeEvidenceSinkHealthReport, ChioRuntimeError> {
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
        let entry_hash_mismatches = sha256_hex(&bytes) != entry.sha256;
        let manifest_report_binding_mismatches =
            runtime_evidence_manifest_report_binding_mismatches(&bytes, entry, manifest)?;
        if entry_hash_mismatches || manifest_report_binding_mismatches {
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
        schema: CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA.to_string(),
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
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    generate_runtime_provider_health_report_with_model_cards(
        profile,
        bindings,
        &BTreeMap::new(),
        now_unix_ms,
    )
}

pub fn generate_runtime_provider_health_report_with_model_cards(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    model_cards_by_id: &BTreeMap<String, ModelCard>,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    generate_runtime_provider_health_report_with_model_card_evidence(
        profile,
        bindings,
        model_cards_by_id,
        &[],
        now_unix_ms,
    )
}

pub fn generate_runtime_provider_health_report_with_model_card_evidence(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    model_cards_by_id: &BTreeMap<String, ModelCard>,
    loaded_weights_evidence: &[RuntimeProviderLoadedWeightsEvidence],
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    validate_runtime_supervisor_profile(profile)?;
    validate_runtime_provider_bindings(bindings)?;
    let observed_loaded_weights = observed_loaded_weights_by_binding_id(loaded_weights_evidence)?;
    let profile_stale =
        now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
    let provider_checks = bindings
        .bindings
        .iter()
        .map(|binding| {
            evaluate_runtime_provider_binding_health(
                binding,
                profile,
                model_cards_by_id,
                &observed_loaded_weights,
                now_unix_ms,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut degraded_provider_ids = provider_checks
        .iter()
        .filter(|check| !check.accepted)
        .map(|check| check.provider_id.clone())
        .collect::<Vec<_>>();
    degraded_provider_ids.sort();
    degraded_provider_ids.dedup();
    let failure_code = if profile_stale {
        Some("runtime_provider_supervisor_profile_stale".to_string())
    } else if let Some(check) = provider_checks.iter().find(|check| {
        check.failure_code.as_deref() == Some("runtime_provider_discovery_not_allowed")
    }) {
        check.failure_code.clone()
    } else if let Some(check) = provider_checks.iter().find(|check| !check.accepted) {
        check.failure_code.clone()
    } else if !degraded_provider_ids.is_empty() {
        Some("runtime_provider_health_degraded".to_string())
    } else {
        None
    };
    let checked_provider_count = u64::try_from(bindings.bindings.len()).unwrap_or(u64::MAX);
    let degraded_count = u64::try_from(degraded_provider_ids.len()).unwrap_or(u64::MAX);
    let report = RuntimeProviderHealthReport {
        schema: CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: failure_code.is_none(),
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        provider_bindings_sha256: canonical_sha256(bindings)?,
        checked_provider_count,
        healthy_provider_count: checked_provider_count.saturating_sub(degraded_count),
        degraded_provider_ids,
        provider_checks,
        checks: vec!["runtime_ops.provider_bindings_health".to_string()],
    };
    validate_runtime_provider_health_report(&report)?;
    Ok(report)
}

fn observed_loaded_weights_by_binding_id(
    loaded_weights_evidence: &[RuntimeProviderLoadedWeightsEvidence],
) -> Result<BTreeMap<&str, &str>, ChioRuntimeError> {
    let mut observed = BTreeMap::new();
    for evidence in loaded_weights_evidence {
        validate_non_empty(
            &evidence.binding_id,
            "runtime_provider_invalid_loaded_weights_evidence",
        )?;
        validate_observed_loaded_weights_hash(evidence.loaded_weights_hash.as_str())?;
        if observed
            .insert(
                evidence.binding_id.as_str(),
                evidence.loaded_weights_hash.as_str(),
            )
            .is_some()
        {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_provider_duplicate_loaded_weights_evidence",
                detail: format!(
                    "runtime provider loaded weights evidence repeats {}",
                    evidence.binding_id
                ),
            });
        }
    }
    Ok(observed)
}

fn validate_observed_loaded_weights_hash(value: &str) -> Result<(), ChioRuntimeError> {
    if is_sha256_hex(value)
        && value
            .as_bytes()
            .iter()
            .all(|byte| !byte.is_ascii_uppercase())
    {
        return Ok(());
    }
    Err(ChioRuntimeError::Rejected {
        code: "runtime_provider_invalid_loaded_weights_hash",
        detail: format!(
            "runtime provider loaded weights evidence {value} is not lowercase sha256 hex"
        ),
    })
}

fn evaluate_runtime_provider_binding_health(
    binding: &RuntimeProviderBinding,
    profile: &RuntimeSupervisorProfile,
    model_cards_by_id: &BTreeMap<String, ModelCard>,
    observed_loaded_weights: &BTreeMap<&str, &str>,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthCheck, ChioRuntimeError> {
    let mode = binding
        .weights_binding_mode
        .unwrap_or(WeightsBindingMode::NotRequired);
    let binding_id = binding.binding_id.clone().unwrap_or_else(|| {
        format!(
            "{}:{}:{}",
            binding.provider_id, binding.server_id, binding.tool_name
        )
    });
    let failure_code = if binding.discovery_allowed {
        Some("runtime_provider_discovery_not_allowed")
    } else if binding.local_kernel_id != profile.local_kernel_id {
        Some("runtime_provider_health_degraded")
    } else {
        runtime_provider_model_card_failure_code(
            binding,
            mode,
            model_cards_by_id,
            observed_loaded_weights,
            &binding_id,
            now_unix_ms,
        )?
    };
    Ok(RuntimeProviderHealthCheck {
        provider_id: binding.provider_id.clone(),
        binding_id,
        accepted: failure_code.is_none(),
        failure_code: failure_code.map(ToOwned::to_owned),
        weights_binding_mode: mode,
        model_card_id: binding.model_card_id.clone(),
        checks: runtime_provider_health_checks_for(mode),
    })
}

fn runtime_provider_model_card_failure_code(
    binding: &RuntimeProviderBinding,
    mode: WeightsBindingMode,
    model_cards_by_id: &BTreeMap<String, ModelCard>,
    observed_loaded_weights: &BTreeMap<&str, &str>,
    binding_id: &str,
    now_unix_ms: u64,
) -> Result<Option<&'static str>, ChioRuntimeError> {
    match mode {
        WeightsBindingMode::NotRequired => Ok(None),
        WeightsBindingMode::Unavailable => Ok(Some("runtime_provider_loaded_weights_unavailable")),
        WeightsBindingMode::Required | WeightsBindingMode::RequiredWithPin => {
            let Some(model_card_id) = binding.model_card_id.as_deref() else {
                return Ok(Some("runtime_provider_model_card_missing"));
            };
            let Some(model_card_digest) = binding.model_card_digest.as_deref() else {
                return Ok(Some("runtime_provider_model_card_missing"));
            };
            let Some(loaded_weights_hash) = binding.loaded_weights_hash.as_deref() else {
                return Ok(Some("runtime_provider_loaded_weights_unavailable"));
            };
            let Some(model_card) = model_cards_by_id.get(model_card_id) else {
                return Ok(Some("runtime_provider_model_card_missing"));
            };
            let card_expires_at_ms = model_card.expires_at.timestamp_millis();
            if card_expires_at_ms < 0 || now_unix_ms >= card_expires_at_ms as u64 {
                return Ok(Some("runtime_provider_model_card_stale"));
            }
            if canonical_sha256(model_card)? != model_card_digest {
                return Ok(Some("runtime_provider_model_card_digest_mismatch"));
            }
            let Some(observed_loaded_weights_hash) = observed_loaded_weights.get(binding_id) else {
                return Ok(Some("runtime_provider_loaded_weights_unavailable"));
            };
            if *observed_loaded_weights_hash != loaded_weights_hash {
                return Ok(Some("runtime_provider_loaded_weights_hash_mismatch"));
            }
            let requested = StringSet::new([binding.tool_name.as_str()]);
            match chio_kernel::weights_binding::evaluate_weights_binding_with_loaded_hash(
                model_card,
                Ok::<&str, &str>(observed_loaded_weights_hash),
                &requested,
                &requested,
            ) {
                Ok(()) => Ok(None),
                Err(error) => Ok(Some(runtime_provider_weights_error_code(&error))),
            }
        }
    }
}

fn runtime_provider_weights_error_code(error: &WeightsError) -> &'static str {
    match error {
        WeightsError::CardMismatch { .. } => "runtime_provider_loaded_weights_hash_mismatch",
        WeightsError::ScopeNotSubset { .. } => "runtime_provider_model_card_scope_not_allowed",
        WeightsError::ToolBanned { .. } => "runtime_provider_model_card_tool_banned",
        WeightsError::Expired { .. } => "runtime_provider_model_card_stale",
        WeightsError::SchemaRejected(_) => "runtime_provider_loaded_weights_unavailable",
        _ => "runtime_provider_model_card_missing",
    }
}

fn runtime_provider_health_checks_for(mode: WeightsBindingMode) -> Vec<String> {
    let mut checks = vec![
        "runtime_provider_kernel".to_string(),
        "runtime_provider_discovery".to_string(),
    ];
    if !matches!(mode, WeightsBindingMode::NotRequired) {
        checks.push("runtime_provider_model_card".to_string());
        checks.push("runtime_provider_loaded_weights".to_string());
    }
    checks
}

pub fn generate_runtime_artifact_retention_plan(
    profile: &RuntimeArtifactRetentionProfile,
    run_ids: &[String],
    now_unix_ms: u64,
) -> Result<RuntimeArtifactRetentionPlan, ChioRuntimeError> {
    validate_runtime_artifact_retention_profile(profile)?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        let report = RuntimeArtifactRetentionPlan {
            schema: CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA.to_string(),
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
) -> Result<(), ChioRuntimeError> {
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

fn runtime_evidence_manifest_report_binding_mismatches(
    bytes: &[u8],
    entry: &RuntimeEvidenceManifestEntry,
    manifest: &RuntimeEvidenceManifest,
) -> Result<bool, ChioRuntimeError> {
    let expected = match entry.role.as_str() {
        "workflow_run_report" => &manifest.workflow_run_report_sha256,
        "proof_regeneration_report" => &manifest.proof_regeneration_report_sha256,
        _ => return Ok(false),
    };
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        ChioRuntimeError::Json(format!(
            "Chio runtime evidence health artifact JSON {}: {error}",
            entry.path
        ))
    })?;
    Ok(canonical_sha256(&value)? != *expected)
}

fn compare_verifier_field<T: Serialize + PartialEq>(
    field: &str,
    baseline: &T,
    candidate: &T,
    drifts: &mut Vec<RuntimeProofDrift>,
) -> Result<(), ChioRuntimeError> {
    compare_semantic_field(field, baseline, candidate, drifts)
}

fn evidence_sink_write_probe(evidence_root: &Path) -> (bool, bool) {
    let probe = evidence_root.join(".chio-runtime-health-probe.tmp");
    let committed = evidence_root.join(".chio-runtime-health-probe.done");
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    let write_ok = fs::write(&probe, b"runtime-evidence-health").is_ok();
    let rename_ok = write_ok && fs::rename(&probe, &committed).is_ok();
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    (write_ok, rename_ok)
}
