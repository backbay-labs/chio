use chio_runtime_core::*;
use std::io;

fn supervisor_profile() -> RuntimeSupervisorProfile {
    RuntimeSupervisorProfile {
        schema: CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA.to_string(),
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

#[test]
fn runtime_ops_input_documents_accept_chio_native_schemas() -> Result<(), Box<dyn std::error::Error>>
{
    let mut supervisor = supervisor_profile();
    supervisor.schema = "chio.runtime.supervisor-profile.v1".to_string();
    validate_runtime_supervisor_profile(&supervisor)?;

    let retention = RuntimeArtifactRetentionProfile {
        schema: "chio.runtime.artifact-retention-profile.v1".to_string(),
        profile_id: "retention-runtime-local".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        min_retain_ms: 86_400_000,
        destructive_hold_ms: 604_800_000,
        legal_hold: false,
        dry_run_only: true,
    };
    validate_runtime_artifact_retention_profile(&retention)?;

    let bindings = RuntimeProviderBindingsDocument {
        schema: "chio.runtime.provider-bindings.v1".to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: false,
        }],
    };
    validate_runtime_provider_bindings(&bindings)?;

    let mut const_schema_supervisor = supervisor_profile();
    const_schema_supervisor.schema = CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA.to_string();
    validate_runtime_supervisor_profile(&const_schema_supervisor)?;
    Ok(())
}

#[test]
fn runtime_workflow_report_requires_structured_step_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeWorkflowRunReport {
        schema: "chio.runtime.workflow-run-report.v1".to_string(),
        run_id: "runtime-loopback-7-2".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        admission_report_sha256: "1".repeat(64),
        evidence_paths: vec!["runtime-admission-report-1.json".to_string()],
        step_evidence: vec![RuntimeStepEvidence {
            schema: "chio.runtime.step-evidence.v1".to_string(),
            step_index: 0,
            admission_id: "adm-live-1".to_string(),
            admission_report_sha256: "1".repeat(64),
            tool_receipt_id: "receipt-live-1".to_string(),
            tool_receipt_sha256: "2".repeat(64),
            output_sha256: "3".repeat(64),
            bilateral_dsse_sha256: "4".repeat(64),
            workflow_step_sha256: "5".repeat(64),
            parent_receipt_sha256: None,
            consistency_anchor: "chio:consistency:wf-live-1:0".to_string(),
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
fn runtime_workflow_report_rejects_unsafe_evidence_paths() -> Result<(), Box<dyn std::error::Error>>
{
    let report = RuntimeWorkflowRunReport {
        schema: CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: "runtime-loopback-7-2".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_001_000,
        admission_report_sha256: "1".repeat(64),
        evidence_paths: vec!["../runtime-admission-report-1.json".to_string()],
        step_evidence: vec![RuntimeStepEvidence {
            schema: CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
            step_index: 0,
            admission_id: "adm-live-1".to_string(),
            admission_report_sha256: "1".repeat(64),
            tool_receipt_id: "receipt-live-1".to_string(),
            tool_receipt_sha256: "2".repeat(64),
            output_sha256: "3".repeat(64),
            bilateral_dsse_sha256: "4".repeat(64),
            workflow_step_sha256: "5".repeat(64),
            parent_receipt_sha256: None,
            consistency_anchor: "chio:consistency:wf-live-1:0".to_string(),
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
        }],
        proof_regeneration_report_sha256: Some("6".repeat(64)),
    };

    let error = match validate_runtime_workflow_run_report(&report) {
        Ok(()) => {
            return Err(io::Error::other("unsafe evidence path unexpectedly accepted").into());
        }
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("runtime_workflow_invalid_evidence_path"));
    Ok(())
}

#[test]
fn runtime_workflow_report_rejects_placeholder_success_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeWorkflowRunReport {
        schema: CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
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
        schema: "chio.runtime.proof-regeneration-report.v1".to_string(),
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
    assert!(json.contains("chio.runtime.proof-regeneration-report.v1"));
    assert!(json.contains("sourceRecords"));
    chio_runtime_core::validate_runtime_proof_regeneration_report(&report)?;
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
        schema: "chio.runtime.evidence-manifest.v1".to_string(),
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
        schema: "chio.runtime.proof-regeneration-input.v1".to_string(),
        run_id: "runtime-loopback-7-3".to_string(),
        evidence_manifest_sha256: "8".repeat(64),
        workflow_run_report_sha256: "5".repeat(64),
        admission_report_sha256: "9".repeat(64),
        trust_bundle_sha256: "a".repeat(64),
        verification_context_sha256: "b".repeat(64),
        source_records: vec![source_record.clone()],
    };
    let parity = RuntimeProofParityReport {
        schema: "chio.runtime.proof-parity-report.v1".to_string(),
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

    let manifest_json = chio_runtime_core::runtime_evidence_manifest_json(&manifest)?;
    let input_json = chio_runtime_core::runtime_proof_regeneration_input_json(&input)?;
    let parity_json = chio_runtime_core::runtime_proof_parity_report_json(&parity)?;
    assert!(manifest_json.contains("chio.runtime.evidence-manifest.v1"));
    assert!(input_json.contains("chio.runtime.proof-regeneration-input.v1"));
    assert!(parity_json.contains("chio.runtime.proof-parity-report.v1"));
    Ok(())
}

#[test]
fn runtime_orchestration_contracts_validate_status_and_run_report(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = chio_runtime_core::RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
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
    let profile_hash = chio_runtime_core::runtime_orchestration_profile_sha256(&profile)?;
    let run_contract = chio_runtime_core::RuntimeRunContract {
        schema: chio_runtime_core::CHIO_RUNTIME_RUN_CONTRACT_SCHEMA.to_string(),
        run_id: "runtime-orchestration-1".to_string(),
        profile_sha256: profile_hash.clone(),
        workflow_id: "wf-chio-refund-001".to_string(),
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
    let run_contract_hash = chio_runtime_core::runtime_run_contract_sha256(&run_contract)?;
    let run_report = chio_runtime_core::RuntimeOrchestrationRunReport {
        schema: "chio.runtime.orchestration-run-report.v1".to_string(),
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
        step_states: vec![chio_runtime_core::RuntimeOrchestrationStepState {
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
    let status = chio_runtime_core::RuntimeOrchestrationStatusReport {
        schema: "chio.runtime.orchestration-status-report.v1".to_string(),
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

    chio_runtime_core::validate_runtime_orchestration_profile(&profile)?;
    chio_runtime_core::validate_runtime_run_contract(&run_contract)?;
    let stale_plan = chio_runtime_core::build_runtime_orchestration_plan(
        &profile,
        &run_contract,
        profile.expires_at_unix_ms,
    )?;
    assert!(!stale_plan.accepted);
    assert_eq!(
        stale_plan.failure_code.as_deref(),
        Some("runtime_orchestration_profile_stale")
    );
    assert_eq!(stale_plan.schema, "chio.runtime.orchestration-plan.v1");
    chio_runtime_core::validate_runtime_orchestration_run_report(&run_report)?;
    chio_runtime_core::validate_runtime_orchestration_status_report(&status)?;
    assert!(
        chio_runtime_core::runtime_orchestration_run_report_json(&run_report)?
            .contains("proof_accepted")
    );
    Ok(())
}

#[test]
fn runtime_orchestration_run_report_rejects_inconsistent_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = chio_runtime_core::RuntimeOrchestrationRunReport {
        schema: CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
        run_id: "runtime-orchestration-outcome".to_string(),
        accepted: true,
        failure_code: None,
        status: "proof_accepted".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        profile_sha256: "1".repeat(64),
        run_contract_sha256: "2".repeat(64),
        workflow_run_report_sha256: Some("3".repeat(64)),
        evidence_manifest_sha256: Some("4".repeat(64)),
        proof_regeneration_report_sha256: Some("5".repeat(64)),
        verifier_report_sha256: Some("6".repeat(64)),
        step_states: vec![chio_runtime_core::RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "adm-loopback-1".to_string(),
            state: "proof_accepted".to_string(),
            destructive: false,
            admission_report_sha256: Some("7".repeat(64)),
            tool_receipt_sha256: Some("8".repeat(64)),
            lease_id: None,
        }],
        checks: vec!["runtime_orchestration.proof_regeneration_verified".to_string()],
    };
    report.accepted = false;
    report.status = "terminal_failure".to_string();
    let error = match chio_runtime_core::validate_runtime_orchestration_run_report(&report) {
        Ok(()) => {
            return Err(io::Error::other(
                "rejected runtime orchestration run report without failure code was accepted",
            )
            .into());
        }
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        "runtime_orchestration_run_missing_failure_code"
    );

    report.accepted = true;
    report.status = "proof_accepted".to_string();
    report.failure_code = Some("runtime_orchestration_forged_failure".to_string());
    let error = match chio_runtime_core::validate_runtime_orchestration_run_report(&report) {
        Ok(()) => {
            return Err(io::Error::other(
                "accepted runtime orchestration run report with failure code was accepted",
            )
            .into());
        }
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        "runtime_orchestration_run_unexpected_failure_code"
    );
    Ok(())
}

#[test]
fn runtime_orchestration_status_rejects_stale_profile() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("runtime-status.sqlite3"))?;
    let profile = RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-runtime-orchestration".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_001_000,
        mode: "enforce".to_string(),
        max_concurrent_runs: 2,
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    };
    let profile_sha256 = chio_runtime_core::runtime_orchestration_profile_sha256(&profile)?;

    let status = store.status_report(&profile, profile_sha256, 1_800_000_001_000, true)?;

    assert_eq!(status.schema, "chio.runtime.orchestration-status-report.v1");
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
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_002_000,
    )?;
    assert_eq!(report.schema, "chio.runtime.proof-drift-report.v1");
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_proof_drift_detected")
    );
    assert_eq!(report.artifact_drifts.len(), 1);
    Ok(())
}

#[test]
fn runtime_proof_drift_report_normalizes_runtime_and_proof_report_artifacts(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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
    baseline_manifest.workflow_run_report_sha256 = baseline_manifest.entries[2].sha256.clone();
    baseline_manifest.proof_regeneration_report_sha256 =
        baseline_manifest.entries[3].sha256.clone();
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    candidate_manifest.generated_at_unix_ms = 1_800_000_002_000;
    candidate_manifest.entries[1].sha256 = "7".repeat(64);
    candidate_manifest.entries[3].sha256 = "9".repeat(64);
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
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_proof_drift_report(
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
fn runtime_proof_drift_report_rejects_proof_outcome_drift() -> Result<(), Box<dyn std::error::Error>>
{
    let mut baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-baseline".to_string(),
        generated_at_unix_ms: 1_800_000_001_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "proof_regeneration_report".to_string(),
            path: "proof-regeneration-report.json".to_string(),
            sha256: "6".repeat(64),
            byte_count: 2048,
        }],
    };
    baseline_manifest.proof_regeneration_report_sha256 =
        baseline_manifest.entries[0].sha256.clone();
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    candidate_manifest.generated_at_unix_ms = 1_800_000_002_000;
    candidate_manifest.entries[0].sha256 = "9".repeat(64);
    candidate_manifest.proof_regeneration_report_sha256 =
        candidate_manifest.entries[0].sha256.clone();
    let source = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "a".repeat(64),
        tool_receipt_sha256: "b".repeat(64),
        bilateral_dsse_sha256: "c".repeat(64),
        workflow_step_sha256: "d".repeat(64),
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
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
    candidate_proof.accepted = false;
    candidate_proof.failure_code = Some("runtime_proof_regeneration_denied".to_string());
    candidate_proof.generated_at_unix_ms = 1_800_000_002_000;
    candidate_proof.checks = vec!["runtime_semantic_proof_regeneration.denied".to_string()];

    let report = chio_runtime_core::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_003_000,
    )?;

    assert!(!report.accepted, "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_proof_drift_detected")
    );
    assert!(report
        .semantic_drifts
        .iter()
        .any(|drift| drift.field == "accepted"));
    assert!(report
        .semantic_drifts
        .iter()
        .any(|drift| drift.field == "failure_code"));
    assert!(report
        .semantic_drifts
        .iter()
        .any(|drift| drift.field == "checks"));
    assert!(
        report.artifact_drifts.is_empty(),
        "proof report artifact drift should be covered semantically: {report:#?}"
    );
    Ok(())
}

#[test]
fn runtime_proof_drift_report_rejects_workflow_report_artifact_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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
        baseline_manifest.entries[2].sha256.clone();
    let mut candidate_manifest = baseline_manifest.clone();
    candidate_manifest.run_id = "runtime-candidate".to_string();
    candidate_manifest.generated_at_unix_ms = 1_800_000_002_000;
    candidate_manifest.entries[1].sha256 = "8".repeat(64);
    candidate_manifest.workflow_run_report_sha256 = candidate_manifest.entries[1].sha256.clone();
    let source = RuntimeProofSourceRecord {
        step_index: 0,
        admission_report_sha256: "a".repeat(64),
        tool_receipt_sha256: "b".repeat(64),
        bilateral_dsse_sha256: "c".repeat(64),
        workflow_step_sha256: "d".repeat(64),
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_proof_drift_report(
        &baseline_manifest,
        &candidate_manifest,
        &proof,
        &candidate_proof,
        1_800_000_003_000,
    )?;

    assert!(!report.accepted, "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_proof_drift_detected")
    );
    assert_eq!(report.artifact_drifts.len(), 1);
    assert_eq!(report.artifact_drifts[0].role, "workflow_run_report");
    assert_eq!(report.artifact_drifts[0].path, "workflow-run-report.json");
    Ok(())
}

#[test]
fn runtime_proof_drift_report_rejects_manifest_proof_run_id_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_proof_drift_report(
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
    assert_eq!(first.schema, "chio.runtime.run-lease.v1");
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
    assert_eq!(takeover.schema, "chio.runtime.run-lease.v1");
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
    assert_eq!(recovered.schema, "chio.runtime.run-lease.v1");
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

    assert_eq!(report.schema, "chio.runtime.scheduler-tick-report.v1");
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
fn runtime_ops_scheduler_tick_ignores_terminal_run_leases_for_capacity(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-terminal-capacity.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-terminal", "pending", None, 1_800_000_000_000)?;
    store.acquire_run_lease(
        "runtime-run-terminal",
        "operator-old",
        1_800_000_001_000,
        60_000,
    )?;
    store.record_run_state(
        "runtime-run-terminal",
        "proof_accepted",
        None,
        1_800_000_001_500,
    )?;
    store.record_run_state("runtime-run-next", "pending", None, 1_800_000_002_000)?;

    let mut profile = supervisor_profile();
    profile.max_concurrent_runs = 1;
    let report = store.scheduler_tick_report(&profile, "operator-a", 1_800_000_003_000, 1)?;

    assert!(report.accepted, "{report:#?}");
    assert_eq!(
        report.claimed_run_ids,
        vec!["runtime-run-next"],
        "{report:#?}"
    );
    assert_eq!(report.skipped_run_count, 0, "{report:#?}");
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

    assert_eq!(report.schema, "chio.runtime.ops-status-report.v1");
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
fn runtime_ops_status_ignores_terminal_lease_for_staleness(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-status-terminal-lease.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-terminal", "pending", None, 1_800_000_000_000)?;
    store.acquire_run_lease(
        "runtime-run-terminal",
        "operator-old",
        1_800_000_001_000,
        1_000,
    )?;
    store.record_run_state(
        "runtime-run-terminal",
        "proof_accepted",
        None,
        1_800_000_002_000,
    )?;

    let report = store.ops_status_report(&supervisor_profile(), 1_800_000_400_000, true, true)?;

    assert_eq!(report.schema, "chio.runtime.ops-status-report.v1");
    assert!(report.accepted, "{report:#?}");
    assert_eq!(report.active_lease_count, 1, "{report:#?}");
    assert_eq!(report.stale_lease_count, 0, "{report:#?}");
    assert!(report.ready, "{report:#?}");
    assert!(!report.degraded, "{report:#?}");
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

    assert_eq!(report.schema, "chio.runtime.recovery-drill-report.v1");
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
fn runtime_ops_recovery_drill_blocks_terminal_failure_steps(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-recovery-terminal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state(
        "runtime-run-terminal",
        "terminal_failure",
        Some("runtime_verifier_rejected"),
        1_800_000_000_000,
    )?;
    store.record_run_step_state(
        "runtime-run-terminal",
        RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "adm-terminal".to_string(),
            state: "terminal_failure".to_string(),
            destructive: false,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: Some("2".repeat(64)),
            lease_id: None,
        },
    )?;

    let report = store.recovery_drill_report("runtime-run-terminal", 1_800_000_001_000)?;

    assert_eq!(report.schema, "chio.runtime.recovery-drill-report.v1");
    assert!(!report.accepted, "{report:#?}");
    assert!(report.blocked, "{report:#?}");
    assert!(!report.resumable, "{report:#?}");
    assert!(report.reusable_step_indices.is_empty(), "{report:#?}");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_resume_destructive_repair_required")
    );
    Ok(())
}

#[test]
fn runtime_ops_recovery_drill_blocks_non_contiguous_reusable_steps(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-ops-recovery-gap.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state("runtime-run-gap", "running", None, 1_800_000_000_000)?;
    store.record_run_step_state(
        "runtime-run-gap",
        RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "adm-gap-0".to_string(),
            state: "planned".to_string(),
            destructive: false,
            admission_report_sha256: None,
            tool_receipt_sha256: None,
            lease_id: None,
        },
    )?;
    store.record_run_step_state(
        "runtime-run-gap",
        RuntimeOrchestrationStepState {
            step_index: 1,
            admission_id: "adm-gap-1".to_string(),
            state: "completed".to_string(),
            destructive: false,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: Some("2".repeat(64)),
            lease_id: None,
        },
    )?;

    let report = store.recovery_drill_report("runtime-run-gap", 1_800_000_001_000)?;

    assert!(!report.accepted, "{report:#?}");
    assert!(report.blocked, "{report:#?}");
    assert!(!report.resumable, "{report:#?}");
    assert_eq!(report.next_step_index, Some(0));
    assert_eq!(report.reusable_step_indices, vec![1]);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_resume_non_contiguous_recovery_steps")
    );
    Ok(())
}

#[test]
fn runtime_ops_recovery_drill_preserves_earlier_terminal_failure_blocker(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir
        .path()
        .join("runtime-ops-recovery-terminal-preserved.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.record_run_state(
        "runtime-run-terminal-preserved",
        "terminal_failure",
        Some("runtime_verifier_rejected"),
        1_800_000_000_000,
    )?;
    store.record_run_step_state(
        "runtime-run-terminal-preserved",
        RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "adm-terminal-0".to_string(),
            state: "terminal_failure".to_string(),
            destructive: false,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: None,
            lease_id: None,
        },
    )?;
    store.record_run_step_state(
        "runtime-run-terminal-preserved",
        RuntimeOrchestrationStepState {
            step_index: 1,
            admission_id: "adm-terminal-1".to_string(),
            state: "completed".to_string(),
            destructive: true,
            admission_report_sha256: Some("2".repeat(64)),
            tool_receipt_sha256: Some("3".repeat(64)),
            lease_id: Some("lease-terminal-1".to_string()),
        },
    )?;
    store.record_evidence_artifact(
        "runtime-run-terminal-preserved",
        &RuntimeEvidenceManifestEntry {
            role: "workflow_run_report".to_string(),
            path: "workflow-run-report.json".to_string(),
            sha256: "4".repeat(64),
            byte_count: 128,
        },
        1_800_000_000_500,
    )?;

    let report =
        store.recovery_drill_report("runtime-run-terminal-preserved", 1_800_000_001_000)?;

    assert!(!report.accepted, "{report:#?}");
    assert!(report.blocked, "{report:#?}");
    assert!(!report.resumable, "{report:#?}");
    assert_eq!(report.next_step_index, Some(0));
    assert_eq!(report.reusable_step_indices, vec![1]);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_resume_destructive_repair_required")
    );
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
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_evidence_sink_health_report(
        "runtime-run-health",
        dir.path(),
        &manifest,
        &["workflow_run_report".to_string()],
        1_800_000_000_000,
        false,
    )?;
    assert_eq!(report.schema, "chio.runtime.evidence-sink-health-report.v1");
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
fn runtime_ops_evidence_health_detects_manifest_report_binding_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let workflow = br#"{"ok":true}"#;
    let proof = br#"{"ok":false}"#;
    std::fs::write(dir.path().join("workflow-run-report.json"), workflow)?;
    std::fs::write(dir.path().join("proof-regeneration-report.json"), proof)?;
    let manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "runtime-run-health".to_string(),
        generated_at_unix_ms: 1_800_000_000_000,
        workflow_run_report_sha256: "1".repeat(64),
        proof_regeneration_report_sha256: "2".repeat(64),
        entries: vec![
            RuntimeEvidenceManifestEntry {
                role: "workflow_run_report".to_string(),
                path: "workflow-run-report.json".to_string(),
                sha256: chio_core_types::crypto::sha256_hex(workflow),
                byte_count: u64::try_from(workflow.len())?,
            },
            RuntimeEvidenceManifestEntry {
                role: "proof_regeneration_report".to_string(),
                path: "proof-regeneration-report.json".to_string(),
                sha256: chio_core_types::crypto::sha256_hex(proof),
                byte_count: u64::try_from(proof.len())?,
            },
        ],
    };

    let report = chio_runtime_core::generate_runtime_evidence_sink_health_report(
        "runtime-run-health",
        dir.path(),
        &manifest,
        &[
            "workflow_run_report".to_string(),
            "proof_regeneration_report".to_string(),
        ],
        1_800_000_000_000,
        false,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_evidence_artifact_hash_mismatch")
    );
    assert!(report
        .artifact_hash_mismatches
        .iter()
        .any(|path| path == "workflow-run-report.json"));
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
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_evidence_sink_health_report(
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
        schema: CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: true,
        }],
    };
    let report = chio_runtime_core::generate_runtime_provider_health_report(
        &supervisor_profile(),
        &bindings,
        1_800_000_000_000,
    )?;
    assert_eq!(report.schema, "chio.runtime.provider-health-report.v1");
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
        schema: CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
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

    let report = chio_runtime_core::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        1_800_000_001_000,
    )?;

    assert_eq!(report.schema, "chio.runtime.provider-health-report.v1");
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
        schema: CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA.to_string(),
        profile_id: "retention-runtime-local".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_001_000,
        min_retain_ms: 86_400_000,
        destructive_hold_ms: 604_800_000,
        legal_hold: false,
        dry_run_only: true,
    };

    let report = chio_runtime_core::generate_runtime_artifact_retention_plan(
        &profile,
        &["runtime-run-1".to_string()],
        1_800_000_001_000,
    )?;

    assert_eq!(report.schema, "chio.runtime.artifact-retention-plan.v1");
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_retention_profile_stale")
    );
    assert!(report.candidate_actions.is_empty());
    Ok(())
}
