#[path = "runtime/admission.rs"]
mod admission;
#[path = "runtime/io.rs"]
mod io;
#[path = "runtime/loopback.rs"]
mod loopback;
#[path = "runtime/ops.rs"]
mod ops;
#[path = "runtime/orchestration.rs"]
mod orchestration;
#[path = "runtime/signing.rs"]
mod signing;

#[cfg(test)]
use crate::CliError;

pub(crate) use admission::{cmd_chio_runtime_admit, cmd_chio_runtime_pheromone_evaluate};
pub(crate) use io::validate_runtime_relative_path;
pub(crate) use loopback::cmd_chio_runtime_run_loopback;
pub(crate) use ops::{
    cmd_chio_runtime_ops_evidence_health, cmd_chio_runtime_ops_provider_health,
    cmd_chio_runtime_ops_recovery_drill, cmd_chio_runtime_ops_retention_plan,
    cmd_chio_runtime_ops_status, cmd_chio_runtime_ops_tick,
};
pub(crate) use orchestration::{
    cmd_chio_runtime_orchestrate_drift, cmd_chio_runtime_orchestrate_lint,
    cmd_chio_runtime_orchestrate_plan, cmd_chio_runtime_orchestrate_resume,
    cmd_chio_runtime_orchestrate_run, cmd_chio_runtime_orchestrate_status,
};
pub(crate) use signing::{
    cmd_chio_runtime_peer_weights_hash, cmd_chio_runtime_sign_peer_weights,
    cmd_chio_runtime_sign_pheromone_query_report, cmd_chio_runtime_sign_policy,
    cmd_chio_runtime_sign_trust_input,
};

#[cfg(test)]
pub(crate) fn canonical_sha256_json<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<String, CliError> {
    let bytes = chio_core_types::canonical::canonical_json_bytes(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod chio_orchestration_cli_tests {
    use super::{
        canonical_sha256_json, cmd_chio_runtime_ops_status, cmd_chio_runtime_orchestrate_drift,
        cmd_chio_runtime_orchestrate_resume, cmd_chio_runtime_orchestrate_run,
        cmd_chio_runtime_orchestrate_status,
    };
    use serde::de::DeserializeOwned;
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const ISSUED_AT: u64 = 1_800_000_000_000;
    const EXPIRES_AT: u64 = 1_800_003_600_000;
    const NOW: u64 = 1_800_000_010_000;

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn orchestration_profile() -> chio_runtime::RuntimeOrchestrationProfile {
        chio_runtime::RuntimeOrchestrationProfile {
            schema: chio_runtime::CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
            profile_id: "profile-runtime-orchestration-cli".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            verifier_id: "did:chio:buyer-verifier".to_string(),
            mode: "enforce".to_string(),
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            max_concurrent_runs: 2,
            fail_closed_on: vec!["runtime_orchestration_profile_stale".to_string()],
        }
    }

    fn supervisor_profile() -> chio_runtime::RuntimeSupervisorProfile {
        chio_runtime::RuntimeSupervisorProfile {
            schema: chio_runtime::CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA.to_string(),
            profile_id: "runtime-supervisor-cli".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            max_concurrent_runs: 2,
            run_lease_ttl_ms: 60_000,
            stale_run_after_ms: 300_000,
            evidence_required_roles: vec![
                "workflow_run_report".to_string(),
                "proof_regeneration_report".to_string(),
            ],
            fail_closed_on: vec!["runtime_evidence_artifact_hash_mismatch".to_string()],
        }
    }

    fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(value)?;
        fs::write(path, format!("{json}\n"))?;
        Ok(())
    }

    fn write_json_with_hashes<T: serde::Serialize>(
        path: &Path,
        value: &T,
    ) -> Result<(String, String, u64), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(value)?;
        let bytes = format!("{json}\n").into_bytes();
        let file_sha256 = chio_core::sha256_hex(&bytes);
        let canonical_sha256 = canonical_sha256_json(value, "test canonical hash")?;
        let byte_count = u64::try_from(bytes.len())?;
        fs::write(path, bytes)?;
        Ok((file_sha256, canonical_sha256, byte_count))
    }

    fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    fn write_profile(
        dir: &Path,
        profile: &chio_runtime::RuntimeOrchestrationProfile,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let path = dir.join("profile.json");
        write_json(&path, profile)?;
        Ok(path)
    }

    fn write_supervisor_profile(
        dir: &Path,
        profile: &chio_runtime::RuntimeSupervisorProfile,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let path = dir.join("supervisor-profile.json");
        write_json(&path, profile)?;
        Ok(path)
    }

    fn runtime_contract(
        profile: &chio_runtime::RuntimeOrchestrationProfile,
        run_id: &str,
    ) -> Result<chio_runtime::RuntimeRunContract, Box<dyn Error>> {
        Ok(chio_runtime::RuntimeRunContract {
            schema: chio_runtime::CHIO_RUNTIME_RUN_CONTRACT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            profile_sha256: chio_runtime::runtime_orchestration_profile_sha256(profile)?,
            workflow_id: format!("workflow-{run_id}"),
            expected_step_count: 1,
            admission_ids: vec!["adm-runtime-cli-0".to_string()],
            store_id: "sqlite-runtime-store".to_string(),
            evidence_sink_id: "local-evidence-sink".to_string(),
            proof_regeneration_required: true,
        })
    }

    fn write_contract(
        dir: &Path,
        contract: &chio_runtime::RuntimeRunContract,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let path = dir.join("run-contract.json");
        write_json(&path, contract)?;
        Ok(path)
    }

    fn write_runtime_evidence(
        dir: &Path,
        run_id: &str,
        generated_at_unix_ms: u64,
        proof_marker: &str,
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(dir)?;
        let proof_package = serde_json::json!({
            "schema": "chio.test.runtime-proof-package.v1",
            "marker": proof_marker
        });
        let (proof_package_file_sha256, proof_package_canonical_sha256, proof_package_byte_count) =
            write_json_with_hashes(&dir.join("proof-package.json"), &proof_package)?;
        let verifier_report = serde_json::json!({
            "schema": chio_attest_buyer_core::report::VERIFIER_REPORT_SCHEMA,
            "packageSha256": proof_package_canonical_sha256.clone(),
            "trustBundleSha256": fixed_hash('8'),
            "contextSha256": fixed_hash('9'),
            "revocationEpochHeight": 1,
            "accepted": true,
            "checks": [{
                "code": "runtime_verifier.accepted",
                "name": "runtime verifier accepted",
                "passed": true
            }]
        });
        let verifier_report_sha256 =
            canonical_sha256_json(&verifier_report, "test verifier report hash")?;
        let source_record = chio_runtime::RuntimeProofSourceRecord {
            step_index: 0,
            admission_report_sha256: fixed_hash('1'),
            tool_receipt_sha256: fixed_hash('2'),
            bilateral_dsse_sha256: fixed_hash('3'),
            workflow_step_sha256: fixed_hash('4'),
        };
        let proof_report = chio_runtime::RuntimeProofRegenerationReport {
            schema: chio_runtime::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms,
            proof_package_sha256: Some(proof_package_canonical_sha256),
            verifier_report_sha256: Some(verifier_report_sha256.clone()),
            workflow_receipt_sha256: Some(fixed_hash('5')),
            source_records: vec![source_record.clone()],
            checks: vec!["runtime_source_records.bound".to_string()],
        };
        let proof_report_sha256 = canonical_sha256_json(&proof_report, "test proof report hash")?;
        let workflow_report = chio_runtime::RuntimeWorkflowRunReport {
            schema: chio_runtime::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms,
            admission_report_sha256: fixed_hash('6'),
            evidence_paths: vec!["proof-package.json".to_string()],
            step_evidence: vec![chio_runtime::RuntimeStepEvidence {
                schema: chio_runtime::CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: 0,
                admission_id: "adm-runtime-cli-0".to_string(),
                admission_report_sha256: source_record.admission_report_sha256.clone(),
                tool_receipt_id: format!("receipt-{run_id}"),
                tool_receipt_sha256: source_record.tool_receipt_sha256.clone(),
                output_sha256: fixed_hash('7'),
                bilateral_dsse_sha256: source_record.bilateral_dsse_sha256.clone(),
                workflow_step_sha256: source_record.workflow_step_sha256.clone(),
                parent_receipt_sha256: None,
                consistency_anchor: format!("chio:runtime:{run_id}:0"),
                destructive: false,
                lease_id: None,
                governance_receipt_id: None,
            }],
            proof_regeneration_report_sha256: Some(proof_report_sha256.clone()),
        };
        let workflow_report_sha256 =
            canonical_sha256_json(&workflow_report, "test workflow report hash")?;
        let manifest = chio_runtime::RuntimeEvidenceManifest {
            schema: chio_runtime::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            generated_at_unix_ms,
            workflow_run_report_sha256: workflow_report_sha256,
            proof_regeneration_report_sha256: proof_report_sha256,
            entries: vec![chio_runtime::RuntimeEvidenceManifestEntry {
                role: "proof_package".to_string(),
                path: "proof-package.json".to_string(),
                sha256: proof_package_file_sha256,
                byte_count: proof_package_byte_count,
            }],
        };

        write_json(&dir.join("workflow-run-report.json"), &workflow_report)?;
        write_json(&dir.join("proof-regeneration-report.json"), &proof_report)?;
        write_json(&dir.join("runtime-evidence-manifest.json"), &manifest)?;
        write_json(&dir.join("verifier-report.json"), &verifier_report)?;
        Ok(())
    }

    fn write_rejected_runtime_evidence_without_verifier(
        dir: &Path,
        run_id: &str,
        generated_at_unix_ms: u64,
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(dir)?;
        let source_record = chio_runtime::RuntimeProofSourceRecord {
            step_index: 0,
            admission_report_sha256: fixed_hash('1'),
            tool_receipt_sha256: fixed_hash('2'),
            bilateral_dsse_sha256: fixed_hash('3'),
            workflow_step_sha256: fixed_hash('4'),
        };
        let proof_report = chio_runtime::RuntimeProofRegenerationReport {
            schema: chio_runtime::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: false,
            failure_code: Some("runtime_proof_regeneration_missing_package_hash".to_string()),
            generated_at_unix_ms,
            proof_package_sha256: None,
            verifier_report_sha256: None,
            workflow_receipt_sha256: None,
            source_records: Vec::new(),
            checks: vec!["runtime_source_records.regeneration_failed".to_string()],
        };
        let (proof_report_file_sha256, proof_report_sha256, proof_report_byte_count) =
            write_json_with_hashes(&dir.join("proof-regeneration-report.json"), &proof_report)?;
        let workflow_report = chio_runtime::RuntimeWorkflowRunReport {
            schema: chio_runtime::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms,
            admission_report_sha256: fixed_hash('6'),
            evidence_paths: vec!["proof-regeneration-report.json".to_string()],
            step_evidence: vec![chio_runtime::RuntimeStepEvidence {
                schema: chio_runtime::CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: 0,
                admission_id: "adm-runtime-cli-0".to_string(),
                admission_report_sha256: source_record.admission_report_sha256,
                tool_receipt_id: format!("receipt-{run_id}"),
                tool_receipt_sha256: source_record.tool_receipt_sha256,
                output_sha256: fixed_hash('7'),
                bilateral_dsse_sha256: source_record.bilateral_dsse_sha256,
                workflow_step_sha256: source_record.workflow_step_sha256,
                parent_receipt_sha256: None,
                consistency_anchor: format!("chio:runtime:{run_id}:0"),
                destructive: false,
                lease_id: None,
                governance_receipt_id: None,
            }],
            proof_regeneration_report_sha256: Some(proof_report_sha256.clone()),
        };
        let (workflow_report_file_sha256, workflow_report_sha256, workflow_report_byte_count) =
            write_json_with_hashes(&dir.join("workflow-run-report.json"), &workflow_report)?;
        let manifest = chio_runtime::RuntimeEvidenceManifest {
            schema: chio_runtime::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            generated_at_unix_ms,
            workflow_run_report_sha256: workflow_report_sha256,
            proof_regeneration_report_sha256: proof_report_sha256,
            entries: vec![
                chio_runtime::RuntimeEvidenceManifestEntry {
                    role: "workflow_run_report".to_string(),
                    path: "workflow-run-report.json".to_string(),
                    sha256: workflow_report_file_sha256,
                    byte_count: workflow_report_byte_count,
                },
                chio_runtime::RuntimeEvidenceManifestEntry {
                    role: "proof_regeneration_report".to_string(),
                    path: "proof-regeneration-report.json".to_string(),
                    sha256: proof_report_file_sha256,
                    byte_count: proof_report_byte_count,
                },
            ],
        };

        write_json(&dir.join("runtime-evidence-manifest.json"), &manifest)?;
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_drift_rejects_stale_profile_window() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let mut profile = orchestration_profile();
        profile.expires_at_unix_ms = NOW;
        let profile_path = write_profile(dir.path(), &profile)?;
        let report_path = dir.path().join("drift-report.json");

        let error = cmd_chio_runtime_orchestrate_drift(
            &profile_path,
            &dir.path().join("runs"),
            ISSUED_AT,
            NOW,
            &report_path,
        )
        .expect_err("stale drift profile unexpectedly passed");

        assert!(error
            .to_string()
            .contains("runtime_orchestration_profile_stale"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_drift_compares_every_run_in_window() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let runs_dir = dir.path().join("runs");
        write_runtime_evidence(&runs_dir.join("run-a"), "run-a", NOW, "same")?;
        write_runtime_evidence(&runs_dir.join("run-b"), "run-b", NOW + 1, "same")?;
        write_runtime_evidence(&runs_dir.join("run-c"), "run-c", NOW + 2, "changed")?;
        let report_path = dir.path().join("drift-report.json");

        cmd_chio_runtime_orchestrate_drift(
            &profile_path,
            &runs_dir,
            NOW - 1,
            NOW + 3,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeProofDriftReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert_eq!(report.baseline_run_id, "run-a");
        assert_eq!(report.candidate_run_id, "run-c");
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_proof_drift_detected")
        );
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_run_rejects_stale_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile = orchestration_profile();
        let profile_path = write_profile(dir.path(), &profile)?;
        let contract = runtime_contract(&profile, "run-stale")?;
        let contract_path = write_contract(dir.path(), &contract)?;
        let evidence_dir = dir.path().join("evidence");
        write_runtime_evidence(&evidence_dir, "run-stale", ISSUED_AT - 1, "stale")?;
        let report_path = dir.path().join("run-report.json");

        cmd_chio_runtime_orchestrate_run(
            &profile_path,
            &contract_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationRunReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_orchestration_evidence_stale")
        );
        assert_eq!(report.status, "terminal_failure");
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_run_records_rejected_proof_without_verifier(
    ) -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile = orchestration_profile();
        let profile_path = write_profile(dir.path(), &profile)?;
        let contract = runtime_contract(&profile, "run-rejected-proof")?;
        let contract_path = write_contract(dir.path(), &contract)?;
        let evidence_dir = dir.path().join("evidence");
        write_rejected_runtime_evidence_without_verifier(&evidence_dir, "run-rejected-proof", NOW)?;
        let report_path = dir.path().join("run-report.json");

        cmd_chio_runtime_orchestrate_run(
            &profile_path,
            &contract_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationRunReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_proof_regeneration_missing_package_hash")
        );
        assert_eq!(report.status, "terminal_failure");
        assert_eq!(report.verifier_report_sha256, None);
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_run_emits_report_for_missing_manifest_artifact(
    ) -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile = orchestration_profile();
        let profile_path = write_profile(dir.path(), &profile)?;
        let contract = runtime_contract(&profile, "run-missing-artifact")?;
        let contract_path = write_contract(dir.path(), &contract)?;
        let evidence_dir = dir.path().join("evidence");
        write_runtime_evidence(&evidence_dir, "run-missing-artifact", NOW, "fresh")?;
        fs::remove_file(evidence_dir.join("proof-package.json"))?;
        let report_path = dir.path().join("run-report.json");

        cmd_chio_runtime_orchestrate_run(
            &profile_path,
            &contract_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationRunReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert_eq!(report.status, "terminal_failure");
        assert_eq!(report.failure_code.as_deref(), Some("runtime_admission_io"));
        assert!(report
            .checks
            .iter()
            .any(|check| check == "runtime_orchestration.evidence_load_failed"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_drift_rejects_stale_evidence_in_window() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile = orchestration_profile();
        let profile_path = write_profile(dir.path(), &profile)?;
        let runs_dir = dir.path().join("runs");
        write_runtime_evidence(&runs_dir.join("run-a"), "run-a", ISSUED_AT - 1, "stale")?;
        write_runtime_evidence(&runs_dir.join("run-b"), "run-b", NOW, "fresh")?;

        let error = cmd_chio_runtime_orchestrate_drift(
            &profile_path,
            &runs_dir,
            ISSUED_AT - 10,
            NOW + 1,
            &dir.path().join("drift-report.json"),
        )
        .expect_err("stale evidence inside drift window unexpectedly passed");

        assert!(error
            .to_string()
            .contains("outside the orchestration profile window"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_missing_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let report_path = dir.path().join("status-report.json");

        cmd_chio_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("missing-evidence"),
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationStatusReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_ops_status_degraded")
        );
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_corrupt_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let evidence_dir = dir.path().join("evidence");
        fs::create_dir_all(&evidence_dir)?;
        fs::write(evidence_dir.join("workflow-run-report.json"), "{not json")?;
        let report_path = dir.path().join("status-report.json");

        cmd_chio_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationStatusReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_stale_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let evidence_dir = dir.path().join("evidence");
        write_runtime_evidence(&evidence_dir, "run-stale", ISSUED_AT - 1, "stale")?;
        let report_path = dir.path().join("status-report.json");

        cmd_chio_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationStatusReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_checks_every_recorded_run_directory() -> Result<(), Box<dyn Error>>
    {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let store_path = dir.path().join("runtime.sqlite3");
        let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(&store_path)?;
        store.record_run_state("run-good", "proof_accepted", None, NOW)?;
        store.record_run_state("run-missing", "proof_accepted", None, NOW)?;
        let evidence_root = dir.path().join("evidence");
        write_runtime_evidence(&evidence_root.join("run-good"), "run-good", NOW, "fresh")?;
        let report_path = dir.path().join("status-report.json");

        cmd_chio_runtime_orchestrate_status(
            &profile_path,
            &store_path,
            &evidence_root,
            NOW,
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOrchestrationStatusReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        assert!(!report.ready);
        Ok(())
    }

    #[test]
    fn runtime_ops_status_rejects_empty_evidence_root_when_store_has_runs(
    ) -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_supervisor_profile(dir.path(), &supervisor_profile())?;
        let store_path = dir.path().join("runtime.sqlite3");
        let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(&store_path)?;
        store.record_run_state("run-without-evidence", "planned", None, NOW)?;
        let evidence_root = dir.path().join("evidence");
        fs::create_dir_all(&evidence_root)?;
        let report_path = dir.path().join("ops-status-report.json");

        cmd_chio_runtime_ops_status(
            &profile_path,
            &store_path,
            &evidence_root,
            None,
            Some(NOW),
            &report_path,
        )?;
        let report: chio_runtime::RuntimeOpsStatusReport = read_json(&report_path)?;

        assert!(!report.evidence_sink_healthy, "{report:#?}");
        assert!(!report.ready, "{report:#?}");
        assert!(report.degraded, "{report:#?}");
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_resume_validates_forged_input() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let resume_path = dir.path().join("resume-plan.json");
        write_json(
            &resume_path,
            &chio_runtime::RuntimeOrchestrationResumePlan {
                schema: chio_runtime::CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA.to_string(),
                run_id: "run-forged".to_string(),
                accepted: true,
                failure_code: None,
                generated_at_unix_ms: NOW,
                next_step_index: Some(1),
                reusable_step_indices: vec![0],
                blocked: true,
                checks: vec!["runtime_orchestration.resume_inputs_loaded".to_string()],
            },
        )?;

        let error = cmd_chio_runtime_orchestrate_resume(
            &profile_path,
            &resume_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("evidence"),
            NOW,
            &dir.path().join("resume-report.json"),
        )
        .expect_err("forged accepted blocked resume plan unexpectedly passed");

        assert!(error
            .to_string()
            .contains("runtime_orchestration_resume_accepted_blocked"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_resume_validates_corrupt_input() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let resume_path = dir.path().join("resume-plan.json");
        write_json(
            &resume_path,
            &serde_json::json!({
                "schema": "chio.runtime.orchestration-resume-plan.v0",
                "runId": "run-corrupt",
                "accepted": true,
                "generatedAtUnixMs": NOW,
                "nextStepIndex": 1,
                "reusableStepIndices": [0],
                "blocked": false,
                "checks": []
            }),
        )?;

        let error = cmd_chio_runtime_orchestrate_resume(
            &profile_path,
            &resume_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("evidence"),
            NOW,
            &dir.path().join("resume-report.json"),
        )
        .expect_err("corrupt resume plan unexpectedly passed");

        assert!(error
            .to_string()
            .contains("unsupported_runtime_orchestration_resume_plan_schema"));
        Ok(())
    }
}
