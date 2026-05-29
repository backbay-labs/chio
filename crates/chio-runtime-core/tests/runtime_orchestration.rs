use std::error::Error;
use std::fs;
use std::path::Path;

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_runtime_core::{
    load_runtime_orchestration_evidence, runtime_orchestration_evidence_sink_healthy,
    runtime_orchestration_profile_sha256, validate_runtime_orchestration_evidence_binding,
    validate_runtime_orchestration_profile, validate_runtime_run_contract, RuntimeEvidenceManifest,
    RuntimeEvidenceManifestEntry, RuntimeOrchestrationProfile, RuntimeProofRegenerationReport,
    RuntimeProofSourceRecord, RuntimeRunContract, RuntimeStepEvidence, RuntimeWorkflowRunReport,
    CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA,
    CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA, CHIO_RUNTIME_RUN_CONTRACT_SCHEMA,
    CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA, CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
};
use serde::Serialize;
use tempfile::TempDir;

const ISSUED_AT: u64 = 1_800_000_000_000;
const EXPIRES_AT: u64 = 1_800_003_600_000;
const NOW: u64 = 1_800_000_010_000;

struct EvidenceFixture {
    profile: RuntimeOrchestrationProfile,
    contract: RuntimeRunContract,
    evidence_dir: TempDir,
}

#[test]
fn runtime_orchestration_input_documents_accept_chio_native_schemas() -> Result<(), Box<dyn Error>>
{
    let profile = RuntimeOrchestrationProfile {
        schema: "chio.runtime.orchestration-profile.v1".to_string(),
        profile_id: "runtime-orchestration-profile".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        mode: "enforce".to_string(),
        issued_at_unix_ms: ISSUED_AT,
        expires_at_unix_ms: EXPIRES_AT,
        max_concurrent_runs: 2,
        fail_closed_on: vec!["runtime_orchestration_profile_stale".to_string()],
    };
    validate_runtime_orchestration_profile(&profile)?;
    let profile_sha256 = runtime_orchestration_profile_sha256(&profile)?;
    let contract = RuntimeRunContract {
        schema: "chio.runtime.run-contract.v1".to_string(),
        run_id: "run-runtime-orchestration".to_string(),
        profile_sha256,
        workflow_id: "workflow-runtime-orchestration".to_string(),
        expected_step_count: 1,
        admission_ids: vec!["admission-A".to_string()],
        store_id: "sqlite-runtime-store".to_string(),
        evidence_sink_id: "local-evidence-sink".to_string(),
        proof_regeneration_required: true,
    };
    validate_runtime_run_contract(&contract)?;

    let mut const_schema_profile = profile;
    const_schema_profile.schema = CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string();
    validate_runtime_orchestration_profile(&const_schema_profile)?;
    Ok(())
}

#[test]
fn runtime_orchestration_evidence_binding_accepts_consistent_artifacts(
) -> Result<(), Box<dyn Error>> {
    let fixture = write_evidence_fixture(NOW)?;
    let evidence = load_runtime_orchestration_evidence(fixture.evidence_dir.path())?;

    validate_runtime_orchestration_evidence_binding(&fixture.contract, &evidence)?;
    assert!(runtime_orchestration_evidence_sink_healthy(
        &fixture.profile,
        fixture.evidence_dir.path(),
        NOW
    )?);

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_binding_rejects_wrong_admission_order(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = write_evidence_fixture(NOW)?;
    fixture.contract.admission_ids = vec!["admission-B".to_string()];
    let evidence = load_runtime_orchestration_evidence(fixture.evidence_dir.path())?;

    let failure = validate_runtime_orchestration_evidence_binding(&fixture.contract, &evidence)
        .err()
        .ok_or("expected admission mismatch")?;
    assert_eq!(
        failure.code(),
        "runtime_orchestration_evidence_admission_mismatch"
    );

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_binding_rejects_wrong_step_index() -> Result<(), Box<dyn Error>> {
    let fixture = write_evidence_fixture(NOW)?;
    let mut evidence = load_runtime_orchestration_evidence(fixture.evidence_dir.path())?;
    evidence.workflow_run_report.step_evidence[0].step_index = 1;

    let failure = validate_runtime_orchestration_evidence_binding(&fixture.contract, &evidence)
        .err()
        .ok_or("expected step index mismatch")?;
    assert_eq!(
        failure.code(),
        "runtime_orchestration_evidence_admission_mismatch"
    );

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_sink_health_rejects_stale_artifacts() -> Result<(), Box<dyn Error>>
{
    let mut fixture = write_evidence_fixture(NOW)?;
    fixture.profile.issued_at_unix_ms = NOW + 100;
    fixture.profile.expires_at_unix_ms = NOW + 1_000;

    assert!(!runtime_orchestration_evidence_sink_healthy(
        &fixture.profile,
        fixture.evidence_dir.path(),
        NOW + 200
    )?);

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_sink_health_rejects_rejected_verifier_report(
) -> Result<(), Box<dyn Error>> {
    let fixture = write_evidence_fixture_with_verifier(NOW, false)?;

    assert!(!runtime_orchestration_evidence_sink_healthy(
        &fixture.profile,
        fixture.evidence_dir.path(),
        NOW
    )?);

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_loads_rejected_proof_without_verifier_report(
) -> Result<(), Box<dyn Error>> {
    let fixture = write_rejected_proof_without_verifier_fixture(NOW)?;

    assert!(!fixture
        .evidence_dir
        .path()
        .join("verifier-report.json")
        .exists());
    let evidence = load_runtime_orchestration_evidence(fixture.evidence_dir.path())?;

    assert!(!evidence.proof_regeneration_report.accepted);
    assert!(!evidence.verifier_report_accepted);
    assert_eq!(evidence.verifier_report_sha256, None);
    assert!(!runtime_orchestration_evidence_sink_healthy(
        &fixture.profile,
        fixture.evidence_dir.path(),
        NOW
    )?);

    Ok(())
}

#[test]
fn runtime_orchestration_evidence_load_rejects_manifest_artifact_hash_mismatch(
) -> Result<(), Box<dyn Error>> {
    let fixture = write_evidence_fixture(NOW)?;
    let proof_package_path = fixture.evidence_dir.path().join("proof-package.json");
    let proof_package = fs::read_to_string(&proof_package_path)?;
    let tampered_proof_package = proof_package.replace("proof-package-A", "proof-package-B");
    assert_eq!(
        proof_package.len(),
        tampered_proof_package.len(),
        "fixture tamper must preserve byte count to exercise hash validation"
    );
    fs::write(proof_package_path, tampered_proof_package)?;

    let error = match load_runtime_orchestration_evidence(fixture.evidence_dir.path()) {
        Ok(_) => panic!("tampered manifest artifact unexpectedly loaded"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "runtime_orchestration_artifact_hash_mismatch");
    Ok(())
}

fn write_evidence_fixture(generated_at_unix_ms: u64) -> Result<EvidenceFixture, Box<dyn Error>> {
    write_evidence_fixture_with_verifier(generated_at_unix_ms, true)
}

fn write_evidence_fixture_with_verifier(
    generated_at_unix_ms: u64,
    verifier_accepted: bool,
) -> Result<EvidenceFixture, Box<dyn Error>> {
    let evidence_dir = TempDir::new()?;
    let profile = RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "runtime-orchestration-profile".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        mode: "enforce".to_string(),
        issued_at_unix_ms: ISSUED_AT,
        expires_at_unix_ms: EXPIRES_AT,
        max_concurrent_runs: 2,
        fail_closed_on: vec!["runtime_orchestration_profile_stale".to_string()],
    };
    let profile_sha256 = runtime_orchestration_profile_sha256(&profile)?;
    let contract = RuntimeRunContract {
        schema: CHIO_RUNTIME_RUN_CONTRACT_SCHEMA.to_string(),
        run_id: "run-runtime-orchestration".to_string(),
        profile_sha256,
        workflow_id: "workflow-runtime-orchestration".to_string(),
        expected_step_count: 1,
        admission_ids: vec!["admission-A".to_string()],
        store_id: "sqlite-runtime-store".to_string(),
        evidence_sink_id: "local-evidence-sink".to_string(),
        proof_regeneration_required: true,
    };
    let step = RuntimeStepEvidence {
        schema: CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
        step_index: 0,
        admission_id: "admission-A".to_string(),
        admission_report_sha256: fixed_hash('a'),
        tool_receipt_id: "receipt-A".to_string(),
        tool_receipt_sha256: fixed_hash('b'),
        output_sha256: fixed_hash('c'),
        bilateral_dsse_sha256: fixed_hash('d'),
        workflow_step_sha256: fixed_hash('e'),
        parent_receipt_sha256: None,
        consistency_anchor: "anchor-A".to_string(),
        destructive: false,
        lease_id: None,
        governance_receipt_id: None,
    };
    let proof_package = serde_json::json!({
        "packageId": "proof-package-A",
        "runId": contract.run_id.clone(),
        "source": "runtime-orchestration-test"
    });
    let (proof_package_file_sha256, proof_package_canonical_sha256, proof_package_bytes) =
        write_json_with_hashes(
            &evidence_dir.path().join("proof-package.json"),
            &proof_package,
        )?;
    let mut verifier_report = serde_json::json!({
        "schema": chio_attest_buyer_core::VERIFIER_REPORT_SCHEMA,
        "packageSha256": proof_package_canonical_sha256.clone(),
        "trustBundleSha256": fixed_hash('8'),
        "contextSha256": fixed_hash('9'),
        "revocationEpochHeight": 1,
        "accepted": verifier_accepted,
        "checks": [{
            "code": "runtime_verifier.accepted",
            "name": "runtime verifier accepted",
            "passed": verifier_accepted
        }]
    });
    if !verifier_accepted {
        verifier_report["failure"] = serde_json::json!({
            "code": "runtime_verifier_rejected",
            "phase": "verification",
            "detail": "verifier rejected fixture proof package"
        });
    }
    let verifier_report_sha256 = canonical_hash(&verifier_report)?;
    write_json(
        &evidence_dir.path().join("verifier-report.json"),
        &verifier_report,
    )?;
    let proof = RuntimeProofRegenerationReport {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms,
        proof_package_sha256: Some(proof_package_canonical_sha256),
        verifier_report_sha256: Some(verifier_report_sha256),
        workflow_receipt_sha256: Some(fixed_hash('f')),
        source_records: vec![RuntimeProofSourceRecord {
            step_index: step.step_index,
            admission_report_sha256: step.admission_report_sha256.clone(),
            tool_receipt_sha256: step.tool_receipt_sha256.clone(),
            bilateral_dsse_sha256: step.bilateral_dsse_sha256.clone(),
            workflow_step_sha256: step.workflow_step_sha256.clone(),
        }],
        checks: vec!["runtime_proof.regenerated".to_string()],
    };
    let proof_sha256 = canonical_hash(&proof)?;
    write_json(
        &evidence_dir.path().join("proof-regeneration-report.json"),
        &proof,
    )?;
    let workflow = RuntimeWorkflowRunReport {
        schema: CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms,
        admission_report_sha256: step.admission_report_sha256.clone(),
        evidence_paths: vec!["proof-package.json".to_string()],
        step_evidence: vec![step],
        proof_regeneration_report_sha256: Some(proof_sha256.clone()),
    };
    let workflow_sha256 = canonical_hash(&workflow)?;
    write_json(
        &evidence_dir.path().join("workflow-run-report.json"),
        &workflow,
    )?;
    let manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        generated_at_unix_ms,
        workflow_run_report_sha256: workflow_sha256,
        proof_regeneration_report_sha256: proof_sha256,
        entries: vec![RuntimeEvidenceManifestEntry {
            role: "proof_package".to_string(),
            path: "proof-package.json".to_string(),
            sha256: proof_package_file_sha256,
            byte_count: proof_package_bytes,
        }],
    };
    write_json(
        &evidence_dir.path().join("runtime-evidence-manifest.json"),
        &manifest,
    )?;
    Ok(EvidenceFixture {
        profile,
        contract,
        evidence_dir,
    })
}

fn write_rejected_proof_without_verifier_fixture(
    generated_at_unix_ms: u64,
) -> Result<EvidenceFixture, Box<dyn Error>> {
    let evidence_dir = TempDir::new()?;
    let profile = RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "runtime-orchestration-profile".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        mode: "enforce".to_string(),
        issued_at_unix_ms: ISSUED_AT,
        expires_at_unix_ms: EXPIRES_AT,
        max_concurrent_runs: 2,
        fail_closed_on: vec!["runtime_orchestration_profile_stale".to_string()],
    };
    let profile_sha256 = runtime_orchestration_profile_sha256(&profile)?;
    let contract = RuntimeRunContract {
        schema: CHIO_RUNTIME_RUN_CONTRACT_SCHEMA.to_string(),
        run_id: "run-runtime-orchestration-rejected-proof".to_string(),
        profile_sha256,
        workflow_id: "workflow-runtime-orchestration".to_string(),
        expected_step_count: 1,
        admission_ids: vec!["admission-A".to_string()],
        store_id: "sqlite-runtime-store".to_string(),
        evidence_sink_id: "local-evidence-sink".to_string(),
        proof_regeneration_required: true,
    };
    let step = RuntimeStepEvidence {
        schema: CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
        step_index: 0,
        admission_id: "admission-A".to_string(),
        admission_report_sha256: fixed_hash('a'),
        tool_receipt_id: "receipt-A".to_string(),
        tool_receipt_sha256: fixed_hash('b'),
        output_sha256: fixed_hash('c'),
        bilateral_dsse_sha256: fixed_hash('d'),
        workflow_step_sha256: fixed_hash('e'),
        parent_receipt_sha256: None,
        consistency_anchor: "anchor-A".to_string(),
        destructive: false,
        lease_id: None,
        governance_receipt_id: None,
    };
    let proof = RuntimeProofRegenerationReport {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: false,
        failure_code: Some("runtime_proof_regeneration_missing_package_hash".to_string()),
        generated_at_unix_ms,
        proof_package_sha256: None,
        verifier_report_sha256: None,
        workflow_receipt_sha256: None,
        source_records: Vec::new(),
        checks: vec!["runtime_proof.regeneration_failed".to_string()],
    };
    let (proof_file_sha256, proof_sha256, proof_bytes) = write_json_with_hashes(
        &evidence_dir.path().join("proof-regeneration-report.json"),
        &proof,
    )?;
    let workflow = RuntimeWorkflowRunReport {
        schema: CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms,
        admission_report_sha256: step.admission_report_sha256.clone(),
        evidence_paths: vec!["proof-regeneration-report.json".to_string()],
        step_evidence: vec![step],
        proof_regeneration_report_sha256: Some(proof_sha256.clone()),
    };
    let (workflow_file_sha256, workflow_sha256, workflow_bytes) = write_json_with_hashes(
        &evidence_dir.path().join("workflow-run-report.json"),
        &workflow,
    )?;
    let manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        generated_at_unix_ms,
        workflow_run_report_sha256: workflow_sha256,
        proof_regeneration_report_sha256: proof_sha256,
        entries: vec![
            RuntimeEvidenceManifestEntry {
                role: "workflow_run_report".to_string(),
                path: "workflow-run-report.json".to_string(),
                sha256: workflow_file_sha256,
                byte_count: workflow_bytes,
            },
            RuntimeEvidenceManifestEntry {
                role: "proof_regeneration_report".to_string(),
                path: "proof-regeneration-report.json".to_string(),
                sha256: proof_file_sha256,
                byte_count: proof_bytes,
            },
        ],
    };
    write_json(
        &evidence_dir.path().join("runtime-evidence-manifest.json"),
        &manifest,
    )?;
    Ok(EvidenceFixture {
        profile,
        contract,
        evidence_dir,
    })
}

fn fixed_hash(ch: char) -> String {
    ch.to_string().repeat(64)
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let bytes = canonical_json_bytes(value)?;
    Ok(sha256_hex(&bytes))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{json}\n"))?;
    Ok(())
}

fn write_json_with_hashes<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(String, String, u64), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    let bytes = format!("{json}\n").into_bytes();
    let file_sha256 = sha256_hex(&bytes);
    let canonical_sha256 = canonical_hash(value)?;
    let byte_count = u64::try_from(bytes.len())?;
    fs::write(path, bytes)?;
    Ok((file_sha256, canonical_sha256, byte_count))
}
