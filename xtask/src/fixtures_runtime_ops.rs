// Ops-hardening and orchestration runtime handlers. `include!`d transitively
// into `fixtures.rs` (via `fixtures_runtime.rs`) so the handlers share that
// module's private helpers.

// -- runtime-ops-hardening -------------------------------------------------

/// `all` runs the runtime-core/CLI surface tests, the schema flow, and the
/// tick / status / recovery / evidence / provider / retention / negative /
/// failure-code flows. `schema-only` runs the schema flow; `negative-only` runs
/// the negative flow.
fn handle_ops_hardening(
    root: &Path,
    _manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("ops-hardening")?;
    let common = ops_write_common_fixtures(&scratch)?;

    if mode == Mode::SchemaOnly {
        return ops_schema_flow(root, &common);
    }
    if mode == Mode::NegativeOnly {
        return ops_negative_flow(root, &scratch, &common);
    }

    run_runtime_cargo_tests(root, facet)?;
    ops_schema_flow(root, &common)?;
    ops_tick_flow(root, &scratch, &common)?;
    ops_status_flow(root, &scratch, &common)?;
    ops_recovery_flow(root, &scratch, &common)?;
    ops_evidence_flow(root, &scratch, &common)?;
    ops_provider_flow(root, &scratch, &common)?;
    ops_retention_flow(root, &scratch, &common)?;
    ops_negative_flow(root, &scratch, &common)?;
    ops_failure_code_flow(root, &common)
}

/// The common fixtures materialized once and reused across the ops flows.
struct OpsFixtures {
    supervisor_profile: PathBuf,
    provider_bindings: PathBuf,
    provider_bindings_bad: PathBuf,
    retention_profile: PathBuf,
    negative_corpus: PathBuf,
    failure_code_registry: PathBuf,
    evidence_root: PathBuf,
    evidence_bad_root: PathBuf,
}

fn ops_write_common_fixtures(scratch: &ScratchDir) -> Result<OpsFixtures, XtaskError> {
    let supervisor_profile = scratch.join("supervisor-profile.json");
    write_json(
        &supervisor_profile,
        &serde_json::json!({
            "schema": "chio.runtime.supervisor-profile.v1",
            "profileId": "runtime-supervisor-local",
            "localKernelId": "kernel.vendor-b",
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "maxConcurrentRuns": 2,
            "runLeaseTtlMs": 60000,
            "staleRunAfterMs": 300000,
            "evidenceRequiredRoles": ["workflow_run_report"],
            "failClosedOn": ["evidence_hash_mismatch"]
        }),
    )?;
    let provider_bindings = scratch.join("provider-bindings.json");
    write_json(&provider_bindings, &ops_provider_binding(false))?;
    let provider_bindings_bad = scratch.join("provider-bindings-bad.json");
    write_json(&provider_bindings_bad, &ops_provider_binding(true))?;
    let retention_profile = scratch.join("retention-profile.json");
    write_json(
        &retention_profile,
        &serde_json::json!({
            "schema": "chio.runtime.artifact-retention-profile.v1",
            "profileId": "runtime-retention-local",
            "localKernelId": "kernel.vendor-b",
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "minRetainMs": 86_400_000_i64,
            "destructiveHoldMs": 604_800_000_i64,
            "legalHold": false,
            "dryRunOnly": true
        }),
    )?;
    let negative_corpus = scratch.join("negative-corpus.json");
    write_json(
        &negative_corpus,
        &serde_json::json!({
            "schema": "chio.runtime.ops-negative-fixture-corpus.v1",
            "cases": [
                { "caseId": "provider-discovery", "expectedCode": "runtime_provider_discovery_not_allowed" },
                { "caseId": "evidence-hash-mismatch", "expectedCode": "runtime_evidence_artifact_hash_mismatch" }
            ]
        }),
    )?;
    let failure_code_registry = scratch.join("failure-code-registry.json");
    write_json(
        &failure_code_registry,
        &serde_json::json!({
            "schema": "chio.runtime.failure-code-registry.v1",
            "codes": [
                "runtime_provider_discovery_not_allowed",
                "runtime_evidence_artifact_hash_mismatch",
                "runtime_run_lease_conflict",
                "runtime_run_stale_fencing_token",
                "runtime_ops_status_degraded",
                "runtime_ops_supervisor_profile_stale",
                "runtime_recovery_supervisor_profile_stale"
            ]
        }),
    )?;

    // Evidence root: a workflow-run-report plus its evidence manifest, the
    // manifest hashes computed over the report bytes.
    let evidence_root = scratch.join("evidence");
    let run_dir = evidence_root.join("runtime-run-health");
    fs::create_dir_all(&run_dir).map_err(|err| XtaskError::Io(display(&run_dir), err))?;
    let report_path = run_dir.join("workflow-run-report.json");
    fs::write(&report_path, "{\"ok\":true}")
        .map_err(|err| XtaskError::Io(display(&report_path), err))?;
    let report_hash = file_sha256(&report_path)?;
    let report_bytes = fs::read(&report_path)
        .map_err(|err| XtaskError::Io(display(&report_path), err))?
        .len();
    let manifest_path = run_dir.join("runtime-evidence-manifest.json");
    write_json(
        &manifest_path,
        &serde_json::json!({
            "schema": "chio.runtime.evidence-manifest.v1",
            "runId": "runtime-run-health",
            "generatedAtUnixMs": 1_800_000_000_000_i64,
            "workflowRunReportSha256": report_hash,
            "proofRegenerationReportSha256": report_hash,
            "entries": [
                {
                    "role": "workflow_run_report",
                    "path": "workflow-run-report.json",
                    "sha256": report_hash,
                    "byteCount": report_bytes,
                }
            ]
        }),
    )?;

    // Bad evidence root: same report, manifest with a corrupted sha256.
    let evidence_bad_root = scratch.join("evidence-bad");
    let bad_run_dir = evidence_bad_root.join("runtime-run-health");
    fs::create_dir_all(&bad_run_dir).map_err(|err| XtaskError::Io(display(&bad_run_dir), err))?;
    fs::copy(&report_path, bad_run_dir.join("workflow-run-report.json"))
        .map_err(|err| XtaskError::Io(display(&bad_run_dir), err))?;
    let mut bad_manifest = load_json(&manifest_path)?;
    if let Some(entries) = bad_manifest.get_mut("entries").and_then(Value::as_array_mut) {
        for entry in entries.iter_mut() {
            set_str(entry, "sha256", &"3".repeat(64));
        }
    }
    write_json(
        &bad_run_dir.join("runtime-evidence-manifest.json"),
        &bad_manifest,
    )?;

    Ok(OpsFixtures {
        supervisor_profile,
        provider_bindings,
        provider_bindings_bad,
        retention_profile,
        negative_corpus,
        failure_code_registry,
        evidence_root,
        evidence_bad_root,
    })
}

fn ops_provider_binding(discovery_allowed: bool) -> Value {
    serde_json::json!({
        "schema": "chio.runtime.provider-bindings.v1",
        "bindings": [
            {
                "providerId": "provider-vendor-b",
                "localKernelId": "kernel.vendor-b",
                "serverId": "vendor-ledger",
                "toolName": "close_account",
                "discoveryAllowed": discovery_allowed
            }
        ]
    })
}

fn ops_schema_flow(root: &Path, fx: &OpsFixtures) -> Result<(), XtaskError> {
    validate_runtime(root, "supervisor-profile.schema.json", &fx.supervisor_profile)?;
    validate_runtime(root, "provider-bindings.schema.json", &fx.provider_bindings)?;
    validate_runtime(
        root,
        "artifact-retention-profile.schema.json",
        &fx.retention_profile,
    )?;
    validate_runtime(
        root,
        "ops-negative-fixture-corpus.schema.json",
        &fx.negative_corpus,
    )?;
    validate_runtime(
        root,
        "failure-code-registry.schema.json",
        &fx.failure_code_registry,
    )
}

fn ops_tick_flow(root: &Path, scratch: &ScratchDir, fx: &OpsFixtures) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");
    let report = scratch.join("tick-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "tick",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_root),
            "--owner-id", "operator-a",
            "--now-unix-ms", "1800000001000",
            "--max-runs", "2",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "scheduler-tick-report.schema.json", &report)
}

fn ops_status_flow(root: &Path, scratch: &ScratchDir, fx: &OpsFixtures) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");
    let report = scratch.join("status-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "status",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_root),
            "--provider-bindings", &display(&fx.provider_bindings),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "ops-status-report.schema.json", &report)?;

    let bad_report = scratch.join("status-bad-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "status",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_bad_root),
            "--provider-bindings", &display(&fx.provider_bindings),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&bad_report),
        ],
    )?;
    assert_report_bool(&bad_report, "accepted", false)?;
    assert_report_bool(&bad_report, "evidenceSinkHealthy", false)?;
    assert_report_str(&bad_report, "failureCode", "runtime_ops_status_degraded")?;
    validate_runtime(root, "ops-status-report.schema.json", &bad_report)
}

fn ops_recovery_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OpsFixtures,
) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");
    let report = scratch.join("recovery-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "recovery-drill",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--run-id", "missing-run",
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_root),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&report),
        ],
    )?;
    assert_report_str(&report, "failureCode", "runtime_recovery_run_not_found")?;
    validate_runtime(root, "recovery-drill-report.schema.json", &report)
}

fn ops_evidence_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OpsFixtures,
) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");
    let report = scratch.join("evidence-health-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "evidence-health",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--run-id", "runtime-run-health",
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_root),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "evidence-sink-health-report.schema.json", &report)
}

fn ops_provider_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OpsFixtures,
) -> Result<(), XtaskError> {
    let report = scratch.join("provider-health-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "provider-health",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--provider-bindings", &display(&fx.provider_bindings),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "provider-health-report.schema.json", &report)
}

fn ops_retention_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OpsFixtures,
) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");
    let report = scratch.join("retention-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "retention", "plan",
            "--retention-profile", &display(&fx.retention_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_root),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "artifact-retention-plan.schema.json", &report)
}

fn ops_negative_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OpsFixtures,
) -> Result<(), XtaskError> {
    let store = scratch.join("runtime.sqlite3");

    // Provider discovery not allowed.
    let provider_bad = scratch.join("provider-health-bad.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "provider-health",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--provider-bindings", &display(&fx.provider_bindings_bad),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&provider_bad),
        ],
    )?;
    assert_report_bool(&provider_bad, "accepted", false)?;
    assert_report_str(
        &provider_bad,
        "failureCode",
        "runtime_provider_discovery_not_allowed",
    )?;

    // Evidence artifact hash mismatch.
    let evidence_bad = scratch.join("evidence-health-bad.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "evidence-health",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--run-id", "runtime-run-health",
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_bad_root),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&evidence_bad),
        ],
    )?;
    assert_report_str(
        &evidence_bad,
        "failureCode",
        "runtime_evidence_artifact_hash_mismatch",
    )?;

    // Status degraded with the bad evidence root.
    let status_bad = scratch.join("status-bad-report.json");
    require_chio(
        root,
        &[
            "runtime", "ops", "status",
            "--supervisor-profile", &display(&fx.supervisor_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&fx.evidence_bad_root),
            "--provider-bindings", &display(&fx.provider_bindings),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&status_bad),
        ],
    )?;
    assert_report_bool(&status_bad, "accepted", false)?;
    assert_report_bool(&status_bad, "evidenceSinkHealthy", false)?;
    assert_report_str(&status_bad, "failureCode", "runtime_ops_status_degraded")?;

    // Retention planning rejects a missing evidence root (fail-closed: success
    // is the error). The original shell gate grep'd the specific stderr marker, so a
    // non-zero exit alone is not enough: pin the expected failure message.
    let missing_report = scratch.join("retention-missing-report.json");
    let missing_root = scratch.join("evidence-missing");
    reject_chio_with_marker(
        root,
        &[
            "runtime", "ops", "retention", "plan",
            "--retention-profile", &display(&fx.retention_profile),
            "--store", &display(&store),
            "--evidence-root", &display(&missing_root),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&missing_report),
        ],
        "requires existing evidence root",
        "retention planning unexpectedly accepted a missing evidence root",
    )
}

fn ops_failure_code_flow(root: &Path, fx: &OpsFixtures) -> Result<(), XtaskError> {
    validate_runtime(
        root,
        "failure-code-registry.schema.json",
        &fx.failure_code_registry,
    )?;
    let src = root.join("crates/kernel/chio-runtime-core/src");
    for code in [
        "runtime_provider_discovery_not_allowed",
        "runtime_evidence_artifact_hash_mismatch",
        "runtime_ops_supervisor_profile_stale",
        "runtime_recovery_supervisor_profile_stale",
    ] {
        if !tree_contains(&src, code)? {
            return Err(invalid(&format!(
                "failure code {code} is not referenced in chio-runtime-core/src"
            )));
        }
    }
    Ok(())
}

/// True if any file under `dir` contains `needle`.
fn tree_contains(dir: &Path, needle: &str) -> Result<bool, XtaskError> {
    for path in walk_files(dir)? {
        let text = fs::read_to_string(&path).map_err(|err| XtaskError::Io(display(&path), err))?;
        if text.contains(needle) {
            return Ok(true);
        }
    }
    Ok(false)
}

// -- runtime-orchestration -------------------------------------------------

/// `all` runs the runtime-core / orchestration / drift / CLI surface tests, the
/// schema checks, the positive lint/plan/run/status flow, the resume flow, the
/// drift flow, and the negative flow. `schema-only` runs the schema checks;
/// `negative-only` runs the negative flow.
fn handle_orchestration(
    root: &Path,
    _manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("orchestration")?;
    let common = orch_write_common_fixtures(&scratch)?;

    if mode == Mode::SchemaOnly {
        return orch_schema_checks(root, &common);
    }
    if mode == Mode::NegativeOnly {
        return orch_negative_flow(root, &scratch, &common);
    }

    run_runtime_cargo_tests(root, facet)?;
    orch_schema_checks(root, &common)?;
    orch_positive_flow(root, &scratch, &common)?;
    orch_resume_flow(root, &scratch, &common)?;
    orch_drift_flow(root, &scratch, &common)?;
    orch_negative_flow(root, &scratch, &common)
}

/// The common orchestration fixtures (profile, run-contract bound to the profile
/// hash, negative corpus).
struct OrchFixtures {
    profile: PathBuf,
    run_contract: PathBuf,
    negative_corpus: PathBuf,
}

fn orch_write_common_fixtures(scratch: &ScratchDir) -> Result<OrchFixtures, XtaskError> {
    let profile = scratch.join("profile.json");
    let profile_value = serde_json::json!({
        "schema": "chio.runtime.orchestration-profile.v1",
        "profileId": "profile-runtime-orchestration",
        "localKernelId": "kernel.vendor-b",
        "verifierId": "did:chio:buyer-verifier",
        "mode": "local",
        "issuedAtUnixMs": 1_800_000_000_000_i64,
        "expiresAtUnixMs": 1_800_003_600_000_i64,
        "maxConcurrentRuns": 1,
        "failClosedOn": ["evidence_sink_unavailable", "proof_regeneration_rejected"]
    });
    write_json(&profile, &profile_value)?;
    let profile_hash = canonical_sha256(&profile_value);

    let run_contract = scratch.join("run-contract.json");
    write_json(
        &run_contract,
        &serde_json::json!({
            "schema": "chio.runtime.run-contract.v1",
            "runId": "runtime-orchestration-1",
            "profileSha256": profile_hash,
            "workflowId": "wf-chio-refund-001",
            "expectedStepCount": 1,
            "admissionIds": ["adm-loopback-1"],
            "storeId": "runtime-store-local",
            "evidenceSinkId": "runtime-evidence-local",
            "proofRegenerationRequired": true
        }),
    )?;

    let negative_corpus = scratch.join("negative-corpus.json");
    write_json(
        &negative_corpus,
        &serde_json::json!({
            "schema": "chio.runtime.orchestration-negative-fixture-corpus.v1",
            "cases": [
                { "caseId": "manifest-hash-mismatch", "expectedCode": "runtime_proof_drift_detected" }
            ]
        }),
    )?;

    Ok(OrchFixtures {
        profile,
        run_contract,
        negative_corpus,
    })
}

fn orch_schema_checks(root: &Path, fx: &OrchFixtures) -> Result<(), XtaskError> {
    validate_runtime(root, "orchestration-profile.schema.json", &fx.profile)?;
    validate_runtime(root, "run-contract.schema.json", &fx.run_contract)?;
    validate_runtime(
        root,
        "orchestration-negative-fixture-corpus.schema.json",
        &fx.negative_corpus,
    )
}

/// Build an evidence directory with a self-consistent hash chain (workflow run
/// report -> proof regeneration report -> verifier report -> evidence manifest).
fn orch_make_evidence_dir(
    dir: &Path,
    run_id: &str,
    proof_payload: &str,
    verifier_accepted: bool,
) -> Result<(), XtaskError> {
    fs::create_dir_all(dir).map_err(|err| XtaskError::Io(display(dir), err))?;

    let proof_package_path = dir.join("buyer-auditor-proof-package.json");
    let proof_package_value = serde_json::json!({ "payload": proof_payload });
    write_json(&proof_package_path, &proof_package_value)?;
    let proof_package_bytes = fs::read(&proof_package_path)
        .map_err(|err| XtaskError::Io(display(&proof_package_path), err))?;
    let proof_package_file_hash = file_sha256(&proof_package_path)?;
    let package_sha = canonical_sha256(&proof_package_value);

    let verifier_report = serde_json::json!({
        "schema": "chio.attest.verifier-report.v1",
        "packageSha256": package_sha,
        "accepted": verifier_accepted,
        "checks": [
            { "code": "runtime.fixture", "name": "runtime-fixture", "passed": verifier_accepted }
        ]
    });
    write_json(&dir.join("verifier-report.json"), &verifier_report)?;
    let verifier_hash = canonical_sha256(&verifier_report);

    let proof_report = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-report.v1",
        "runId": run_id,
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_001_000_i64,
        "proofPackageSha256": package_sha,
        "verifierReportSha256": verifier_hash,
        "workflowReceiptSha256": "b".repeat(64),
        "sourceRecords": [
            {
                "stepIndex": 0,
                "admissionReportSha256": "1".repeat(64),
                "toolReceiptSha256": "2".repeat(64),
                "bilateralDsseSha256": "4".repeat(64),
                "workflowStepSha256": "5".repeat(64)
            }
        ],
        "checks": ["runtime_semantic_proof_regeneration.verified"]
    });
    write_json(&dir.join("proof-regeneration-report.json"), &proof_report)?;
    let proof_hash = canonical_sha256(&proof_report);

    let workflow_report = serde_json::json!({
        "schema": "chio.runtime.workflow-run-report.v1",
        "runId": run_id,
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_001_000_i64,
        "admissionReportSha256": "1".repeat(64),
        "evidencePaths": ["proof-regeneration-report.json"],
        "stepEvidence": [
            {
                "schema": "chio.runtime.step-evidence.v1",
                "stepIndex": 0,
                "admissionId": "adm-loopback-1",
                "admissionReportSha256": "1".repeat(64),
                "toolReceiptId": "receipt-live-1",
                "toolReceiptSha256": "2".repeat(64),
                "outputSha256": "3".repeat(64),
                "bilateralDsseSha256": "4".repeat(64),
                "workflowStepSha256": "5".repeat(64),
                "consistencyAnchor": "chio:consistency:wf-chio-refund-001:0",
                "destructive": false
            }
        ],
        "proofRegenerationReportSha256": proof_hash
    });
    write_json(&dir.join("workflow-run-report.json"), &workflow_report)?;
    let workflow_hash = canonical_sha256(&workflow_report);

    let manifest = serde_json::json!({
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": run_id,
        "generatedAtUnixMs": 1_800_000_001_000_i64,
        "workflowRunReportSha256": workflow_hash,
        "proofRegenerationReportSha256": proof_hash,
        "entries": [
            {
                "role": "proof_package",
                "path": "buyer-auditor-proof-package.json",
                "sha256": proof_package_file_hash,
                "byteCount": proof_package_bytes.len()
            }
        ]
    });
    write_json(&dir.join("runtime-evidence-manifest.json"), &manifest)
}

fn orch_positive_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OrchFixtures,
) -> Result<(), XtaskError> {
    let run_a = scratch.join("run-a");
    orch_make_evidence_dir(&run_a, "runtime-orchestration-1", "runtime-proof-package-a", true)?;
    let store = scratch.join("runtime.sqlite3");
    let lint = scratch.join("lint-report.json");
    let plan = scratch.join("plan-report.json");
    let run = scratch.join("run-report.json");
    let status = scratch.join("status-report.json");

    require_chio(
        root,
        &[
            "runtime", "orchestrate", "lint",
            "--profile", &display(&fx.profile),
            "--report", &display(&lint),
        ],
    )?;
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "plan",
            "--profile", &display(&fx.profile),
            "--run-contract", &display(&fx.run_contract),
            "--store", &display(&store),
            "--evidence-dir", &display(&run_a),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&plan),
        ],
    )?;
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "run",
            "--profile", &display(&fx.profile),
            "--run-contract", &display(&fx.run_contract),
            "--store", &display(&store),
            "--evidence-dir", &display(&run_a),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&run),
        ],
    )?;
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "status",
            "--profile", &display(&fx.profile),
            "--store", &display(&store),
            "--evidence-dir", &display(&run_a),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&status),
        ],
    )?;
    validate_runtime(root, "orchestration-status-report.schema.json", &lint)?;
    validate_runtime(root, "orchestration-plan.schema.json", &plan)?;
    validate_runtime(root, "orchestration-run-report.schema.json", &run)?;
    validate_runtime(root, "orchestration-status-report.schema.json", &status)?;
    assert_report_bool(&status, "accepted", true)?;
    assert_report_bool(&status, "ready", true)
}

fn orch_resume_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OrchFixtures,
) -> Result<(), XtaskError> {
    // The resume flow reuses run-a from the positive flow; rebuild it so resume
    // can run independently in the `all` ordering.
    let run_a = scratch.join("run-a");
    if !run_a.exists() {
        orch_make_evidence_dir(&run_a, "runtime-orchestration-1", "runtime-proof-package-a", true)?;
    }
    let store = scratch.join("runtime.sqlite3");
    let resume_input = scratch.join("resume-input.json");
    write_json(
        &resume_input,
        &serde_json::json!({
            "schema": "chio.runtime.orchestration-resume-plan.v1",
            "runId": "runtime-orchestration-1",
            "accepted": true,
            "generatedAtUnixMs": 1_800_000_000_000_i64,
            "nextStepIndex": 0,
            "reusableStepIndices": [],
            "blocked": false,
            "checks": ["runtime_orchestration.resume_requested"]
        }),
    )?;
    let report = scratch.join("resume-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "resume",
            "--profile", &display(&fx.profile),
            "--resume-plan", &display(&resume_input),
            "--store", &display(&store),
            "--evidence-dir", &display(&run_a),
            "--now-unix-ms", "1800000002000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "orchestration-resume-plan.schema.json", &report)
}

fn orch_drift_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OrchFixtures,
) -> Result<(), XtaskError> {
    let runs = scratch.join("runs");
    orch_make_evidence_dir(
        &runs.join("run-a"),
        "runtime-orchestration-a",
        "runtime-proof-package-a",
        true,
    )?;
    orch_make_evidence_dir(
        &runs.join("run-b"),
        "runtime-orchestration-b",
        "runtime-proof-package-a",
        true,
    )?;
    let report = scratch.join("drift-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "drift",
            "--profile", &display(&fx.profile),
            "--runs-dir", &display(&runs),
            "--since-unix-ms", "1800000000000",
            "--until-unix-ms", "1800000002000",
            "--report", &display(&report),
        ],
    )?;
    validate_runtime(root, "proof-drift-report.schema.json", &report)
}

fn orch_negative_flow(
    root: &Path,
    scratch: &ScratchDir,
    fx: &OrchFixtures,
) -> Result<(), XtaskError> {
    // Drift detected: two runs with divergent proof payloads.
    let neg_runs = scratch.join("negative-runs");
    orch_make_evidence_dir(
        &neg_runs.join("run-a"),
        "runtime-orchestration-a",
        "runtime-proof-package-a",
        true,
    )?;
    orch_make_evidence_dir(
        &neg_runs.join("run-b"),
        "runtime-orchestration-b",
        "runtime-proof-package-b",
        true,
    )?;
    let neg_drift = scratch.join("negative-drift-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "drift",
            "--profile", &display(&fx.profile),
            "--runs-dir", &display(&neg_runs),
            "--since-unix-ms", "1800000000000",
            "--until-unix-ms", "1800000002000",
            "--report", &display(&neg_drift),
        ],
    )?;
    assert_report_bool(&neg_drift, "accepted", false)?;
    assert_report_str(&neg_drift, "failureCode", "runtime_proof_drift_detected")?;
    validate_runtime(root, "proof-drift-report.schema.json", &neg_drift)?;

    // Missing proof package: the run must fail with runtime_admission_io.
    let proof_missing_run = scratch.join("proof-missing-run");
    orch_make_evidence_dir(
        &proof_missing_run,
        "runtime-orchestration-1",
        "runtime-proof-package-a",
        true,
    )?;
    let proof_package = proof_missing_run.join("buyer-auditor-proof-package.json");
    fs::remove_file(&proof_package).map_err(|err| XtaskError::Io(display(&proof_package), err))?;
    let proof_missing_report = scratch.join("proof-missing-run-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "run",
            "--profile", &display(&fx.profile),
            "--run-contract", &display(&fx.run_contract),
            "--store", &display(&scratch.join("runtime-proof-missing.sqlite3")),
            "--evidence-dir", &display(&proof_missing_run),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&proof_missing_report),
        ],
    )?;
    assert_report_bool(&proof_missing_report, "accepted", false)?;
    assert_report_str(&proof_missing_report, "failureCode", "runtime_admission_io")?;
    validate_runtime(
        root,
        "orchestration-run-report.schema.json",
        &proof_missing_report,
    )?;

    // Verifier package mismatch.
    let mismatch_run = scratch.join("verifier-package-mismatch-run");
    orch_make_evidence_dir(
        &mismatch_run,
        "runtime-orchestration-1",
        "runtime-proof-package-a",
        true,
    )?;
    orch_corrupt_verifier_package_sha(&mismatch_run)?;
    let mismatch_report = scratch.join("verifier-package-mismatch-run-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "run",
            "--profile", &display(&fx.profile),
            "--run-contract", &display(&fx.run_contract),
            "--store", &display(&scratch.join("runtime-verifier-package-mismatch.sqlite3")),
            "--evidence-dir", &display(&mismatch_run),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&mismatch_report),
        ],
    )?;
    assert_report_bool(&mismatch_report, "accepted", false)?;
    assert_report_str(
        &mismatch_report,
        "failureCode",
        "runtime_orchestration_evidence_hash_mismatch",
    )?;
    validate_runtime(root, "orchestration-run-report.schema.json", &mismatch_report)?;

    // Verifier report rejected.
    let rejected_run = scratch.join("verifier-rejected-run");
    orch_make_evidence_dir(
        &rejected_run,
        "runtime-orchestration-1",
        "runtime-proof-package-a",
        false,
    )?;
    let rejected_report = scratch.join("verifier-rejected-run-report.json");
    require_chio(
        root,
        &[
            "runtime", "orchestrate", "run",
            "--profile", &display(&fx.profile),
            "--run-contract", &display(&fx.run_contract),
            "--store", &display(&scratch.join("runtime-verifier-negative.sqlite3")),
            "--evidence-dir", &display(&rejected_run),
            "--now-unix-ms", "1800000001000",
            "--report", &display(&rejected_report),
        ],
    )?;
    assert_report_bool(&rejected_report, "accepted", false)?;
    assert_report_str(
        &rejected_report,
        "failureCode",
        "runtime_orchestration_verifier_report_rejected",
    )?;
    validate_runtime(root, "orchestration-run-report.schema.json", &rejected_report)
}

/// Corrupt the verifier report's `packageSha256` and re-chain the proof,
/// workflow, and manifest hashes.
fn orch_corrupt_verifier_package_sha(dir: &Path) -> Result<(), XtaskError> {
    let verifier_path = dir.join("verifier-report.json");
    let mut verifier = load_json(&verifier_path)?;
    set_str(&mut verifier, "packageSha256", &"0".repeat(64));
    write_json(&verifier_path, &verifier)?;
    let verifier_hash = canonical_sha256(&verifier);

    let proof_path = dir.join("proof-regeneration-report.json");
    let mut proof = load_json(&proof_path)?;
    set_str(&mut proof, "verifierReportSha256", &verifier_hash);
    write_json(&proof_path, &proof)?;
    let proof_hash = canonical_sha256(&proof);

    let workflow_path = dir.join("workflow-run-report.json");
    let mut workflow = load_json(&workflow_path)?;
    set_str(&mut workflow, "proofRegenerationReportSha256", &proof_hash);
    write_json(&workflow_path, &workflow)?;
    let workflow_hash = canonical_sha256(&workflow);

    let manifest_path = dir.join("runtime-evidence-manifest.json");
    let mut manifest = load_json(&manifest_path)?;
    set_str(&mut manifest, "proofRegenerationReportSha256", &proof_hash);
    set_str(&mut manifest, "workflowRunReportSha256", &workflow_hash);
    write_json(&manifest_path, &manifest)
}

// -- Runtime dispatch ------------------------------------------------------

/// Dispatch a runtime facet to its typed handler. Fail-closed: an unknown kind
/// is a Manifest error, never a silent pass.
fn dispatch_runtime_handler(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    match facet.kind.as_str() {
        "spine_fixtures" => {
            // The spine-fixtures gate is purely schema/guard work; it has no
            // distinct negative-only path, so every mode runs the same body.
            handle_spine_fixtures(root, manifest, facet)
        }
        "spine" => handle_spine(root, manifest, facet, mode),
        "proof_parity" => handle_proof_parity(root, manifest, facet, mode),
        "policy" => handle_policy(root, manifest, facet, mode),
        "ops_hardening" => handle_ops_hardening(root, manifest, facet, mode),
        "orchestration" => handle_orchestration(root, manifest, facet, mode),
        "attack_simulation" => handle_attack_simulation(root, manifest, facet, mode),
        "chaos" => handle_chaos(root, manifest, facet, mode),
        other => Err(XtaskError::Manifest(format!(
            "unknown runtime facet kind {other}"
        ))),
    }
}
