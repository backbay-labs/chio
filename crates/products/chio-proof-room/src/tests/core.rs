use super::support::*;
use super::*;

#[test]
fn source_runtime_parity_rejects_tampered_proof_regeneration_report() -> Result<(), Box<dyn Error>>
{
    let context = runtime_regeneration_context(true)?;
    let mut report = serde_json::json!({});

    let error = super::attach_source_runtime_proof_parity_report(&context, &mut report)
        .err()
        .ok_or("tampered runtime proof regeneration report unexpectedly verified")?;

    assert!(
        error.contains("runtime proof regeneration report hash mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn verifies_single_call_authority_bundle() -> Result<(), Box<dyn Error>> {
    let bundle = repo_root()?.join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    );

    verify_proof_room_bundle(&bundle)?;

    Ok(())
}

#[test]
fn verifies_single_call_authority_bundle_runs_bad_receipt_signature_negative(
) -> Result<(), Box<dyn Error>> {
    let bundle = repo_root()?.join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    );
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
    let has_bad_receipt_signature_negative = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest negative cases missing")?
        .iter()
        .any(|negative_case| {
            negative_case.get("id").and_then(serde_json::Value::as_str)
                == Some("bad-receipt-signature")
        });

    assert!(has_bad_receipt_signature_negative);
    verify_proof_room_bundle(&bundle)?;

    Ok(())
}

#[test]
fn verifies_single_call_authority_bundle_runs_stale_capability_negative(
) -> Result<(), Box<dyn Error>> {
    let bundle = repo_root()?.join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    );
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
    let has_stale_capability_negative = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest negative cases missing")?
        .iter()
        .any(|negative_case| {
            negative_case.get("id").and_then(serde_json::Value::as_str) == Some("stale-capability")
        });

    assert!(has_stale_capability_negative);
    verify_proof_room_bundle(&bundle)?;

    Ok(())
}

#[test]
fn verifies_single_call_authority_bundle_runs_guard_deny_negative() -> Result<(), Box<dyn Error>> {
    let bundle = repo_root()?.join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    );
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
    let has_guard_deny_negative = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest negative cases missing")?
        .iter()
        .any(|negative_case| {
            negative_case.get("id").and_then(serde_json::Value::as_str) == Some("guard-deny")
        });

    assert!(has_guard_deny_negative);
    verify_proof_room_bundle(&bundle)?;

    Ok(())
}

#[test]
fn rejects_source_family_verifier_policy_missing_schema_field() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root
        .join("fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    remove_verifier_policy_field_and_rehash(work.path(), "omitted_claims")?;
    let manifest_path = work.path().join("manifest.json");

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("proof room bundle with malformed source verifier policy unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.verifier-policy.invalid"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_receipt_coverage_status_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    let manifest_path = work.path().join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path)?;
    let mutated = manifest.replace(
        "\"terminal_status\": \"denied_guard_request\"",
        "\"terminal_status\": \"allowed_executed\"",
    );
    fs::write(&manifest_path, mutated)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.receipt-coverage.status-mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_excluded_receipt_coverage_without_reason_at_schema() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let coverage = manifest
        .get_mut("receipt_coverage")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("manifest receipt coverage missing")?
        .iter_mut()
        .find(|entry| {
            entry.get("category").and_then(serde_json::Value::as_str)
                == Some("runtime_terminal_failure")
        })
        .ok_or("runtime failure coverage missing")?;
    coverage
        .as_object_mut()
        .ok_or("runtime failure coverage is not an object")?
        .remove("exclusion_reason");
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_first_run_receipt_signature_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    receipt["signature"] = serde_json::Value::String("0".repeat(128));
    fs::write(&receipt_path, json_bytes(&receipt)?)?;
    let receipt_sha256 = sha256_file(&receipt_path)?;

    let evidence_graph_path = work.path().join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str)
            == Some("artifacts/receipts/allow-receipt.json")
        {
            node["sha256"] = serde_json::Value::String(receipt_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
    )?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.receipt-coverage.signature-invalid: runtime_terminal_allow"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_first_run_receipt_body_forgery_with_rehashed_artifact() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    receipt["execution_lease_ref"] =
        serde_json::Value::String("first-run-forged-lease".to_string());
    fs::write(&receipt_path, json_bytes(&receipt)?)?;
    let receipt_sha256 = sha256_file(&receipt_path)?;

    let evidence_graph_path = work.path().join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str)
            == Some("artifacts/receipts/allow-receipt.json")
        {
            node["sha256"] = serde_json::Value::String(receipt_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
    )?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.receipt-coverage.signature-invalid: runtime_terminal_allow"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_first_run_receipt_projection_with_unexpected_field() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    receipt["ambient_authority"] = serde_json::Value::Bool(true);
    sign_first_run_receipt_projection(&mut receipt)?;
    fs::write(&receipt_path, json_bytes(&receipt)?)?;
    let receipt_sha256 = sha256_file(&receipt_path)?;
    update_evidence_graph_node_hash(
        work.path(),
        "artifacts/receipts/allow-receipt.json",
        &receipt_sha256,
    )?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
    )?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: first_run_receipt"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_first_run_guard_denial_receipt_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let guard_report_path = work.path().join("artifacts/authority/guard-report.json");
    let mut guard_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&guard_report_path)?)?;
    guard_report["denial_receipt_ref"] =
        serde_json::Value::String("first-run-single-call-allow".to_string());
    fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
    let guard_report_sha256 = sha256_file(&guard_report_path)?;

    let evidence_graph_path = work.path().join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str)
            == Some("artifacts/authority/guard-report.json")
        {
            node["sha256"] = serde_json::Value::String(guard_report_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
    )?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.first-run.guard-denial-receipt-mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_schema_drift() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["unshipped_public_field"] = serde_json::Value::String("accepted".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_without_signature_at_schema() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest
        .as_object_mut()
        .ok_or("manifest is not an object")?
        .remove("signature");
    fs::write(&manifest_path, json_bytes(&manifest)?)?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_with_unsupported_signature_kind_at_schema() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["signature"]["kind"] = serde_json::Value::String("unsigned".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_excluded_artifact_with_unsafe_path_at_schema() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["excluded_artifacts"] = serde_json::json!([
        {
            "path": "../outside.json",
            "reason": "outside bundle"
        }
    ]);
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_artifact_ref_with_dot_segment_at_schema() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["verifier_report_ref"]["path"] =
        serde_json::Value::String("verifier/./report.json".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_artifact_ref_with_encoded_parent_segment_at_schema(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["verifier_report_ref"]["path"] =
        serde_json::Value::String("verifier/%2e%2e/report.json".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_artifact_ref_with_encoded_separator_before_filesystem(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["verifier_report_ref"]["path"] =
        serde_json::Value::String("verifier%2freport.json".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifested_artifact_schema_drift() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let artifact_relative_path = "artifacts/release/docker-quickstart-evidence.json";
    let artifact_path = work.path().join(artifact_relative_path);
    let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
    artifact["endpoints"] = serde_json::Value::Array(Vec::new());
    let artifact_bytes = json_bytes(&artifact)?;
    fs::write(&artifact_path, &artifact_bytes)?;
    let artifact_sha256 = super::sha256_hex(&artifact_bytes);

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    for entry in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        if entry.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path) {
            entry["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: artifact"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_release_truth_schema_drift() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let artifact_relative_path = "artifacts/release/release-truth.json";
    let artifact_path = work.path().join(artifact_relative_path);
    let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
    artifact["truth"]
        .as_object_mut()
        .ok_or("release truth object missing")?
        .remove("hosted_demo");
    fs::write(&artifact_path, json_bytes(&artifact)?)?;
    let artifact_sha256 = sha256_file(&artifact_path)?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    for entry in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        if entry.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path) {
            entry["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: artifact"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_detached_signature_payload_hash_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let signature_path = work.path().join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
    signature["payloadRef"]["sha256"] = serde_json::Value::String("0".repeat(64));
    fs::write(&signature_path, json_bytes(&signature)?)?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.signature.payload-hash-mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_detached_signature_forgery() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let signature_path = work.path().join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
    signature["signatures"][0]["sig"] = serde_json::Value::String("0".repeat(128));
    fs::write(&signature_path, json_bytes(&signature)?)?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.signature.verification-failed"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_detached_signature_from_untrusted_key() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let untrusted_keypair = Keypair::from_seed(&[8; 32]);
    sign_bundle_signature_with_key(work.path(), &untrusted_keypair)?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("untrusted proof room bundle signature unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.signature.signer-untrusted"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_detached_signature_without_trust_roots() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
        .retain(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                != Some("artifacts/authority/trust-roots.json")
        });
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    let untrusted_keypair = Keypair::from_seed(&[8; 32]);
    sign_bundle_signature_with_key(work.path(), &untrusted_keypair)?;

    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: super::ProofRoomBundleManifest = serde_json::from_slice(&manifest_bytes)?;
    let error = super::verify_bundle_signature(work.path(), &manifest, &manifest_bytes)
        .err()
        .ok_or("proof room bundle signature without trust roots unexpectedly verified")?;

    assert!(
        error.contains("proof-room.signature.trust-roots-missing"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_ui_report_schema_drift() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["unshipped_public_field"] = serde_json::Value::String("accepted".to_string());
    write_ui_report_and_rehash_manifest(work.path(), &ui_report)?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: ui-report"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_ui_report_rendered_claim_result_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["rendered_claims"][0]["verdict"] = serde_json::Value::String("failed".to_string());
    write_ui_report_and_rehash_manifest(work.path(), &ui_report)?;

    let manifest_path = work.path().join("manifest.json");
    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("UI report claim verdict mismatch unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.ui-report.rendered-claim-result-mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_manifest_claim_result_mismatch_with_source_verifier() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["claims"][0]["result"] = serde_json::Value::String("failed".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;

    let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["rendered_claims"][0]["verdict"] = serde_json::Value::String("failed".to_string());
    write_ui_report_and_rehash_manifest(work.path(), &ui_report)?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("manifest source claim result mismatch unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.claim.source-result-mismatch"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_referenced_bundle_assets() -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(bundle, ui.path().to_path_buf());

    let cases = [
        (
            "/verifier/report.json",
            "chio.transaction.verifier-report.v1",
        ),
        (
            "/roots/transaction-passport.json",
            "chio.transaction-passport.v1",
        ),
        ("/artifacts/receipts/allow-receipt.json", "allowed_executed"),
        (
            "/negatives/missing-denial-receipt.json",
            "expected_failure_code",
        ),
    ];

    for (path, expected) in cases {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains(expected), "{path} did not contain {expected}");
    }

    Ok(())
}

#[tokio::test]
async fn quickstart_router_does_not_host_unmanifested_bundle_files() -> Result<(), Box<dyn Error>> {
    let source =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    let internal_dir = work.path().join("artifacts/internal");
    fs::create_dir_all(&internal_dir)?;
    fs::write(
        internal_dir.join("debug-notes.json"),
        br#"{"schema":"debug-notes.v1","note":"not manifest evidence"}"#,
    )?;
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(work.path().to_path_buf(), ui.path().to_path_buf());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/artifacts/internal/debug-notes.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(!body.contains("debug-notes.v1"));
    Ok(())
}
