use std::{collections::BTreeMap, error::Error, fs, path::Path};

use chio_core_types::Keypair;

use crate::{
    dsse_pre_auth_encoding, proof_room_router as build_proof_room_router,
    proof_room_router_with_fixture_root as build_proof_room_router_with_fixture_root, sha256_hex,
    SourceVerifierContext, PROOF_ROOM_DSSE_PAYLOAD_TYPE,
};

pub(crate) const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
pub(crate) const TEST_RECEIPT_SEED: [u8; 32] = [23; 32];
pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";

pub(crate) fn configure_agent_web_fixture_secret() {
    std::env::set_var(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
        STANDARD_WEBHOOKS_VERIFIER_SECRET,
    );
}

pub(crate) fn proof_room_router(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
) -> axum::Router {
    configure_agent_web_fixture_secret();
    match build_proof_room_router(bundle, ui_dir) {
        Ok(router) => router,
        Err(error) => panic!("proof room router builds: {error}"),
    }
}

pub(crate) fn proof_room_router_with_fixture_root(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
    fixture_root: std::path::PathBuf,
) -> axum::Router {
    configure_agent_web_fixture_secret();
    match build_proof_room_router_with_fixture_root(bundle, ui_dir, Some(fixture_root)) {
        Ok(router) => router,
        Err(error) => panic!("proof room router builds: {error}"),
    }
}

pub(crate) fn proof_room_router_with_repo_fixture_root(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
) -> Result<axum::Router, Box<dyn Error>> {
    Ok(proof_room_router_with_fixture_root(
        bundle,
        ui_dir,
        repo_root()?.join("fixtures/proof-room"),
    ))
}

pub(crate) fn runtime_regeneration_context(
    tamper_report: bool,
) -> Result<SourceVerifierContext, Box<dyn Error>> {
    let passport_bytes = fs::read(
        repo_root()?.join("fixtures/proof-room/minimal-passport/valid/transaction-passport.json"),
    )?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)?;
    let proof_package = serde_json::json!({
        "schema": "test.runtime-proof-package.v1",
        "packageId": "runtime-proof-package-1"
    });
    let verifier_report = serde_json::json!({
        "schema": "test.runtime-verifier-report.v1",
        "verdict": "verified"
    });
    let workflow_receipt = serde_json::json!({
        "schema": "test.runtime-workflow-receipt.v1",
        "receiptId": "runtime-workflow-receipt-1"
    });
    let proof_package_bytes = json_bytes(&proof_package)?;
    let verifier_report_bytes = json_bytes(&verifier_report)?;
    let workflow_receipt_bytes = json_bytes(&workflow_receipt)?;
    let proof_package_sha256 = canonical_json_sha256(&proof_package)?;
    let verifier_report_sha256 = canonical_json_sha256(&verifier_report)?;
    let workflow_receipt_sha256 = canonical_json_sha256(&workflow_receipt)?;
    let source_record = serde_json::json!({
        "stepIndex": 0,
        "admissionReportSha256": "a".repeat(64),
        "toolReceiptSha256": "b".repeat(64),
        "bilateralDsseSha256": "c".repeat(64),
        "workflowStepSha256": "d".repeat(64)
    });
    let proof_report = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-report.v1",
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "proofPackageSha256": proof_package_sha256,
        "verifierReportSha256": verifier_report_sha256,
        "workflowReceiptSha256": workflow_receipt_sha256,
        "sourceRecords": [source_record.clone()],
        "checks": ["runtime_regeneration.source_records_bound"]
    });
    let proof_report_sha256 = canonical_json_sha256(&proof_report)?;
    let workflow_report = serde_json::json!({
        "schema": "chio.runtime.workflow-run-report.v1",
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "admissionReportSha256": "a".repeat(64),
        "evidencePaths": ["proof-regeneration-report.json"],
        "stepEvidence": [{
            "schema": "chio.runtime.step-evidence.v1",
            "stepIndex": 0,
            "admissionId": "admission-1",
            "admissionReportSha256": "a".repeat(64),
            "toolReceiptId": "tool-receipt-1",
            "toolReceiptSha256": "b".repeat(64),
            "outputSha256": "e".repeat(64),
            "bilateralDsseSha256": "c".repeat(64),
            "workflowStepSha256": "d".repeat(64),
            "consistencyAnchor": "anchor-1",
            "destructive": false
        }],
        "proofRegenerationReportSha256": proof_report_sha256
    });
    let workflow_report_bytes = json_bytes(&workflow_report)?;
    let workflow_report_sha256 = canonical_json_sha256(&workflow_report)?;
    let manifest = serde_json::json!({
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": "runtime-loopback-1",
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "workflowRunReportSha256": workflow_report_sha256,
        "proofRegenerationReportSha256": proof_report_sha256,
        "entries": [
            runtime_manifest_entry("proof_package", "runtime-proof-package.json", &proof_package_bytes),
            runtime_manifest_entry("verifier_report", "runtime-verifier-report.json", &verifier_report_bytes),
            runtime_manifest_entry("workflow_receipt", "runtime-workflow-receipt.json", &workflow_receipt_bytes),
            runtime_manifest_entry("proof_regeneration_report", "proof-regeneration-report.json", &json_bytes(&proof_report)?),
            runtime_manifest_entry("runtime_run_report", "runtime-workflow-run-report.json", &workflow_report_bytes)
        ]
    });
    let manifest_bytes = json_bytes(&manifest)?;
    let manifest_sha256 = canonical_json_sha256(&manifest)?;
    let proof_input = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-input.v1",
        "runId": "runtime-loopback-1",
        "evidenceManifestSha256": manifest_sha256,
        "workflowRunReportSha256": workflow_report_sha256,
        "admissionReportSha256": "a".repeat(64),
        "trustBundleSha256": "f".repeat(64),
        "verificationContextSha256": "1".repeat(64),
        "sourceRecords": [source_record]
    });
    let mut proof_report_for_artifact = proof_report;
    if tamper_report {
        proof_report_for_artifact["checks"]
            .as_array_mut()
            .ok_or("proof report checks missing")?
            .push(serde_json::Value::String(
                "runtime_regeneration.tampered".to_string(),
            ));
    }
    let proof_report_bytes = json_bytes(&proof_report_for_artifact)?;
    let proof_input_bytes = json_bytes(&proof_input)?;
    let parity_report = serde_json::json!({
        "schema": chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA,
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "staticProofPackageSha256": "2".repeat(64),
        "runtimeProofPackageSha256": "2".repeat(64),
        "staticVerifierReportSha256": "3".repeat(64),
        "runtimeVerifierReportSha256": "3".repeat(64),
        "comparedFields": ["verified_claims"],
        "mismatches": []
    });
    let parity_report_bytes = json_bytes(&parity_report)?;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "runtime-proof-parity-report.json".to_string(),
        parity_report_bytes.clone(),
    );
    artifacts.insert(
        "proof-regeneration-report.json".to_string(),
        proof_report_bytes.clone(),
    );
    artifacts.insert(
        "proof-regeneration-input.json".to_string(),
        proof_input_bytes.clone(),
    );
    artifacts.insert(
        "runtime-evidence-manifest.json".to_string(),
        manifest_bytes.clone(),
    );
    artifacts.insert(
        "runtime-workflow-run-report.json".to_string(),
        workflow_report_bytes.clone(),
    );
    artifacts.insert(
        "runtime-proof-package.json".to_string(),
        proof_package_bytes,
    );
    artifacts.insert(
        "runtime-verifier-report.json".to_string(),
        verifier_report_bytes,
    );
    artifacts.insert(
        "runtime-workflow-receipt.json".to_string(),
        workflow_receipt_bytes,
    );

    let evidence_graph = serde_json::json!({
        "nodes": [
            runtime_graph_node("runtime-proof-parity-report", chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, "runtime-proof-parity-report.json", &parity_report_bytes),
            runtime_graph_node("runtime-proof-regeneration-report", "chio.runtime.proof-regeneration-report.v1", "proof-regeneration-report.json", &proof_report_bytes),
            runtime_graph_node("runtime-proof-regeneration-input", "chio.runtime.proof-regeneration-input.v1", "proof-regeneration-input.json", &proof_input_bytes),
            runtime_graph_node("runtime-evidence-manifest", "chio.runtime.evidence-manifest.v1", "runtime-evidence-manifest.json", &manifest_bytes),
            runtime_graph_node("runtime-workflow-run-report", "chio.runtime.workflow-run-report.v1", "runtime-workflow-run-report.json", &workflow_report_bytes),
            runtime_graph_node("runtime-proof-package", "test.runtime-proof-package.v1", "runtime-proof-package.json", artifacts.get("runtime-proof-package.json").ok_or("proof package missing")?),
            runtime_graph_node("runtime-verifier-report", "test.runtime-verifier-report.v1", "runtime-verifier-report.json", artifacts.get("runtime-verifier-report.json").ok_or("verifier report missing")?),
            runtime_graph_node("runtime-workflow-receipt", "test.runtime-workflow-receipt.v1", "runtime-workflow-receipt.json", artifacts.get("runtime-workflow-receipt.json").ok_or("workflow receipt missing")?)
        ]
    });

    Ok(SourceVerifierContext {
        passport,
        passport_report_path: String::new(),
        evidence_graph_bytes: json_bytes(&evidence_graph)?,
        verifier_policy_bytes: Vec::new(),
        artifacts,
    })
}

pub(crate) fn runtime_manifest_entry(role: &str, path: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "path": path,
        "sha256": super::sha256_hex(bytes),
        "byteCount": bytes.len()
    })
}

pub(crate) fn runtime_graph_node(
    role: &str,
    schema: &str,
    path: &str,
    bytes: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "schema": schema,
        "path": path,
        "sha256": super::sha256_hex(bytes)
    })
}

pub(crate) fn canonical_json_sha256(value: &serde_json::Value) -> Result<String, Box<dyn Error>> {
    let bytes = chio_core_types::crypto::canonical_json_bytes(value)?;
    Ok(super::sha256_hex(&bytes))
}

pub(crate) fn repo_root() -> Result<std::path::PathBuf, Box<dyn Error>> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        path = path
            .parent()
            .ok_or("crate manifest directory has no repo parent")?
            .to_path_buf();
    }
    Ok(path)
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

pub(crate) fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok([serde_json::to_vec_pretty(value)?.as_slice(), b"\n"].concat())
}

pub(crate) fn refresh_bundle_signature(bundle: &Path) -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    sign_bundle_signature_with_key(bundle, &keypair)
}

pub(crate) fn write_ui_report_and_rehash_manifest(
    bundle: &Path,
    ui_report: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let ui_report_bytes = json_bytes(ui_report)?;
    fs::write(&ui_report_path, &ui_report_bytes)?;
    let ui_report_sha256 = crate::sha256_hex(&ui_report_bytes);

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        if artifact.get("path").and_then(serde_json::Value::as_str)
            == Some("ui/proof-room-static/load-report.json")
        {
            artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

fn trust_test_bundle_signer(bundle: &Path) -> Result<String, Box<dyn Error>> {
    let test_key_id = Keypair::from_seed(&TEST_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let trust_roots_path = bundle.join("artifacts/authority/trust-roots.json");
    let mut trust_roots: serde_json::Value = serde_json::from_slice(&fs::read(&trust_roots_path)?)?;
    let root = trust_roots["roots"]
        .as_array_mut()
        .and_then(|roots| roots.first_mut())
        .ok_or("trust roots missing")?;
    root["key_id"] = serde_json::Value::String(test_key_id.clone());
    root["key_digest"] = serde_json::Value::String(super::sha256_hex(test_key_id.as_bytes()));
    fs::write(&trust_roots_path, json_bytes(&trust_roots)?)?;
    sha256_file(&trust_roots_path)
}

pub(crate) fn sign_bundle_signature_with_key(
    bundle: &Path,
    keypair: &Keypair,
) -> Result<(), Box<dyn Error>> {
    let manifest_path = bundle.join("manifest.json");
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    signature["payloadRef"]["sha256"] = serde_json::Value::String(sha256_hex(&manifest_bytes));
    signature["signatures"][0]["keyid"] = serde_json::Value::String(keypair.public_key().to_hex());
    signature["signatures"][0]["sig"] =
        serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
    fs::write(&signature_path, json_bytes(&signature)?)?;
    Ok(())
}

pub(crate) fn remove_graph_node_and_rehash(
    bundle: &Path,
    artifact_path: &str,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn remove_guard_report_capability_binding_and_rehash(
    bundle: &Path,
) -> Result<(), Box<dyn Error>> {
    let guard_report_path = bundle.join("artifacts/authority/guard-report.json");
    let mut guard_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&guard_report_path)?)?;
    guard_report
        .as_object_mut()
        .ok_or("guard report object missing")?
        .remove("capability_id");
    fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
    let guard_report_sha256 = sha256_file(&guard_report_path)?;

    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
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
        bundle,
        Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
    )?;
    Ok(())
}

pub(crate) fn add_unexpected_field_to_bundle_artifact_and_rehash(
    bundle: &Path,
    artifact_relative_path: &str,
) -> Result<(), Box<dyn Error>> {
    let artifact_path = bundle.join(artifact_relative_path);
    let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
    artifact["ambient_authority"] = serde_json::Value::Bool(true);
    fs::write(&artifact_path, json_bytes(&artifact)?)?;
    let artifact_sha256 = sha256_file(&artifact_path)?;

    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    if let Some(nodes) = evidence_graph["nodes"].as_array_mut() {
        for node in nodes {
            if node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
            {
                node["sha256"] = serde_json::Value::String(artifact_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    }

    refresh_source_roots_and_manifest(bundle, Some((artifact_relative_path, artifact_sha256)))?;
    Ok(())
}

pub(crate) fn sign_first_run_receipt_projection(
    receipt: &mut serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::from_seed(&TEST_RECEIPT_SEED);
    receipt["kernel_key"] = serde_json::Value::String(keypair.public_key().to_hex());
    let mut signed_body = receipt.clone();
    signed_body
        .as_object_mut()
        .ok_or("receipt projection object missing")?
        .remove("signature");
    let (signature, _canonical) = keypair.sign_canonical(&signed_body)?;
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(())
}

pub(crate) fn update_evidence_graph_node_hash(
    bundle: &Path,
    artifact_relative_path: &str,
    artifact_sha256: &str,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    let node = evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .iter_mut()
        .find(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
        })
        .ok_or("evidence graph node missing")?;
    node["sha256"] = serde_json::Value::String(artifact_sha256.to_string());
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    Ok(())
}

pub(crate) fn refresh_source_roots_and_manifest(
    bundle: &Path,
    extra_artifact_hash: Option<(&str, String)>,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some(path) => {
                if let Some((extra_path, extra_hash)) = extra_artifact_hash.as_ref() {
                    if path == *extra_path {
                        artifact["sha256"] = serde_json::Value::String(extra_hash.to_string());
                    }
                }
            }
            None => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn add_required_claim_to_verifier_policy(
    bundle: &Path,
    claim: &str,
) -> Result<(), Box<dyn Error>> {
    let verifier_policy_path = bundle.join("roots/verifier-policy.json");
    let mut verifier_policy: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
    verifier_policy["required_claims"]
        .as_array_mut()
        .ok_or("verifier policy required_claims missing")?
        .push(serde_json::Value::String(claim.to_string()));
    fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;
    let trust_roots_sha256 = trust_test_bundle_signer(bundle)?;

    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json") {
            node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
        }
        if node.get("path").and_then(serde_json::Value::as_str)
            == Some("artifacts/authority/trust-roots.json")
        {
            node["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    verifier_report["verifier_policy_sha256"] =
        serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("roots/verifier-policy.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some("artifacts/authority/trust-roots.json") => {
                artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn remove_verifier_policy_field_and_rehash(
    bundle: &Path,
    field: &str,
) -> Result<(), Box<dyn Error>> {
    let verifier_policy_path = bundle.join("roots/verifier-policy.json");
    let mut verifier_policy: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
    verifier_policy
        .as_object_mut()
        .ok_or("verifier policy object missing")?
        .remove(field);
    fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;

    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json") {
            node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    verifier_report["verifier_policy_sha256"] =
        serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let trust_roots_sha256 = trust_test_bundle_signer(bundle)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("roots/verifier-policy.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some("artifacts/authority/trust-roots.json") => {
                artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(super::sha256_hex(&fs::read(path)?))
}
