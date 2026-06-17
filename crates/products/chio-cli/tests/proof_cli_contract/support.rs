use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    Keypair,
};
use chio_test_support::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

pub(crate) const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str =
    "application/vnd.chio.proof-room.bundle.v1+json";
pub(crate) const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
pub(crate) const COLLECT_SIGNATURE_SEED: [u8; 32] = [11; 32];
pub(crate) const PROOF_SERVE_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

pub(crate) fn chio(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(args)
        .output()
        .test_expect("chio command runs")
}

pub(crate) fn stdout(output: std::process::Output) -> String {
    String::from_utf8(output.stdout).test_expect("stdout is utf8")
}

pub(crate) fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_failure(output: &std::process::Output, expected: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(expected),
        "expected failure to contain {expected:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) struct ChildGuard {
    pub(crate) child: Child,
}

pub(crate) struct RunningProofServe {
    _guard: ChildGuard,
    pub(crate) address: SocketAddr,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn utf8_path(path: &Path) -> String {
    path.to_str().test_expect("path is utf8").to_string()
}

pub(crate) fn assert_json_schema_accepts(relative_schema_path: &str, instance: &serde_json::Value) {
    let schema_path = workspace_root().join(relative_schema_path);
    let schema_bytes = std::fs::read(&schema_path).test_expect("schema file reads");
    let schema: serde_json::Value =
        serde_json::from_slice(&schema_bytes).test_expect("schema parses");
    let validator = jsonschema::validator_for(&schema).test_expect("schema compiles");
    if validator.is_valid(instance) {
        return;
    }

    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    panic!(
        "schema {relative_schema_path} rejected instance:\n{}\nerrors={errors}",
        serde_json::to_string_pretty(instance).test_expect("instance pretty prints")
    );
}

pub(crate) fn http_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, PROOF_SERVE_HTTP_REQUEST_TIMEOUT)?;
    stream.set_read_timeout(Some(PROOF_SERVE_HTTP_REQUEST_TIMEOUT))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

pub(crate) fn wait_for_http_body(address: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path) {
            Ok(response) if response.starts_with("HTTP/1.1 200") => {
                return response
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body.to_string())
                    .test_expect("http response has body");
            }
            Ok(response) => {
                last_error = response
                    .lines()
                    .next()
                    .unwrap_or("empty response")
                    .to_string();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {path}: {last_error}");
}

pub(crate) fn wait_for_http_response(address: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path) {
            Ok(response) => return response,
            Err(error) => {
                last_error = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {path}: {last_error}");
}

pub(crate) fn spawn_proof_serve(bundle: &Path, ui_dir: Option<&Path>) -> RunningProofServe {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    if let Some(ui_dir) = ui_dir {
        command.env("CHIO_PROOF_ROOM_UI_DIR", ui_dir);
    }
    let mut child = command
        .arg("proof")
        .arg("serve")
        .arg(bundle)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .test_expect("spawn proof serve");
    let stdout = child.stdout.take().test_expect("proof serve stdout");
    let mut reader = BufReader::new(stdout);
    let mut report_line = String::new();
    reader
        .read_line(&mut report_line)
        .test_expect("read proof serve report");
    let report: serde_json::Value =
        serde_json::from_str(&report_line).test_expect("parse proof serve report");
    let listen = report
        .get("listen")
        .and_then(serde_json::Value::as_str)
        .test_expect("serve report listen address");
    let address: SocketAddr = listen.parse().test_expect("listen address parses");
    assert_ne!(address.port(), 0);
    RunningProofServe {
        _guard: ChildGuard { child },
        address,
    }
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else {
            std::fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn append_symlink_member<W: Write>(
    builder: &mut tar::Builder<W>,
    outside_passport: &Path,
) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_mode(0o777);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_link(&mut header, "transaction-passport.json", outside_passport)
        .test_expect("append symlink member");
}

#[cfg(unix)]
pub(crate) fn write_tgz_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish gzip");
}

#[cfg(unix)]
pub(crate) fn write_tar_zst_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = zstd::stream::write::Encoder::new(file, 0).test_expect("create zstd encoder");
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish zstd");
}

pub(crate) fn tgz_member_names(path: &Path) -> BTreeSet<String> {
    let file = std::fs::File::open(path).test_expect("open tgz archive");
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .entries()
        .test_expect("read archive entries")
        .map(|entry| {
            entry
                .test_expect("read archive entry")
                .path()
                .test_expect("read archive path")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

pub(crate) fn proof_room_bundle_fixture() -> PathBuf {
    workspace_root().join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle")
}

pub(crate) fn mutate_proof_room_bundle(
    negative_case: &str,
) -> (tempfile::TempDir, PathBuf, String) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");

    let negative_path = source
        .join("negatives")
        .join(format!("{negative_case}.json"));
    let negative: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&negative_path).test_expect("read negative case"))
            .test_expect("negative case parses");
    let expected = negative["expected_failure_code"]
        .as_str()
        .test_expect("negative case has expected failure code")
        .to_string();

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");

    match negative_case {
        "report-hash-mismatch" => {
            manifest["verifier_report_ref"]["sha256"] = negative["mutation"]["value"].clone();
        }
        "missing-denial-receipt" => {
            let claim_id = negative["mutation"]["claim_id"]
                .as_str()
                .test_expect("negative case has claim id");
            let claim = manifest["claims"]
                .as_array_mut()
                .test_expect("manifest claims array")
                .iter_mut()
                .find(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) == Some(claim_id)
                })
                .test_expect("manifest claim exists");
            claim["required_artifacts"] = negative["mutation"]["required_artifacts"].clone();
        }
        "receipt-coverage-status-mismatch" => {
            let category = negative["mutation"]["category"]
                .as_str()
                .test_expect("negative case has category");
            let terminal_status = negative["mutation"]["terminal_status"]
                .as_str()
                .test_expect("negative case has terminal status");
            let coverage = manifest["receipt_coverage"]
                .as_array_mut()
                .test_expect("manifest receipt coverage array")
                .iter_mut()
                .find(|entry| {
                    entry.get("category").and_then(serde_json::Value::as_str) == Some(category)
                })
                .test_expect("coverage category exists");
            coverage["terminal_status"] = serde_json::Value::String(terminal_status.to_string());
        }
        "missing-authority-evidence" => {
            let claim_id = negative["mutation"]["claim_id"]
                .as_str()
                .test_expect("negative case has claim id");
            if let Some(claims) = manifest["claims"].as_array_mut() {
                claims.retain(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) != Some(claim_id)
                });
            }
            let artifact_paths = negative["mutation"]["artifact_paths"]
                .as_array()
                .test_expect("negative case has artifact paths")
                .iter()
                .map(|path| {
                    path.as_str()
                        .test_expect("artifact path is string")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            if let Some(artifacts) = manifest["artifacts"].as_array_mut() {
                artifacts.retain(|artifact| {
                    artifact
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|path| !artifact_paths.contains(path))
                });
            }
            for artifact_path in artifact_paths {
                let _ = std::fs::remove_file(bundle.join(artifact_path));
            }
        }
        "missing-authority-graph-node" => {
            let artifact_path = negative["mutation"]["artifact_path"]
                .as_str()
                .test_expect("negative case has artifact path");
            remove_evidence_graph_node_and_rehash(&bundle, &mut manifest, artifact_path);
        }
        other => panic!("unsupported negative case: {other}"),
    }

    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, [&manifest_bytes[..], b"\n"].concat())
        .test_expect("write manifest");
    refresh_bundle_signature(&bundle);

    (tempdir, bundle, expected)
}

pub(crate) fn remove_evidence_graph_node_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
) {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    write_json(&passport_path, &passport);
    let passport_sha256 = sha256_file(&passport_path);

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&verifier_report_path).test_expect("read report"))
            .test_expect("report parses");
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    write_json(&verifier_report_path, &verifier_report);
    let verifier_report_sha256 = sha256_file(&verifier_report_path);

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json(&ui_report_path, &ui_report);
    let ui_report_sha256 = sha256_file(&ui_report_path);

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
        .test_expect("manifest artifacts array")
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
}

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(value).test_expect("serialize JSON");
    std::fs::write(path, [&bytes[..], b"\n"].concat()).test_expect("write JSON");
}

pub(crate) fn signed_terminal_receipt(
    receipt_id: &str,
    terminal_status: &str,
    policy_digest: &str,
) -> serde_json::Value {
    sign_terminal_receipt(serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": receipt_id,
        "terminal_status": terminal_status,
        "policy_digest": policy_digest
    }))
}

pub(crate) fn sign_terminal_receipt(mut receipt: serde_json::Value) -> serde_json::Value {
    let keypair = Keypair::from_seed(&[23; 32]);
    let receipt_object = receipt
        .as_object_mut()
        .test_expect("terminal receipt is object");
    receipt_object.remove("signature");
    receipt_object.insert(
        "kernel_key".to_string(),
        serde_json::Value::String(keypair.public_key().to_hex()),
    );
    let (signature, _) = keypair
        .sign_canonical(&receipt)
        .test_expect("terminal receipt signs");
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    receipt
}

pub(crate) fn sign_transaction_receipt_artifact(bundle: &Path, artifact_path: &str) {
    let receipt_path = bundle.join(artifact_path);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    write_json(&receipt_path, &sign_terminal_receipt(receipt));
    refresh_transaction_artifact_digest(bundle, artifact_path);
}

pub(crate) fn refresh_transaction_artifact_digest(bundle: &Path, artifact_path: &str) {
    if bundle.join("roots/evidence-graph.json").is_file() {
        refresh_transaction_artifact_digest_at(
            bundle,
            &bundle.join("roots/evidence-graph.json"),
            &bundle.join("roots/transaction-passport.json"),
            artifact_path,
        );
    }
    refresh_transaction_artifact_digest_at(
        bundle,
        &bundle.join("evidence-graph.json"),
        &bundle.join("transaction-passport.json"),
        artifact_path,
    );
}

pub(crate) fn refresh_transaction_artifact_digest_at(
    bundle: &Path,
    evidence_graph_path: &Path,
    passport_path: &Path,
    artifact_path: &str,
) {
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    let graph_nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    let mut refreshed = false;
    for node in graph_nodes {
        if node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path) {
            node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(artifact_path)));
            refreshed = true;
        }
    }
    assert!(
        refreshed,
        "transaction evidence graph did not contain {artifact_path}"
    );
    write_json(evidence_graph_path, &evidence_graph);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(sha256_file(evidence_graph_path));
    write_json(passport_path, &passport);
}

pub(crate) fn artifact_ref(bundle: &Path, path: &str, schema: &str) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "sha256": sha256_file(&bundle.join(path)),
        "schema": schema
    })
}

pub(crate) fn artifact(
    bundle: &Path,
    path: &str,
    schema: &str,
    artifact_class: &str,
    renderer_hint: &str,
) -> serde_json::Value {
    let mut value = artifact_ref(bundle, path, schema);
    value["media_type"] = serde_json::Value::String("application/json".to_string());
    value["artifact_class"] = serde_json::Value::String(artifact_class.to_string());
    value["sensitivity_class"] = serde_json::Value::String("public-fixture".to_string());
    value["producer"] =
        serde_json::Value::String("fixtures/proof-room/minimal-passport/valid".to_string());
    value["participates_in_primary_verdict"] = serde_json::Value::Bool(true);
    value["renderer_hint"] = serde_json::Value::String(renderer_hint.to_string());
    value
}

pub(crate) fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).test_expect("read file for sha256");
    hex::encode(Sha256::digest(&bytes))
}

pub(crate) fn graph_node_by_schema<'a>(
    evidence_graph: &'a serde_json::Value,
    schema: &str,
) -> &'a serde_json::Value {
    evidence_graph["nodes"]
        .as_array()
        .test_expect("evidence graph nodes array")
        .iter()
        .find(|node| node.get("schema").and_then(serde_json::Value::as_str) == Some(schema))
        .unwrap_or_else(|| panic!("evidence graph missing schema {schema}"))
}

pub(crate) fn assert_graph_node_hashes_bundle_artifact(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    schema: &str,
) -> serde_json::Value {
    let node = graph_node_by_schema(evidence_graph, schema);
    let path = node["path"]
        .as_str()
        .test_expect("evidence graph node path is string");
    assert_eq!(
        node["sha256"].as_str(),
        Some(sha256_file(&bundle.join(path)).as_str()),
        "evidence graph digest mismatch for {schema}"
    );
    serde_json::from_slice(&std::fs::read(bundle.join(path)).test_expect("read graph artifact"))
        .test_expect("graph artifact parses")
}

pub(crate) fn resign_agent_web_receipts_for_policy(bundle: &Path, policy_sha256: &str) {
    let receipts_dir = bundle.join("receipts");
    if !receipts_dir.is_dir() {
        return;
    }
    let keypair = Keypair::from_seed(&[17u8; 32]);
    for entry in std::fs::read_dir(&receipts_dir).test_expect("read Agent Web receipts dir") {
        let entry = entry.test_expect("read Agent Web receipt entry");
        let receipt_path = entry.path();
        if receipt_path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        let receipt: ChioReceipt =
            serde_json::from_slice(&std::fs::read(&receipt_path).test_expect("read receipt"))
                .test_expect("Agent Web receipt parses");
        let Some(receipt_ref) = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let body = ChioReceiptBody {
            id: receipt_ref.to_string(),
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            action: receipt.action,
            decision: receipt.decision,
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            redaction_mode: receipt.redaction_mode,
            actor_chain: receipt.actor_chain,
            content_hash: receipt.content_hash,
            policy_hash: policy_sha256.to_string(),
            evidence: receipt.evidence,
            metadata: receipt.metadata,
            trust_level: receipt.trust_level,
            tenant_id: receipt.tenant_id,
            kernel_key: keypair.public_key(),
            bbs_projection_version: receipt.bbs_projection_version,
        };
        let signed_receipt =
            ChioReceipt::sign(body, &keypair).test_expect("Agent Web receipt signs");
        let bytes =
            serde_json::to_vec_pretty(&signed_receipt).test_expect("Agent Web receipt serializes");
        std::fs::write(&receipt_path, [&bytes[..], b"\n"].concat())
            .test_expect("write Agent Web receipt");
    }
}

pub(crate) fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

pub(crate) fn sign_bundle_signature(bundle: &Path, signature: &mut serde_json::Value) {
    sign_bundle_signature_with_seed(bundle, signature, TEST_SIGNATURE_SEED);
}

pub(crate) fn sign_bundle_signature_with_seed(
    bundle: &Path,
    signature: &mut serde_json::Value,
    seed: [u8; 32],
) {
    let manifest_bytes = std::fs::read(bundle.join("manifest.json")).test_expect("read manifest");
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    let keypair = chio_core::Keypair::from_seed(&seed);
    signature["payloadRef"]["sha256"] =
        serde_json::Value::String(hex::encode(Sha256::digest(&manifest_bytes)));
    signature["signatures"][0]["keyid"] = serde_json::Value::String(keypair.public_key().to_hex());
    signature["signatures"][0]["sig"] =
        serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
}

pub(crate) fn proof_room_trust_roots_for_seed(seed: [u8; 32]) -> serde_json::Value {
    let keypair = chio_core::Keypair::from_seed(&seed);
    let key_id = keypair.public_key().to_hex();
    let key_digest = hex::encode(Sha256::digest(key_id.as_bytes()));
    serde_json::json!({
        "schema": "chio.proof.first-run.trust-roots.v1",
        "id": "trust-roots-test-bundle",
        "trust_domain": "did:chio:proof-room-test",
        "roots": [
            {
                "subject": "did:chio:test-authority",
                "key_id": key_id,
                "key_digest": key_digest
            }
        ],
        "signature": "sig-trust-roots-test-bundle"
    })
}

pub(crate) fn build_runtime_commerce_passport_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let runtime_source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let commerce_source =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle = tempdir.path().join("runtime-commerce-passport");
    copy_dir_all(&runtime_source, &bundle).test_expect("copy runtime bundle");

    for path in [
        "order-context.json",
        "event-log.json",
        "payment-lifecycle.json",
        "mandate-allowance-ledger.json",
    ] {
        std::fs::copy(commerce_source.join(path), bundle.join(path))
            .test_expect("copy commerce artifact");
    }

    let policy_path = bundle.join("verifier-policy.json");
    let commerce_policy_path = commerce_source.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    let commerce_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&commerce_policy_path).test_expect("read commerce verifier policy"),
    )
    .test_expect("commerce verifier policy parses");
    let required_claims = policy["required_claims"]
        .as_array_mut()
        .test_expect("policy required_claims array");
    for claim in commerce_policy["required_claims"]
        .as_array()
        .test_expect("commerce policy required_claims array")
    {
        required_claims.push(claim.clone());
    }
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    for path in ["execution-lease.json", "allow-receipt.json"] {
        let artifact_path = bundle.join(path);
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
        write_json(&artifact_path, &artifact);
    }

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    let graph_nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    for node in graph_nodes.iter_mut() {
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path)));
    }

    let commerce_graph_path = commerce_source.join("evidence-graph.json");
    let commerce_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&commerce_graph_path).test_expect("read commerce graph"),
    )
    .test_expect("commerce graph parses");
    for node in commerce_graph["nodes"]
        .as_array()
        .test_expect("commerce graph nodes array")
    {
        let path = node["path"].as_str().test_expect("commerce node path");
        let mut node = node.clone();
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path)));
        graph_nodes.push(node);
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_commerce_transfer_group_mismatch_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle = tempdir.path().join("commerce-transfer-group-mismatch");
    copy_dir_all(&source, &bundle).test_expect("copy commerce bundle");

    let payment_path = bundle.join("payment-lifecycle.json");
    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&payment_path).test_expect("read payment lifecycle"))
            .test_expect("payment lifecycle parses");
    payment_lifecycle["transfer_group"] = serde_json::json!("order-commerce-other");
    write_json(&payment_path, &payment_lifecycle);

    let order_context_path = bundle.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("order context parses");
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(sha256_file(&payment_path));
    write_json(&order_context_path, &order_context);

    refresh_transaction_artifact_digest(&bundle, "order-context.json");
    refresh_transaction_artifact_digest(&bundle, "payment-lifecycle.json");

    (tempdir, bundle)
}

pub(crate) fn build_commerce_settlement_passport_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let commerce_source =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let settlement_source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle = tempdir.path().join("commerce-settlement-passport");
    copy_dir_all(&commerce_source, &bundle).test_expect("copy commerce bundle");

    let settlement_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(settlement_source.join("transaction-passport.json"))
            .test_expect("read public settlement passport"),
    )
    .test_expect("public settlement passport parses");
    let passport_id = settlement_passport["id"]
        .as_str()
        .test_expect("public settlement passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    );
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    append_graph_artifacts_from_fixture(
        &bundle,
        &settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", passport_id)],
    );

    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path)));
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["id"] = serde_json::Value::String(passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle(
) -> (tempfile::TempDir, PathBuf) {
    let (tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let settlement_source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let agent_web_source =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");

    let passport_path = bundle.join("transaction-passport.json");
    let agent_web_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(agent_web_source.join("transaction-passport.json"))
            .test_expect("read Agent Web passport"),
    )
    .test_expect("Agent Web passport parses");
    let passport_id = agent_web_passport["id"]
        .as_str()
        .test_expect("Agent Web passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    );
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"));
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    for path in ["execution-lease.json", "allow-receipt.json"] {
        let artifact_path = bundle.join(path);
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
        write_json(&artifact_path, &artifact);
    }

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    append_graph_artifacts_from_fixture(
        &bundle,
        &settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", passport_id)],
    );
    append_graph_artifacts_from_fixture(&bundle, &agent_web_source, &mut evidence_graph, &[]);
    resign_agent_web_receipts_for_policy(&bundle, &policy_sha256);

    let graph_nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    for node in graph_nodes.iter_mut() {
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path)));
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["id"] = serde_json::Value::String(passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_disclosure_agent_web_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let disclosure_source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let agent_web_source =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = tempdir.path().join("disclosure-agent-web-envelope");
    copy_dir_all(&disclosure_source, &bundle).test_expect("copy disclosure bundle");

    let passport_path = bundle.join("transaction-passport.json");
    let disclosure_passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("disclosure passport parses");
    let disclosure_passport_id = disclosure_passport["id"]
        .as_str()
        .test_expect("disclosure passport has id");
    let agent_web_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(agent_web_source.join("transaction-passport.json"))
            .test_expect("read Agent Web passport"),
    )
    .test_expect("Agent Web passport parses");
    let agent_web_passport_id = agent_web_passport["id"]
        .as_str()
        .test_expect("Agent Web passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"));
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    replace_json_strings_in_graph_artifacts(
        &bundle,
        &evidence_graph,
        &[(disclosure_passport_id, agent_web_passport_id)],
    );
    refresh_signed_lineage_subgraph_digest(&bundle);
    append_graph_artifacts_from_fixture(&bundle, &agent_web_source, &mut evidence_graph, &[]);
    resign_agent_web_receipts_for_policy(&bundle, &policy_sha256);

    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path)));
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let mut passport = disclosure_passport;
    passport["id"] = serde_json::Value::String(agent_web_passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_risk_only_policy_bundle(
    fixture_path: &str,
    bundle_name: &str,
) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join(fixture_path);
    let bundle = tempdir.path().join(bundle_name);
    copy_dir_all(&source, &bundle).test_expect("copy proof bundle");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    policy["required_claims"] = serde_json::json!(["claim.risk.comptroller_report_bound"]);
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_standalone_risk_only_policy_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = tempdir.path().join("standalone-risk-only");
    copy_dir_all(&source, &bundle).test_expect("copy proof bundle");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    policy["required_claims"] = serde_json::json!(["claim.risk.comptroller_report_bound"]);
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| {
            matches!(
                node.get("role").and_then(serde_json::Value::as_str),
                Some(
                    "risk-comptroller-report"
                        | "data-governance-report"
                        | "approval-case"
                        | "evidence-export-bundle"
                )
            )
        });
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        if node.get("role").and_then(serde_json::Value::as_str) != Some("risk-comptroller-report") {
            node["role"] = serde_json::Value::String("risk-supporting-evidence".to_string());
        }
    }
    evidence_graph["edges"] = serde_json::Value::Array(Vec::new());
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn build_enterprise_bundle_with_unrelated_runtime_evidence(
) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let enterprise_source =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let runtime_source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let bundle = tempdir.path().join("enterprise-with-runtime-evidence");
    copy_dir_all(&enterprise_source, &bundle).test_expect("copy enterprise proof bundle");

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    append_graph_artifacts_from_fixture(&bundle, &runtime_source, &mut evidence_graph, &[]);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn remove_standalone_risk_graph_node(bundle: &Path, removed_node_id: &str) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| node.get("id").and_then(serde_json::Value::as_str) != Some(removed_node_id));
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
}

pub(crate) fn add_standalone_risk_unbound_reserve_ledger(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-risk-ledger-bound"]);
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(100);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-unbound-receipt",
            "receipt_ref": "risk-receipt-not-in-graph",
            "lane": "claim_payout",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-ledger-bound",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "settlement-not-in-graph",
            "payer_subject": "did:chio:buyer-enterprise",
            "payee_subject": "did:chio:buyer-enterprise"
        }
    ]);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn point_standalone_risk_lifecycle_authority_at_supporting_evidence(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["facility_lifecycle"][0]["authority_receipt_ref"] =
        serde_json::json!("data-governance-report");
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn deny_standalone_risk_approval_case(bundle: &Path) {
    let approval_path = bundle.join("approval-case.json");
    let mut approval: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&approval_path).test_expect("read approval case"))
            .test_expect("approval case parses");
    approval["decision"] = serde_json::json!("denied");
    write_json(&approval_path, &approval);
    rehash_standalone_risk_graph_artifact(bundle, "approval-case", &approval_path);
}

pub(crate) fn rehash_standalone_risk_graph_artifact(
    bundle: &Path,
    node_id: &str,
    artifact_path: &Path,
) {
    let artifact_sha256 = sha256_file(artifact_path);
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        if node.get("id").and_then(serde_json::Value::as_str) == Some(node_id) {
            node["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
}

pub(crate) fn add_standalone_risk_uncovered_reserve_ledger_claim(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]
        .as_object_mut()
        .test_expect("risk coverage object")
        .remove("covered_claim_ids");
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(100);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-uncovered-claim",
            "receipt_ref": "approval-case",
            "lane": "claim_payout",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-ledger-without-coverage",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "payer_subject": "did:chio:buyer-enterprise",
            "payee_subject": "did:chio:buyer-enterprise"
        }
    ]);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn add_standalone_risk_sanction_backed_market_slash(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-risk-market-slash"]);
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(0);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(0);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-market-slash",
            "receipt_ref": "approval-case",
            "lane": "market_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "sanction_bridge": {
                "bridge_id": "sanction-bridge-risk-market-slash",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report",
                "jurisdiction_ref": "approval-case",
                "sanction_subject": "did:chio:buyer-enterprise",
                "maximum_slash_units": 100
            }
        }
    ]);
    risk_report["sanction_reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "sanction-ledger-market-slash",
            "bridge_id": "sanction-bridge-risk-market-slash",
            "lane": "market_slash",
            "receipt_ref": "approval-case",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report",
            "jurisdiction_ref": "approval-case"
        }
    ]);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn write_standalone_risk_report_and_rehash(
    bundle: &Path,
    risk_report: serde_json::Value,
) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    write_json(&risk_report_path, &risk_report);
    let risk_report_sha256 = sha256_file(&risk_report_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        if node.get("id").and_then(serde_json::Value::as_str) == Some("risk-comptroller-report") {
            node["sha256"] = serde_json::Value::String(risk_report_sha256.clone());
        }
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
}

pub(crate) fn append_required_claims_from_policy(
    policy: &mut serde_json::Value,
    source_policy_path: &Path,
) {
    let source_policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source_policy_path).test_expect("read policy"))
            .test_expect("policy parses");
    let required_claims = policy["required_claims"]
        .as_array_mut()
        .test_expect("policy required_claims array");
    for claim in source_policy["required_claims"]
        .as_array()
        .test_expect("source policy required_claims array")
    {
        if !required_claims.contains(claim) {
            required_claims.push(claim.clone());
        }
    }
}

pub(crate) fn append_graph_artifacts_from_fixture(
    bundle: &Path,
    source: &Path,
    evidence_graph: &mut serde_json::Value,
    replacements: &[(&str, &str)],
) {
    let source_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source.join("evidence-graph.json")).test_expect("read graph"),
    )
    .test_expect("graph parses");
    let mut retained_ids = BTreeSet::new();
    for node in source_graph["nodes"]
        .as_array()
        .test_expect("source graph nodes array")
    {
        let path = node["path"].as_str().test_expect("source node path");
        if matches!(
            path,
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        let destination_path = bundle.join(path);
        if let Some(parent) = destination_path.parent() {
            std::fs::create_dir_all(parent).test_expect("create artifact parent");
        }
        if replacements.is_empty() {
            std::fs::copy(source.join(path), &destination_path).test_expect("copy artifact");
        } else {
            let mut artifact: serde_json::Value = serde_json::from_slice(
                &std::fs::read(source.join(path)).test_expect("read artifact"),
            )
            .test_expect("artifact parses");
            for (from, to) in replacements {
                replace_json_string(&mut artifact, from, to);
            }
            write_json(&destination_path, &artifact);
        }

        let mut node = node.clone();
        node["sha256"] = serde_json::Value::String(sha256_file(&destination_path));
        retained_ids.insert(node["id"].as_str().test_expect("node id").to_string());
        evidence_graph["nodes"]
            .as_array_mut()
            .test_expect("graph nodes array")
            .push(node);
    }

    for edge in source_graph["edges"]
        .as_array()
        .test_expect("source graph edges array")
    {
        let from = edge["from"].as_str().test_expect("edge from");
        let to = edge["to"].as_str().test_expect("edge to");
        if retained_ids.contains(from) && retained_ids.contains(to) {
            evidence_graph["edges"]
                .as_array_mut()
                .test_expect("graph edges array")
                .push(edge.clone());
        }
    }
}

pub(crate) fn replace_json_strings_in_graph_artifacts(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    replacements: &[(&str, &str)],
) {
    for node in evidence_graph["nodes"]
        .as_array()
        .test_expect("graph nodes array")
    {
        let path = node["path"].as_str().test_expect("node path");
        if matches!(
            path,
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        let artifact_path = bundle.join(path);
        if !artifact_path.is_file() {
            continue;
        }
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        for (from, to) in replacements {
            replace_json_string(&mut artifact, from, to);
        }
        write_json(&artifact_path, &artifact);
    }
}

pub(crate) fn replace_json_string(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(text) if text == from => {
            *text = to.to_string();
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_json_string(item, from, to);
            }
        }
        serde_json::Value::Object(entries) => {
            for item in entries.values_mut() {
                replace_json_string(item, from, to);
            }
        }
        _ => {}
    }
}

pub(crate) fn refresh_signed_lineage_subgraph_digest(bundle: &Path) {
    let path = bundle.join("signed-lineage-subgraph.json");
    let mut lineage: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).test_expect("read signed lineage subgraph"))
            .test_expect("signed lineage subgraph parses");
    let digest_material = serde_json::json!({
        "id": lineage["id"].clone(),
        "transaction_passport_ref": lineage["transaction_passport_ref"].clone(),
        "root_receipt_ids": lineage["root_receipt_ids"].clone(),
        "nodes": lineage["nodes"].clone(),
        "edges": lineage["edges"].clone(),
        "redactions": lineage["redactions"].clone()
    });
    let canonical = chio_core::canonical::canonical_json_bytes(&digest_material)
        .test_expect("signed lineage subgraph canonicalizes");
    let digest = hex::encode(Sha256::digest(&canonical));
    lineage["subgraph_sha256"] = serde_json::Value::String(digest.clone());
    lineage["signature"] = serde_json::Value::String(format!("sig-sha256:{digest}"));
    write_json(&path, &lineage);
}

pub(crate) fn refresh_bundle_signature(bundle: &Path) {
    refresh_bundle_signature_with_seed(bundle, TEST_SIGNATURE_SEED);
}

pub(crate) fn refresh_bundle_signature_with_seed(bundle: &Path, seed: [u8; 32]) {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature_with_seed(bundle, &mut signature, seed);
    write_json(&signature_path, &signature);
}

pub(crate) fn refresh_verifier_report_refs_with_seed(bundle: &Path, seed: [u8; 32]) {
    let verifier_report_sha256 = sha256_file(&bundle.join("verifier/report.json"));

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json(&ui_report_path, &ui_report);
    let ui_report_sha256 = sha256_file(&ui_report_path);

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature_with_seed(bundle, seed);
}

pub(crate) fn refresh_manifest_artifact_ref(bundle: &Path, artifact_path: &str) {
    let artifact_sha256 = sha256_file(&bundle.join(artifact_path));
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    match artifact_path {
        "roots/transaction-passport.json" => {
            manifest["transaction_passport_ref"]["sha256"] =
                serde_json::Value::String(artifact_sha256.clone());
        }
        "roots/evidence-graph.json" => {
            manifest["evidence_graph_ref"]["sha256"] =
                serde_json::Value::String(artifact_sha256.clone());
        }
        "verifier/report.json" => {
            manifest["verifier_report_ref"]["sha256"] =
                serde_json::Value::String(artifact_sha256.clone());
        }
        "ui/proof-room-static/load-report.json" => {
            manifest["proof_room_verifier_report_ref"]["sha256"] =
                serde_json::Value::String(artifact_sha256.clone());
        }
        _ => {}
    }
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path) {
            artifact["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(bundle);
}

pub(crate) fn copy_proof_room_bundle_to_temp() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    (tempdir, bundle)
}

pub(crate) fn build_minimal_passport_proof_room_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("minimal-passport-proof-room-bundle");
    std::fs::create_dir_all(bundle.join("roots")).test_expect("create roots dir");
    std::fs::create_dir_all(bundle.join("verifier")).test_expect("create verifier dir");
    std::fs::create_dir_all(bundle.join("artifacts/authority")).test_expect("create authority dir");
    std::fs::create_dir_all(bundle.join("ui/proof-room-static")).test_expect("create ui dir");

    for file in [
        "transaction-passport.json",
        "evidence-graph.json",
        "verifier-policy.json",
    ] {
        std::fs::copy(source.join(file), bundle.join("roots").join(file))
            .test_expect("copy root artifact");
    }
    for file in [
        "capability-proof.json",
        "guard-decision.json",
        "kernel-receipt.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(file), bundle.join(file)).test_expect("copy evidence artifact");
    }

    let passport_path = source.join("transaction-passport.json");
    let verify_output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);
    assert_success(&verify_output);
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).test_expect("verifier report parses");
    let verifier_report_path = bundle.join("verifier/report.json");
    write_json(&verifier_report_path, &verifier_report);

    let verifier_report_ref = artifact_ref(
        &bundle,
        "verifier/report.json",
        "chio.transaction.verifier-report.v1",
    );
    let ui_report = serde_json::json!({
        "schema": "chio.proof-room.verifier-report.v1",
        "id": "proof-room-verifier-report-minimal-passport-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "verdict": "verified",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "source_verifier_report_ref": verifier_report_ref,
        "ui_verdict_source": "verifier_report_ref",
        "rendered_claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "source": "verifier/report.json",
                "verdict": "verified"
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "source": "verifier/report.json",
                "verdict": "verified"
            }
        ]
    });
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    write_json(&ui_report_path, &ui_report);
    write_json(
        &bundle.join("artifacts/authority/trust-roots.json"),
        &proof_room_trust_roots_for_seed(TEST_SIGNATURE_SEED),
    );

    let manifest = serde_json::json!({
        "schema": "chio.proof-room.bundle.v1",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "stage": "stage-0",
        "created_at": "2026-06-10T00:00:00Z",
        "source_commit": "fixture-static",
        "source_branch": "main",
        "source_command": "chio proof verify roots/transaction-passport.json",
        "chio_version": "0.1.0",
        "schema_versions": {
            "proof_room_bundle": "chio.proof-room.bundle.v1",
            "proof_room_verifier_report": "chio.proof-room.verifier-report.v1",
            "transaction_passport": "chio.transaction-passport.v1",
            "transaction_evidence_graph": "chio.transaction.evidence-graph.v1",
            "transaction_verifier_policy": "chio.transaction.verifier-policy.v1",
            "transaction_verifier_report": "chio.transaction.verifier-report.v1"
        },
        "hash_algorithm": "sha256",
        "transaction_passport_ref": artifact_ref(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1"),
        "evidence_graph_ref": artifact_ref(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1"),
        "verifier_report_ref": artifact_ref(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1"),
        "proof_room_verifier_report_ref": artifact_ref(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1"),
        "artifacts": [
            artifact(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1", "transaction-root", "transaction-passport"),
            artifact(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1", "transaction-root", "evidence-graph"),
            artifact(&bundle, "roots/verifier-policy.json", "chio.transaction.verifier-policy.v1", "transaction-policy", "verifier-policy"),
            artifact(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1", "verifier-output", "verifier-report"),
            artifact(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1", "proof-room-display", "proof-room-report"),
            artifact(&bundle, "capability-proof.json", "chio.capability.proof.v1", "transaction-root", "capability-proof"),
            artifact(&bundle, "guard-decision.json", "chio.guard.decision.v1", "transaction-root", "guard-decision"),
            artifact(&bundle, "kernel-receipt.json", "chio.receipt.v1", "receipt", "receipt"),
            artifact(&bundle, "policy.json", "chio.policy.bundle.v1", "transaction-policy", "policy"),
            artifact(&bundle, "request-digest.json", "chio.request.digest.v1", "transaction-root", "request-digest"),
            artifact(&bundle, "response-digest.json", "chio.response.digest.v1", "transaction-root", "response-digest"),
            artifact(&bundle, "trust-root.json", "chio.trust.root.v1", "transaction-root", "trust-root"),
            artifact(&bundle, "artifacts/authority/trust-roots.json", "chio.proof.first-run.trust-roots.v1", "proof-room-authority", "trust-roots")
        ],
        "claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "required_artifacts": [
                    "roots/transaction-passport.json",
                    "roots/evidence-graph.json",
                    "roots/verifier-policy.json",
                    "verifier/report.json"
                ],
                "checker": "chio proof verify roots/transaction-passport.json",
                "result": "verified",
                "proof_level": "deterministic-verifier-report",
                "caveat": "",
                "source_refs": ["verifier/report.json"]
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "required_artifacts": [
                    "verifier/report.json",
                    "ui/proof-room-static/load-report.json"
                ],
                "checker": "chio proof serve --dry-run",
                "result": "verified",
                "proof_level": "hash-bound-display-report",
                "caveat": "The UI report is a consumer of verifier output, not a proof source.",
                "source_refs": ["ui/proof-room-static/load-report.json"]
            }
        ],
        "receipt_coverage": [
            {
                "category": "runtime_terminal_allow",
                "status": "covered",
                "artifact_path": "kernel-receipt.json",
                "terminal_status": "allowed_executed"
            }
        ],
        "negative_cases": [],
        "advisory_artifacts": [],
        "excluded_artifacts": [],
        "signature": {
            "kind": "detached-dsse",
            "signature_ref": "bundle-signature.dsse.json"
        }
    });
    write_json(&bundle.join("manifest.json"), &manifest);

    let mut signature = serde_json::json!({
        "payloadType": "application/vnd.chio.proof-room.bundle.v1+json",
        "payloadRef": artifact_ref(&bundle, "manifest.json", "chio.proof-room.bundle.v1"),
        "signatures": [
            {
                "keyid": "",
                "sig": ""
            }
        ]
    });
    sign_bundle_signature(&bundle, &mut signature);
    write_json(&bundle.join("bundle-signature.dsse.json"), &signature);

    (tempdir, bundle)
}
