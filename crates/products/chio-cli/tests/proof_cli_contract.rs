use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    Keypair,
};
use chio_test_support::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
const COLLECT_SIGNATURE_SEED: [u8; 32] = [11; 32];
const PROOF_SERVE_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

fn chio(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(args)
        .output()
        .test_expect("chio command runs")
}

fn stdout(output: std::process::Output) -> String {
    String::from_utf8(output.stdout).test_expect("stdout is utf8")
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output, expected: &str) {
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

struct ChildGuard {
    child: Child,
}

struct RunningProofServe {
    _guard: ChildGuard,
    address: SocketAddr,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn utf8_path(path: &Path) -> String {
    path.to_str().test_expect("path is utf8").to_string()
}

fn assert_json_schema_accepts(relative_schema_path: &str, instance: &serde_json::Value) {
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

fn http_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
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

fn wait_for_http_body(address: SocketAddr, path: &str) -> String {
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

fn wait_for_http_response(address: SocketAddr, path: &str) -> String {
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

fn spawn_proof_serve(bundle: &Path, ui_dir: Option<&Path>) -> RunningProofServe {
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

fn copy_dir_all(source: &Path, destination: &Path) -> std::io::Result<()> {
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
fn append_symlink_member<W: Write>(builder: &mut tar::Builder<W>, outside_passport: &Path) {
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
fn write_tgz_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish gzip");
}

#[cfg(unix)]
fn write_tar_zst_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = zstd::stream::write::Encoder::new(file, 0).test_expect("create zstd encoder");
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish zstd");
}

fn tgz_member_names(path: &Path) -> BTreeSet<String> {
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

fn proof_room_bundle_fixture() -> PathBuf {
    workspace_root().join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle")
}

fn mutate_proof_room_bundle(negative_case: &str) -> (tempfile::TempDir, PathBuf, String) {
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

fn remove_evidence_graph_node_and_rehash(
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

fn write_json(path: &Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(value).test_expect("serialize JSON");
    std::fs::write(path, [&bytes[..], b"\n"].concat()).test_expect("write JSON");
}

fn signed_terminal_receipt(
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

fn sign_terminal_receipt(mut receipt: serde_json::Value) -> serde_json::Value {
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

fn sign_transaction_receipt_artifact(bundle: &Path, artifact_path: &str) {
    let receipt_path = bundle.join(artifact_path);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    write_json(&receipt_path, &sign_terminal_receipt(receipt));
    refresh_transaction_artifact_digest(bundle, artifact_path);
}

fn refresh_transaction_artifact_digest(bundle: &Path, artifact_path: &str) {
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

fn refresh_transaction_artifact_digest_at(
    bundle: &Path,
    evidence_graph_path: &Path,
    passport_path: &Path,
    artifact_path: &str,
) {
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
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
    write_json(&evidence_graph_path, &evidence_graph);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);
}

fn artifact_ref(bundle: &Path, path: &str, schema: &str) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "sha256": sha256_file(&bundle.join(path)),
        "schema": schema
    })
}

fn artifact(
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

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).test_expect("read file for sha256");
    hex::encode(Sha256::digest(&bytes))
}

fn graph_node_by_schema<'a>(
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

fn assert_graph_node_hashes_bundle_artifact(
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

fn resign_agent_web_receipts_for_policy(bundle: &Path, policy_sha256: &str) {
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

fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
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

fn sign_bundle_signature(bundle: &Path, signature: &mut serde_json::Value) {
    sign_bundle_signature_with_seed(bundle, signature, TEST_SIGNATURE_SEED);
}

fn sign_bundle_signature_with_seed(
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

fn build_runtime_commerce_passport_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn build_commerce_transfer_group_mismatch_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn build_commerce_settlement_passport_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn build_integrated_runtime_commerce_settlement_agent_web_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn build_disclosure_agent_web_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn build_risk_only_policy_bundle(
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

fn build_standalone_risk_only_policy_bundle() -> (tempfile::TempDir, PathBuf) {
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

fn remove_standalone_risk_graph_node(bundle: &Path, removed_node_id: &str) {
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

fn add_standalone_risk_unbound_reserve_ledger(bundle: &Path) {
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

fn point_standalone_risk_lifecycle_authority_at_supporting_evidence(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["facility_lifecycle"][0]["authority_receipt_ref"] =
        serde_json::json!("data-governance-report");
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

fn deny_standalone_risk_approval_case(bundle: &Path) {
    let approval_path = bundle.join("approval-case.json");
    let mut approval: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&approval_path).test_expect("read approval case"))
            .test_expect("approval case parses");
    approval["decision"] = serde_json::json!("denied");
    write_json(&approval_path, &approval);
    rehash_standalone_risk_graph_artifact(bundle, "approval-case", &approval_path);
}

fn rehash_standalone_risk_graph_artifact(bundle: &Path, node_id: &str, artifact_path: &Path) {
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

fn add_standalone_risk_uncovered_reserve_ledger_claim(bundle: &Path) {
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

fn add_standalone_risk_sanction_backed_market_slash(bundle: &Path) {
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

fn write_standalone_risk_report_and_rehash(bundle: &Path, risk_report: serde_json::Value) {
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

fn append_required_claims_from_policy(policy: &mut serde_json::Value, source_policy_path: &Path) {
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

fn append_graph_artifacts_from_fixture(
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

fn replace_json_strings_in_graph_artifacts(
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

fn replace_json_string(value: &mut serde_json::Value, from: &str, to: &str) {
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

fn refresh_signed_lineage_subgraph_digest(bundle: &Path) {
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

fn refresh_bundle_signature(bundle: &Path) {
    refresh_bundle_signature_with_seed(bundle, TEST_SIGNATURE_SEED);
}

fn refresh_bundle_signature_with_seed(bundle: &Path, seed: [u8; 32]) {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature_with_seed(bundle, &mut signature, seed);
    write_json(&signature_path, &signature);
}

fn refresh_verifier_report_refs_with_seed(bundle: &Path, seed: [u8; 32]) {
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

fn refresh_manifest_artifact_ref(bundle: &Path, artifact_path: &str) {
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

fn copy_proof_room_bundle_to_temp() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    (tempdir, bundle)
}

fn build_minimal_passport_proof_room_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("minimal-passport-proof-room-bundle");
    std::fs::create_dir_all(bundle.join("roots")).test_expect("create roots dir");
    std::fs::create_dir_all(bundle.join("verifier")).test_expect("create verifier dir");
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
            artifact(&bundle, "trust-root.json", "chio.trust.root.v1", "transaction-root", "trust-root")
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

#[test]
fn proof_fixture_list_reports_proof_fixtures() {
    let output = chio(&["proof", "fixture", "list", "--json"]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture list report parses");
    let fixture_ids = report["fixtures"]
        .as_array()
        .test_expect("fixtures array")
        .iter()
        .map(|fixture| fixture["id"].as_str().test_expect("fixture id").to_string())
        .collect::<BTreeSet<_>>();

    for expected_fixture_id in [
        "single-call-authority",
        "commerce-transaction-passport",
        "minimal-passport-valid",
        "runtime-side-effecting-call",
        "commerce-offline-psp",
        "workflow-preflight-valid",
        "workflow-preflight-broader-child-scope",
        "workflow-preflight-planning-artifact-claims-authority",
        "recursive-runtime-swarm",
        "disclosure-and-agent-web-envelope",
        "recursive-runtime-swarm-stale-continuation",
        "recursive-runtime-swarm-budget-allocations-exceed-pool",
        "recursive-runtime-swarm-graph-cycle",
        "recursive-runtime-swarm-join-parent-set-mismatch",
        "recursive-runtime-swarm-replayed-continuation-nonce",
        "recursive-runtime-swarm-revoked-task",
        "recursive-runtime-swarm-stale-route-plan",
        "recursive-runtime-swarm-witness-child-scope-mismatch",
        "disclosure-lineage-ledger",
        "crypto-context-valid-bbs",
        "crypto-context-forbidden-algorithm",
        "crypto-context-missing-holder-binding",
        "crypto-context-missing-revocation-snapshot",
        "crypto-context-preview-transparency",
        "crypto-context-replayed-nonce",
        "crypto-context-stale-key",
        "crypto-context-wrong-audience",
        "public-settlement-offline-finality",
        "public-settlement-finality-below-threshold",
        "public-settlement-observed-execution-outside-window",
        "public-settlement-missing-commerce-order-binding",
        "public-settlement-order-evidence-mismatch",
        "public-settlement-missing-oracle-evidence",
        "public-settlement-refunded-posture-without-reversal",
        "public-settlement-wrong-chain-id",
        "agent-web-interop",
        "agent-web-external-digest-mismatch",
        "agent-web-missing-required-signature",
        "agent-web-cloudevents-specversion-mismatch",
        "agent-web-graphql-http-draft-version-missing",
        "agent-web-graphql-errors-projected-as-success",
        "agent-web-mcp-authority-claim-not-limited",
        "agent-web-sidecar-claim-marked-native",
        "agent-web-unsupported-claim-not-limited",
        "agent-web-external-subject-schema-mismatch",
        "agent-web-acp-client-unsupported-bridge-allowed",
        "agent-web-email-send-missing-message-digest",
        "agent-web-calendar-time-range-mismatch",
        "agent-web-slack-failed-provider-response",
        "agent-web-kubernetes-admission-uid-mismatch",
        "agent-web-oci-tag-only-ref",
        "agent-web-slsa-unverified-provenance",
        "agent-web-a2a-authority-claim-not-limited",
        "agent-web-ap2-detached-from-order",
        "agent-web-vc-unbound-receipt",
        "enterprise-autonomous-commerce",
        "trust-market-context",
        "minimal-passport-evidence-graph-digest-mismatch",
        "minimal-passport-policy-digest-mismatch",
        "minimal-passport-unknown-schema",
        "runtime-missing-execution-lease",
        "runtime-expired-execution-lease",
        "runtime-advisory-used-as-authorization",
        "runtime-ack-outside-lease",
        "runtime-missing-terminal-receipt",
        "runtime-reused-nonce",
        "runtime-sandbox-mismatch",
        "runtime-stale-revocation",
        "commerce-payment-wrong-merchant",
        "commerce-expired-mandate",
        "commerce-payment-before-budget",
        "commerce-quote-evidence-mismatch",
        "commerce-open-dispute-completed",
        "commerce-fraud-declined",
        "commerce-currency-mismatch",
        "commerce-payment-amount-mismatch",
        "commerce-mandate-occurrence-limit",
        "enterprise-coverage-subject-mismatch",
        "enterprise-risk-reserve-state-missing",
        "enterprise-settlement-counterparty-mismatch",
        "enterprise-control-map-missing-gate",
        "enterprise-double-consumed-reserve",
        "enterprise-duplicate-reserve-receipt-id",
        "enterprise-export-bundle-digest-mismatch",
        "enterprise-market-slash-facility-reserve",
        "enterprise-reverse-slash-without-prior-penalty",
        "enterprise-missing-approval-case",
        "enterprise-open-appeal-reserve-release",
        "enterprise-pii-overdisclosure",
        "enterprise-telemetry-digest-mismatch",
        "enterprise-facility-lifecycle-final-state-mismatch",
        "enterprise-insurance-copy-exceeds-actuarial-support",
        "enterprise-risk-exposure-exceeds-capital",
        "enterprise-risk-portfolio-capital-overallocated",
        "enterprise-actuarial-backtest-breach",
        "enterprise-mixed-currency-risk",
        "enterprise-claim-outside-coverage",
        "enterprise-payout-amount-mismatch",
        "disclosure-lineage-missing-ledger-entry",
        "disclosure-lineage-unknown-lineage-root",
        "trust-market-guarantee-wrong-beneficiary",
        "trust-market-unsupported-guarantee-type",
        "trust-market-unsupported-collateral-source",
        "trust-market-guarantee-without-backing",
        "trust-market-reputation-import-overweight",
        "trust-market-required-unsupported-market-claim",
        "trust-market-score-recompute-mismatch",
        "trust-market-selected-provider-absent",
        "trust-market-sla-wrong-order",
        "trust-market-slash-authority-outside-jurisdiction",
        "trust-market-stale-discovery",
        "trust-market-stale-reputation",
    ] {
        assert!(
            fixture_ids.contains(expected_fixture_id),
            "missing proof fixture id: {expected_fixture_id}"
        );
    }
}

#[test]
fn proof_fixture_generate_reports_verifiable_single_call_authority_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("single-call-authority");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "single-call-authority",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&["proof", "verify", verify_path]);

    assert_success(&verify_output);
}

#[test]
fn proof_fixture_generate_reports_verifiable_commerce_transaction_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("commerce-transaction-passport");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "commerce-transaction-passport",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("commerce-transaction-passport")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    let readme = std::fs::read_to_string(out_path.join("proof-room-bundle/README.md"))
        .test_expect("read generated Proof Room README");
    assert!(readme.contains("commerce-transaction-passport"));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("commerce-transaction-passport")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate commerce-transaction-passport")
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "commerce",
        "--require",
        "settlement",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(verify_stdout.contains("\"claim.public_settlement.finality_verified\""));
}

#[test]
fn proof_fixture_generate_keeps_commerce_stage_available_with_installed_fixture_root() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let fixture_root = workspace_root().join("fixtures/proof-room");
    let out_path = tempdir.path().join("commerce-transaction-passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &fixture_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("commerce-transaction-passport")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "commerce",
        "--require",
        "settlement",
    ]);

    assert_success(&verify_output);
}

#[test]
fn proof_fixture_generate_reports_verifiable_recursive_runtime_swarm_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("recursive-runtime-swarm");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "recursive-runtime-swarm",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("recursive-runtime-swarm")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let bundle = out_path.join("proof-room-bundle");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/runtime-proof-parity-report.json")
        .exists());
    let parity_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/runtime-proof-parity-report.json"))
            .test_expect("read generated runtime parity report"),
    )
    .test_expect("generated runtime parity report parses");
    for field in [
        "staticProofPackageSha256",
        "runtimeProofPackageSha256",
        "staticVerifierReportSha256",
        "runtimeVerifierReportSha256",
    ] {
        let digest = parity_report[field]
            .as_str()
            .test_expect("runtime parity report digest is a string");
        assert_ne!(digest, "a".repeat(64));
        assert_ne!(digest, "b".repeat(64));
        assert_ne!(digest, "c".repeat(64));
        assert_ne!(digest, "d".repeat(64));
    }
    let evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join("evidence-graph.json"))
            .test_expect("read generated evidence graph"),
    )
    .test_expect("generated evidence graph parses");
    for schema in [
        "chio.runtime.proof-parity-report.v1",
        "chio.runtime.proof-regeneration-report.v1",
        "chio.runtime.proof-regeneration-input.v1",
        "chio.runtime.evidence-manifest.v1",
        "chio.runtime.workflow-run-report.v1",
    ] {
        let artifact = assert_graph_node_hashes_bundle_artifact(&bundle, &evidence_graph, schema);
        assert_eq!(
            artifact["schema"].as_str(),
            Some(schema),
            "runtime artifact schema mismatch for {schema}"
        );
        assert_eq!(
            artifact["runId"].as_str(),
            Some("runtime-loopback-1"),
            "runtime artifact run id mismatch for {schema}"
        );
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("recursive-runtime-swarm")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate recursive-runtime-swarm")
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(verify_stdout.contains("\"runtime_proof_parity_report\""));
    assert!(verify_stdout.contains("\"runId\":\"runtime-loopback-1\""));
}

#[test]
fn proof_verify_runtime_parity_rejects_tampered_regeneration_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("recursive-runtime-swarm");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "recursive-runtime-swarm",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);
    assert_success(&output);

    let bundle = out_path.join("proof-room-bundle");
    let report_path = bundle.join("proof-regeneration-report.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read proof report"))
            .test_expect("proof report parses");
    report["checks"]
        .as_array_mut()
        .test_expect("proof report checks array")
        .push(serde_json::Value::String(
            "runtime_regeneration.tampered".to_string(),
        ));
    write_json(&report_path, &report);
    refresh_transaction_artifact_digest(&bundle, "proof-regeneration-report.json");
    refresh_manifest_artifact_ref(&bundle, "proof-regeneration-report.json");
    refresh_manifest_artifact_ref(&bundle, "roots/evidence-graph.json");
    refresh_manifest_artifact_ref(&bundle, "roots/transaction-passport.json");
    refresh_bundle_signature_with_seed(&bundle, COLLECT_SIGNATURE_SEED);

    let verify_output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_failure(
        &verify_output,
        "runtime proof regeneration report hash mismatch",
    );
}

#[test]
fn proof_fixture_generate_reports_verifiable_disclosure_agent_web_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("disclosure-and-agent-web-envelope");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "disclosure-and-agent-web-envelope",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("disclosure-and-agent-web-envelope")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("disclosure-and-agent-web-envelope")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate disclosure-and-agent-web-envelope")
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "disclosure",
        "--require",
        "external-envelope",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(verify_stdout.contains("\"claim.agent_web.projection_manifest_bound\""));
}

#[test]
fn proof_fixture_generate_copies_domain_passport_fixture() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("commerce-offline-psp");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "commerce-offline-psp",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    assert!(out_path.join("evidence-graph.json").exists());
    assert!(out_path.join("order-context.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"commerce-offline-psp\""));
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    let verifier_report_path = out_path.join("verifier/report.json");
    let verifier_report_path_string = verifier_report_path.to_string_lossy().into_owned();
    assert_eq!(
        report["verifier_report_path"].as_str(),
        Some(verifier_report_path_string.as_str())
    );
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&verifier_report_path).test_expect("read report"))
            .test_expect("verifier report parses");
    assert_eq!(
        verifier_report["schema"],
        "chio.transaction.verifier-report.v1"
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        out_dir.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
    let serve_report: serde_json::Value =
        serde_json::from_slice(&serve_output.stdout).test_expect("serve report parses");
    assert_eq!(
        serve_report
            .get("verifier_parity")
            .and_then(serde_json::Value::as_str),
        Some("verified")
    );
}

#[test]
fn proof_fixture_generate_outputs_servable_enterprise_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("enterprise-autonomous-commerce");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "enterprise-autonomous-commerce",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);
    assert_success(&output);

    let serve_output = chio(&[
        "proof",
        "serve",
        out_dir.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_success(&serve_output);
}

#[test]
fn proof_fixture_generate_copies_crypto_context_fixture() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("crypto-context-valid-bbs");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "crypto-context-valid-bbs",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    assert!(out_path.join("verification-context.json").exists());
    assert!(out_path.join("crypto-context-report.json").exists());
    assert!(out_path.join("key-state.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"crypto-context-valid-bbs\""));
}

#[test]
fn proof_fixture_generate_reports_crypto_context_rejection_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("crypto-context-wrong-audience");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "crypto-context-wrong-audience",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "rejected");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("disclosure_context_audience_mismatch"));
    let verifier_report_path = report["verifier_report_path"]
        .as_str()
        .test_expect("fixture generate report includes verifier report path");
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(verifier_report_path).test_expect("read report"))
            .test_expect("verifier report parses");
    assert_eq!(
        verifier_report["schema"],
        "chio.disclosure.crypto-context-report.v1"
    );
    assert_eq!(verifier_report["verdict"], "rejected");
    assert!(verifier_report["rejected_checks"]
        .as_array()
        .test_expect("rejected checks array")
        .iter()
        .any(|check| check["code"] == "disclosure_context_audience_mismatch"));
}

#[test]
fn proof_fixture_generate_reports_negative_fixture_expected_failure() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("policy-digest-mismatch");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "minimal-passport-policy-digest-mismatch",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("verifier policy digest mismatch"));
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&["proof", "verify", verify_path]);

    assert_failure(&verify_output, "verifier policy digest mismatch");
}

#[test]
fn proof_fixture_root_catalog_uses_registered_schema() {
    let catalog_path = workspace_root().join("fixtures/proof-room/catalog.json");
    let catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&catalog_path).test_expect("read fixture catalog"))
            .test_expect("fixture catalog parses");
    let schema = "chio.proof-room.fixture-root-catalog.v1";

    assert_eq!(catalog["schema"], schema);
    assert!(
        chio_core_types::is_supported_signed_artifact_schema(schema),
        "fixture root catalog schema must be registry-backed"
    );
    assert_json_schema_accepts(
        "spec/schemas/chio-proof-room/v1/fixture-root-catalog.schema.json",
        &catalog,
    );
}

#[test]
fn proof_fixture_generate_uses_installed_fixture_root() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/valid");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed fixture");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "minimal-passport-valid",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Installed minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    std::fs::write(
        installed_fixture.join("installed-root-marker.txt"),
        "installed fixture root\n",
    )
    .test_expect("write installed marker");
    let out_path = tempdir.path().join("generated-minimal-passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("minimal-passport-valid")
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    assert!(out_path.join("installed-root-marker.txt").exists());
}

#[test]
fn proof_fixture_list_uses_installed_fixture_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Packaged minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("list")
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture list report parses");
    let fixture_ids: BTreeSet<_> = report["fixtures"]
        .as_array()
        .test_expect("fixture list includes fixtures")
        .iter()
        .map(|fixture| {
            fixture["id"]
                .as_str()
                .test_expect("fixture id is a string")
                .to_string()
        })
        .collect();
    assert!(fixture_ids.contains("packaged-minimal-passport"));
}

#[test]
fn proof_fixture_list_rejects_configured_fixture_root_without_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("list")
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "proof fixture catalog missing");
}

#[test]
fn proof_fixture_generate_uses_installed_fixture_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/valid");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed fixture");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Packaged minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-minimal-passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("packaged-minimal-passport")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"packaged-minimal-passport\""));
}

#[test]
fn proof_fixture_generate_rejects_negative_fixture_expected_failure_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/invalid-policy-digest-mismatch");
    let installed_metadata = installed_root.join("minimal-passport/negatives");
    let source = workspace_root()
        .join("fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("invalid-policy-digest-mismatch.json"),
        serde_json::json!({
            "schema": "chio.transaction.negative-fixture.v1",
            "id": "invalid-policy-digest-mismatch",
            "claim_ref": "claim.transaction.policy_digest_bound",
            "base_fixture": "fixtures/proof-room/minimal-passport/valid/transaction-passport.json",
            "case": "PolicyDigestMismatch",
            "expected_failure_code": "expected failure that does not occur"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-policy-digest-mismatch",
                    "kind": "negative-transaction-passport",
                    "path": "minimal-passport/invalid-policy-digest-mismatch",
                    "description": "Packaged policy digest mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-policy-digest-mismatch");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("packaged-policy-digest-mismatch")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "expected failure that does not occur");
}

#[test]
fn proof_fixture_generate_rejects_negative_fixture_failure_prefix() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("commerce-payments/payment-wrong-merchant");
    let installed_metadata = installed_root.join("commerce-payments/negatives");
    let source =
        workspace_root().join("fixtures/proof-room/commerce-payments/payment-wrong-merchant");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("payment-wrong-merchant.json"),
        serde_json::json!({
            "schema": "chio.commerce.negative-fixture.v1",
            "id": "payment-wrong-merchant",
            "claim_ref": "claim.commerce.payment_lifecycle_bound",
            "base_fixture": "fixtures/proof-room/commerce-payments/offline-psp-valid/transaction-passport.json",
            "case": "PaymentWrongMerchant",
            "expected_failure_code": "payment merchant"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "commerce-payment-wrong-merchant",
                    "kind": "negative-transaction-passport",
                    "path": "commerce-payments/payment-wrong-merchant",
                    "description": "Packaged commerce payment mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-commerce-mismatch");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("commerce-payment-wrong-merchant")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "payment merchant mismatch");
}

#[test]
fn proof_fixture_generate_rejects_installed_catalog_path_escape() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let outside_fixture = tempdir.path().join("outside-fixture");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &outside_fixture).test_expect("copy outside fixture");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "escaped-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "../outside-fixture",
                    "description": "Escaped packaged fixture path"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-escaped-fixture");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("escaped-minimal-passport")
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "installed proof fixture path escapes root");
    assert!(!out_path.exists());
}

#[test]
fn proof_fixture_generate_rejects_existing_output_directory() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_dir = utf8_path(tempdir.path());

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "single-call-authority",
        "--out",
        out_dir.as_str(),
    ]);

    assert_failure(&output, "proof output directory already exists");
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_plan() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("workflow-preflight-valid");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-valid",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_success(&preflight_output);
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_denial() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir
        .path()
        .join("workflow-preflight-planning-artifact-claims-authority");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-planning-artifact-claims-authority",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("cannot satisfy live authority claims"));
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_failure(&preflight_output, "cannot satisfy live authority claims");
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_scope_denial() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir
        .path()
        .join("workflow-preflight-broader-child-scope");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-broader-child-scope",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("outside parent scope"));
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_failure(&preflight_output, "outside parent scope");
}

#[test]
fn proof_fixture_generate_copies_runnable_negative_passport_fixtures() {
    for (fixture_id, expected_file, expected_failure) in [
        (
            "minimal-passport-evidence-graph-digest-mismatch",
            "verifier-policy.json",
            "evidence graph digest mismatch",
        ),
        (
            "minimal-passport-policy-digest-mismatch",
            "verifier-policy.json",
            "verifier policy digest mismatch",
        ),
        (
            "minimal-passport-unknown-schema",
            "transaction-passport.json",
            "unsupported transaction passport schema",
        ),
        (
            "minimal-passport-stale-capability",
            "capability-proof.json",
            "capability proof expired before evidence graph issuance",
        ),
        (
            "runtime-missing-execution-lease",
            "tool-server-ack.json",
            "missing execution lease",
        ),
        (
            "runtime-expired-execution-lease",
            "execution-lease.json",
            "execution lease expired before issuance",
        ),
        (
            "runtime-advisory-used-as-authorization",
            "execution-lease.json",
            "advisory evidence cannot authorize runtime execution",
        ),
        (
            "runtime-ack-outside-lease",
            "tool-server-ack.json",
            "acknowledgement outside execution lease",
        ),
        (
            "runtime-missing-terminal-receipt",
            "evidence-graph.json",
            "missing terminal receipt for execution lease",
        ),
        (
            "runtime-reused-nonce",
            "evidence-graph.json",
            "reused nonce",
        ),
        (
            "runtime-sandbox-mismatch",
            "sandbox-attestation.json",
            "sandbox tool binding mismatch",
        ),
        (
            "runtime-stale-revocation",
            "revocation-freshness-proof.json",
            "revocation freshness stale",
        ),
        (
            "commerce-payment-wrong-merchant",
            "payment-lifecycle.json",
            "payment merchant mismatch",
        ),
        (
            "commerce-expired-mandate",
            "mandate-allowance-ledger.json",
            "mandate expired before payment capture",
        ),
        (
            "commerce-payment-before-budget",
            "event-log.json",
            "unknown commerce transition",
        ),
        (
            "commerce-quote-evidence-mismatch",
            "event-log.json",
            "quote event missing quote evidence",
        ),
        (
            "commerce-open-dispute-completed",
            "payment-lifecycle.json",
            "unresolved payment recovery state",
        ),
        (
            "commerce-fraud-declined",
            "payment-lifecycle.json",
            "fraud outcome was not accepted",
        ),
        (
            "commerce-currency-mismatch",
            "payment-lifecycle.json",
            "payment amount or currency mismatch",
        ),
        (
            "commerce-payment-amount-mismatch",
            "payment-lifecycle.json",
            "payment amount or currency mismatch",
        ),
        (
            "commerce-mandate-occurrence-limit",
            "mandate-allowance-ledger.json",
            "mandate occurrence limit exceeded",
        ),
        (
            "recursive-runtime-swarm-stale-continuation",
            "continuation-child-a.json",
            "swarm continuation token is stale",
        ),
        (
            "recursive-runtime-swarm-budget-allocations-exceed-pool",
            "budget-pool.json",
            "swarm budget allocations exceed pool total",
        ),
        (
            "recursive-runtime-swarm-graph-cycle",
            "task-graph.json",
            "swarm task graph cycle at task-child-a",
        ),
        (
            "recursive-runtime-swarm-join-parent-set-mismatch",
            "join-receipt.json",
            "swarm join receipt parent set mismatch",
        ),
        (
            "recursive-runtime-swarm-replayed-continuation-nonce",
            "continuation-child-b.json",
            "swarm continuation nonce replay",
        ),
        (
            "recursive-runtime-swarm-revoked-task",
            "revocation-epoch.json",
            "swarm task is revoked",
        ),
        (
            "recursive-runtime-swarm-stale-route-plan",
            "route-child-a.json",
            "swarm route-plan receipt is stale",
        ),
        (
            "recursive-runtime-swarm-route-plan-mismatch",
            "route-child-a.json",
            "swarm route-plan selected route bridge mismatch",
        ),
        (
            "recursive-runtime-swarm-witness-child-scope-mismatch",
            "witness-child-a.json",
            "swarm witness child scope mismatch",
        ),
        (
            "public-settlement-wrong-chain-id",
            "settlement-proof-bundle.json",
            "settlement chain id mismatch",
        ),
        (
            "public-settlement-finality-below-threshold",
            "settlement-proof-bundle.json",
            "settlement finality below threshold",
        ),
        (
            "public-settlement-observed-execution-outside-window",
            "settlement-proof-bundle.json",
            "observed execution timestamp falls outside dispatch execution window",
        ),
        (
            "public-settlement-missing-commerce-order-binding",
            "settlement-proof-bundle.json",
            "public_settlement.commerce_order_id",
        ),
        (
            "public-settlement-order-evidence-mismatch",
            "settlement-proof-bundle.json",
            "public settlement commerce order evidence mismatch",
        ),
        (
            "public-settlement-missing-oracle-evidence",
            "settlement-proof-bundle.json",
            "receipt requires oracle_evidence for FX-sensitive settlement paths",
        ),
        (
            "public-settlement-refunded-posture-without-reversal",
            "settlement-proof-bundle.json",
            "refunded dispute posture requires reversed or timed out settlement",
        ),
        (
            "agent-web-external-digest-mismatch",
            "cloudevents-envelope.json",
            "external subject digest mismatch",
        ),
        (
            "agent-web-missing-required-signature",
            "standard-webhooks-envelope.json",
            "missing external signature",
        ),
        (
            "agent-web-cloudevents-specversion-mismatch",
            "external/cloudevent.json",
            "CloudEvents specversion mismatch",
        ),
        (
            "agent-web-graphql-http-draft-version-missing",
            "graphql-http-manifest.json",
            "GraphQL over HTTP version must be draft-labeled",
        ),
        (
            "agent-web-graphql-errors-projected-as-success",
            "external/graphql-operation.json",
            "GraphQL response contains errors",
        ),
        (
            "agent-web-mcp-authority-claim-not-limited",
            "mcp-envelope.json",
            "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority",
        ),
        (
            "agent-web-sidecar-claim-marked-native",
            "cloudevents-manifest.json",
            "sidecar claim presented as native external proof",
        ),
        (
            "agent-web-unsupported-claim-not-limited",
            "cloudevents-envelope.json",
            "unsupported claim was not limited",
        ),
        (
            "agent-web-x402-detached-from-order",
            "evidence-graph.json",
            "missing x402 order binding",
        ),
        (
            "agent-web-external-subject-schema-mismatch",
            "evidence-graph.json",
            "external subject schema mismatch",
        ),
        (
            "agent-web-acp-client-unsupported-bridge-allowed",
            "external/acp-client-permission.json",
            "unsupported ACP-Client bridge allowed",
        ),
        (
            "agent-web-email-send-missing-message-digest",
            "external/email-message.json",
            "missing email message digest",
        ),
        (
            "agent-web-calendar-time-range-mismatch",
            "external/calendar-event.json",
            "Calendar time range changed after approval",
        ),
        (
            "agent-web-slack-failed-provider-response",
            "external/slack-message.json",
            "Slack response was not successful",
        ),
        (
            "agent-web-kubernetes-admission-uid-mismatch",
            "external/kubernetes-admission-review.json",
            "Kubernetes admission response UID mismatch",
        ),
        (
            "agent-web-oci-tag-only-ref",
            "external/oci-ref.json",
            "OCI reference must be digest-pinned",
        ),
        (
            "agent-web-slsa-unverified-provenance",
            "external/slsa-provenance.json",
            "unsupported SLSA verification status",
        ),
        (
            "agent-web-a2a-authority-claim-not-limited",
            "a2a-envelope.json",
            "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority",
        ),
        (
            "agent-web-ap2-detached-from-order",
            "evidence-graph.json",
            "missing ap2 order binding",
        ),
        (
            "agent-web-vc-unbound-receipt",
            "vc-envelope.json",
            "VC receipt ref is not bound",
        ),
        (
            "enterprise-coverage-subject-mismatch",
            "risk-comptroller-report.json",
            "risk coverage subject mismatch",
        ),
        (
            "enterprise-coverage-order-mismatch",
            "risk-comptroller-report.json",
            "risk coverage order mismatch",
        ),
        (
            "enterprise-risk-reserve-state-missing",
            "risk-comptroller-report.json",
            "risk reserve state missing",
        ),
        (
            "enterprise-settlement-counterparty-mismatch",
            "risk-comptroller-report.json",
            "risk settlement counterparty mismatch",
        ),
        (
            "enterprise-control-map-missing-gate",
            "control-evidence-map.json",
            "control gate did not run",
        ),
        (
            "enterprise-double-consumed-reserve",
            "risk-comptroller-report.json",
            "risk reserve double consumption",
        ),
        (
            "enterprise-duplicate-reserve-receipt-id",
            "risk-comptroller-report.json",
            "risk reserve ledger duplicate receipt",
        ),
        (
            "enterprise-export-bundle-digest-mismatch",
            "evidence-export-bundle.json",
            "export bundle digest mismatch",
        ),
        (
            "enterprise-market-slash-facility-reserve",
            "risk-comptroller-report.json",
            "risk market slash requires sanction bridge",
        ),
        (
            "enterprise-reverse-slash-without-prior-penalty",
            "risk-comptroller-report.json",
            "risk reverse slash missing prior reserve slash",
        ),
        (
            "enterprise-missing-approval-case",
            "evidence-graph.json",
            "missing approval case",
        ),
        (
            "enterprise-open-appeal-reserve-release",
            "risk-comptroller-report.json",
            "risk open appeal blocks reserve action",
        ),
        (
            "enterprise-open-appeal-claim-payout",
            "risk-comptroller-report.json",
            "risk open appeal blocks reserve action",
        ),
        (
            "enterprise-open-appeal-facility-closure",
            "risk-comptroller-report.json",
            "risk open appeal blocks facility closure",
        ),
        (
            "enterprise-pii-overdisclosure",
            "data-governance-report.json",
            "PII field was not redacted",
        ),
        (
            "enterprise-telemetry-digest-mismatch",
            "telemetry-projection.json",
            "telemetry artifact digest mismatch",
        ),
        (
            "enterprise-facility-lifecycle-final-state-mismatch",
            "risk-comptroller-report.json",
            "risk facility lifecycle final state mismatch",
        ),
        (
            "enterprise-insurance-copy-exceeds-actuarial-support",
            "risk-comptroller-report.json",
            "risk insurance copy exceeds actuarial support",
        ),
        (
            "enterprise-risk-exposure-exceeds-capital",
            "risk-comptroller-report.json",
            "risk exposure exceeds capital",
        ),
        (
            "enterprise-risk-capital-adequacy-breach",
            "risk-comptroller-report.json",
            "risk capital adequacy breach",
        ),
        (
            "enterprise-risk-portfolio-capital-overallocated",
            "risk-comptroller-report-secondary.json",
            "risk portfolio capital adequacy breach",
        ),
        (
            "enterprise-actuarial-backtest-breach",
            "risk-comptroller-report.json",
            "risk actuarial backtest breach",
        ),
        (
            "enterprise-mixed-currency-risk",
            "risk-comptroller-report.json",
            "risk coverage currency mismatch",
        ),
        (
            "enterprise-claim-outside-coverage",
            "risk-comptroller-report.json",
            "risk claim outside coverage",
        ),
        (
            "enterprise-payout-amount-mismatch",
            "risk-comptroller-report.json",
            "risk payout settlement mismatch",
        ),
        (
            "disclosure-lineage-missing-ledger-entry",
            "leakage-ledger.json",
            "disclosed field absent from leakage ledger",
        ),
        (
            "disclosure-lineage-unknown-lineage-root",
            "signed-lineage-subgraph.json",
            "unknown lineage root receipt",
        ),
        (
            "trust-market-guarantee-wrong-beneficiary",
            "guarantee-decision.json",
            "guarantee beneficiary mismatch",
        ),
        (
            "trust-market-unsupported-guarantee-type",
            "guarantee-decision.json",
            "guarantee type unsupported",
        ),
        (
            "trust-market-unsupported-collateral-source",
            "collateral-position-report.json",
            "collateral source type unsupported",
        ),
        (
            "trust-market-guarantee-without-backing",
            "guarantee-decision.json",
            "guarantee backing missing",
        ),
        (
            "trust-market-reputation-import-overweight",
            "reputation-import-report.json",
            "reputation import local weight exceeds policy",
        ),
        (
            "trust-market-required-unsupported-market-claim",
            "verifier-policy.json",
            "unsupported market claim cannot be required",
        ),
        (
            "trust-market-score-recompute-mismatch",
            "trust-scorecard-snapshot.json",
            "scorecard recompute mismatch",
        ),
        (
            "trust-market-selected-provider-absent",
            "provider-selection-report.json",
            "selected provider absent from discovery snapshot",
        ),
        (
            "trust-market-sla-wrong-order",
            "sla-commitment.json",
            "SLA order mismatch",
        ),
        (
            "trust-market-slash-authority-outside-jurisdiction",
            "collateral-position-report.json",
            "slash authority not bound to jurisdiction",
        ),
        (
            "trust-market-stale-discovery",
            "provider-discovery-snapshot.json",
            "discovery snapshot is stale",
        ),
        (
            "trust-market-stale-reputation",
            "trust-scorecard-snapshot.json",
            "scorecard component evidence is stale",
        ),
    ] {
        let tempdir = tempfile::tempdir().test_expect("tempdir");
        let out_path = tempdir.path().join(fixture_id);
        let out_dir = utf8_path(&out_path);

        let output = chio(&[
            "proof",
            "fixture",
            "generate",
            fixture_id,
            "--out",
            out_dir.as_str(),
            "--json",
        ]);

        assert_success(&output);
        assert!(out_path.join("transaction-passport.json").exists());
        assert!(out_path.join(expected_file).exists());
        let stdout = stdout(output);
        assert!(stdout.contains(&format!("\"fixture_id\":\"{fixture_id}\"")));

        let verify_output = chio(&["proof", "verify", out_dir.as_str()]);
        assert_failure(&verify_output, expected_failure);
    }
}

#[test]
fn proof_collect_outputs_servable_bundle_for_passport_artifacts() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = utf8_path(&artifact_dir);
    let out_path = tempdir.path().join("collected-passport");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        artifact_dir.as_str(),
        "--out",
        out_dir.as_str(),
    ]);

    assert_success(&output);
    let passport_path = out_path.join("transaction-passport.json");
    let verifier_report_path = out_path.join("verifier/report.json");
    assert!(passport_path.exists());
    assert!(verifier_report_path.exists());

    let verify_output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);
    assert_success(&verify_output);
    let collected_report =
        std::fs::read(verifier_report_path).test_expect("read collected verifier report");
    assert_eq!(collected_report, verify_output.stdout);

    let manifest_path = out_path.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read collected manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("report-hash-mismatch")
            })
        })
        .test_expect("collected bundle includes verifier-backed negative case");
    assert_eq!(
        negative_case
            .get("expected_failure_code")
            .and_then(serde_json::Value::as_str),
        Some("proof-room.report.hash-mismatch")
    );
    assert_eq!(
        negative_case
            .get("observed_failure_code")
            .and_then(serde_json::Value::as_str),
        Some("proof-room.report.hash-mismatch")
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        out_dir.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
    let serve_report: serde_json::Value =
        serde_json::from_slice(&serve_output.stdout).test_expect("serve report parses");
    assert_eq!(
        serve_report
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some("chio.proof.serve-report.v1")
    );
    assert_eq!(
        serve_report
            .get("verifier_parity")
            .and_then(serde_json::Value::as_str),
        Some("verified")
    );

    let archive_path = tempdir.path().join("collected-passport.tgz");
    let archive = utf8_path(&archive_path);
    let export_output = chio(&[
        "proof",
        "export",
        out_dir.as_str(),
        "--out",
        archive.as_str(),
    ]);
    assert_success(&export_output);
    let archive_verify = chio(&["proof", "verify", archive.as_str()]);
    assert_success(&archive_verify);
}

#[test]
fn proof_collect_binds_bundle_signature_to_manifest_trust_roots() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let out_path = tempdir.path().join("collected-passport");

    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&collect);

    let signature_path = out_path.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature_with_seed(&out_path, &mut signature, [99; 32]);
    write_json(&signature_path, &signature);

    let verify = chio(&["proof", "verify", utf8_path(&out_path).as_str()]);

    assert_failure(&verify, "proof-room.signature.signer-untrusted");
}

#[test]
fn proof_collect_ioa_web3_outputs_verifiable_commerce_settlement_bundle() {
    let (tempdir, artifact_dir) = build_commerce_settlement_passport_bundle();
    let out_path = tempdir.path().join("collected-ioa-web3");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "ioa-web3",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).test_expect("collect report parses");
    assert_eq!(
        report.get("kind").and_then(serde_json::Value::as_str),
        Some("ioa-web3")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "commerce",
        "--require",
        "settlement",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.public_settlement.finality_verified\""));
}

#[test]
fn proof_collect_agent_web_envelope_outputs_verifiable_external_envelope_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let out_path = tempdir.path().join("collected-agent-web-envelope");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "agent-web-envelope",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).test_expect("collect report parses");
    assert_eq!(
        report.get("kind").and_then(serde_json::Value::as_str),
        Some("agent-web-envelope")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "external-envelope",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_collect_disclosure_agent_web_envelope_outputs_verifiable_combined_bundle() {
    let (tempdir, artifact_dir) = build_disclosure_agent_web_bundle();
    let out_path = tempdir
        .path()
        .join("collected-disclosure-agent-web-envelope");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "disclosure-agent-web-envelope",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).test_expect("collect report parses");
    assert_eq!(
        report.get("kind").and_then(serde_json::Value::as_str),
        Some("disclosure-agent-web-envelope")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "disclosure",
        "--require",
        "external-envelope",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_collect_disclosure_agent_web_envelope_rejects_missing_disclosure_family() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let out_path = tempdir
        .path()
        .join("collected-disclosure-agent-web-missing-disclosure");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "disclosure-agent-web-envelope",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_failure(&output, "required proof claim family missing: disclosure");
}

#[test]
fn proof_collect_binds_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("commerce-payment-wrong-merchant")
            })
        })
        .test_expect("collected commerce bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("payment merchant mismatch")));

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_preserves_domain_claims_in_manifest() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let verifier_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("verifier/report.json"))
            .test_expect("read collected verifier report"),
    )
    .test_expect("collected verifier report parses");
    assert_json_schema_accepts(
        "spec/schemas/chio-transaction/v1/verifier-report.schema.json",
        &verifier_report,
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let ui_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("ui/proof-room-static/load-report.json"))
            .test_expect("read collected ui report"),
    )
    .test_expect("collected ui report parses");

    let verified_commerce_claim = verifier_report["family_reports"]
        .as_array()
        .test_expect("family reports array")
        .iter()
        .flat_map(|report| report["verified_claims"].as_array().into_iter().flatten())
        .filter_map(serde_json::Value::as_str)
        .find(|claim| claim.starts_with("claim.commerce."))
        .test_expect("commerce verifier report includes commerce claim");
    let checker_provenance = verifier_report["checker_provenance"]
        .as_array()
        .test_expect("collected verifier report includes checker provenance");
    assert!(checker_provenance.iter().any(|entry| {
        entry["claim_id"] == verified_commerce_claim
            && entry["checker"] == "chio proof verify --require commerce"
    }));
    let manifest_claims = manifest["claims"]
        .as_array()
        .test_expect("manifest claims array")
        .iter()
        .filter_map(|claim| claim["claim_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(manifest_claims.contains(verified_commerce_claim));
    let rendered_claims = ui_report["rendered_claims"]
        .as_array()
        .test_expect("ui rendered claims array")
        .iter()
        .filter_map(|claim| claim["claim_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(rendered_claims.contains(verified_commerce_claim));
    let rendered_commerce_claim = ui_report["rendered_claims"]
        .as_array()
        .test_expect("ui rendered claims array")
        .iter()
        .find(|claim| claim["claim_id"] == verified_commerce_claim)
        .test_expect("ui renders commerce claim");
    assert_eq!(
        rendered_commerce_claim["checker"].as_str(),
        Some("chio proof verify --require commerce")
    );
}

#[test]
fn proof_collect_rejects_catalog_negative_fixture_expected_failure_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("commerce-payments/payment-wrong-merchant");
    let installed_metadata = installed_root.join("commerce-payments/negatives");
    let source =
        workspace_root().join("fixtures/proof-room/commerce-payments/payment-wrong-merchant");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("payment-wrong-merchant.json"),
        serde_json::json!({
            "schema": "chio.commerce.negative-fixture.v1",
            "id": "payment-wrong-merchant",
            "claim_ref": "claim.commerce.payment_lifecycle_bound",
            "base_fixture": "fixtures/proof-room/commerce-payments/offline-psp-valid/transaction-passport.json",
            "case": "PaymentWrongMerchant",
            "expected_failure_code": "expected failure that does not occur"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "commerce-payment-wrong-merchant",
                    "kind": "negative-transaction-passport",
                    "path": "commerce-payments/payment-wrong-merchant",
                    "description": "Packaged commerce payment mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("collect")
        .arg("--kind")
        .arg("transaction-passport")
        .arg("--artifact-dir")
        .arg(&artifact_dir)
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "catalog negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "expected failure that does not occur");
}

#[test]
fn proof_collect_rejects_catalog_negative_fixture_failure_prefix() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("commerce-payments/payment-wrong-merchant");
    let installed_metadata = installed_root.join("commerce-payments/negatives");
    let source =
        workspace_root().join("fixtures/proof-room/commerce-payments/payment-wrong-merchant");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("payment-wrong-merchant.json"),
        serde_json::json!({
            "schema": "chio.commerce.negative-fixture.v1",
            "id": "payment-wrong-merchant",
            "claim_ref": "claim.commerce.payment_lifecycle_bound",
            "base_fixture": "fixtures/proof-room/commerce-payments/offline-psp-valid/transaction-passport.json",
            "case": "PaymentWrongMerchant",
            "expected_failure_code": "payment merchant"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "commerce-payment-wrong-merchant",
                    "kind": "negative-transaction-passport",
                    "path": "commerce-payments/payment-wrong-merchant",
                    "description": "Packaged commerce payment mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("collect")
        .arg("--kind")
        .arg("transaction-passport")
        .arg("--artifact-dir")
        .arg(&artifact_dir)
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "catalog negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "payment merchant mismatch");
}

#[test]
fn proof_collect_binds_runtime_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let out_path = tempdir.path().join("collected-runtime-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("runtime-missing-execution-lease")
            })
        })
        .test_expect("collected runtime bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/runtime-missing-execution-lease/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/runtime-missing-execution-lease/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("missing execution lease")));
    let allow_coverage = manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
        .and_then(|coverage| {
            coverage.iter().find(|entry| {
                entry.get("category").and_then(serde_json::Value::as_str)
                    == Some("runtime_terminal_allow")
            })
        })
        .test_expect("collected runtime bundle reports allow receipt coverage");
    assert_eq!(
        allow_coverage
            .get("status")
            .and_then(serde_json::Value::as_str),
        Some("excluded")
    );
    assert!(allow_coverage
        .get("exclusion_reason")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|reason| reason.contains("signature")));

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_binds_risk_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/enterprise-export/standalone-risk-comptroller");
    let out_path = tempdir.path().join("collected-risk-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("enterprise-double-consumed-reserve")
            })
        })
        .test_expect("collected risk bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/enterprise-double-consumed-reserve/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/enterprise-double-consumed-reserve/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("risk reserve double consumption")));
}

#[test]
fn proof_assemble_writes_deterministic_verifiable_passport_roots() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("minimal-artifacts");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "capability-proof.json",
        "guard-decision.json",
        "kernel-receipt.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy source artifact");
    }

    let verifier_policy = source.join("verifier-policy.json");
    let first_out = tempdir.path().join("assembled-first");
    let second_out = tempdir.path().join("assembled-second");
    for out in [&first_out, &second_out] {
        let output = chio(&[
            "proof",
            "assemble",
            "--artifact-dir",
            utf8_path(&artifact_dir).as_str(),
            "--verifier-policy",
            utf8_path(&verifier_policy).as_str(),
            "--passport-id",
            "passport-assembled-minimal",
            "--issued-at",
            "2026-06-10T00:00:00Z",
            "--out",
            utf8_path(out).as_str(),
            "--json",
        ]);
        assert_success(&output);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).test_expect("assemble report parses");
        assert_eq!(report["schema"], "chio.proof.assemble-report.v1");
        assert_eq!(report["passport_id"], "passport-assembled-minimal");
        assert_eq!(report["out"], utf8_path(out));

        let verify = chio(&["proof", "verify", utf8_path(out).as_str()]);
        assert_success(&verify);
        let verify_stdout = stdout(verify);
        assert!(verify_stdout.contains("\"passport_id\":\"passport-assembled-minimal\""));
        assert!(verify_stdout.contains("\"verdict\":\"verified\""));
    }

    for artifact in [
        "transaction-passport.json",
        "evidence-graph.json",
        "verifier-policy.json",
    ] {
        let first = std::fs::read(first_out.join(artifact)).test_expect("read first artifact");
        let second = std::fs::read(second_out.join(artifact)).test_expect("read second artifact");
        assert_eq!(first, second, "{artifact} should be deterministic");
    }
}

#[test]
fn proof_assemble_rejects_reserved_roots_without_partial_output() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("artifact-dir-with-stale-root");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    std::fs::copy(
        source.join("kernel-receipt.json"),
        artifact_dir.join("kernel-receipt.json"),
    )
    .test_expect("copy receipt artifact");
    std::fs::copy(
        source.join("verifier-policy.json"),
        artifact_dir.join("verifier-policy.json"),
    )
    .test_expect("copy stale verifier policy root");

    let out = tempdir.path().join("assembled");
    let output = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-minimal",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(&output, "verifier-policy.json");
    assert!(
        !out.exists(),
        "proof assemble should not leave a partial output directory after rejecting stale roots"
    );
}

#[test]
fn proof_assemble_rejects_missing_required_receipt_without_partial_output() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("artifact-dir-without-receipt");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "capability-proof.json",
        "guard-decision.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy source artifact");
    }

    let out = tempdir.path().join("assembled");
    let output = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-minimal",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(&output, "requires at least one receipt artifact");
    assert!(
        !out.exists(),
        "proof assemble should not leave a partial output directory after rejecting missing receipts"
    );
}

#[test]
fn proof_assemble_outputs_runtime_security_bundle_verifiable_by_runtime_requirement() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let artifact_dir = tempdir.path().join("runtime-artifacts");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "allow-receipt.json",
        "execution-lease.json",
        "revocation-freshness-proof.json",
        "sandbox-attestation.json",
        "tool-server-ack.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy runtime artifact");
    }

    let out = tempdir.path().join("assembled-runtime");
    let assemble = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-runtime",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);
    assert_success(&assemble);

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out).as_str(),
        "--require",
        "runtime",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.runtime.advisory_not_used_as_authorization\""));
}

#[test]
fn proof_collect_derives_receipt_coverage_for_each_terminal_status() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-terminal-receipts");
    copy_dir_all(&source, &artifact_path).test_expect("copy artifact dir");
    sign_transaction_receipt_artifact(&artifact_path, "kernel-receipt.json");

    let kernel_receipt_path = artifact_path.join("kernel-receipt.json");
    let kernel_receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&kernel_receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    let policy_digest = kernel_receipt["policy_digest"]
        .as_str()
        .test_expect("receipt policy digest")
        .to_string();
    for (path, receipt_id, terminal_status) in [
        (
            "denial-receipt.json",
            "receipt-terminal-denial",
            "denied_guard_request",
        ),
        (
            "failure-receipt.json",
            "receipt-terminal-failure",
            "failed_tool_unreachable",
        ),
    ] {
        write_json(
            &artifact_path.join(path),
            &signed_terminal_receipt(receipt_id, terminal_status, &policy_digest),
        );
    }

    let evidence_graph_path = artifact_path.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    for (node_id, path) in [
        ("terminal-denial-receipt", "denial-receipt.json"),
        ("terminal-failure-receipt", "failure-receipt.json"),
    ] {
        nodes.push(serde_json::json!({
            "id": node_id,
            "schema": "chio.receipt.v1",
            "path": path,
            "sha256": sha256_file(&artifact_path.join(path)),
            "role": "receipt"
        }));
    }
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = artifact_path.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    let out_path = tempdir.path().join("collected-terminal-coverage");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read manifest"),
    )
    .test_expect("manifest parses");
    let categories = manifest["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array")
        .iter()
        .map(|entry| {
            entry["category"]
                .as_str()
                .test_expect("coverage category")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            "runtime_terminal_allow".to_string(),
            "runtime_terminal_denial".to_string(),
            "runtime_terminal_failure".to_string(),
        ])
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);

    let verify_denials = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "denials",
    ]);
    assert_success(&verify_denials);
}

#[test]
fn proof_collect_records_receipt_coverage_exclusions_for_missing_terminal_statuses() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-denial-receipt");
    copy_dir_all(&source, &artifact_path).test_expect("copy artifact dir");
    sign_transaction_receipt_artifact(&artifact_path, "kernel-receipt.json");

    let kernel_receipt_path = artifact_path.join("kernel-receipt.json");
    let kernel_receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&kernel_receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    let policy_digest = kernel_receipt["policy_digest"]
        .as_str()
        .test_expect("receipt policy digest")
        .to_string();
    write_json(
        &artifact_path.join("denial-receipt.json"),
        &signed_terminal_receipt(
            "receipt-terminal-denial",
            "denied_guard_request",
            &policy_digest,
        ),
    );

    let evidence_graph_path = artifact_path.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": "terminal-denial-receipt",
            "schema": "chio.receipt.v1",
            "path": "denial-receipt.json",
            "sha256": sha256_file(&artifact_path.join("denial-receipt.json")),
            "role": "receipt"
        }));
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = artifact_path.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    let out_path = tempdir.path().join("collected-terminal-exclusions");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read manifest"),
    )
    .test_expect("manifest parses");
    let coverage = manifest["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array");
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_allow" && entry["status"] == "covered"
    }));
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_denial" && entry["status"] == "covered"
    }));
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_failure"
            && entry["status"] == "excluded"
            && entry["exclusion_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("runtime_terminal_failure"))
    }));
    assert!(manifest["claims"]
        .as_array()
        .test_expect("manifest claims array")
        .iter()
        .any(|claim| claim["claim_id"] == "claim.proof_room.receipt_coverage_matrix_bound"));

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_rejects_existing_output_directory() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = utf8_path(&artifact_dir);
    let out_dir = utf8_path(tempdir.path());

    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        artifact_dir.as_str(),
        "--out",
        out_dir.as_str(),
    ]);

    assert_failure(&output, "proof output directory already exists");
}

#[test]
fn proof_verify_requires_commerce_claims_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let commerce_bundle =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let commerce_bundle = utf8_path(&commerce_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "commerce",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: commerce",
    );

    let commerce_output = chio(&[
        "proof",
        "verify",
        commerce_bundle.as_str(),
        "--require",
        "commerce",
    ]);

    assert_success(&commerce_output);
}

#[test]
fn proof_verify_rejects_commerce_payment_wrong_transfer_group() {
    let (_tempdir, bundle) = build_commerce_transfer_group_mismatch_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "commerce"]);

    assert_failure(&output, "payment transfer group mismatch");
}

#[test]
fn proof_verify_requires_runtime_claims_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let runtime_bundle =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let runtime_bundle = utf8_path(&runtime_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "runtime",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: runtime",
    );

    let runtime_output = chio(&[
        "proof",
        "verify",
        runtime_bundle.as_str(),
        "--require",
        "runtime",
    ]);

    assert_success(&runtime_output);
}

#[test]
fn proof_verify_runtime_requirement_rejects_advisory_only_runtime_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let bundle = tempdir.path().join("runtime-advisory-only");
    copy_dir_all(&source, &bundle).test_expect("copy runtime bundle");

    let verifier_policy_path = bundle.join("verifier-policy.json");
    let mut verifier_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("verifier policy parses");
    verifier_policy["required_claims"] =
        serde_json::json!(["claim.runtime.advisory_not_used_as_authorization"]);
    write_json(&verifier_policy_path, &verifier_policy);
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let policy_node = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .iter_mut()
        .find(|node| {
            node.get("role").and_then(serde_json::Value::as_str) == Some("verifier-policy")
        })
        .test_expect("verifier policy graph node");
    policy_node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256);
    write_json(&passport_path, &passport);

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "runtime",
    ]);

    assert_failure(&output, "required proof runtime authority missing");
}

#[test]
fn proof_verify_accepts_mixed_runtime_and_commerce_claim_policy() {
    let (_tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        bundle.as_str(),
        "--require",
        "runtime",
        "--require",
        "commerce",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
}

#[test]
fn proof_verify_accepts_integrated_runtime_commerce_settlement_and_agent_web_claim_policy() {
    let (_tempdir, bundle) = build_integrated_runtime_commerce_settlement_agent_web_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        bundle.as_str(),
        "--require",
        "runtime",
        "--require",
        "commerce",
        "--require",
        "settlement",
        "--require",
        "external-envelope",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.public_settlement.finality_verified\""));
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_verify_routes_risk_only_policy_through_domain_verifiers() {
    for (fixture_path, bundle_name) in [
        (
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "enterprise-risk-only",
        ),
        (
            "fixtures/proof-room/trust-market/valid-marketplace-context",
            "trust-market-risk-only",
        ),
    ] {
        let (_tempdir, bundle) = build_risk_only_policy_bundle(fixture_path, bundle_name);
        let bundle = utf8_path(&bundle);

        let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

        assert_success(&output);
        let stdout = stdout(output);
        assert!(stdout.contains("\"claim.risk.comptroller_report_bound\""));
    }
}

#[test]
fn proof_verify_routes_standalone_risk_policy_through_risk_comptroller() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"claim.risk.comptroller_report_bound\""));
    assert!(
        stdout.contains("\"risk_comptroller_report_ref\":\"risk-comptroller-enterprise-valid\"")
    );
}

#[test]
fn proof_verify_rejects_standalone_risk_with_unbound_evidence_ref() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    remove_standalone_risk_graph_node(&bundle, "data-governance-report");
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk facility lifecycle evidence missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_with_unbound_reserve_ledger_refs() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_unbound_reserve_ledger(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk reserve ledger receipt missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_lifecycle_authority_wrong_evidence_kind() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    point_standalone_risk_lifecycle_authority_at_supporting_evidence(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk facility lifecycle authority missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_denied_approval_case() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    deny_standalone_risk_approval_case(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk approval case denied");
}

#[test]
fn proof_verify_rejects_standalone_risk_with_uncovered_reserve_ledger_claim() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_uncovered_reserve_ledger_claim(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk claim outside coverage");
}

#[test]
fn proof_verify_requires_denial_evidence_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let proof_room_bundle = proof_room_bundle_fixture();
    let proof_room_bundle = utf8_path(&proof_room_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "denials",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: denials",
    );

    let proof_room_output = chio(&[
        "proof",
        "verify",
        proof_room_bundle.as_str(),
        "--require",
        "denials",
    ]);

    assert_success(&proof_room_output);
}

#[test]
fn proof_verify_file_input_revalidates_sibling_manifest_before_denials_requirement() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("passport-with-forged-manifest");
    copy_dir_all(&source, &bundle).test_expect("copy minimal passport fixture");

    let manifest_path = bundle.join("manifest.json");
    let manifest = serde_json::json!({
        "schema": "chio.proof-room.bundle.v1",
        "claims": [
            {
                "claim_id": "claim.proof_room.allow_and_deny_visible",
                "required_artifacts": [],
                "checker": "forged",
                "result": "verified",
                "proof_level": "fixture-evidence",
                "caveat": "",
                "source_refs": []
            }
        ]
    });
    write_json(&manifest_path, &manifest);

    let passport_path = bundle.join("transaction-passport.json");
    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&passport_path).as_str(),
        "--require",
        "denials",
    ]);

    assert_failure(&output, "proof room bundle");
}

#[test]
fn proof_verify_requires_documented_claim_families_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);

    for (requirement, fixture_path, expected_label) in [
        (
            "delegation",
            "fixtures/proof-room/swarm-authority/valid-recursive-delegation",
            "delegation",
        ),
        (
            "disclosure",
            "fixtures/proof-room/disclosure-lineage/valid-lineage-ledger",
            "disclosure",
        ),
        (
            "enterprise",
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "enterprise",
        ),
        (
            "settlement",
            "fixtures/proof-room/public-settlement/valid-offline-finality",
            "settlement",
        ),
        (
            "trust-market",
            "fixtures/proof-room/trust-market/valid-marketplace-context",
            "trust-market",
        ),
        (
            "external-envelope",
            "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
            "external-envelope",
        ),
        (
            "risk",
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "risk",
        ),
    ] {
        let minimal_output = chio(&[
            "proof",
            "verify",
            minimal_bundle.as_str(),
            "--require",
            requirement,
        ]);
        assert_failure(
            &minimal_output,
            &format!("required proof claim family missing: {expected_label}"),
        );

        let proof_bundle = workspace_root().join(fixture_path);
        let proof_bundle = utf8_path(&proof_bundle);
        let proof_output = chio(&[
            "proof",
            "verify",
            proof_bundle.as_str(),
            "--require",
            requirement,
        ]);
        assert_success(&proof_output);
    }
}

#[test]
fn proof_verify_runtime_parity_requires_explicit_parity_evidence() {
    let runtime_bundle =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let runtime_bundle = utf8_path(&runtime_bundle);

    let output = chio(&[
        "proof",
        "verify",
        runtime_bundle.as_str(),
        "--require",
        "runtime-parity",
    ]);

    assert_failure(&output, "required proof runtime parity missing");
}

fn build_swarm_bundle_with_runtime_parity() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle = tempdir.path().join("swarm-with-runtime-parity");
    copy_dir_all(&source, &bundle).test_expect("copy swarm bundle");

    let parity_path = bundle.join("runtime-proof-parity-report.json");
    write_json(
        &parity_path,
        &serde_json::json!({
            "schema": "chio.runtime.proof-parity-report.v1",
            "runId": "runtime-swarm-valid",
            "accepted": true,
            "generatedAtUnixMs": 1800000001000_u64,
            "staticProofPackageSha256": "a".repeat(64),
            "runtimeProofPackageSha256": "a".repeat(64),
            "staticVerifierReportSha256": "b".repeat(64),
            "runtimeVerifierReportSha256": "b".repeat(64),
            "comparedFields": ["workflow_id", "workflow_steps"],
            "mismatches": []
        }),
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": "runtime-proof-parity-report",
            "schema": "chio.runtime.proof-parity-report.v1",
            "path": "runtime-proof-parity-report.json",
            "sha256": sha256_file(&parity_path),
            "role": "runtime-proof-parity-report"
        }));
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

#[test]
fn proof_verify_runtime_parity_accepts_evidence_graph_bound_report() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(stdout.contains("\"runtime_proof_parity_report\""));
    assert!(stdout.contains("\"runId\":\"runtime-swarm-valid\""));
}

#[test]
fn proof_verify_runtime_parity_rejects_accepted_package_hash_drift() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();
    let parity_path = bundle.join("runtime-proof-parity-report.json");
    let mut parity_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&parity_path).test_expect("read parity report"))
            .test_expect("parity report parses");
    parity_report["runtimeProofPackageSha256"] = serde_json::Value::String("c".repeat(64));
    write_json(&parity_path, &parity_report);
    refresh_transaction_artifact_digest(&bundle, "runtime-proof-parity-report.json");

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_failure(&output, "runtime_proof_parity_accepted_package_hash_drift");
}

#[test]
fn proof_collect_runtime_spine_requires_delegation_and_runtime_parity() {
    let (tempdir, artifact_dir) = build_swarm_bundle_with_runtime_parity();
    let out_path = tempdir.path().join("collected-runtime-spine");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "runtime-spine",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).test_expect("collect report parses");
    assert_eq!(
        report.get("kind").and_then(serde_json::Value::as_str),
        Some("runtime-spine")
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    assert_eq!(
        manifest
            .get("source_command")
            .and_then(serde_json::Value::as_str),
        Some("chio proof collect --kind runtime-spine")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);
    assert_success(&verify);
}

#[test]
fn proof_explain_reports_claim_status_and_evidence_path() {
    let bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim_id\":\"claim.transaction.passport_root_verified\""));
    assert!(stdout.contains("\"status\":\"verified\""));
    assert!(stdout.contains("\"transaction-passport.json\""));
}

#[test]
fn proof_explain_reports_swarm_claims_as_verified() {
    let bundle =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.swarm.task_graph_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.swarm.task_graph_bound");
    assert_eq!(report["status"], "verified");
    assert!(report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array")
        .iter()
        .any(|path| path
            .as_str()
            .is_some_and(|path| path.ends_with("transaction-passport.json"))));
}

#[test]
fn proof_explain_reports_agent_web_projection_reasoning() {
    let bundle = workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.agent_web.unsupported_claims_limited",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(
        report["claim_id"],
        "claim.agent_web.unsupported_claims_limited"
    );
    assert_eq!(report["status"], "verified");
    let agent_web = &report["agent_web"];
    assert!(agent_web["projections"]
        .as_array()
        .test_expect("Agent Web projections array")
        .iter()
        .any(|projection| projection["source_protocol"] == "mcp"
            && projection["external_subject_digest"].as_str().is_some()));
    assert!(agent_web["unsupported_claims"]
        .as_array()
        .test_expect("Agent Web unsupported claims array")
        .iter()
        .any(|claim| claim == "claim.external.mcp_tool_call_is_chio_authority"));
    assert!(agent_web["limitations"]
        .as_array()
        .test_expect("Agent Web limitations array")
        .iter()
        .any(|limitation| limitation
            .as_str()
            .is_some_and(|limitation| limitation.contains("not Chio capability authority"))));
}

#[test]
fn proof_explain_reports_risk_facility_reasoning() {
    let bundle =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.risk.comptroller_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.risk.comptroller_report_bound");
    assert_eq!(report["status"], "verified");
    let risk = &report["risk"];
    assert_eq!(
        risk["risk_comptroller_report_ref"],
        "risk-comptroller-enterprise-valid"
    );
    assert_eq!(risk["facility"]["state"], "settlement_matched");
    assert!(risk["facility_lifecycle"]
        .as_array()
        .test_expect("risk facility lifecycle array")
        .iter()
        .any(|transition| transition["from_state"] == "coverage_bound"
            && transition["to_state"] == "settlement_matched"));
    assert_eq!(risk["reconciliation"]["status"], "balanced");
    assert_eq!(risk["actuarial_evidence"]["backtest"]["status"], "passed");
    assert_eq!(
        risk["insurance_copy"]["coverage_statement"],
        "coverage limited to supported exposure"
    );
}

#[test]
fn proof_explain_reports_risk_sanction_reserve_ledger() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_sanction_backed_market_slash(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.risk.comptroller_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.risk.comptroller_report_bound");
    assert_eq!(report["status"], "verified", "report: {report}");
    let sanction_ledger = report["risk"]["sanction_reserve_ledger"]
        .as_array()
        .test_expect("risk sanction reserve ledger array");
    assert!(sanction_ledger.iter().any(|entry| entry["bridge_id"]
        == "sanction-bridge-risk-market-slash"
        && entry["jurisdiction_ref"] == "approval-case"));
}

#[test]
fn proof_explain_reports_domain_claim_evidence_graph() {
    let bundle =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.enterprise.control_map_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.enterprise.control_map_bound");
    assert_eq!(report["status"], "verified");
    let evidence_paths = report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array");
    assert!(evidence_paths.iter().any(|path| path
        .as_str()
        .is_some_and(|path| path.ends_with("evidence-graph.json"))));
    assert!(evidence_paths.iter().any(|path| path
        .as_str()
        .is_some_and(|path| path.ends_with("verifier-policy.json"))));
}

#[test]
fn proof_explain_reports_negative_passport_verifier_failure() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(
        report["claim_id"],
        "claim.transaction.passport_root_verified"
    );
    assert_eq!(report["status"], "failed");
    assert!(report["verifier_error"]
        .as_str()
        .test_expect("verifier error string")
        .contains("verifier policy digest mismatch"));
    let evidence_paths = report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(evidence_paths
        .iter()
        .any(|path| path.ends_with("transaction-passport.json")));
    assert!(evidence_paths
        .iter()
        .any(|path| path.ends_with("verifier-policy.json")));
}

#[test]
fn proof_explain_text_reports_negative_passport_verifier_failure() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/minimal-passport/evidence-graph-digest-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("status: failed"));
    assert!(stdout.contains("verifier-error:"));
    assert!(stdout.contains("evidence graph digest mismatch"));
}

#[test]
fn proof_explain_reports_proof_room_claim_sources() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    for claim in [
        "claim.proof_room.allow_and_deny_visible",
        "claim.proof_room.receipt_coverage_matrix_bound",
    ] {
        let output = chio(&[
            "proof",
            "explain",
            bundle.as_str(),
            "--claim",
            claim,
            "--json",
        ]);

        assert_success(&output);
        let stdout = stdout(output);
        assert!(stdout.contains(&format!("\"claim_id\":\"{claim}\"")));
        assert!(stdout.contains("\"status\":\"verified\""));
        assert!(stdout.contains("artifacts/receipts/allow-receipt.json"));
        assert!(stdout.contains("artifacts/receipts/denial-receipt.json"));
    }
}

#[test]
fn proof_explain_reports_proof_room_manifest_claim_metadata() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.proof_room.verifier_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.proof_room.verifier_report_bound");
    assert_eq!(report["status"], "verified");
    assert_eq!(
        report["checker"],
        "chio proof doctor --scenario single-call-authority"
    );
    assert_eq!(report["proof_level"], "hash-bound-display-report");
    assert_eq!(
        report["caveat"],
        "The UI report is a consumer of verifier output, not a proof source."
    );
}

#[test]
fn proof_explain_reports_receipt_coverage_exclusions_for_matrix_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-denial-receipt");
    copy_dir_all(&source, &artifact_path).test_expect("copy artifact dir");
    sign_transaction_receipt_artifact(&artifact_path, "kernel-receipt.json");

    let kernel_receipt_path = artifact_path.join("kernel-receipt.json");
    let kernel_receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&kernel_receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    let policy_digest = kernel_receipt["policy_digest"]
        .as_str()
        .test_expect("receipt policy digest")
        .to_string();
    write_json(
        &artifact_path.join("denial-receipt.json"),
        &signed_terminal_receipt(
            "receipt-terminal-denial",
            "denied_guard_request",
            &policy_digest,
        ),
    );

    let evidence_graph_path = artifact_path.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": "terminal-denial-receipt",
            "schema": "chio.receipt.v1",
            "path": "denial-receipt.json",
            "sha256": sha256_file(&artifact_path.join("denial-receipt.json")),
            "role": "receipt"
        }));
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = artifact_path.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    let out_path = tempdir.path().join("collected-terminal-exclusions");
    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&collect);

    let explain = chio(&[
        "proof",
        "explain",
        utf8_path(&out_path).as_str(),
        "--claim",
        "claim.proof_room.receipt_coverage_matrix_bound",
        "--json",
    ]);
    assert_success(&explain);
    let stdout = stdout(explain);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    let coverage = report["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array");
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_failure"
            && entry["status"] == "excluded"
            && entry["exclusion_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("runtime_terminal_failure"))
    }));
}

#[test]
fn proof_explain_text_reports_receipt_coverage_exclusions_for_matrix_claim() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.proof_room.receipt_coverage_matrix_bound",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("coverage: runtime_terminal_allow covered"));
    assert!(stdout.contains("coverage: runtime_terminal_denial covered"));
    assert!(stdout.contains("coverage: runtime_terminal_failure excluded"));
    assert!(stdout.contains(
        "Single-call authority fixture covers allow and guard denial terminal receipts only."
    ));
}

#[test]
fn proof_export_writes_tgz_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tgz");
    let output_file = utf8_path(&output_file);

    let output = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);

    assert_success(&output);
    let metadata = std::fs::metadata(output_file).test_expect("export file metadata");
    assert!(metadata.len() > 0);
}

#[test]
fn proof_export_rejects_existing_output_archive() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tgz");
    std::fs::write(&output_file, b"existing archive").test_expect("write existing archive");
    let output_file = utf8_path(&output_file);

    let output = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);

    assert_failure(&output, "proof export output already exists");
    let bytes = std::fs::read(output_file).test_expect("read existing archive");
    assert_eq!(bytes, b"existing archive");
}

#[test]
fn proof_export_public_redaction_excludes_unmanifested_internal_files() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let internal_dir = bundle.join("artifacts/internal");
    std::fs::create_dir_all(&internal_dir).test_expect("create internal dir");
    std::fs::write(
        internal_dir.join("debug-notes.json"),
        b"{\"internal\":true}\n",
    )
    .test_expect("write internal artifact");
    let output_file = tempdir.path().join("proof-room-public.tgz");

    let output = chio(&[
        "proof",
        "export",
        utf8_path(&bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
        "--redact",
        "public",
    ]);

    assert_success(&output);
    let members = tgz_member_names(&output_file);
    assert!(members.contains("manifest.json"));
    assert!(members.contains("verifier/report.json"));
    assert!(!members.contains("artifacts/internal/debug-notes.json"));

    let verify = chio(&["proof", "verify", utf8_path(&output_file).as_str()]);
    assert_success(&verify);
}

#[test]
fn proof_export_public_redaction_excludes_manifested_internal_artifacts() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let internal_path = "artifacts/internal/debug-notes.json";
    let internal_file = bundle.join(internal_path);
    std::fs::create_dir_all(
        internal_file
            .parent()
            .test_expect("internal artifact has parent"),
    )
    .test_expect("create internal artifact dir");
    std::fs::write(
        &internal_file,
        b"{\"schema\":\"chio.proof-room.internal-debug-notes.v1\",\"internal\":true}\n",
    )
    .test_expect("write internal artifact");

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .push(serde_json::json!({
            "path": internal_path,
            "sha256": sha256_file(&internal_file),
            "schema": "chio.proof-room.internal-debug-notes.v1",
            "media_type": "application/json",
            "artifact_class": "debug-notes",
            "sensitivity_class": "internal",
            "producer": "test-fixture",
            "participates_in_primary_verdict": false,
            "renderer_hint": "hidden"
        }));
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output_file = tempdir.path().join("proof-room-public.tgz");
    let output = chio(&[
        "proof",
        "export",
        utf8_path(&bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
        "--redact",
        "public",
    ]);

    assert_success(&output);
    let members = tgz_member_names(&output_file);
    assert!(members.contains("manifest.json"));
    assert!(members.contains("verifier/report.json"));
    assert!(!members.contains(internal_path));

    let verify = chio(&["proof", "verify", utf8_path(&output_file).as_str()]);
    assert_success(&verify);
}

#[test]
fn proof_export_public_redaction_preserves_collected_catalog_negative_artifacts() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let collected_bundle = tempdir.path().join("collected-commerce-passport");
    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&collected_bundle).as_str(),
    ]);
    assert_success(&collect);
    let output_file = tempdir.path().join("collected-commerce-public.tgz");

    let export = chio(&[
        "proof",
        "export",
        utf8_path(&collected_bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
        "--redact",
        "public",
    ]);
    assert_success(&export);

    let verify = chio(&["proof", "verify", utf8_path(&output_file).as_str()]);
    assert_success(&verify);
}

#[test]
fn proof_export_rejects_unsupported_archive_extension() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.zip");
    let output_file = utf8_path(&output_file);

    let output = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);

    assert_failure(&output, "unsupported proof export archive extension");
    assert!(!Path::new(&output_file).exists());
}

#[test]
fn proof_export_rejects_passport_directory_without_proof_room_manifest() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("passport-only.tgz");
    let output_file = utf8_path(&output_file);

    let output = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);

    assert_failure(&output, "proof room bundle manifest missing");
    assert!(!Path::new(&output_file).exists());
}

#[test]
fn proof_verify_accepts_exported_tgz_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tgz");
    let output_file = utf8_path(&output_file);

    let export = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);
    assert_success(&export);

    let verify = chio(&["proof", "verify", output_file.as_str()]);

    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-minimal-valid\""));
}

#[cfg(unix)]
#[test]
fn proof_verify_rejects_exported_bundle_symlink_member() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let outside_passport = tempdir.path().join("outside-passport.json");
    std::fs::write(&outside_passport, "{}\n").test_expect("write outside passport");
    let archive_path = tempdir.path().join("unsafe-proof.tgz");
    write_tgz_with_symlink_member(&archive_path, &outside_passport);

    let output = chio(&["proof", "verify", utf8_path(&archive_path).as_str()]);

    assert_failure(&output, "proof archive contains a non-regular member");
}

#[cfg(unix)]
#[test]
fn proof_verify_rejects_exported_zstd_bundle_symlink_member() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let outside_passport = tempdir.path().join("outside-passport.json");
    std::fs::write(&outside_passport, "{}\n").test_expect("write outside passport");
    let archive_path = tempdir.path().join("unsafe-proof.tar.zst");
    write_tar_zst_with_symlink_member(&archive_path, &outside_passport);

    let output = chio(&["proof", "verify", utf8_path(&archive_path).as_str()]);

    assert_failure(&output, "proof archive contains a non-regular member");
}

#[test]
fn proof_verify_rejects_invalid_proof_room_bundle() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("report-hash-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str()]);

    assert_failure(&output, &expected);
}

#[test]
fn proof_verify_rejects_proof_room_signature_payload_hash_mismatch() {
    let (_tempdir, bundle) = copy_proof_room_bundle_to_temp();
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    signature["payloadRef"]["sha256"] = serde_json::Value::String("0".repeat(64));
    write_json(&signature_path, &signature);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str()]);

    assert_failure(&output, "proof-room.signature.payload-hash-mismatch");
}

#[test]
fn proof_verify_root_passport_input_revalidates_enclosing_proof_room_bundle() {
    let (_tempdir, bundle) = copy_proof_room_bundle_to_temp();
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    signature["payloadRef"]["sha256"] = serde_json::Value::String("0".repeat(64));
    write_json(&signature_path, &signature);
    let passport_path = bundle.join("roots/transaction-passport.json");

    let output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);

    assert_failure(&output, "proof-room.signature.payload-hash-mismatch");
}

#[test]
fn proof_verify_rejects_proof_room_manifest_schema_drift() {
    let (_tempdir, bundle) = copy_proof_room_bundle_to_temp();

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["unshipped_public_field"] = serde_json::Value::String("accepted".to_string());
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, [&manifest_bytes[..], b"\n"].concat())
        .test_expect("write manifest");
    refresh_bundle_signature(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str()]);

    assert_failure(&output, "proof-room.schema-violation: manifest");
}

#[test]
fn proof_verify_rejects_manifested_artifact_schema_drift() {
    let (_tempdir, bundle) = copy_proof_room_bundle_to_temp();
    let docker_evidence_path = bundle.join("artifacts/release/docker-quickstart-evidence.json");
    let mut docker_evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&docker_evidence_path).test_expect("read evidence"))
            .test_expect("evidence parses");
    docker_evidence["endpoints"] = serde_json::Value::Array(Vec::new());
    write_json(&docker_evidence_path, &docker_evidence);
    refresh_manifest_artifact_ref(&bundle, "artifacts/release/docker-quickstart-evidence.json");
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str()]);

    assert_failure(&output, "proof-room.schema-violation: artifact");
}

#[test]
fn proof_export_and_verify_support_tar_zst_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tar.zst");
    let output_file = utf8_path(&output_file);

    let export = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);
    assert_success(&export);

    let verify = chio(&["proof", "verify", output_file.as_str()]);

    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-minimal-valid\""));
}

#[test]
fn proof_explain_accepts_exported_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tar.zst");
    let output_file = utf8_path(&output_file);

    let export = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);
    assert_success(&export);

    let explain = chio(&[
        "proof",
        "explain",
        output_file.as_str(),
        "--claim",
        "claim.proof_room.verifier_report_bound",
        "--json",
    ]);

    assert_success(&explain);
    let stdout = stdout(explain);
    assert!(stdout.contains("\"claim_id\":\"claim.proof_room.verifier_report_bound\""));
    assert!(stdout.contains("\"status\":\"verified\""));
    assert!(stdout.contains("verifier/report.json"));
}

#[test]
fn proof_explain_rejects_invalid_proof_room_bundle() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("missing-authority-evidence");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.proof_room.authority_evidence_bound",
        "--json",
    ]);

    assert_failure(&output, &expected);
}

#[test]
fn proof_export_rejects_invalid_proof_room_bundle_without_archive() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("receipt-coverage-status-mismatch");
    let out = bundle.join("invalid-proof-room.tgz");
    let bundle = utf8_path(&bundle);
    let output_file = utf8_path(&out);

    let output = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);

    assert_failure(&output, &expected);
    assert!(!out.exists());
}

#[cfg(unix)]
#[test]
fn proof_export_rejects_bundle_with_symlink_member() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    std::os::unix::fs::symlink("manifest.json", bundle.join("manifest-link.json"))
        .test_expect("create manifest symlink");
    let output_file = tempdir.path().join("proof-room.tgz");

    let output = chio(&[
        "proof",
        "export",
        utf8_path(&bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
    ]);

    assert_failure(&output, "unsupported proof bundle file type");
    assert!(!output_file.exists());
}

#[test]
fn proof_serve_dry_run_reports_static_root() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"schema\":\"chio.proof.serve-report.v1\""));
    assert!(stdout.contains("\"verifier_parity\":\"verified\""));
    let report: serde_json::Value = serde_json::from_str(&stdout).test_expect("serve report json");
    let static_root = report
        .get("static_root")
        .and_then(serde_json::Value::as_str)
        .test_expect("serve report static root");
    assert!(static_root.ends_with("proof-room-bundle"));
    assert!(!static_root.ends_with("ui/proof-room-static"));
}

#[test]
fn proof_serve_dry_run_rejects_configured_static_ui_without_index() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let ui_dir = tempdir.path().join("empty-ui-dist");
    std::fs::create_dir_all(&ui_dir).test_expect("create empty ui dir");
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "proof",
            "serve",
            bundle.as_str(),
            "--listen",
            "127.0.0.1:0",
            "--dry-run",
            "--json",
        ])
        .env("CHIO_PROOF_ROOM_UI_DIR", &ui_dir)
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "proof room UI index missing");
}

#[test]
fn proof_serve_json_reports_actual_bound_address_for_ephemeral_port() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "proof",
            "serve",
            bundle.as_str(),
            "--listen",
            "127.0.0.1:0",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .test_expect("spawn proof serve");
    let stdout = child.stdout.take().test_expect("proof serve stdout");
    let _guard = ChildGuard { child };
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
    let manifest = wait_for_http_response(address, "/manifest.json");
    assert!(manifest.starts_with("HTTP/1.1 200"));
}

#[test]
fn proof_serve_json_bind_failure_does_not_emit_success_report() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind occupied loopback port");
    let listen = listener.local_addr().test_expect("read occupied port");
    let listen = listen.to_string();

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        listen.as_str(),
        "--json",
    ]);

    assert_failure(&output, "proof serve bind");
    assert!(
        output.stdout.is_empty(),
        "bind failure emitted stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn proof_serve_dry_run_accepts_minimal_passport_static_bundle() {
    let (_tempdir, bundle) = build_minimal_passport_proof_room_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"schema\":\"chio.proof.serve-report.v1\""));
    assert!(stdout.contains("\"verifier_parity\":\"verified\""));
}

#[test]
fn proof_serve_dry_run_rejects_passport_directory_without_proof_room_manifest() {
    let bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, "proof room bundle manifest missing");
}

#[test]
fn proof_serve_dry_run_rejects_invalid_proof_room_bundle() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("report-hash-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, &expected);
}

#[test]
fn proof_serve_dry_run_rejects_missing_authority_evidence() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("missing-authority-evidence");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, &expected);
}

#[test]
fn proof_serve_dry_run_rejects_missing_authority_graph_node() {
    let (_tempdir, bundle, expected) = mutate_proof_room_bundle("missing-authority-graph-node");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, &expected);
}

#[test]
fn proof_serve_dry_run_rejects_proof_room_negative_case_expected_failure_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["negative_cases"][0]["expected_failure_code"] =
        serde_json::Value::String("expected failure that does not occur".to_string());
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, [&manifest_bytes[..], b"\n"].concat())
        .test_expect("write manifest");
    refresh_bundle_signature(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, "proof-room.negative-case.failure-mismatch");
}

#[test]
fn proof_serve_dry_run_rejects_broad_proof_room_negative_case_failure_code() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    let negative_case = manifest["negative_cases"]
        .as_array_mut()
        .test_expect("manifest negative cases array")
        .iter_mut()
        .find(|negative_case| {
            negative_case.get("id").and_then(serde_json::Value::as_str)
                == Some("report-hash-mismatch")
        })
        .test_expect("report hash negative case exists");
    negative_case["expected_failure_code"] =
        serde_json::Value::String("proof-room.report".to_string());
    negative_case["observed_failure_code"] =
        serde_json::Value::String("proof-room.report".to_string());
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, [&manifest_bytes[..], b"\n"].concat())
        .test_expect("write manifest");

    let negative_path = bundle.join("negatives/report-hash-mismatch.json");
    let mut negative: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&negative_path).test_expect("read negative case"))
            .test_expect("negative case parses");
    negative["expected_failure_code"] = serde_json::Value::String("proof-room.report".to_string());
    write_json(&negative_path, &negative);
    refresh_bundle_signature(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "serve",
        bundle.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, "proof-room.negative-case.failure-mismatch");
}

#[test]
fn proof_serve_rejects_collected_family_report_not_recomputed_from_passport() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let (_source_tempdir, passport_bundle) = build_commerce_settlement_passport_bundle();
    let collected_bundle = tempdir.path().join("collected-commerce-settlement");
    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&passport_bundle).as_str(),
        "--out",
        utf8_path(&collected_bundle).as_str(),
    ]);
    assert_success(&collect);

    let verifier_report_path = collected_bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&verifier_report_path).test_expect("read report"))
            .test_expect("report parses");
    let family_reports = verifier_report["family_reports"]
        .as_array_mut()
        .test_expect("family reports array");
    assert!(
        family_reports.len() > 1,
        "collected report should carry multiple family reports"
    );
    family_reports[0]["verdict"] = serde_json::Value::String("failed".to_string());
    write_json(&verifier_report_path, &verifier_report);
    refresh_verifier_report_refs_with_seed(&collected_bundle, COLLECT_SIGNATURE_SEED);

    let output = chio(&[
        "proof",
        "serve",
        utf8_path(&collected_bundle).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_failure(&output, "proof-room.report.mismatch");
}

#[test]
fn proof_serve_hosts_static_ui_and_verifier_bundle_assets() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let ui_dir = tempdir.path().join("ui-dist");
    std::fs::create_dir_all(&ui_dir).test_expect("create ui dir");
    std::fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><title>Proof Room shell</title><main>Proof Room shell</main>",
    )
    .test_expect("write ui index");

    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let bundle = utf8_path(&bundle);
    let server = spawn_proof_serve(Path::new(&bundle), Some(&ui_dir));

    let index = wait_for_http_body(server.address, "/proof-room?view=proof-room");
    let manifest = wait_for_http_body(server.address, "/manifest.json");
    let load_report = wait_for_http_body(server.address, "/ui/proof-room-static/load-report.json");
    let fixture_catalog = wait_for_http_body(server.address, "/proof-room-fixture-catalog.json");

    assert!(index.contains("Proof Room shell"));
    assert!(manifest.contains("\"schema\": \"chio.proof-room.bundle.v1\""));
    assert!(load_report.contains("\"schema\": \"chio.proof-room.verifier-report.v1\""));
    assert!(fixture_catalog.contains("\"schema\":\"chio.proof-room.fixture-catalog.v1\""));
    assert!(fixture_catalog.contains("\"fixture_id\":\"single-call-authority\""));
    let catalog: serde_json::Value =
        serde_json::from_str(&fixture_catalog).test_expect("fixture catalog parses");
    let available_fixture_ids = catalog["available_fixtures"]
        .as_array()
        .test_expect("catalog exposes available fixtures")
        .iter()
        .map(|fixture| {
            fixture["id"]
                .as_str()
                .test_expect("available fixture id")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert!(available_fixture_ids.contains("minimal-passport-valid"));
    assert!(available_fixture_ids.contains("commerce-offline-psp"));
    assert!(available_fixture_ids.contains("recursive-runtime-swarm"));
}

#[test]
fn proof_serve_does_not_host_unmanifested_bundle_files() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let internal_dir = bundle.join("artifacts/internal");
    std::fs::create_dir_all(&internal_dir).test_expect("create internal artifact dir");
    std::fs::write(
        internal_dir.join("debug-notes.json"),
        br#"{"schema":"debug-notes.v1","note":"not manifest evidence"}"#,
    )
    .test_expect("write internal debug notes");

    let server = spawn_proof_serve(&bundle, None);

    let manifest = wait_for_http_response(server.address, "/manifest.json");
    let internal_file =
        wait_for_http_response(server.address, "/artifacts/internal/debug-notes.json");

    assert!(manifest.starts_with("HTTP/1.1 200"), "{manifest}");
    assert!(
        !internal_file.starts_with("HTTP/1.1 200"),
        "{internal_file}"
    );
}

#[test]
fn proof_serve_hosts_fixture_catalog_asset_links() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let ui_dir = tempdir.path().join("ui-dist");
    std::fs::create_dir_all(&ui_dir).test_expect("create ui dir");
    std::fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><title>Proof Room shell</title><main>Proof Room shell</main>",
    )
    .test_expect("write ui index");

    let bundle = proof_room_bundle_fixture();
    let server = spawn_proof_serve(&bundle, Some(&ui_dir));

    let passport = wait_for_http_body(
        server.address,
        "/proof-room-fixtures/minimal-passport-valid/transaction-passport.json",
    );
    let verifier_report = wait_for_http_body(
        server.address,
        "/proof-room-fixtures/minimal-passport-valid/verifier-report.json",
    );
    let negative_verifier_response = wait_for_http_response(
        server.address,
        "/proof-room-fixtures/minimal-passport-policy-digest-mismatch/verifier-report.json",
    );
    assert!(
        negative_verifier_response.starts_with("HTTP/1.1 422"),
        "{negative_verifier_response}"
    );
    let negative_verifier_report = negative_verifier_response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .test_expect("negative verifier response has body");

    assert!(passport.contains("\"schema\":\"chio.transaction-passport.v1\""));
    assert!(passport.contains("\"id\":\"passport-minimal-valid\""));
    assert!(verifier_report.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(verifier_report.contains("\"verdict\":\"verified\""));
    assert!(negative_verifier_report.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(negative_verifier_report.contains("\"verdict\":\"failed\""));
    assert!(negative_verifier_report.contains("verifier policy digest mismatch"));
}

#[test]
fn proof_serve_root_opens_proof_room_view() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let ui_dir = tempdir.path().join("ui-dist");
    std::fs::create_dir_all(&ui_dir).test_expect("create ui dir");
    std::fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><title>Proof Room shell</title><main>Proof Room shell</main>",
    )
    .test_expect("write ui index");

    let bundle = workspace_root()
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let server = spawn_proof_serve(&bundle, Some(&ui_dir));

    let response = wait_for_http_response(server.address, "/");

    assert!(
        response.starts_with("HTTP/1.1 307"),
        "expected root redirect, got:\n{response}"
    );
    assert!(response.contains("location: /proof-room?view=proof-room"));
}

#[test]
fn proof_serve_hosts_minimal_passport_bundle_root_artifacts_with_ui() {
    let (_bundle_tempdir, bundle) = build_minimal_passport_proof_room_bundle();
    let ui_tempdir = tempfile::tempdir().test_expect("ui tempdir");
    let ui_dir = ui_tempdir.path().join("ui-dist");
    std::fs::create_dir_all(&ui_dir).test_expect("create ui dir");
    std::fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><title>Proof Room shell</title><main>Proof Room shell</main>",
    )
    .test_expect("write ui index");

    let server = spawn_proof_serve(&bundle, Some(&ui_dir));

    let index = wait_for_http_body(server.address, "/proof-room?view=proof-room");
    let artifact_response =
        http_get(server.address, "/kernel-receipt.json").test_expect("read root artifact response");

    assert!(index.contains("Proof Room shell"));
    assert!(
        artifact_response.starts_with("HTTP/1.1 200"),
        "{artifact_response}"
    );
    assert!(artifact_response.contains("\"schema\":\"chio.receipt.v1\""));
}

#[test]
fn proof_serve_hosts_exported_bundle_assets() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);
    let output_file = tempdir.path().join("proof-room.tar.zst");
    let output_file = utf8_path(&output_file);
    let export = chio(&[
        "proof",
        "export",
        bundle.as_str(),
        "--out",
        output_file.as_str(),
    ]);
    assert_success(&export);

    let server = spawn_proof_serve(Path::new(&output_file), None);

    let manifest = wait_for_http_body(server.address, "/manifest.json");
    let load_report = wait_for_http_body(server.address, "/ui/proof-room-static/load-report.json");

    assert!(manifest.contains("\"schema\": \"chio.proof-room.bundle.v1\""));
    assert!(load_report.contains("\"schema\": \"chio.proof-room.verifier-report.v1\""));
}
