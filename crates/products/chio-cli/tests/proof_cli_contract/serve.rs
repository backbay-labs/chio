use super::support::*;
use chio_test_support::prelude::*;
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    path::Path,
    process::Stdio,
};

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

    let output = chio_command()
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
    let mut child = chio_command()
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
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest).test_expect("manifest parses");
    assert_eq!(
        manifest.get("schema").and_then(serde_json::Value::as_str),
        Some("chio.proof-room.bundle.v1")
    );
    let load_report: serde_json::Value =
        serde_json::from_str(&load_report).test_expect("load report parses");
    assert_eq!(
        load_report
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some("chio.proof-room.verifier-report.v1")
    );
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
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join("manifest.json")).test_expect("read manifest"),
    )
    .test_expect("manifest parses");
    let negative_case_path = manifest["negative_cases"]
        .as_array()
        .test_expect("negative cases array")
        .first()
        .and_then(|negative_case| negative_case.get("path"))
        .and_then(serde_json::Value::as_str)
        .test_expect("negative case path");
    let negative_case_dir = Path::new(negative_case_path)
        .parent()
        .test_expect("negative case path has parent");
    let negative_debug_dir = bundle.join(negative_case_dir);
    std::fs::write(
        negative_debug_dir.join("debug-notes.json"),
        br#"{"schema":"debug-notes.v1","note":"not manifest negative evidence"}"#,
    )
    .test_expect("write negative debug notes");

    let server = spawn_proof_serve(&bundle, None);

    let manifest = wait_for_http_response(server.address, "/manifest.json");
    let internal_file =
        wait_for_http_response(server.address, "/artifacts/internal/debug-notes.json");
    let negative_internal_file = wait_for_http_response(
        server.address,
        &format!("/{}/debug-notes.json", negative_case_dir.display()),
    );

    assert!(manifest.starts_with("HTTP/1.1 200"), "{manifest}");
    assert!(
        !internal_file.starts_with("HTTP/1.1 200"),
        "{internal_file}"
    );
    assert!(
        !negative_internal_file.starts_with("HTTP/1.1 200"),
        "{negative_internal_file}"
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

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest).test_expect("manifest parses");
    assert_eq!(
        manifest.get("schema").and_then(serde_json::Value::as_str),
        Some("chio.proof-room.bundle.v1")
    );
    let load_report: serde_json::Value =
        serde_json::from_str(&load_report).test_expect("load report parses");
    assert_eq!(
        load_report
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some("chio.proof-room.verifier-report.v1")
    );
}
