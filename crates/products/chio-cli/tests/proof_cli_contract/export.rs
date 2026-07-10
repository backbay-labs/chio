use super::support::*;
use chio_test_support::prelude::*;
use std::path::Path;

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
fn proof_export_public_redaction_requires_configured_signer() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle = proof_room_bundle_fixture();
    let output_file = tempdir.path().join("proof-room-public.tgz");
    let mut command = chio_command();
    let output = command
        .env_remove("CHIO_PROOF_EXPORT_BUNDLE_SIGNER_SEED_HEX")
        .args([
            "proof",
            "export",
            utf8_path(&bundle).as_str(),
            "--out",
            utf8_path(&output_file).as_str(),
            "--redact",
            "public",
        ])
        .output()
        .test_expect("proof export runs");

    assert_failure(
        &output,
        "public proof export requires CHIO_PROOF_EXPORT_BUNDLE_SIGNER_SEED_HEX",
    );
    assert!(!output_file.exists());
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
fn proof_export_public_redaction_excludes_manifested_receipt_log() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let receipt_log_path = "receipts.ndjson";
    let receipt_log_file = bundle.join(receipt_log_path);
    std::fs::write(
        &receipt_log_file,
        b"{\"schema\":\"chio.receipts.log.v1\",\"tenant_id\":\"tenant-secret\",\"body\":\"raw receipt body\"}\n",
    )
    .test_expect("write receipt log");
    let tenant_body_path = "tenants/tenant-secret/body.json";
    let tenant_body_file = bundle.join(tenant_body_path);
    std::fs::create_dir_all(
        tenant_body_file
            .parent()
            .test_expect("tenant body has parent"),
    )
    .test_expect("create tenant body dir");
    std::fs::write(
        &tenant_body_file,
        b"{\"schema\":\"chio.tenant.body.v1\",\"tenant_id\":\"tenant-secret\",\"body\":\"private tenant body\"}\n",
    )
    .test_expect("write tenant body");

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .push(serde_json::json!({
            "path": receipt_log_path,
            "sha256": sha256_file(&receipt_log_file),
            "schema": "chio.receipts.log.v1",
            "media_type": "application/json",
            "artifact_class": "receipt-log",
            "sensitivity_class": "public",
            "producer": "test-fixture",
            "participates_in_primary_verdict": false,
            "renderer_hint": "hidden"
        }));
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .push(serde_json::json!({
            "path": tenant_body_path,
            "sha256": sha256_file(&tenant_body_file),
            "schema": "chio.tenant.body.v1",
            "media_type": "application/json",
            "artifact_class": "tenant-body",
            "sensitivity_class": "public",
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
    assert!(!members.contains(receipt_log_path));
    assert!(!members.contains(tenant_body_path));

    let verify = chio(&["proof", "verify", utf8_path(&output_file).as_str()]);
    assert_success(&verify);
}

#[test]
fn proof_export_admin_full_evidence_v1_preserves_manifested_private_evidence() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    let receipt_log_path = "receipts.ndjson";
    let receipt_log_file = bundle.join(receipt_log_path);
    std::fs::write(
        &receipt_log_file,
        b"{\"schema\":\"chio.receipts.log.v1\",\"tenant_id\":\"tenant-secret\",\"body\":\"raw receipt body\"}\n",
    )
    .test_expect("write receipt log");
    let tenant_body_path = "tenants/tenant-secret/body.json";
    let tenant_body_file = bundle.join(tenant_body_path);
    std::fs::create_dir_all(
        tenant_body_file
            .parent()
            .test_expect("tenant body has parent"),
    )
    .test_expect("create tenant body dir");
    std::fs::write(
        &tenant_body_file,
        b"{\"schema\":\"chio.tenant.body.v1\",\"tenant_id\":\"tenant-secret\",\"body\":\"private tenant body\"}\n",
    )
    .test_expect("write tenant body");

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .push(serde_json::json!({
            "path": receipt_log_path,
            "sha256": sha256_file(&receipt_log_file),
            "schema": "chio.receipts.log.v1",
            "media_type": "application/json",
            "artifact_class": "receipt-log",
            "sensitivity_class": "restricted",
            "producer": "test-fixture",
            "participates_in_primary_verdict": false,
            "renderer_hint": "hidden"
        }));
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .push(serde_json::json!({
            "path": tenant_body_path,
            "sha256": sha256_file(&tenant_body_file),
            "schema": "chio.tenant.body.v1",
            "media_type": "application/json",
            "artifact_class": "tenant-body",
            "sensitivity_class": "restricted",
            "producer": "test-fixture",
            "participates_in_primary_verdict": false,
            "renderer_hint": "hidden"
        }));
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output_file = tempdir.path().join("proof-room-admin-full.tgz");
    let output = chio(&[
        "proof",
        "export",
        utf8_path(&bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
        "--redact",
        "admin-full-evidence-v1",
    ]);

    assert_success(&output);
    let members = tgz_member_names(&output_file);
    assert!(members.contains(receipt_log_path));
    assert!(members.contains(tenant_body_path));

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
fn proof_export_public_redaction_honors_manifest_ref_paths_and_signature_ref() {
    let (_bundle_tempdir, bundle) = build_minimal_passport_proof_room_bundle();
    let output_tempdir = tempfile::tempdir().test_expect("output tempdir");

    move_bundle_member(
        &bundle,
        "roots/transaction-passport.json",
        "public-roots/passport.json",
    );
    move_bundle_member(
        &bundle,
        "roots/evidence-graph.json",
        "public-roots/graph.json",
    );
    move_bundle_member(
        &bundle,
        "roots/claim-set.json",
        "public-roots/claim-set.json",
    );
    move_bundle_member(
        &bundle,
        "roots/verifier-policy.json",
        "public-roots/verifier-policy.json",
    );
    move_bundle_member(
        &bundle,
        "verifier/report.json",
        "public-verifier/report.json",
    );
    move_bundle_member(
        &bundle,
        "ui/proof-room-static/load-report.json",
        "public-ui/load-report.json",
    );
    move_bundle_member(
        &bundle,
        "bundle-signature.dsse.json",
        "signatures/bundle.dsse.json",
    );

    let evidence_graph_path = bundle.join("public-roots/graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    replace_manifest_path_strings(
        &mut evidence_graph,
        &[(
            "roots/verifier-policy.json",
            "public-roots/verifier-policy.json",
        )],
    );
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("public-roots/passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_path"] = serde_json::Value::String("graph.json".to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    passport["verifier_policy_path"] =
        serde_json::Value::String("verifier-policy.json".to_string());
    write_json(&passport_path, &passport);

    let verifier_report_path = bundle.join("public-verifier/report.json");
    let mut verifier_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_report_path).test_expect("read verifier report"),
    )
    .test_expect("verifier report parses");
    verifier_report["passport_path"] = serde_json::Value::String("passport.json".to_string());
    verifier_report["evidence_graph_path"] = serde_json::Value::String("graph.json".to_string());
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    verifier_report["verifier_policy_path"] =
        serde_json::Value::String("verifier-policy.json".to_string());
    write_json(&verifier_report_path, &verifier_report);
    let verifier_report_sha256 = sha256_file(&verifier_report_path);

    let ui_report_path = bundle.join("public-ui/load-report.json");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    replace_manifest_path_strings(
        &mut ui_report,
        &[("verifier/report.json", "public-verifier/report.json")],
    );
    ui_report["source_verifier_report_ref"]["path"] =
        serde_json::Value::String("public-verifier/report.json".to_string());
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256);
    write_json(&ui_report_path, &ui_report);

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    replace_manifest_path_strings(
        &mut manifest,
        &[
            (
                "roots/transaction-passport.json",
                "public-roots/passport.json",
            ),
            ("roots/evidence-graph.json", "public-roots/graph.json"),
            ("roots/claim-set.json", "public-roots/claim-set.json"),
            (
                "roots/verifier-policy.json",
                "public-roots/verifier-policy.json",
            ),
            ("verifier/report.json", "public-verifier/report.json"),
            (
                "ui/proof-room-static/load-report.json",
                "public-ui/load-report.json",
            ),
            ("bundle-signature.dsse.json", "signatures/bundle.dsse.json"),
        ],
    );
    refresh_manifest_ref_and_artifact_sha256(
        &bundle,
        &mut manifest,
        "transaction_passport_ref",
        "public-roots/passport.json",
    );
    refresh_manifest_ref_and_artifact_sha256(
        &bundle,
        &mut manifest,
        "evidence_graph_ref",
        "public-roots/graph.json",
    );
    refresh_manifest_ref_and_artifact_sha256(
        &bundle,
        &mut manifest,
        "verifier_report_ref",
        "public-verifier/report.json",
    );
    refresh_manifest_ref_and_artifact_sha256(
        &bundle,
        &mut manifest,
        "proof_room_verifier_report_ref",
        "public-ui/load-report.json",
    );
    refresh_manifest_artifact_sha256(&bundle, &mut manifest, "public-roots/claim-set.json");
    refresh_manifest_artifact_sha256(&bundle, &mut manifest, "public-roots/verifier-policy.json");
    write_json(&manifest_path, &manifest);

    let signature_path = bundle.join("signatures/bundle.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature(&bundle, &mut signature);
    write_json(&signature_path, &signature);

    let input_verify = chio(&["proof", "serve", utf8_path(&bundle).as_str(), "--dry-run"]);
    assert_success(&input_verify);

    let output_file = output_tempdir.path().join("proof-room-public.tgz");
    let export = chio(&[
        "proof",
        "export",
        utf8_path(&bundle).as_str(),
        "--out",
        utf8_path(&output_file).as_str(),
        "--redact",
        "public",
    ]);
    assert_success(&export);

    let members = tgz_member_names(&output_file);
    for path in [
        "public-roots/passport.json",
        "public-roots/graph.json",
        "public-roots/claim-set.json",
        "public-verifier/report.json",
        "public-ui/load-report.json",
        "signatures/bundle.dsse.json",
    ] {
        assert!(members.contains(path), "exported archive missing {path}");
    }
    for path in [
        "roots/transaction-passport.json",
        "roots/evidence-graph.json",
        "roots/claim-set.json",
        "verifier/report.json",
        "ui/proof-room-static/load-report.json",
        "bundle-signature.dsse.json",
    ] {
        assert!(!members.contains(path), "exported archive kept {path}");
    }

    let verify = chio(&[
        "proof",
        "serve",
        utf8_path(&output_file).as_str(),
        "--dry-run",
    ]);
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

fn move_bundle_member(bundle: &Path, from: &str, to: &str) {
    let from_path = bundle.join(from);
    let to_path = bundle.join(to);
    std::fs::create_dir_all(to_path.parent().test_expect("moved member has parent"))
        .test_expect("create moved member parent");
    std::fs::rename(from_path, to_path).test_expect("move bundle member");
}

fn replace_manifest_path_strings(value: &mut serde_json::Value, replacements: &[(&str, &str)]) {
    match value {
        serde_json::Value::String(text) => {
            if let Some((_, replacement)) = replacements.iter().find(|(from, _)| text == from) {
                *text = (*replacement).to_string();
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                replace_manifest_path_strings(value, replacements);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                replace_manifest_path_strings(value, replacements);
            }
        }
        _ => {}
    }
}

fn refresh_manifest_ref_and_artifact_sha256(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    ref_field: &str,
    path: &str,
) {
    let sha256 = sha256_file(&bundle.join(path));
    manifest[ref_field]["sha256"] = serde_json::Value::String(sha256.clone());
    set_manifest_artifact_sha256(manifest, path, &sha256);
}

fn refresh_manifest_artifact_sha256(bundle: &Path, manifest: &mut serde_json::Value, path: &str) {
    let sha256 = sha256_file(&bundle.join(path));
    set_manifest_artifact_sha256(manifest, path, &sha256);
}

fn set_manifest_artifact_sha256(manifest: &mut serde_json::Value, path: &str, sha256: &str) {
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str) == Some(path) {
            artifact["sha256"] = serde_json::Value::String(sha256.to_string());
        }
    }
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

    assert_failure_exit_code(&output, "proof-room.signature.payload-hash-mismatch", 20);
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

    assert_failure_exit_code(&output, "proof-room.signature.payload-hash-mismatch", 20);
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

    assert_failure_exit_code(&output, "proof-room.schema-violation: manifest", 30);
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

    assert_failure_exit_code(&output, "proof-room.schema-violation: artifact", 30);
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
