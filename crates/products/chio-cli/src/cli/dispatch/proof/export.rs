use super::*;
use std::collections::BTreeSet;

const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const PROOF_ROOM_TRUST_ROOTS_PATH: &str = "artifacts/authority/trust-roots.json";
const PROOF_ROOM_EVIDENCE_GRAPH_PATH: &str = "roots/evidence-graph.json";
const PROOF_ROOM_TRANSACTION_PASSPORT_PATH: &str = "roots/transaction-passport.json";
const PROOF_ROOM_VERIFIER_REPORT_PATH: &str = "verifier/report.json";
const PROOF_ROOM_UI_REPORT_PATH: &str = "ui/proof-room-static/load-report.json";

pub(super) fn export_proof_bundle(
    bundle: &Path,
    out: &Path,
    redaction_profile: Option<ProofExportRedactProfile>,
    json_output: bool,
) -> Result<(), CliError> {
    let archive_format = proof_export_archive_format(out)?;
    verify_static_proof_bundle(bundle)?;
    let entries = collect_proof_archive_entries(bundle, redaction_profile)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CliError::cli_io_error(format!(
                    "proof export output already exists: {}",
                    out.display()
                ))
            } else {
                CliError::from(error)
            }
        })?;
    match archive_format {
        ProofExportArchiveFormat::ZstdTar => {
            let encoder = zstd::stream::write::Encoder::new(file, 0)?;
            let mut archive = tar::Builder::new(encoder);
            append_proof_archive_entries(&mut archive, &entries)?;
            archive.finish()?;
            let encoder = archive.into_inner()?;
            encoder.finish()?;
        }
        ProofExportArchiveFormat::GzipTar => {
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            append_proof_archive_entries(&mut archive, &entries)?;
            archive.finish()?;
            let encoder = archive.into_inner()?;
            encoder.finish()?;
        }
    }

    let mut stdout = std::io::stdout();
    if json_output {
        let mut report = serde_json::json!({
            "schema": "chio.proof.export-report.v1",
            "bundle": bundle.to_string_lossy(),
            "out": out.to_string_lossy(),
            "verifier_parity": "verified",
        });
        if let Some(redaction_profile) = redaction_profile {
            report["redaction_profile"] =
                serde_json::Value::String(redaction_profile.as_str().to_string());
        }
        serde_json::to_writer(
            &mut stdout,
            &report,
        )?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(stdout, "exported {} to {}", bundle.display(), out.display())?;
    }
    Ok(())
}

struct ProofArchiveEntry {
    path: String,
    bytes: Vec<u8>,
}

enum ProofExportArchiveFormat {
    GzipTar,
    ZstdTar,
}

pub(super) fn proof_archive_limits() -> crate::archive::SafeArchiveLimits {
    crate::archive::SafeArchiveLimits {
        max_compressed_bytes: 512 * 1024 * 1024,
        max_member_bytes: 128 * 1024 * 1024,
        max_total_bytes: 1024 * 1024 * 1024,
        max_member_count: 8192,
        max_decompression_ratio: 200,
    }
}

fn proof_export_archive_format(path: &Path) -> Result<ProofExportArchiveFormat, CliError> {
    if archive::is_zstd_tar_path(path) {
        Ok(ProofExportArchiveFormat::ZstdTar)
    } else if archive::is_gzip_tar_path(path) {
        Ok(ProofExportArchiveFormat::GzipTar)
    } else {
        Err(CliError::cli_other_error(format!(
            "unsupported proof export archive extension: {} (use .tgz, .tar.gz, or .tar.zst)",
            path.display()
        )))
    }
}

fn collect_proof_archive_entries(
    bundle: &Path,
    redaction_profile: Option<ProofExportRedactProfile>,
) -> Result<Vec<ProofArchiveEntry>, CliError> {
    let root = fs::canonicalize(bundle)?;
    let mut entries = Vec::new();
    collect_proof_archive_entries_from(&root, &root, &mut entries)?;
    if matches!(redaction_profile, Some(ProofExportRedactProfile::Public)) {
        entries = redact_public_proof_archive_entries(&root, entries)?;
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    validate_proof_archive_entries(&entries)?;
    Ok(entries)
}

fn redact_public_proof_archive_entries(
    root: &Path,
    mut entries: Vec<ProofArchiveEntry>,
) -> Result<Vec<ProofArchiveEntry>, CliError> {
    let manifest_path = root.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let redacted_paths = redact_public_manifest_artifacts(&mut manifest)?;
    let export_signer = prepare_public_bundle_export_signer(&mut entries, &mut manifest)?;
    let manifest_bytes = pretty_json_line(&manifest)?;
    let signature_bytes = redact_public_bundle_signature(root, &manifest_bytes, export_signer)?;
    let allowed = public_proof_archive_member_allowlist(root, &manifest)?;
    Ok(entries
        .into_iter()
        .filter_map(|mut entry| {
            if !allowed.contains(&entry.path) {
                return None;
            }
            if entry.path == "manifest.json" {
                entry.bytes = manifest_bytes.clone();
            } else if entry.path == "bundle-signature.dsse.json" {
                entry.bytes = signature_bytes.clone();
            }
            Some(entry)
        })
        .filter(|entry| !redacted_paths.contains(&entry.path))
        .collect())
}

fn redact_public_manifest_artifacts(
    manifest: &mut serde_json::Value,
) -> Result<BTreeSet<String>, CliError> {
    let required_paths = required_public_manifest_paths(manifest)?;
    let mut redacted_paths = BTreeSet::new();
    if let Some(artifacts) = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
    {
        for artifact in artifacts {
            let path = artifact.get("path").and_then(serde_json::Value::as_str);
            let Some(path) = path else {
                continue;
            };
            let sensitivity_class = artifact
                .get("sensitivity_class")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if is_public_sensitivity_class(sensitivity_class) {
                continue;
            }
            let path = crate::archive::safe_archive_member_path(path, "proof archive")?;
            if artifact
                .get("participates_in_primary_verdict")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(CliError::cli_other_error(format!(
                    "public redaction cannot remove primary-verdict artifact: {path}"
                )));
            }
            if required_paths.contains(&path) {
                return Err(CliError::cli_other_error(format!(
                    "public redaction cannot remove required artifact: {path}"
                )));
            }
            redacted_paths.insert(path);
        }
    }

    if redacted_paths.is_empty() {
        return Ok(redacted_paths);
    }

    if let Some(artifacts) = manifest
        .get_mut("artifacts")
        .and_then(serde_json::Value::as_array_mut)
    {
        artifacts.retain(|artifact| {
            artifact
                .get("path")
                .and_then(serde_json::Value::as_str)
                .and_then(|path| crate::archive::safe_archive_member_path(path, "proof archive").ok())
                .is_none_or(|path| !redacted_paths.contains(&path))
        });
    }
    if let Some(advisory_artifacts) = manifest
        .get_mut("advisory_artifacts")
        .and_then(serde_json::Value::as_array_mut)
    {
        advisory_artifacts.retain(|artifact| {
            artifact
                .get("path")
                .and_then(serde_json::Value::as_str)
                .and_then(|path| crate::archive::safe_archive_member_path(path, "proof archive").ok())
                .is_none_or(|path| !redacted_paths.contains(&path))
        });
    }
    let excluded_artifacts = manifest
        .get_mut("excluded_artifacts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            CliError::cli_other_error(
                "public redaction requires excluded_artifacts array in manifest".to_string(),
            )
        })?;
    for path in &redacted_paths {
        if !excluded_artifacts.iter().any(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str) == Some(path.as_str())
        }) {
            excluded_artifacts.push(serde_json::json!({
                "path": path,
                "reason": "excluded by public redaction profile"
            }));
        }
    }

    Ok(redacted_paths)
}

fn required_public_manifest_paths(
    manifest: &serde_json::Value,
) -> Result<BTreeSet<String>, CliError> {
    let mut paths = BTreeSet::new();
    for field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        if let Some(path) = manifest
            .get(field)
            .and_then(|reference| reference.get("path"))
            .and_then(serde_json::Value::as_str)
        {
            insert_allowed_member(&mut paths, path)?;
        }
    }
    if let Some(claims) = manifest.get("claims").and_then(serde_json::Value::as_array) {
        for claim in claims {
            for field in ["required_artifacts", "source_refs"] {
                if let Some(paths_value) = claim.get(field).and_then(serde_json::Value::as_array) {
                    for path in paths_value {
                        if let Some(path) = path.as_str() {
                            insert_allowed_member(&mut paths, path)?;
                        }
                    }
                }
            }
        }
    }
    if let Some(negative_cases) = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
    {
        for negative_case in negative_cases {
            if let Some(path) = negative_case.get("path").and_then(serde_json::Value::as_str) {
                insert_allowed_member(&mut paths, path)?;
            }
        }
    }
    if let Some(coverage) = manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
    {
        for row in coverage {
            if let Some(path) = row.get("artifact_path").and_then(serde_json::Value::as_str) {
                insert_allowed_member(&mut paths, path)?;
            }
        }
    }
    Ok(paths)
}

fn is_public_sensitivity_class(sensitivity_class: &str) -> bool {
    sensitivity_class == "public" || sensitivity_class.starts_with("public-")
}

fn prepare_public_bundle_export_signer(
    entries: &mut [ProofArchiveEntry],
    manifest: &mut serde_json::Value,
) -> Result<Option<chio_core::Keypair>, CliError> {
    if !entries
        .iter()
        .any(|entry| entry.path == "bundle-signature.dsse.json")
    {
        return Ok(None);
    }

    let keypair = chio_core::Keypair::generate();
    if !manifest_artifact_path_exists(manifest, PROOF_ROOM_TRUST_ROOTS_PATH) {
        return Ok(Some(keypair));
    }

    let public_key = keypair.public_key().to_hex();
    let trust_roots_sha256 = update_export_trust_roots(entries, &public_key)?;
    let evidence_graph_sha256 = update_export_evidence_graph_optional_node(
        entries,
        PROOF_ROOM_TRUST_ROOTS_PATH,
        &trust_roots_sha256,
    )?;
    let transaction_passport_sha256 =
        update_export_transaction_passport(entries, &evidence_graph_sha256)?;
    let verifier_report_sha256 = update_export_verifier_report(entries, &evidence_graph_sha256)?;
    let ui_report_sha256 = update_export_ui_report(entries, &verifier_report_sha256)?;

    set_manifest_ref_sha256(
        manifest,
        "transaction_passport_ref",
        &transaction_passport_sha256,
    )?;
    set_manifest_ref_sha256(manifest, "evidence_graph_ref", &evidence_graph_sha256)?;
    set_manifest_ref_sha256(manifest, "verifier_report_ref", &verifier_report_sha256)?;
    set_manifest_ref_sha256(
        manifest,
        "proof_room_verifier_report_ref",
        &ui_report_sha256,
    )?;
    for (path, sha256) in [
        (PROOF_ROOM_TRUST_ROOTS_PATH, trust_roots_sha256.as_str()),
        (PROOF_ROOM_EVIDENCE_GRAPH_PATH, evidence_graph_sha256.as_str()),
        (
            PROOF_ROOM_TRANSACTION_PASSPORT_PATH,
            transaction_passport_sha256.as_str(),
        ),
        (PROOF_ROOM_VERIFIER_REPORT_PATH, verifier_report_sha256.as_str()),
        (PROOF_ROOM_UI_REPORT_PATH, ui_report_sha256.as_str()),
    ] {
        set_manifest_artifact_sha256(manifest, path, sha256)?;
    }

    Ok(Some(keypair))
}

fn manifest_artifact_path_exists(manifest: &serde_json::Value, path: &str) -> bool {
    manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|artifacts| {
            artifacts
                .iter()
                .any(|artifact| artifact.get("path").and_then(serde_json::Value::as_str) == Some(path))
        })
}

fn update_export_trust_roots(
    entries: &mut [ProofArchiveEntry],
    public_key: &str,
) -> Result<String, CliError> {
    let bytes = archive_entry_bytes_mut(entries, PROOF_ROOM_TRUST_ROOTS_PATH)?;
    let mut trust_roots: serde_json::Value = serde_json::from_slice(bytes)?;
    let roots = trust_roots
        .get_mut("roots")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| CliError::cli_other_error("proof room trust roots missing".to_string()))?;
    if roots.is_empty() {
        return Err(CliError::cli_other_error(
            "proof room trust roots missing".to_string(),
        ));
    }
    roots[0]["key_id"] = serde_json::Value::String(public_key.to_string());
    roots[0]["key_digest"] =
        serde_json::Value::String(chio_core::sha256_hex(public_key.as_bytes()));
    *bytes = pretty_json_line(&trust_roots)?;
    Ok(chio_core::sha256_hex(bytes))
}

fn update_export_evidence_graph_optional_node(
    entries: &mut [ProofArchiveEntry],
    artifact_path: &str,
    sha256: &str,
) -> Result<String, CliError> {
    let bytes = archive_entry_bytes_mut(entries, PROOF_ROOM_EVIDENCE_GRAPH_PATH)?;
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(bytes)?;
    let nodes = evidence_graph
        .get_mut("nodes")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            CliError::cli_other_error("proof room evidence graph missing nodes".to_string())
        })?;
    let Some(node) = nodes
        .iter_mut()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path))
    else {
        return Ok(chio_core::sha256_hex(bytes));
    };
    node["sha256"] = serde_json::Value::String(sha256.to_string());
    *bytes = pretty_json_line(&evidence_graph)?;
    Ok(chio_core::sha256_hex(bytes))
}

fn update_export_transaction_passport(
    entries: &mut [ProofArchiveEntry],
    evidence_graph_sha256: &str,
) -> Result<String, CliError> {
    let bytes = archive_entry_bytes_mut(entries, PROOF_ROOM_TRANSACTION_PASSPORT_PATH)?;
    let mut passport: serde_json::Value = serde_json::from_slice(bytes)?;
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.to_string());
    *bytes = pretty_json_line(&passport)?;
    Ok(chio_core::sha256_hex(bytes))
}

fn update_export_verifier_report(
    entries: &mut [ProofArchiveEntry],
    evidence_graph_sha256: &str,
) -> Result<String, CliError> {
    let bytes = archive_entry_bytes_mut(entries, PROOF_ROOM_VERIFIER_REPORT_PATH)?;
    let mut report: serde_json::Value = serde_json::from_slice(bytes)?;
    report["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.to_string());
    *bytes = pretty_json_line(&report)?;
    Ok(chio_core::sha256_hex(bytes))
}

fn update_export_ui_report(
    entries: &mut [ProofArchiveEntry],
    verifier_report_sha256: &str,
) -> Result<String, CliError> {
    let bytes = archive_entry_bytes_mut(entries, PROOF_ROOM_UI_REPORT_PATH)?;
    let mut report: serde_json::Value = serde_json::from_slice(bytes)?;
    report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.to_string());
    *bytes = pretty_json_line(&report)?;
    Ok(chio_core::sha256_hex(bytes))
}

fn archive_entry_bytes_mut<'a>(
    entries: &'a mut [ProofArchiveEntry],
    path: &str,
) -> Result<&'a mut Vec<u8>, CliError> {
    entries
        .iter_mut()
        .find(|entry| entry.path == path)
        .map(|entry| &mut entry.bytes)
        .ok_or_else(|| CliError::cli_other_error(format!("proof archive missing member: {path}")))
}

fn set_manifest_ref_sha256(
    manifest: &mut serde_json::Value,
    field: &str,
    sha256: &str,
) -> Result<(), CliError> {
    let reference = manifest
        .get_mut(field)
        .ok_or_else(|| CliError::cli_other_error(format!("proof manifest missing {field}")))?;
    reference["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

fn set_manifest_artifact_sha256(
    manifest: &mut serde_json::Value,
    path: &str,
    sha256: &str,
) -> Result<(), CliError> {
    let artifacts = manifest
        .get_mut("artifacts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| CliError::cli_other_error("proof manifest missing artifacts".to_string()))?;
    let artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact.get("path").and_then(serde_json::Value::as_str) == Some(path))
        .ok_or_else(|| {
            CliError::cli_other_error(format!("proof manifest missing artifact: {path}"))
        })?;
    artifact["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

fn redact_public_bundle_signature(
    root: &Path,
    manifest_bytes: &[u8],
    signer: Option<chio_core::Keypair>,
) -> Result<Vec<u8>, CliError> {
    let signature_path = root.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
    if signature
        .get("payloadRef")
        .and_then(|payload_ref| payload_ref.get("path"))
        .and_then(serde_json::Value::as_str)
        == Some("manifest.json")
    {
        let keypair = signer.unwrap_or_else(chio_core::Keypair::generate);
        let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, manifest_bytes);
        signature["payloadType"] =
            serde_json::Value::String(PROOF_ROOM_DSSE_PAYLOAD_TYPE.to_string());
        signature["payloadRef"]["sha256"] =
            serde_json::Value::String(chio_core::sha256_hex(manifest_bytes));
        let signatures =
            signature
                .get_mut("signatures")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "proof room bundle signature missing signatures array".to_string(),
                    )
                })?;
        signatures.clear();
        signatures.push(serde_json::json!({
            "keyid": keypair.public_key().to_hex(),
            "sig": keypair.sign(&signed_payload).to_hex()
        }));
    }
    pretty_json_line(&signature)
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

fn pretty_json_line(value: &serde_json::Value) -> Result<Vec<u8>, CliError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn public_proof_archive_member_allowlist(
    root: &Path,
    manifest: &serde_json::Value,
) -> Result<BTreeSet<String>, CliError> {
    let mut members = BTreeSet::new();
    insert_allowed_member(&mut members, "manifest.json")?;
    if root.join("bundle-signature.dsse.json").is_file() {
        insert_allowed_member(&mut members, "bundle-signature.dsse.json")?;
    }
    if root.join("README.md").is_file() {
        insert_allowed_member(&mut members, "README.md")?;
    }
    for field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        if let Some(path) = manifest
            .get(field)
            .and_then(|reference| reference.get("path"))
            .and_then(serde_json::Value::as_str)
        {
            insert_allowed_member(&mut members, path)?;
        }
    }
    if let Some(artifacts) = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
    {
        for artifact in artifacts {
            if let Some(path) = artifact.get("path").and_then(serde_json::Value::as_str) {
                insert_allowed_member(&mut members, path)?;
            }
        }
    }
    if let Some(claims) = manifest.get("claims").and_then(serde_json::Value::as_array) {
        for claim in claims {
            for field in ["required_artifacts", "source_refs"] {
                if let Some(paths) = claim.get(field).and_then(serde_json::Value::as_array) {
                    for path in paths {
                        if let Some(path) = path.as_str() {
                            insert_allowed_member(&mut members, path)?;
                        }
                    }
                }
            }
        }
    }
    if let Some(negative_cases) = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
    {
        for negative_case in negative_cases {
            if let Some(path) = negative_case.get("path").and_then(serde_json::Value::as_str) {
                insert_allowed_negative_case_members(root, &mut members, path)?;
            }
        }
    }
    if let Some(coverage) = manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
    {
        for row in coverage {
            if let Some(path) = row.get("artifact_path").and_then(serde_json::Value::as_str) {
                insert_allowed_member(&mut members, path)?;
            }
        }
    }
    Ok(members)
}

fn insert_allowed_negative_case_members(
    root: &Path,
    members: &mut BTreeSet<String>,
    path: &str,
) -> Result<(), CliError> {
    let path = crate::archive::safe_archive_member_path(path, "proof archive")?;
    members.insert(path.clone());
    let Some(parent) = Path::new(&path).parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let directory = root.join(parent);
    if !directory.is_dir() {
        return Ok(());
    }
    insert_allowed_members_under(root, &directory, members)
}

fn insert_allowed_members_under(
    root: &Path,
    directory: &Path,
    members: &mut BTreeSet<String>,
) -> Result<(), CliError> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let path = child.path();
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_dir() {
            insert_allowed_members_under(root, &path, members)?;
        } else if file_type.is_file() {
            let relative_path = proof_archive_relative_path(root, &path)?;
            members.insert(relative_path);
        } else {
            return Err(CliError::cli_other_error(format!(
                "unsupported proof bundle file type: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn insert_allowed_member(members: &mut BTreeSet<String>, path: &str) -> Result<(), CliError> {
    let path = crate::archive::safe_archive_member_path(path, "proof archive")?;
    members.insert(path);
    Ok(())
}

fn collect_proof_archive_entries_from(
    root: &Path,
    current: &Path,
    entries: &mut Vec<ProofArchiveEntry>,
) -> Result<(), CliError> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let path = child.path();
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_dir() {
            collect_proof_archive_entries_from(root, &path, entries)?;
        } else if file_type.is_file() {
            let relative_path = proof_archive_relative_path(root, &path)?;
            let bytes = fs::read(&path)?;
            entries.push(ProofArchiveEntry {
                path: relative_path,
                bytes,
            });
        } else {
            return Err(CliError::cli_other_error(format!(
                "unsupported proof bundle file type: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn proof_archive_relative_path(root: &Path, path: &Path) -> Result<String, CliError> {
    let relative = path.strip_prefix(root).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof archive member {} is outside bundle root {}: {error}",
            path.display(),
            root.display()
        ))
    })?;
    let relative = relative.to_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof archive member path is not UTF-8: {}",
            path.display()
        ))
    })?;
    crate::archive::safe_archive_member_path(relative, "proof archive")
}

fn validate_proof_archive_entries(entries: &[ProofArchiveEntry]) -> Result<(), CliError> {
    if entries.is_empty() {
        return Err(CliError::cli_other_error(
            "proof archive has no members".to_string(),
        ));
    }
    let limits = proof_archive_limits();
    if entries.len() > limits.max_member_count {
        return Err(CliError::cli_other_error(
            "proof archive has too many members".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut seen_casefold = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in entries {
        let path = crate::archive::safe_archive_member_path(&entry.path, "proof archive")?;
        if !seen.insert(path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "proof archive duplicate member {path}"
            )));
        }
        if !seen_casefold.insert(path.to_ascii_lowercase()) {
            return Err(CliError::cli_other_error(
                "proof archive member has a casefold collision".to_string(),
            ));
        }
        let len = u64::try_from(entry.bytes.len()).map_err(|_| {
            CliError::cli_other_error("proof archive member size overflow".to_string())
        })?;
        if len > limits.max_member_bytes {
            return Err(CliError::cli_other_error(format!(
                "proof archive member {path} exceeds byte limit"
            )));
        }
        total_bytes = total_bytes.checked_add(len).ok_or_else(|| {
            CliError::cli_other_error("proof archive byte count overflow".to_string())
        })?;
        if total_bytes > limits.max_total_bytes {
            return Err(CliError::cli_other_error(
                "proof archive exceeds decompressed byte limit".to_string(),
            ));
        }
    }
    Ok(())
}

fn append_proof_archive_entries<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    entries: &[ProofArchiveEntry],
) -> Result<(), CliError> {
    for entry in entries {
        let path = crate::archive::safe_archive_member_path(&entry.path, "proof archive")?;
        let size = u64::try_from(entry.bytes.len()).map_err(|_| {
            CliError::cli_other_error("proof archive member size overflow".to_string())
        })?;
        let mut header = tar::Header::new_ustar();
        header.set_size(size);
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(
            &mut header,
            path,
            std::io::Cursor::new(entry.bytes.as_slice()),
        )?;
    }
    Ok(())
}
