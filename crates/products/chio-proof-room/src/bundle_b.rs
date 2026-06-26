use super::*;

pub(crate) fn verify_proof_room_report(
    bytes: &[u8],
    bundle_id: &str,
    fixture_id: &str,
    verifier_report_ref: &ProofRoomArtifactRef,
    source_verifier_verdict: &str,
    manifest_claims: &[ProofRoomClaim],
) -> Result<(), String> {
    let report_value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.ui-report.invalid-json: {error}"))?;
    validate_proof_room_schema(
        &report_value,
        PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON,
        "ui-report",
    )?;
    let report: ProofRoomVerifierReport = serde_json::from_value(report_value)
        .map_err(|error| format!("proof-room.ui-report.invalid-json: {error}"))?;
    if report.schema != PROOF_ROOM_VERIFIER_REPORT_SCHEMA {
        return Err(format!(
            "proof-room.ui-report.schema-mismatch: expected {PROOF_ROOM_VERIFIER_REPORT_SCHEMA}"
        ));
    }
    if report.bundle_id != bundle_id {
        return Err("proof-room.ui-report.bundle-mismatch".to_string());
    }
    if report.fixture_id != fixture_id {
        return Err("proof-room.ui-report.fixture-mismatch".to_string());
    }
    if report.verdict != "verified" && report.verdict != "failed" {
        return Err("proof-room.ui-report.verdict-not-verified".to_string());
    }
    if report.verdict != source_verifier_verdict {
        return Err("proof-room.ui-report.verdict-mismatch".to_string());
    }
    if report.ui_verdict_source != "verifier_report_ref" {
        return Err("proof-room.ui.verdict-unauthenticated".to_string());
    }
    if report.source_verifier_report_ref.path != verifier_report_ref.path
        || report.source_verifier_report_ref.sha256 != verifier_report_ref.sha256
        || report.source_verifier_report_ref.schema != verifier_report_ref.schema
    {
        return Err("proof-room.report.hash-mismatch: UI report source ref drifted".to_string());
    }
    verify_rendered_claims(
        &report.rendered_claims,
        verifier_report_ref,
        manifest_claims,
    )?;
    Ok(())
}

pub(crate) fn verify_rendered_claims(
    rendered_claims: &[ProofRoomRenderedClaim],
    verifier_report_ref: &ProofRoomArtifactRef,
    manifest_claims: &[ProofRoomClaim],
) -> Result<(), String> {
    if rendered_claims.is_empty() {
        return Err("proof-room.ui-report.rendered-claims-missing".to_string());
    }
    let mut rendered_claim_ids = BTreeSet::new();
    for rendered_claim in rendered_claims {
        if !rendered_claim_ids.insert(rendered_claim.claim_id.as_str()) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-duplicate: {}",
                rendered_claim.claim_id
            ));
        }
        let Some(manifest_claim) = manifest_claims
            .iter()
            .find(|claim| claim.claim_id == rendered_claim.claim_id)
        else {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-unbacked: {}",
                rendered_claim.claim_id
            ));
        };
        if rendered_claim.source != verifier_report_ref.path
            && !manifest_claim
                .required_artifacts
                .iter()
                .any(|artifact| artifact == &rendered_claim.source)
        {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-source-unbacked: {} -> {}",
                rendered_claim.claim_id, rendered_claim.source
            ));
        }
        if !matches!(
            rendered_claim.verdict.as_str(),
            "verified" | "failed" | "unsupported"
        ) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-verdict-invalid: {}",
                rendered_claim.claim_id
            ));
        }
        if rendered_claim.verdict != manifest_claim.result {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-result-mismatch: {}",
                rendered_claim.claim_id
            ));
        }
        if rendered_claim.verdict == "verified"
            && !manifest_claim
                .required_artifacts
                .iter()
                .any(|artifact| artifact == &rendered_claim.source)
        {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-source-unbacked: {} -> {}",
                rendered_claim.claim_id, rendered_claim.source
            ));
        }
    }
    for manifest_claim in manifest_claims {
        if !rendered_claim_ids.contains(manifest_claim.claim_id.as_str()) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-missing: {}",
                manifest_claim.claim_id
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_json_artifact_schema(
    bytes: &[u8],
    expected_schema: &str,
    label: &str,
) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.artifact.invalid-json: {label}: {error}"))?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(actual_schema) if actual_schema == expected_schema => Ok(()),
        Some(actual_schema) => Err(format!(
            "proof-room.schema-mismatch: {label} expected {expected_schema} got {actual_schema}"
        )),
        None => Err(format!(
            "proof-room.schema-missing: {label} missing schema field"
        )),
    }?;
    if let Some(schema_json) = proof_room_artifact_schema_json(expected_schema) {
        validate_proof_room_schema(&value, schema_json, label)?;
    }
    Ok(())
}

pub(crate) fn proof_room_artifact_schema_json(schema: &str) -> Option<&'static str> {
    match schema {
        PROOF_ROOM_VERIFIER_REPORT_SCHEMA => Some(PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON),
        PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA => {
            Some(PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA_JSON)
        }
        PROOF_ROOM_RELEASE_TRUTH_SCHEMA => Some(PROOF_ROOM_RELEASE_TRUTH_SCHEMA_JSON),
        PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA_JSON)
        }
        PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA => Some(PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA_JSON),
        TRANSACTION_REQUEST_DIGEST_SCHEMA => Some(TRANSACTION_REQUEST_DIGEST_SCHEMA_JSON),
        TRANSACTION_RESPONSE_DIGEST_SCHEMA => Some(TRANSACTION_RESPONSE_DIGEST_SCHEMA_JSON),
        RUNTIME_TERMINAL_RECEIPT_SCHEMA => Some(RUNTIME_TERMINAL_RECEIPT_SCHEMA_JSON),
        RUNTIME_TRUSTED_TIME_PROOF_SCHEMA => Some(RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_JSON),
        _ => None,
    }
}

pub(crate) fn validate_proof_room_schema(
    value: &serde_json::Value,
    schema_json: &str,
    label: &str,
) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|error| format!("proof-room.schema-invalid: {label}: {error}"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("proof-room.schema-invalid: {label}: {error}"))?;
    if validator.is_valid(value) {
        return Ok(());
    }
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    Err(format!("proof-room.schema-violation: {label}: {errors}"))
}

pub(crate) fn resolve_proof_room_bundle_path(
    bundle_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validate_bundle_relative_path(relative_path)?;
    let bundle_root = fs::canonicalize(bundle_root)
        .map_err(|error| format!("proof-room.bundle.unreadable: {error}"))?;
    let joined_path = bundle_root.join(relative_path);
    let resolved_path = fs::canonicalize(&joined_path)
        .map_err(|error| format!("proof-room.artifact.unreadable: {relative_path}: {error}"))?;
    if resolved_path.starts_with(&bundle_root) {
        Ok(resolved_path)
    } else {
        Err(format!(
            "proof-room.artifact.escape: artifact path escapes bundle: {relative_path}"
        ))
    }
}

pub(crate) fn resolve_nested_bundle_path(
    bundle_root: &Path,
    base_dir: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validate_bundle_relative_path(relative_path)?;
    let bundle_root = fs::canonicalize(bundle_root)
        .map_err(|error| format!("proof-room.bundle.unreadable: {error}"))?;
    let joined_path = base_dir.join(relative_path);
    let resolved_path = fs::canonicalize(&joined_path)
        .map_err(|error| format!("proof-room.artifact.unreadable: {relative_path}: {error}"))?;
    if resolved_path.starts_with(&bundle_root) {
        Ok(resolved_path)
    } else {
        Err(format!(
            "proof-room.artifact.escape: artifact path escapes bundle: {relative_path}"
        ))
    }
}

pub(crate) fn validate_bundle_relative_path(relative_path: &str) -> Result<(), String> {
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(unsafe_bundle_path_error(relative_path));
    }
    for segment in relative_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(unsafe_bundle_path_error(relative_path));
        }
        let decoded = percent_decode_path_segment(segment, relative_path)?;
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(unsafe_bundle_path_error(relative_path));
        }
    }
    Ok(())
}

pub(crate) fn percent_decode_path_segment(
    segment: &str,
    full_path: &str,
) -> Result<String, String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(unsafe_bundle_path_error(full_path));
            }
            let high =
                hex_value(bytes[index + 1]).ok_or_else(|| unsafe_bundle_path_error(full_path))?;
            let low =
                hex_value(bytes[index + 2]).ok_or_else(|| unsafe_bundle_path_error(full_path))?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| unsafe_bundle_path_error(full_path))
}

pub(crate) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn unsafe_bundle_path_error(relative_path: &str) -> String {
    format!("proof-room.artifact.unsafe-path: {relative_path}")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn default_base_manifest() -> String {
    "manifest.json".to_string()
}

static NEGATIVE_CASE_TEMP_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn create_negative_case_work_dir(case_id: &str) -> Result<PathBuf, String> {
    let case_id = sanitize_temp_path_component(case_id);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("proof-room.negative-case.clock: {error}"))?
        .as_nanos();
    for _ in 0..1024 {
        let sequence =
            NEGATIVE_CASE_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = env::temp_dir();
        path.push(format!(
            "chio-proof-room-negative-{}-{timestamp}-{sequence}-{case_id}",
            process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "proof-room.negative-case.tempdir: {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err(format!(
        "proof-room.negative-case.tempdir: exhausted unique path attempts for {case_id}"
    ))
}

pub(crate) fn sanitize_temp_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn validate_bundle_tree_file_types(root: &Path) -> Result<(), String> {
    let file_type = fs::symlink_metadata(root)
        .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", root.display()))?
        .file_type();
    if !file_type.is_dir() {
        return Err(format!(
            "unsupported proof bundle file type: {}",
            root.display()
        ));
    }
    validate_bundle_tree_file_types_from(root)
}

pub(crate) fn validate_bundle_tree_file_types_from(current: &Path) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", current.display()))?
    {
        let entry = entry
            .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", current.display()))?;
        let path = entry.path();
        let file_type = fs::symlink_metadata(&path)
            .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", path.display()))?
            .file_type();
        if file_type.is_dir() {
            validate_bundle_tree_file_types_from(&path)?;
        } else if !file_type.is_file() {
            return Err(format!(
                "unsupported proof bundle file type: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "proof-room.negative-case.copy: {}: {error}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "proof-room.negative-case.copy: {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "proof-room.negative-case.copy: {}: {error}",
                source.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "proof-room.negative-case.copy: {}: {error}",
                entry.path().display()
            )
        })?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &destination_path).map_err(|error| {
                format!(
                    "proof-room.negative-case.copy: {}: {error}",
                    destination_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "proof-room.negative-case.copy: unsupported file type: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn apply_proof_room_negative_descriptor(
    bundle: &Path,
    descriptor: &ProofRoomNegativeDescriptor,
) -> Result<(), String> {
    let manifest_path = resolve_proof_room_bundle_path(bundle, &descriptor.base_manifest)?;
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("proof-room.negative-case.manifest: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.manifest-json: {error}"))?;
    let mutation = &descriptor.mutation;

    if let Some(path) = mutation.get("path").and_then(serde_json::Value::as_array) {
        let value = mutation
            .get("value")
            .ok_or_else(|| "proof-room.negative-case.mutation-value-missing".to_string())?;
        set_json_path(&mut manifest, path, value.clone())?;
    } else if let Some(category) = mutation.get("category").and_then(serde_json::Value::as_str) {
        let terminal_status = mutation
            .get("terminal_status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "proof-room.negative-case.terminal-status-missing".to_string())?;
        let coverage =
            find_array_object_mut(&mut manifest, "receipt_coverage", "category", category)?;
        coverage["terminal_status"] = serde_json::Value::String(terminal_status.to_string());
    } else if let Some(artifact_path) = mutation
        .get("artifact_path")
        .and_then(serde_json::Value::as_str)
    {
        if mutation.get("json_path").is_some() {
            mutate_json_artifact_and_rehash(bundle, &mut manifest, artifact_path, mutation)?;
        } else {
            remove_graph_node_and_rehash(bundle, &mut manifest, artifact_path)?;
        }
    } else if let Some(claim_id) = mutation.get("claim_id").and_then(serde_json::Value::as_str) {
        if let Some(required_artifacts) = mutation.get("required_artifacts") {
            let claim = find_array_object_mut(&mut manifest, "claims", "claim_id", claim_id)?;
            claim["required_artifacts"] = required_artifacts.clone();
        } else if let Some(artifact_paths) = mutation
            .get("artifact_paths")
            .and_then(serde_json::Value::as_array)
        {
            if let Some(claims) = manifest
                .get_mut("claims")
                .and_then(serde_json::Value::as_array_mut)
            {
                claims.retain(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) != Some(claim_id)
                });
            }
            let artifact_paths = artifact_paths
                .iter()
                .map(|path| {
                    path.as_str()
                        .ok_or_else(|| "proof-room.negative-case.artifact-path-invalid".to_string())
                        .map(str::to_string)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if let Some(artifacts) = manifest
                .get_mut("artifacts")
                .and_then(serde_json::Value::as_array_mut)
            {
                artifacts.retain(|artifact| {
                    artifact
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|path| !artifact_paths.contains(path))
                });
            }
            for artifact_path in artifact_paths {
                let resolved = resolve_proof_room_bundle_path(bundle, &artifact_path)?;
                fs::remove_file(&resolved).map_err(|error| {
                    format!("proof-room.negative-case.remove-artifact: {artifact_path}: {error}")
                })?;
            }
        } else {
            return Err("proof-room.negative-case.claim-mutation-unsupported".to_string());
        }
    } else {
        return Err("proof-room.negative-case.mutation-unsupported".to_string());
    }

    write_json_file(&manifest_path, &manifest)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn mutate_json_artifact_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
    mutation: &serde_json::Value,
) -> Result<(), String> {
    let json_path = mutation
        .get("json_path")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.negative-case.json-path-missing".to_string())?;
    let value = mutation
        .get("value")
        .ok_or_else(|| "proof-room.negative-case.mutation-value-missing".to_string())?;
    let resolved = resolve_proof_room_bundle_path(bundle, artifact_path)?;
    let mut artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&resolved).map_err(|error| {
            format!("proof-room.negative-case.artifact: {artifact_path}: {error}")
        })?)
        .map_err(|error| {
            format!("proof-room.negative-case.artifact-json: {artifact_path}: {error}")
        })?;
    set_json_path(&mut artifact, json_path, value.clone())?;
    write_json_file(&resolved, &artifact)?;
    let artifact_sha256 = sha256_file(&resolved)?;

    update_graph_node_hash_and_rehash(bundle, manifest, artifact_path, &artifact_sha256)
}

pub(crate) fn find_array_object_mut<'a>(
    value: &'a mut serde_json::Value,
    array_field: &str,
    key: &str,
    expected: &str,
) -> Result<&'a mut serde_json::Value, String> {
    let array = value
        .get_mut(array_field)
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| format!("proof-room.negative-case.array-missing: {array_field}"))?;
    array
        .iter_mut()
        .find(|entry| entry.get(key).and_then(serde_json::Value::as_str) == Some(expected))
        .ok_or_else(|| {
            format!("proof-room.negative-case.array-entry-missing: {array_field}.{key}={expected}")
        })
}

pub(crate) fn set_json_path(
    value: &mut serde_json::Value,
    path: &[serde_json::Value],
    replacement: serde_json::Value,
) -> Result<(), String> {
    let mut cursor = value;
    let Some((last, parents)) = path.split_last() else {
        return Err("proof-room.negative-case.path-empty".to_string());
    };
    for segment in parents {
        let key = segment
            .as_str()
            .ok_or_else(|| "proof-room.negative-case.path-segment-invalid".to_string())?;
        cursor = cursor
            .get_mut(key)
            .ok_or_else(|| format!("proof-room.negative-case.path-missing: {key}"))?;
    }
    let key = last
        .as_str()
        .ok_or_else(|| "proof-room.negative-case.path-segment-invalid".to_string())?;
    let object = cursor
        .as_object_mut()
        .ok_or_else(|| "proof-room.negative-case.path-parent-invalid".to_string())?;
    if !object.contains_key(key) {
        return Err(format!("proof-room.negative-case.path-missing: {key}"));
    }
    object.insert(key.to_string(), replacement);
    Ok(())
}

pub(crate) fn remove_graph_node_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
) -> Result<(), String> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &fs::read(&evidence_graph_path)
            .map_err(|error| format!("proof-room.negative-case.evidence-graph: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.evidence-graph-json: {error}"))?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or_else(|| "proof-room.negative-case.evidence-graph-nodes-missing".to_string())?
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    write_json_file(&evidence_graph_path, &evidence_graph)?;
    refresh_roots_and_manifest_after_evidence_graph_change(bundle, manifest)
}

pub(crate) fn update_graph_node_hash_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
    artifact_sha256: &str,
) -> Result<(), String> {
    set_manifest_artifact_hash(manifest, artifact_path, artifact_sha256)?;
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &fs::read(&evidence_graph_path)
            .map_err(|error| format!("proof-room.negative-case.evidence-graph: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.evidence-graph-json: {error}"))?;
    let node = evidence_graph["nodes"]
        .as_array_mut()
        .ok_or_else(|| "proof-room.negative-case.evidence-graph-nodes-missing".to_string())?
        .iter_mut()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path))
        .ok_or_else(|| {
            format!("proof-room.negative-case.evidence-graph-node-missing: {artifact_path}")
        })?;
    let old_node_id = node
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "proof-room.negative-case.evidence-graph-node-id-missing".to_string())?
        .to_string();
    node["id"] = serde_json::Value::String(artifact_sha256.to_string());
    node["sha256"] = serde_json::Value::String(artifact_sha256.to_string());
    if old_node_id != artifact_sha256 {
        for edge in evidence_graph["edges"]
            .as_array_mut()
            .ok_or_else(|| "proof-room.negative-case.evidence-graph-edges-missing".to_string())?
        {
            if edge.get("from").and_then(serde_json::Value::as_str) == Some(old_node_id.as_str()) {
                edge["from"] = serde_json::Value::String(artifact_sha256.to_string());
            }
            if edge.get("to").and_then(serde_json::Value::as_str) == Some(old_node_id.as_str()) {
                edge["to"] = serde_json::Value::String(artifact_sha256.to_string());
            }
        }
    }
    write_json_file(&evidence_graph_path, &evidence_graph)?;
    refresh_roots_and_manifest_after_evidence_graph_change(bundle, manifest)
}

pub(crate) fn refresh_roots_and_manifest_after_evidence_graph_change(
    bundle: &Path,
    manifest: &mut serde_json::Value,
) -> Result<(), String> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(
        &fs::read(&passport_path)
            .map_err(|error| format!("proof-room.negative-case.passport: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.passport-json: {error}"))?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    write_json_file(&passport_path, &passport)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&verifier_report_path)
            .map_err(|error| format!("proof-room.negative-case.verifier-report: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.verifier-report-json: {error}"))?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    write_json_file(&verifier_report_path, &verifier_report)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&ui_report_path)
            .map_err(|error| format!("proof-room.negative-case.ui-report: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.ui-report-json: {error}"))?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json_file(&ui_report_path, &ui_report)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    set_manifest_hash(manifest, "transaction_passport_ref", &passport_sha256)?;
    set_manifest_hash(manifest, "evidence_graph_ref", &evidence_graph_sha256)?;
    set_manifest_hash(manifest, "verifier_report_ref", &verifier_report_sha256)?;
    set_manifest_hash(
        manifest,
        "proof_room_verifier_report_ref",
        &ui_report_sha256,
    )?;
    set_manifest_artifact_hash(
        manifest,
        "roots/transaction-passport.json",
        &passport_sha256,
    )?;
    set_manifest_artifact_hash(
        manifest,
        "roots/evidence-graph.json",
        &evidence_graph_sha256,
    )?;
    set_manifest_artifact_hash(manifest, "verifier/report.json", &verifier_report_sha256)?;
    set_manifest_artifact_hash(
        manifest,
        "ui/proof-room-static/load-report.json",
        &ui_report_sha256,
    )?;
    Ok(())
}

pub(crate) fn set_manifest_hash(
    manifest: &mut serde_json::Value,
    field: &str,
    sha256: &str,
) -> Result<(), String> {
    let reference = manifest
        .get_mut(field)
        .ok_or_else(|| format!("proof-room.negative-case.manifest-ref-missing: {field}"))?;
    reference["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

pub(crate) fn set_manifest_artifact_hash(
    manifest: &mut serde_json::Value,
    path: &str,
    sha256: &str,
) -> Result<(), String> {
    let artifact = find_array_object_mut(manifest, "artifacts", "path", path)?;
    artifact["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

pub(crate) fn refresh_bundle_signature(bundle: &Path) -> Result<(), String> {
    let manifest_path = bundle.join("manifest.json");
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value = serde_json::from_slice(
        &fs::read(&signature_path)
            .map_err(|error| format!("proof-room.signature.unreadable: {error}"))?,
    )
    .map_err(|error| format!("proof-room.signature.invalid-json: {error}"))?;
    signature["payloadRef"]["sha256"] = serde_json::Value::String(sha256_file(&manifest_path)?);
    write_json_file(&signature_path, &signature)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "proof-room.artifact.unreadable: {}: {error}",
            path.display()
        )
    })?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("proof-room.json.encode: {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes)
        .map_err(|error| format!("proof-room.json.write: {}: {error}", path.display()))
}
